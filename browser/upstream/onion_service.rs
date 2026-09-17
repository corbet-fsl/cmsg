//! Ephemeral browser-owned onion service for the separately patched Arti runtime.
//! No persistent onion identity or introduction-key recovery API is exposed.
use crate::{onion_stream::{OnionStreamRegistry, StreamState}, TorClient};
use futures::{future::{select, AbortHandle, Abortable, Either}, Stream, StreamExt, FutureExt};
use gloo_timers::future::TimeoutFuture;
use safelog::DisplayRedacted as _;
use std::{cell::{Cell, RefCell}, pin::Pin, rc::{Rc, Weak}, sync::Arc};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{HsNickname, OnionServiceConfig, RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use wasm_bindgen::prelude::*;

fn failure() -> JsValue { JsValue::from_str("tor-js:OnionService") }
fn integer(value: f64, maximum: u32) -> Result<u32, JsValue> {
    if !value.is_finite() || value.fract() != 0.0 || value < 1.0 || value > f64::from(maximum) {
        return Err(failure());
    }
    Ok(value as u32)
}

type Requests = Pin<Box<dyn Stream<Item = StreamRequest>>>;

pub(crate) struct ServiceState {
    service: RefCell<Option<Arc<RunningOnionService>>>,
    requests: RefCell<Option<Requests>>,
    accept_abort: RefCell<Option<AbortHandle>>,
    children: RefCell<Vec<Weak<StreamState>>>,
    streams: Rc<OnionStreamRegistry>,
    closed: Cell<bool>,
    port: u16,
    maximum_streams: usize,
}

impl ServiceState {
    pub(crate) fn close(&self) {
        if self.closed.replace(true) { return; }
        if let Some(abort) = self.accept_abort.borrow_mut().take() { abort.abort(); }
        self.requests.borrow_mut().take();
        self.service.borrow_mut().take();
        for stream in self.children.borrow_mut().drain(..).filter_map(|s| s.upgrade()) { stream.close(); }
    }
}

#[wasm_bindgen]
pub struct BrowserOnionService {
    state: Rc<ServiceState>,
    host: String,
    readiness: &'static str,
}

impl Drop for BrowserOnionService { fn drop(&mut self) { self.state.close(); } }

#[wasm_bindgen]
impl BrowserOnionService {
    #[wasm_bindgen(getter)]
    pub fn host(&self) -> String { self.host.clone() }

    #[wasm_bindgen(getter)]
    pub fn port(&self) -> u16 { self.state.port }

    /// Snapshot at successful publication, not a promise of future availability.
    #[wasm_bindgen(getter)]
    pub fn readiness(&self) -> String { self.readiness.to_owned() }

    /// Wait for one accepted byte stream. An idle timeout retains the listener;
    /// explicit service/client close cancels the accept and all child streams.
    pub fn accept(&self, deadline_ms: f64) -> js_sys::Promise {
        let state = Rc::clone(&self.state);
        let deadline = integer(deadline_ms, 60000);
        wasm_bindgen_futures::future_to_promise(async move {
            let deadline = deadline?;
            if state.closed.get() { return Err(failure()); }
            {
                let mut children = state.children.borrow_mut();
                children.retain(|stream| stream.upgrade().is_some_and(|s| !s.is_closed()));
                if children.len() >= state.maximum_streams { return Err(failure()); }
            }
            let mut requests = state.requests.borrow_mut().take().ok_or_else(failure)?;
            let (abort, registration) = AbortHandle::new_pair();
            *state.accept_abort.borrow_mut() = Some(abort);
            let result = {
                let operation = Abortable::new(async {
                    // Bound work from rejected requests as well as wait time.
                    for _ in 0..32 {
                        let request = requests.next().await.ok_or_else(failure)?;
                        if matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == state.port) {
                            let stream = request.accept(Connected::new_empty()).await.map_err(|_| failure())?;
                            return state.streams.track(stream);
                        }
                        request.reject(End::new_with_reason(EndReason::DONE)).await.map_err(|_| failure())?;
                    }
                    Err(failure())
                }, registration).boxed_local();
                match select(operation, TimeoutFuture::new(deadline).boxed_local()).await {
                    Either::Left((Ok(result), _)) => result,
                    _ => Err(failure()),
                }
            };
            state.accept_abort.borrow_mut().take();
            if state.closed.get() { return Err(failure()); }
            *state.requests.borrow_mut() = Some(requests);
            let stream = result?;
            state.children.borrow_mut().push(Rc::downgrade(&stream.state));
            Ok(stream.into())
        })
    }

    pub fn close(&self) { self.state.close(); }
}

#[wasm_bindgen]
impl TorClient {
    #[wasm_bindgen(js_name = onionServiceSupported)]
    pub fn onion_service_supported() -> bool { true }

    /// Launch exactly one ephemeral onion service for this client lifetime.
    /// Return only after Arti reports fully reachable (Running or
    /// DegradedReachable). Actual reachability requires a client connection.
    #[wasm_bindgen(js_name = hostOnion)]
    pub fn host_onion(&self, port: f64, maximum_streams: f64, deadline_ms: f64) -> js_sys::Promise {
        let launch: Result<(BrowserOnionService, u32), JsValue> = (|| {
            let port = integer(port, 65535)? as u16;
            let maximum_streams = integer(maximum_streams, 32)? as usize;
            // Publication can include Arti's five-minute HSDir retry episode.
            // This independent bound does not change stream/accept deadlines.
            let deadline = integer(deadline_ms, 600000)?;
            let client = self.inner.as_ref().ok_or_else(failure)?;
            if self.onion_service_started.replace(true) { return Err(failure()); }
            let config = OnionServiceConfig::builder()
                .nickname(HsNickname::new("cmsg-session".into()).map_err(|_| failure())?)
                .build().map_err(|_| failure())?;
            let (service, rendezvous) = client.launch_onion_service(config)
                .map_err(|_| failure())?.ok_or_else(failure)?;
            let host = service.onion_address().ok_or_else(failure)?.display_unredacted().to_string();
            // Unlike upstream's convenience helper, keep the number of pending
            // rendezvous handshakes finite. Arti still validates every request.
            let requests = rendezvous.flat_map_unordered(Some(maximum_streams), |request| {
                Box::pin(request.accept()).map(|outcome| match outcome {
                    Ok(streams) => Either::Left(streams),
                    Err(_) => Either::Right(futures::stream::empty()),
                }).flatten_stream()
            });
            let state = Rc::new(ServiceState {
                service: RefCell::new(Some(service)), requests: RefCell::new(Some(Box::pin(requests))),
                accept_abort: RefCell::new(None), children: RefCell::new(Vec::new()),
                streams: Rc::clone(&self.onion_streams), closed: Cell::new(false), port, maximum_streams,
            });
            *self.onion_service.borrow_mut() = Some(Rc::downgrade(&state));
            Ok((BrowserOnionService { state, host, readiness: "unavailable" }, deadline))
        })();
        wasm_bindgen_futures::future_to_promise(async move {
            let (mut service, deadline) = launch?;
            let ready = async {
                loop {
                    if service.state.closed.get() { return Err(failure()); }
                    let state = service.state.service.borrow().as_ref().ok_or_else(failure)?.status().state();
                    if state.is_fully_reachable() {
                        // Preserve the exact readiness decision in the returned
                        // snapshot; future/unknown variants must not succeed.
                        return match state {
                            tor_hsservice::status::State::Running => Ok("running"),
                            tor_hsservice::status::State::DegradedReachable => Ok("degraded-reachable"),
                            _ => Err(failure()),
                        };
                    }
                    match state {
                        tor_hsservice::status::State::Broken => return Err(failure()),
                        _ => (),
                    }
                    TimeoutFuture::new(100).await;
                }
            }.boxed_local();
            let outcome = match select(ready, TimeoutFuture::new(deadline).boxed_local()).await {
                Either::Left((result, _)) => result,
                _ => Err(failure()),
            };
            service.readiness = outcome?;
            Ok(service.into())
        })
    }
}
