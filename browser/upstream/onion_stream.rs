//! Experimental browser/native raw onion streams for the pinned TorJS build.
//! No clearnet addresses, implicit gateways, generic fetch or payload logging.
use crate::TorClient;
use arti_client::{DataReader, DataStream, DataWriter};
use futures::{future::{select, AbortHandle, Abortable, Either}, io::{AsyncReadExt, AsyncWriteExt}, FutureExt};
use gloo_timers::future::TimeoutFuture;
use safelog::DisplayRedacted as _;
use std::{cell::{Cell, RefCell}, rc::{Rc, Weak}, sync::Arc};
use tor_hscrypto::pk::HsId;
use wasm_bindgen::prelude::*;

fn failure() -> JsValue { JsValue::from_str("tor-js:OnionTransport") }
fn integer(value: f64, maximum: u32) -> Result<u32, JsValue> {
    if !value.is_finite() || value.fract() != 0.0 || value < 1.0 || value > f64::from(maximum) {
        return Err(failure());
    }
    Ok(value as u32)
}

pub(crate) struct StreamState {
    reader: RefCell<Option<DataReader>>,
    writer: RefCell<Option<DataWriter>>,
    read_abort: RefCell<Option<AbortHandle>>,
    write_abort: RefCell<Option<AbortHandle>>,
    closed: Cell<bool>,
}

impl StreamState {
    pub(crate) fn is_closed(&self) -> bool { self.closed.get() }
    pub(crate) fn close(&self) {
        if self.closed.replace(true) { return; }
        if let Some(abort) = self.read_abort.borrow_mut().take() { abort.abort(); }
        if let Some(abort) = self.write_abort.borrow_mut().take() { abort.abort(); }
        self.reader.borrow_mut().take();
        self.writer.borrow_mut().take();
    }
}

#[derive(Default)]
pub(crate) struct OnionStreamRegistry {
    streams: RefCell<Vec<Weak<StreamState>>>,
    pending: RefCell<Option<AbortHandle>>,
    closed: Cell<bool>,
}

impl OnionStreamRegistry {
    pub(crate) fn close(&self) {
        if self.closed.replace(true) { return; }
        if let Some(abort) = self.pending.borrow_mut().take() { abort.abort(); }
        for stream in self.streams.borrow_mut().drain(..).filter_map(|stream| stream.upgrade()) {
            stream.close();
        }
    }

    pub(crate) fn track(&self, stream: DataStream) -> Result<OnionStream, JsValue> {
        if self.closed.get() { return Err(failure()); }
        let mut streams = self.streams.borrow_mut();
        streams.retain(|stream| stream.upgrade().is_some_and(|state| !state.closed.get()));
        if streams.len() >= 64 { return Err(failure()); }
        let stream = OnionStream::from_stream(stream);
        streams.push(Rc::downgrade(&stream.state));
        Ok(stream)
    }
}

/// One Tor DataStream with at most one outstanding read and one write.
/// Every operation has its own explicit bounded deadline. Close aborts both.
#[wasm_bindgen]
pub struct OnionStream { pub(crate) state: Rc<StreamState> }

impl OnionStream {
    pub(crate) fn from_stream(stream: DataStream) -> Self {
        let (reader, writer) = stream.split();
        Self { state: Rc::new(StreamState {
            reader: RefCell::new(Some(reader)), writer: RefCell::new(Some(writer)),
            read_abort: RefCell::new(None), write_abort: RefCell::new(None),
            closed: Cell::new(false),
        }) }
    }
}

impl Drop for OnionStream { fn drop(&mut self) { self.state.close(); } }

#[wasm_bindgen]
impl OnionStream {
    /// Return up to 64 KiB, or an empty array on EOF. A second pending read fails.
    #[wasm_bindgen(js_name = read)]
    pub fn read(&self, maximum: f64, deadline_ms: f64) -> js_sys::Promise {
        let state = Rc::clone(&self.state);
        let parameters = integer(maximum, 65536).and_then(|limit| {
            integer(deadline_ms, 60000).map(|deadline| (limit, deadline))
        });
        wasm_bindgen_futures::future_to_promise(async move {
            let (limit, deadline) = parameters?;
            if state.closed.get() { return Err(failure()); }
            let mut reader = state.reader.borrow_mut().take().ok_or_else(failure)?;
            let (abort, registration) = AbortHandle::new_pair();
            *state.read_abort.borrow_mut() = Some(abort);
            let mut bytes = vec![0; limit as usize];
            let result = {
                let operation = Abortable::new(reader.read(&mut bytes), registration).boxed_local();
                match select(operation, TimeoutFuture::new(deadline).boxed_local()).await {
                    Either::Left((Ok(Ok(count)), _)) => Ok(count),
                    _ => Err(failure()),
                }
            };
            state.read_abort.borrow_mut().take();
            match result {
                Ok(count) if !state.closed.get() => {
                    bytes.truncate(count);
                    if count == 0 { state.close(); }
                    else { *state.reader.borrow_mut() = Some(reader); }
                    Ok(js_sys::Uint8Array::from(bytes.as_slice()).into())
                }
                _ => { bytes.fill(0); state.close(); Err(failure()) }
            }
        })
    }

    /// Send at most one cmsg-sized wire chunk. A second pending write fails.
    #[wasm_bindgen(js_name = write)]
    pub fn write(&self, mut bytes: Vec<u8>, deadline_ms: f64) -> js_sys::Promise {
        let state = Rc::clone(&self.state);
        let deadline = integer(deadline_ms, 60000);
        wasm_bindgen_futures::future_to_promise(async move {
            let deadline = deadline?;
            if state.closed.get() || bytes.is_empty() || bytes.len() > 1024 * 1024 + 4 { return Err(failure()); }
            let mut writer = state.writer.borrow_mut().take().ok_or_else(failure)?;
            let (abort, registration) = AbortHandle::new_pair();
            *state.write_abort.borrow_mut() = Some(abort);
            let result = {
                let operation = Abortable::new(async {
                    writer.write_all(&bytes).await?;
                    writer.flush().await
                }, registration).boxed_local();
                match select(operation, TimeoutFuture::new(deadline).boxed_local()).await {
                    Either::Left((Ok(Ok(())), _)) => Ok(()),
                    _ => Err(failure()),
                }
            };
            bytes.fill(0);
            state.write_abort.borrow_mut().take();
            match result {
                Ok(()) if !state.closed.get() => {
                    *state.writer.borrow_mut() = Some(writer);
                    Ok(JsValue::UNDEFINED)
                }
                _ => { state.close(); Err(failure()) }
            }
        })
    }

    pub fn close(&self) { self.state.close(); }
}

#[wasm_bindgen]
impl TorClient {
    #[wasm_bindgen(js_name = onionStreamSupported)]
    pub fn onion_stream_supported() -> bool { true }

    /// Connect only to a checksum-valid onion through this browser's Arti client.
    #[wasm_bindgen(js_name = connectOnion)]
    pub fn connect_onion(&self, host: String, port: f64, deadline_ms: f64) -> js_sys::Promise {
        let client = self.inner.as_ref().map(Arc::clone);
        let registry = Rc::clone(&self.onion_streams);
        let parameters = integer(port, 65535).and_then(|port| {
            integer(deadline_ms, 60000).map(|deadline| (port as u16, deadline))
        });
        wasm_bindgen_futures::future_to_promise(async move {
            let (port, deadline) = parameters?;
            let onion: HsId = host.parse().map_err(|_| failure())?;
            if onion.display_unredacted().to_string() != host { return Err(failure()); }
            let client = client.ok_or_else(failure)?;
            if registry.closed.get() || registry.pending.borrow().is_some() { return Err(failure()); }
            let (abort, registration) = AbortHandle::new_pair();
            *registry.pending.borrow_mut() = Some(abort);
            let connection = Abortable::new(client.connect((host.as_str(), port)), registration).boxed_local();
            let result = match select(connection, TimeoutFuture::new(deadline).boxed_local()).await {
                Either::Left((Ok(Ok(stream)), _)) => registry.track(stream).map(JsValue::from),
                _ => Err(failure()),
            };
            registry.pending.borrow_mut().take();
            result
        })
    }
}
