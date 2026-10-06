//! Original Records and application operations over one browser Tor listener.
use super::super::{ErrorCode, Result, network_browser::BrowserTor};
use cdht::{
    Capacity,
    rpc::{
        UnverifiedPeerInfoBytes,
        envelope::TimeWindow,
        peers::{Advertisement, DHTV, DIRECT, ExtensionDialInfo},
    },
    watches::WatchLimits,
};
use cmsh::{
    tor_applications::TorApplications,
    tor_discovery::{
        TorDiscovery, TorDiscoveryConfig, TorDiscoveryLimits, TorEnvelopeTime, TorNodeIdentity,
        TorWatcher,
    },
    tor_records::{TorRecordLimits, TorRecords},
};
use futures_channel::oneshot;
use futures_util::{
    FutureExt,
    future::{AbortHandle, Abortable, Either, LocalBoxFuture, Shared, select},
};
use std::{
    cell::{Cell, RefCell},
    num::{NonZeroU32, NonZeroUsize},
    rc::{Rc, Weak},
    sync::Arc,
};

/// Parent-owned narrow transport capability. Implementations must use the same
/// retained epoch-zero session for node operations and advertisement signing.
/// Clock/window are the originating ENV0 acceptance inputs, not new overrides.
pub trait Identity: TorNodeIdentity + 'static {
    type Clock: ckmg::Clock + 'static;
    type Authority: ckmg::Authority + 'static;
    fn transport(&self) -> &Rc<BrowserTor<Self::Clock, Self::Authority>>;
    fn lifetime(&self) -> crate::door::custody::CustodyLifetime;
    fn envelope_time(&self) -> Arc<dyn TorEnvelopeTime>;
    fn envelope_window(&self) -> TimeWindow;
    fn advertise(
        &self,
        advertisement: Advertisement,
    ) -> LocalBoxFuture<'_, std::result::Result<UnverifiedPeerInfoBytes, cdht::Error>>;
}

/// Original strict Keys verification; no caller-supplied acceptance predicate.
#[derive(Clone, Copy)]
pub struct Verifier;
impl cdht::Verifier for Verifier {
    fn verify(&self, key: &cdht::NodeId, bytes: &[u8], signature: &[u8; 64]) -> bool {
        ckmg::verify(
            &ckmg::PublicKey::new(ckmg::VLD0, *key),
            bytes,
            &ckmg::Signature::new(ckmg::VLD0, *signature),
        )
        .is_ok()
    }
}
pub type Discovery<I> = TorDiscovery<I, Verifier>;
pub type Records<I, W> = TorRecords<I, Verifier, W>;
pub type Applications<I> = TorApplications<I, Verifier>;

/// Trusted resource policy only. Neither record credentials nor acceptance time
/// nor a replacement transport window can enter through this configuration.
pub struct Configuration {
    pub discovery: TorDiscoveryLimits,
    pub records: TorRecordLimits,
    pub storage: Option<(Capacity, WatchLimits)>,
    pub bootstrap: Vec<UnverifiedPeerInfoBytes>,
    pub maximum_bootstrap_bytes: NonZeroUsize,
    pub record_concurrency: NonZeroUsize,
    /// Bounded original application queue, at most 1024 events.
    pub application_queue: NonZeroUsize,
    /// Original application payload bound, at most 32 KiB.
    pub application_payload: NonZeroUsize,
    pub startup_millis: NonZeroU32,
}
impl Configuration {
    fn validate(&self, drivers: usize) -> Result<()> {
        if self.bootstrap.len() > self.discovery.peers.get()
            || self.record_concurrency.get() > drivers
            || self.application_queue.get() > 1024
            || self.application_payload.get() > 32 * 1024
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut remaining = self.maximum_bootstrap_bytes.get();
        for entry in &self.bootstrap {
            remaining = remaining
                .checked_sub(entry.as_bytes().len())
                .ok_or(ErrorCode::Capacity)?;
        }
        Ok(())
    }
}

struct Control {
    closed: Cell<bool>,
    close_transport: Box<dyn Fn()>,
    service: RefCell<Option<AbortHandle>>,
    last_error: Cell<Option<cdht::Error>>,
}
impl Control {
    fn close(&self) {
        self.closed.set(true);
        (self.close_transport)();
        if let Some(abort) = self.service.borrow_mut().take() {
            abort.abort();
        }
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.close();
    }
}
struct ServiceExit(Weak<Control>);
impl Drop for ServiceExit {
    fn drop(&mut self) {
        if let Some(control) = self.0.upgrade() {
            control.close();
        }
    }
}

/// Holds one shared authenticated receiver and original maintenance lane. Retaining
/// this guard implies no member admission, restored state or record availability.
#[must_use = "drop closes Records, Tor drivers and transport custody"]
pub struct Network<I: Identity, W: TorWatcher> {
    control: Rc<Control>,
    transport: Rc<BrowserTor<I::Clock, I::Authority>>,
    records: Arc<Records<I, W>>,
    applications: Arc<Applications<I>>,
    advertisement: UnverifiedPeerInfoBytes,
    done: Shared<LocalBoxFuture<'static, Result<()>>>,
}
impl<I: Identity, W: TorWatcher + 'static> Network<I, W> {
    /// Use the running node from the parent's identity capability. Once its
    /// listener is claimed, failure/cancellation closes the entire transport.
    pub async fn start(identity: I, watcher: W, config: Configuration) -> Result<Self> {
        let transport = identity.transport().clone();
        config.validate(transport.driver_limit())?;
        if identity.node_id() != *transport.public_key().value() {
            return Err(ErrorCode::Unauthorized);
        }
        transport.claim_listener()?;
        let close_transport = transport.clone();
        let lifetime = identity.lifetime();
        let control = Rc::new(Control {
            closed: Cell::new(false),
            close_transport: Box::new(move || {
                lifetime.close();
                close_transport.close();
            }),
            service: RefCell::new(None),
            last_error: Cell::new(None),
        });
        let timeout = gloo_timers::future::TimeoutFuture::new(config.startup_millis.get());
        let stopped = transport.stopped();
        let construct =
            Self::construct(identity, watcher, config, transport, control).boxed_local();
        match select(
            construct,
            select(timeout.boxed_local(), stopped).boxed_local(),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(ErrorCode::Unavailable),
        }
    }

    #[allow(clippy::arc_with_non_send_sync)]
    async fn construct(
        identity: I,
        watcher: W,
        config: Configuration,
        transport: Rc<BrowserTor<I::Clock, I::Authority>>,
        control: Rc<Control>,
    ) -> Result<Self> {
        let messages = transport.messages();
        let listener = messages
            .listen()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let endpoint = ctrn::OnionEndpoint::from_address(listener.address())
            .map_err(|_| ErrorCode::Unavailable)?;
        let time = identity.envelope_time();
        let window = identity.envelope_window();
        let advertisement = identity
            .advertise(Advertisement {
                timestamp_us: time.now_us().map_err(|_| ErrorCode::Clock)?,
                capabilities: if config.storage.is_some() {
                    vec![DHTV]
                } else {
                    vec![]
                },
                outbound_protocols: vec![ctrn::TOR3],
                address_types: vec![ctrn::TOR3],
                dial_info: vec![ExtensionDialInfo {
                    class: DIRECT,
                    protocol: ctrn::TOR3,
                    detail: endpoint.address().bytes().to_vec(),
                }],
            })
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let own = UnverifiedPeerInfoBytes::from_bytes(advertisement.as_bytes().to_vec())
            .map_err(|_| ErrorCode::Unavailable)?;
        let discovery = Arc::new(
            TorDiscovery::new(
                TorDiscoveryConfig {
                    messages,
                    identity,
                    verifier: Verifier,
                    own,
                    bootstrap: config.bootstrap,
                    clock: transport.clock(),
                    limits: config.discovery,
                    envelope_time: time,
                    envelope_window: window,
                },
                &listener,
            )
            .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        let applications = Arc::new(
            TorApplications::new(
                discovery.clone(),
                config.application_queue,
                config.application_payload,
            )
            .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        let records = Arc::new(
            TorRecords::new(discovery, watcher, config.storage, config.records)
                .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        let serving = records.clone();
        let serving_applications = applications.clone();
        let errors = Rc::downgrade(&control);
        let exited = ServiceExit(Rc::downgrade(&control));
        let stopped = transport.stopped();
        let (abort, registration) = AbortHandle::new_pair();
        *control.service.borrow_mut() = Some(abort);
        let (finished, completion) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let _exited = exited;
            let run = serving
                .run_shared(
                    listener,
                    config.record_concurrency,
                    &serving_applications,
                    |error| {
                        if let Some(control) = errors.upgrade() {
                            control.last_error.set(Some(error));
                        }
                    },
                )
                .boxed_local();
            let result = match select(Abortable::new(run, registration), stopped).await {
                Either::Left((Ok(result), _)) => result.map_err(|_| ErrorCode::Unavailable),
                _ => Ok(()), // explicit stop/cancellation; all original watches become lost
            };
            serving.transport_lost();
            let _ = finished.send(result);
        });
        Ok(Self {
            control,
            transport,
            records,
            applications,
            advertisement,
            done: async move { completion.await.map_err(|_| ErrorCode::Reconcile)? }
                .boxed_local()
                .shared(),
        })
    }

    pub fn records(&self) -> Result<&Arc<Records<I, W>>> {
        if self.control.closed.get() || self.transport.is_closed() {
            self.close();
            return Err(ErrorCode::Unavailable);
        }
        Ok(&self.records)
    }
    pub fn discovery(&self) -> Result<&Arc<Discovery<I>>> {
        Ok(self.records()?.discovery())
    }
    /// Original Mesh backend; listening consumes its queue, not a second service.
    pub fn applications(&self) -> Result<&Arc<Applications<I>>> {
        self.records()?;
        Ok(&self.applications)
    }
    pub fn advertisement(&self) -> Result<&UnverifiedPeerInfoBytes> {
        self.records()?;
        Ok(&self.advertisement)
    }
    pub fn last_record_error(&self) -> Option<cdht::Error> {
        self.control.last_error.get()
    }
    pub fn close(&self) {
        self.applications.close();
        self.records.transport_lost();
        self.control.close();
    }
    pub async fn shutdown(self) -> Result<()> {
        self.close();
        let service = self.done.clone().await;
        let drivers = self.transport.shutdown().await;
        service.and(drivers)
    }
}
impl<I: Identity, W: TorWatcher> Drop for Network<I, W> {
    fn drop(&mut self) {
        self.applications.close();
        self.records.transport_lost();
        self.control.close();
    }
}
