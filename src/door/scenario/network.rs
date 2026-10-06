//! Retained native Tor Records and application service. No member-record/read
//! authority is made here; callers supply the original watcher and owners.
use super::{ErrorCode, TransportClient, TransportOwner, Verifier};
use cdht::{
    rpc::{
        peers::{Advertisement, ExtensionDialInfo, DHTV, DIRECT},
        UnverifiedPeerInfoBytes,
    },
    watches::WatchLimits,
    Capacity,
};
use cmsh::{
    tor_applications::TorApplications,
    tor_discovery::{
        TorDiscovery, TorDiscoveryConfig, TorDiscoveryLimits, TorEnvelopeTime, TorWatcher,
    },
    tor_records::{TorRecordLimits, TorRecords},
};
use futures_util::{
    future::{LocalBoxFuture, Shared},
    FutureExt,
};
use std::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
    rc::{Rc, Weak},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{oneshot, Notify},
    task::JoinHandle,
};

type Result<T> = super::super::Result<T>;
/// The original authenticated routing owner with the same transport identity.
pub type Discovery = TorDiscovery<TransportClient, Verifier>;
/// Original authenticated Records RPC/storage/watch owner, not runtime::Backend.
pub type Records<W> = TorRecords<TransportClient, Verifier, W>;
/// Original Mesh application backend sharing that exact authenticated discovery.
pub type Applications = TorApplications<TransportClient, Verifier>;

/// Trusted native construction only. No JSON installation, keys, roster or
/// supplied readiness state. All budgets are explicit; original owners validate
/// their own settings. Directories are consumed by original Arti construction.
pub struct Configuration {
    pub tor: arti_client::config::TorClientConfigBuilder,
    pub directories: ctrn::arti::Directories,
    pub scope: ctrn::Scope,
    pub transport: ctrn::Limits,
    pub messages: ctrn::MessageLimits,
    pub discovery: TorDiscoveryLimits,
    pub records: TorRecordLimits,
    /// None constructs a routing-only participant with no record store/DHTV.
    /// Some constructs the original bounded member storage and server watches.
    pub storage: Option<(Capacity, WatchLimits)>,
    pub bootstrap: Vec<UnverifiedPeerInfoBytes>,
    pub maximum_bootstrap_bytes: NonZeroUsize,
    /// Outstanding Ferry drivers, including inbound and outbound connections.
    pub driver_tasks: NonZeroUsize,
    /// Passed unchanged to TorRecords::run_shared; maintenance remains separate.
    pub record_concurrency: NonZeroUsize,
    /// Bounded original application queue, at most 1024 events.
    pub application_queue: NonZeroUsize,
    /// Original application payload bound, at most 32 KiB.
    pub application_payload: NonZeroUsize,
    /// Includes custody authorization, Tor startup, publication and advertisement.
    pub startup_timeout: Duration,
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        if self.startup_timeout.is_zero()
            || self.driver_tasks.get() > self.transport.streams
            || self.record_concurrency.get() > self.driver_tasks.get()
            || self.bootstrap.len() > self.discovery.peers.get()
            || self.application_queue.get() > 1024
            || self.application_payload.get() > 32 * 1024
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut remaining = self.maximum_bootstrap_bytes.get();
        for entry in &self.bootstrap {
            remaining = remaining
                .checked_sub(entry.as_bytes().len())
                .ok_or(ErrorCode::InvalidRequest)?;
        }
        Ok(())
    }
}

/// Actual wall time, using the same original clock conversion as transport
/// envelope opening. Callers cannot supply time or a second acceptance window.
struct Time;
impl TorEnvelopeTime for Time {
    fn now_us(&self) -> std::result::Result<u64, cdht::Error> {
        super::now_us()
    }
}

struct DriverState {
    closed: bool,
    tasks: Vec<JoinHandle<()>>,
}
struct Drivers {
    runtime: tokio::runtime::Handle,
    maximum: usize,
    state: Mutex<DriverState>,
}
impl ctrn::messages::Spawn for Drivers {
    fn spawn(&self, future: ctrn::BoxFuture<'static, ()>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.tasks.retain(|task| !task.is_finished());
        if state.closed || state.tasks.len() >= self.maximum {
            // Spawn has no error return. Dropping the original driver closes its
            // connection; the original bounded message operation then refuses.
            drop(state);
            drop(future);
            return;
        }
        state.tasks.push(self.runtime.spawn(future));
    }
}
impl Drivers {
    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        for task in &state.tasks {
            task.abort();
        }
    }
    fn take(&self) -> Vec<JoinHandle<()>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        std::mem::take(&mut state.tasks)
    }
}
impl Drop for Drivers {
    fn drop(&mut self) {
        self.close();
    }
}

/// Local control keeps the non-Send transport owner on its original LocalSet.
/// The service task holds a weak reference, so it cannot keep its own owner alive.
struct Control {
    closed: Cell<bool>,
    node: RefCell<Option<Arc<ctrn::Node>>>,
    transport: RefCell<Option<TransportOwner>>,
    drivers: Arc<Drivers>,
    service: RefCell<Option<JoinHandle<Result<()>>>>,
    last_record_error: Cell<Option<cdht::Error>>,
    stop: Notify,
    done: Shared<LocalBoxFuture<'static, Result<()>>>,
}
impl Control {
    fn live(&self) -> Result<()> {
        if self.closed.get() {
            Err(ErrorCode::Unavailable)
        } else {
            Ok(())
        }
    }
    fn stop_resources(&self) {
        self.closed.set(true);
        self.stop.notify_one();
        if let Some(node) = self.node.borrow().as_ref() {
            node.stop();
        }
        self.drivers.close();
        if let Some(owner) = self.transport.borrow_mut().as_mut() {
            owner.close();
        }
    }
    fn close(&self) {
        self.stop_resources();
        if let Some(task) = self.service.borrow().as_ref() {
            task.abort();
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
            control.stop_resources();
        }
    }
}

/// Only closure and actual task completion; conveys no custody or readiness.
/// Retain before awaiting startup so cancelled initialization can be drained.
#[derive(Clone)]
pub struct Drain(Rc<Control>);
impl Drain {
    pub fn close(&self) {
        self.0.close();
    }
    pub async fn drain(&self) -> Result<()> {
        self.0.done.clone().await
    }
}
struct Startup(Option<Rc<Control>>);
impl Drop for Startup {
    fn drop(&mut self) {
        if let Some(control) = &self.0 {
            control.close();
        }
    }
}
async fn drain(control: Rc<Control>, finished: oneshot::Sender<Result<()>>) {
    control.stop.notified().await;
    control.close();
    let task = control.service.borrow_mut().take();
    let mut result = Ok(());
    if let Some(task) = task {
        match task.await {
            Ok(Ok(())) => (),
            Err(error) if error.is_cancelled() => (),
            _ => result = Err(ErrorCode::Reconcile),
        }
    }
    for task in control.drivers.take() {
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                result = Err(ErrorCode::Reconcile);
            }
        }
    }
    let owner = control.transport.borrow_mut().take();
    if let Some(owner) = owner {
        if owner.shutdown().await.is_err() {
            result = Err(ErrorCode::Reconcile);
        }
    }
    let _ = finished.send(result);
}

/// One authenticated Records/application listener and original routing owners. Retain
/// this local guard throughout parent member-record construction and use. Its
/// existence proves no member admission, record availability or restored data.
#[must_use = "retain with the native runtime; drop closes Tor and transport custody"]
pub struct Network<W: TorWatcher> {
    control: Rc<Control>,
    records: Arc<Records<W>>,
    applications: Arc<Applications>,
    advertisement: UnverifiedPeerInfoBytes,
}
impl<W: TorWatcher + 'static> Network<W> {
    /// Call on the existing native owner LocalSet. Consume the matching transport
    /// pair and original watcher; credential work continues on its independent
    /// task while this future awaits actual Tor bootstrap/publication.
    pub async fn start(
        client: TransportClient,
        owner: TransportOwner,
        configuration: Configuration,
        watcher: W,
    ) -> Result<Self> {
        let (cleanup, startup) = Self::prepare(client, owner, configuration, watcher);
        let result = startup.await;
        if result.is_err() {
            let _ = cleanup.drain().await;
        }
        result
    }

    /// Construct on the existing active LocalSet. Cleanup exists even before
    /// the returned future is polled and remains awaitable after its cancellation.
    pub fn prepare(
        client: TransportClient,
        owner: TransportOwner,
        configuration: Configuration,
        watcher: W,
    ) -> (Drain, LocalBoxFuture<'static, Result<Self>>) {
        let same_session = Arc::ptr_eq(&client.session, &owner.session);
        let runtime = tokio::runtime::Handle::current();
        let (finished, completion) = oneshot::channel();
        let control = Rc::new(Control {
            closed: Cell::new(false),
            node: RefCell::new(None),
            transport: RefCell::new(Some(owner)),
            drivers: Arc::new(Drivers {
                runtime,
                maximum: configuration.driver_tasks.get(),
                state: Mutex::new(DriverState {
                    closed: false,
                    tasks: Vec::new(),
                }),
            }),
            service: RefCell::new(None),
            last_record_error: Cell::new(None),
            stop: Notify::new(),
            done: async move { completion.await.map_err(|_| ErrorCode::Reconcile)? }
                .boxed_local()
                .shared(),
        });
        let cleanup = Drain(control.clone());
        let mut guard = Startup(Some(control.clone()));
        tokio::task::spawn_local(drain(control.clone(), finished));
        let startup = async move {
            if !same_session {
                return Err(ErrorCode::Unauthorized);
            }
            control.live()?;
            configuration.validate()?;
            let timeout = configuration.startup_timeout;
            let network = tokio::time::timeout(
                timeout,
                Self::construct(client, configuration, watcher, control),
            )
            .await
            .map_err(|_| ErrorCode::Unavailable)??;
            guard.0.take(); // Actual Network now owns closure.
            Ok(network)
        }
        .boxed_local();
        (cleanup, startup)
    }

    async fn construct(
        client: TransportClient,
        config: Configuration,
        watcher: W,
        control: Rc<Control>,
    ) -> Result<Self> {
        control.live()?;
        let initializer = client.native_initializer(config.scope).await?;
        control.live()?;
        // Match the native transport's maintained TLS provider selection; an
        // embedding runtime's already-installed provider remains authoritative.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let runtime = tor_rtcompat::tokio::TokioRustlsRuntime::current()
            .map_err(|_| ErrorCode::Unavailable)?;
        let clock = Arc::new(ctrn::arti::TokioClock::default());
        let node = initializer
            .initialize(
                runtime,
                config.tor,
                config.directories,
                clock.clone(),
                config.transport,
            )
            .map_err(|_| ErrorCode::Unavailable)?;
        *control.node.borrow_mut() = Some(node.clone());
        let messages = Arc::new(
            ctrn::messages::Messages::new(
                node.clone(),
                control.drivers.clone(),
                clock.clone(),
                config.messages,
            )
            .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        node.start().await.map_err(|_| ErrorCode::Unavailable)?;
        control.live()?;
        // Original authenticated Records and application operations share this
        // listener. Its actual published endpoint is the only self-ad input.
        let listener = messages
            .listen()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        control.live()?;
        let endpoint = ctrn::OnionEndpoint::from_address(listener.address())
            .map_err(|_| ErrorCode::Unavailable)?;
        let advertisement = client
            .advertise(Advertisement {
                timestamp_us: super::now_us().map_err(|_| ErrorCode::Unavailable)?,
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
        control.live()?;
        // Preserve the exact original signed advertisement for the trusted peer
        // harness; no new bootstrap format or unsigned identity map is emitted.
        let own = UnverifiedPeerInfoBytes::from_bytes(advertisement.as_bytes().to_vec())
            .map_err(|_| ErrorCode::Unavailable)?;
        let window = client.window;
        let discovery = Arc::new(
            TorDiscovery::new(
                TorDiscoveryConfig {
                    messages,
                    identity: client,
                    verifier: Verifier,
                    own,
                    bootstrap: config.bootstrap,
                    clock,
                    limits: config.discovery,
                    envelope_time: Arc::new(Time),
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
        let exited = ServiceExit(Rc::downgrade(&control));
        let errors = Rc::downgrade(&control);
        let task = tokio::task::spawn_local(async move {
            let _exited = exited;
            // Original shared receiver drives requests with its maintained
            // one-second timer, watch renewal and pending notifications.
            serving
                .run_shared(
                    listener,
                    config.record_concurrency,
                    &serving_applications,
                    |error| {
                        if let Some(control) = errors.upgrade() {
                            control.last_record_error.set(Some(error));
                        }
                    },
                )
                .await
                .map_err(|_| ErrorCode::Unavailable)
        });
        *control.service.borrow_mut() = Some(task);
        Ok(Self {
            control,
            records,
            applications,
            advertisement,
        })
    }

    /// Retrieve original Foyer authority ports after starting the independent
    /// node. The parent supplies genuine Records and constructs member Keys.
    pub fn take_member_authority(&self) -> Result<super::super::custody::MemberAuthorityBuilder> {
        if self.control.closed.get() {
            return Err(ErrorCode::Unavailable);
        }
        self.control
            .transport
            .borrow_mut()
            .as_mut()
            .ok_or(ErrorCode::Unavailable)?
            .take_member_authority()
    }

    /// Original authenticated owner only. No unsigned runtime Backend is built.
    pub fn records(&self) -> Result<&Arc<Records<W>>> {
        if self.control.closed.get() {
            return Err(ErrorCode::Unavailable);
        }
        Ok(&self.records)
    }
    pub fn discovery(&self) -> Result<&Arc<Discovery>> {
        Ok(self.records()?.discovery())
    }
    /// Original Mesh backend; listening consumes its queue, not a second service.
    pub fn applications(&self) -> Result<&Arc<Applications>> {
        self.records()?;
        Ok(&self.applications)
    }
    /// Original signed PeerInfo from this exact live listener; not a readiness DTO.
    pub fn advertisement(&self) -> Result<&UnverifiedPeerInfoBytes> {
        if self.control.closed.get() {
            return Err(ErrorCode::Unavailable);
        }
        Ok(&self.advertisement)
    }
    /// Bounded coarse diagnostic for rejected requests or failed maintenance.
    /// Original TorRecords retains watch-loss state; this never clears it.
    pub fn last_record_error(&self) -> Option<cdht::Error> {
        self.control.last_record_error.get()
    }

    /// Forward only the original verified observation to the retained owner.
    /// Refusal also stops idle Records/listener work; no read grant is created.
    pub fn observe_lineage(
        &self,
        observed: &cvlt::VerifiedLineageObservation<'_>,
        now: u64,
    ) -> Result<()> {
        if self.control.closed.get() {
            return Err(ErrorCode::Unavailable);
        }
        let result = {
            let mut retained = self.control.transport.borrow_mut();
            retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .observe_lineage(observed, now)
                .map_err(|_| ErrorCode::Unauthorized)
        };
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Stop admission, listeners, drivers and custody without a network await.
    pub fn close(&self) {
        self.applications.close();
        self.records.transport_lost();
        self.control.close();
    }
    /// Close then join independently owned cleanup, even after cancellation.
    pub async fn shutdown(self) -> Result<()> {
        self.close();
        self.control.done.clone().await
    }
}
impl<W: TorWatcher> Drop for Network<W> {
    fn drop(&mut self) {
        self.applications.close();
        self.records.transport_lost();
        self.control.close();
    }
}
