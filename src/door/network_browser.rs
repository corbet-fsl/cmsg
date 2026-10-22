//! Trusted browser transport composition inside the isolated Vault frame.
//! The parent retains this owner through restore and all subsequent member use.
use super::{facades::keys_error, ErrorCode, Result};
use futures_channel::oneshot;
use futures_util::{
    future::{AbortHandle, Abortable, LocalBoxFuture, Shared},
    lock::Mutex,
    FutureExt,
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    sync::Arc,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/src/door/browser/tor.ts")]
extern "C" {
    #[wasm_bindgen(catch, js_name = factory)]
    fn factory(
        bootstrap: u32,
        operation: u32,
        streams: u32,
    ) -> std::result::Result<js_sys::Function, JsValue>;
    #[wasm_bindgen(js_name = monotonicMillis)]
    fn monotonic_millis() -> f64;
}

/// Explicit trusted resource bounds; no transport override or key is accepted.
pub struct Configuration {
    pub limits: ctrn::Limits,
    pub messages: ctrn::MessageLimits,
}

/// Browser monotonic time, shared by Node, Ferry and Records discovery.
pub struct Clock;
impl ctrn::Clock for Clock {
    fn now(&self) -> u64 {
        let value = monotonic_millis();
        if value.is_finite() && (0.0..=9_007_199_254_740_991.0).contains(&value) {
            value as u64
        } else {
            u64::MAX // Original Node deadline checks refuse this sentinel.
        }
    }
    fn sleep_until(&self, deadline: u64) -> ctrn::BoxFuture<'_, ()> {
        Box::pin(async move {
            loop {
                let remaining = deadline.saturating_sub(self.now());
                if remaining == 0 {
                    break;
                }
                gloo_timers::future::TimeoutFuture::new(remaining.min(u32::MAX as u64) as u32)
                    .await;
            }
        })
    }
}

type Completion = Shared<LocalBoxFuture<'static, Result<()>>>;
struct DriverState {
    closed: bool,
    next: u64,
    tasks: BTreeMap<u64, (AbortHandle, Completion)>,
}
struct Drivers {
    maximum: usize,
    state: RefCell<DriverState>,
}
// CTRN uses Arc on both targets; browser owners deliberately remain non-Send.
struct DriverSpawner(Arc<Drivers>);
impl ctrn::messages::Spawn for DriverSpawner {
    fn spawn(&self, future: ctrn::BoxFuture<'static, ()>) {
        let mut state = self.0.state.borrow_mut();
        if state.closed || state.tasks.len() >= self.0.maximum {
            return; // Dropping the original driver closes its connection.
        }
        let Some(id) = state.next.checked_add(1) else {
            return;
        };
        state.next = id;
        let (abort, registration) = AbortHandle::new_pair();
        let (finished, completion) = oneshot::channel();
        state.tasks.insert(
            id,
            (
                abort,
                async move { completion.await.map_err(|_| ErrorCode::Reconcile) }
                    .boxed_local()
                    .shared(),
            ),
        );
        let drivers = Arc::downgrade(&self.0);
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(future, registration).await;
            if let Some(drivers) = drivers.upgrade() {
                drivers.state.borrow_mut().tasks.remove(&id);
            }
            let _ = finished.send(());
        });
    }
}
impl Drivers {
    fn close(&self) {
        let mut state = self.state.borrow_mut();
        state.closed = true;
        for (abort, _) in state.tasks.values() {
            abort.abort();
        }
    }
    async fn drain(&self) -> Result<()> {
        self.close();
        let tasks: Vec<_> = self
            .state
            .borrow()
            .tasks
            .values()
            .map(|(_, done)| done.clone())
            .collect();
        let results = futures_util::future::join_all(tasks).await;
        results.into_iter().collect()
    }
}

/// The transport custody one BrowserTor owns: the vault-derived epoch-zero session, or a
/// fresh registration's ephemeral keys (before any vault exists; in memory only, one per
/// scope, dropped at `Done`).
pub enum Session<C, A> {
    Vault(ckmg::TransportSession<C, A>),
    Ephemeral(ckmg::EphemeralTransport),
}
impl<C, A> From<ckmg::TransportSession<C, A>> for Session<C, A> {
    fn from(session: ckmg::TransportSession<C, A>) -> Self {
        Self::Vault(session)
    }
}
impl<C, A> From<ckmg::EphemeralTransport> for Session<C, A> {
    fn from(transport: ckmg::EphemeralTransport) -> Self {
        Self::Ephemeral(transport)
    }
}
impl<C: ckmg::Clock, A: ckmg::Authority> Session<C, A> {
    async fn browser_initializer(
        &mut self,
        scope: ctrn::Scope,
    ) -> std::result::Result<ckmg::BrowserTorInitializer, ckmg::Error> {
        match self {
            Self::Vault(session) => session.browser_initializer(scope).await,
            Self::Ephemeral(transport) => transport.browser_initializer(scope),
        }
    }
    fn public_key(&self) -> std::result::Result<ckmg::PublicKey, ckmg::Error> {
        match self {
            Self::Vault(session) => session.public_key(),
            Self::Ephemeral(transport) => transport.public_key(),
        }
    }
    async fn with_node<T>(
        &mut self,
        operation: impl for<'key> FnOnce(ckmg::Vld0Signer<'key>, ckmg::Vld0NodeCipher<'key>) -> T,
    ) -> std::result::Result<T, ckmg::Error> {
        match self {
            Self::Vault(session) => session.with_node(operation).await,
            Self::Ephemeral(transport) => transport.with_node(operation),
        }
    }
}
impl<C, A> Session<C, A> {
    fn lock(&mut self) {
        match self {
            Self::Vault(session) => session.lock(),
            Self::Ephemeral(transport) => transport.lock(),
        }
    }
}

/// Owns the sole epoch-zero transport session, independently of member Keys and
/// the serial Door queue. No root, PRF or purpose seed is exposed by this port.
pub struct BrowserTor<C, A> {
    session: Mutex<Session<C, A>>,
    node: Arc<ctrn::Node>,
    messages: Arc<ctrn::messages::Messages>,
    clock: Arc<Clock>,
    public_key: ckmg::PublicKey,
    pending: Cell<usize>,
    closed: Cell<bool>,
    checking: RefCell<Option<AbortHandle>>,
    drivers: Arc<Drivers>,
    listener_claimed: Cell<bool>,
    stop: RefCell<Option<oneshot::Sender<()>>>,
    stopped: Shared<LocalBoxFuture<'static, ()>>,
}

struct Admission<'a>(&'a Cell<usize>);
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

struct Starting(Option<Arc<ctrn::Node>>);
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(node) = self.0.take() {
            node.stop();
        }
    }
}

impl<C: ckmg::Clock, A: ckmg::Authority> BrowserTor<C, A> {
    /// Consume the session produced by PreparedOpen.transport, or a registration's
    /// `ckmg::EphemeralTransport` before any vault exists. Never replace a vault session
    /// with a legacy member Keys initializer after restoring the checkpoint.
    /// Startup owns cancellation: any failure/drop stops the original engine.
    #[allow(clippy::arc_with_non_send_sync)]
    pub async fn start(
        session: impl Into<Session<C, A>>,
        scope: ctrn::Scope,
        configuration: Configuration,
    ) -> Result<Self> {
        let mut session = session.into();
        let limits = configuration.limits;
        // TorJS has a smaller stream bound than the cross-platform Node.
        if !(1..=64).contains(&limits.streams)
            || !(1..=600_000).contains(&limits.bootstrap_ms)
            || !(1..=60_000).contains(&limits.operation_ms)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let factory = factory(
            limits.bootstrap_ms as u32,
            limits.operation_ms as u32,
            limits.streams as u32,
        )
        .map_err(|_| ErrorCode::Unavailable)?;
        let initializer = session
            .browser_initializer(scope)
            .await
            .map_err(keys_error)?;
        let clock = Arc::new(Clock);
        let node = initializer
            .initialize(factory, clock.clone(), limits)
            .map_err(|_| ErrorCode::Unavailable)?;
        let mut starting = Starting(Some(node.clone()));
        let drivers = Arc::new(Drivers {
            maximum: limits.streams,
            state: RefCell::new(DriverState {
                closed: false,
                next: 0,
                tasks: BTreeMap::new(),
            }),
        });
        let messages = Arc::new(
            ctrn::messages::Messages::new(
                node.clone(),
                Arc::new(DriverSpawner(drivers.clone())),
                clock.clone(),
                configuration.messages,
            )
            .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        node.start().await.map_err(|_| ErrorCode::Unavailable)?;
        let public_key = session.public_key().map_err(keys_error)?;
        let (stop, stopped) = oneshot::channel();
        let owner = Self {
            session: Mutex::new(session),
            node,
            messages,
            clock,
            public_key,
            pending: Cell::new(0),
            closed: Cell::new(false),
            checking: RefCell::new(None),
            drivers,
            listener_claimed: Cell::new(false),
            stop: RefCell::new(Some(stop)),
            stopped: async move {
                let _ = stopped.await;
            }
            .boxed_local()
            .shared(),
        };
        // Ownership now belongs to BrowserTor's Drop guard.
        starting.0.take();
        Ok(owner)
    }

    pub fn public_key(&self) -> ckmg::PublicKey {
        self.public_key
    }

    /// Original signing/DH callback only. Schedule callers independently from
    /// Door; the callback returns owned envelopes before any network await.
    pub async fn with_node<T>(
        &self,
        operation: impl for<'key> FnOnce(ckmg::Vld0Signer<'key>, ckmg::Vld0NodeCipher<'key>) -> T,
    ) -> Result<T> {
        if self.closed.get() {
            return Err(ErrorCode::Unavailable);
        }
        if self.pending.get() >= super::MAX_CLIENTS {
            return Err(ErrorCode::Capacity);
        }
        self.pending.set(self.pending.get() + 1);
        let _admission = Admission(&self.pending);
        let mut session = self.session.lock().await;
        if self.closed.get() {
            session.lock();
            return Err(ErrorCode::Unavailable);
        }
        let (abort, registration) = AbortHandle::new_pair();
        *self.checking.borrow_mut() = Some(abort);
        let result = Abortable::new(session.with_node(operation), registration).await;
        self.checking.borrow_mut().take();
        if self.closed.get() {
            session.lock();
            return Err(ErrorCode::Unavailable);
        }
        let result = result
            .map_err(|_| ErrorCode::Unavailable)?
            .map_err(keys_error);
        drop(session);
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Original complete-message port for TorDiscovery/TorRecords composition.
    /// Calling listen awaits genuine onion publication; start alone does not.
    pub fn messages(&self) -> Arc<ctrn::messages::Messages> {
        self.messages.clone()
    }

    pub fn clock(&self) -> Arc<dyn ctrn::Clock> {
        self.clock.clone()
    }

    /// Claim the sole listener before Records startup installs its close guard.
    /// A duplicate claimant cannot stop the already retained runtime.
    pub(super) fn claim_listener(&self) -> Result<()> {
        if self.is_closed() {
            return Err(ErrorCode::Unavailable);
        }
        if self.listener_claimed.replace(true) {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }

    pub(super) fn driver_limit(&self) -> usize {
        self.drivers.maximum
    }
    pub(super) fn is_closed(&self) -> bool {
        if self.closed.get() || self.node.health() != ctrn::State::Ready {
            self.close();
            true
        } else {
            false
        }
    }
    pub(super) fn stopped(&self) -> Shared<LocalBoxFuture<'static, ()>> {
        self.stopped.clone()
    }

    /// Await cancellation of original Ferry drivers after stopping the node.
    pub async fn shutdown(&self) -> Result<()> {
        self.close();
        self.drivers.drain().await
    }

    /// Stop reachability before wiping transport custody. Parent must also close
    /// its shared CustodyLifetime on lock, removal, cancellation and revocation.
    pub fn close(&self) {
        self.closed.set(true);
        if let Some(stop) = self.stop.borrow_mut().take() {
            let _ = stop.send(());
        }
        self.node.stop();
        self.drivers.close();
        if let Some(checking) = self.checking.borrow_mut().take() {
            checking.abort();
        }
        if let Some(mut session) = self.session.try_lock() {
            session.lock();
        }
    }
}

impl<C, A> Drop for BrowserTor<C, A> {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.get_mut().take() {
            let _ = stop.send(());
        }
        self.node.stop();
        self.drivers.close();
        self.session.get_mut().lock();
    }
}
