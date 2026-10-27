//! Native HTTP projection. Host and Origin are checked independently, and every
//! response is no-store. The runtime chooses a loopback listener; no body logs.
use super::*;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use futures_util::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit};

#[cfg(feature = "native-tor")]
pub mod deployment;
#[cfg(feature = "native-tor")]
pub use deployment::{DeviceSetup, DoorBuilder, NativeDeployment, RepeatableBuilder};

/// Rebuilds the Door and its composer on the Door's thread through the start's unchanged path
/// (a device restart, see [`Client::invoke_bytes`]).
pub(super) type Rebuild = std::rc::Rc<
    dyn Fn()
        -> futures_util::future::LocalBoxFuture<'static, Result<(Door, Box<dyn VaultComposer>)>>,
>;

/// A device restart on the Door's thread: the rebuilt Door, paired again for the same client.
type Restart = std::rc::Rc<
    dyn Fn() -> futures_util::future::LocalBoxFuture<
        'static,
        Result<(Door, ClientToken, Option<Box<dyn VaultComposer>>)>,
    >,
>;

/// The one action a device restart repeats (once) after the fresh login.
const REPEATED_AFTER_RESTART: &str = "community_join";

/// Injected trusted clock. Member-controlled request data never supplies time.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone)]
struct HttpState {
    runtime: Owner,
    hosts: BTreeSet<String>,
    requests: Arc<tokio::sync::Semaphore>,
    operations: Arc<Operations>,
    /// Longest one hop of the operation protocol waits for completion.
    hop_wait: Duration,
}

impl HttpState {
    fn new(runtime: Owner, hosts: BTreeSet<String>) -> Self {
        Self {
            runtime,
            hosts,
            requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
            operations: Arc::default(),
            hop_wait: HOP_WAIT,
        }
    }
}

/// Operation protocol (opt-in per request with `cmsg-operation: 1`). An action
/// is identified by its caller and exact bytes, so a repeated identical request
/// attaches to the running action or receives its kept outcome instead of
/// starting it again. One hop waits at most `hop_wait`; a still-running action
/// answers `pending` and the caller asks again. A transport timeout therefore
/// never decides an action's outcome. The device keeps each outcome until the
/// caller acknowledges it (`cmsg-acknowledge` on a later request), so a
/// restarted caller repeating its request receives the same outcome.
const OPERATION: HeaderName = HeaderName::from_static("cmsg-operation");
const ACKNOWLEDGE: HeaderName = HeaderName::from_static("cmsg-acknowledge");
const HOP_WAIT: Duration = Duration::from_secs(3);
const CLIENT_HOP: Duration = Duration::from_secs(10);
const LOST_HOP_PAUSE: Duration = Duration::from_millis(100);
/// Kept unacknowledged outcomes; the oldest is dropped beyond this bound.
const MAX_KEPT: usize = 32;
const MAX_ACKNOWLEDGED: usize = 8;

type OperationId = [u8; 32];

fn operation_id(origin: &str, token: &str, envelope: &[u8]) -> OperationId {
    let mut hash = Sha256::new();
    hash.update(b"cmsg native operation v1\0");
    for part in [origin.as_bytes(), token.as_bytes()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.update(envelope);
    hash.finalize().into()
}

fn encode_operation(id: &OperationId) -> String {
    BASE64URL_NOPAD.encode(id)
}

fn decode_operation(value: &str) -> Option<OperationId> {
    let bytes = match BASE64URL_NOPAD.decode(value.as_bytes()) {
        Ok(bytes) => bytes,
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "BASE64URL_NOPAD.decode", &__cause);
            return None;
        }
    };
    bytes.try_into().ok()
}

#[derive(Default)]
struct Operations(std::sync::Mutex<OperationTable>);

#[derive(Default)]
struct OperationTable {
    running: std::collections::HashMap<OperationId, watch::Receiver<Option<Output>>>,
    kept: std::collections::HashMap<OperationId, Kept>,
    sequence: u64,
    #[cfg(test)]
    started: usize,
}

struct Kept {
    sequence: u64,
    capability: [u8; 32],
    output: Output,
}

enum Attached {
    Kept(Output),
    Running(watch::Receiver<Option<Output>>),
    Started(Finish, watch::Receiver<Option<Output>>),
}

impl Operations {
    fn table(&self) -> std::sync::MutexGuard<'_, OperationTable> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn acknowledge(&self, ids: &[OperationId]) {
        let mut table = self.table();
        for id in ids {
            table.kept.remove(id);
        }
    }

    /// A capability that is no longer valid loses every outcome kept for it.
    fn forget(&self, capability: &[u8; 32]) {
        self.table()
            .kept
            .retain(|_, kept| kept.capability != *capability);
    }

    fn attach(self: &Arc<Self>, id: OperationId, capability: [u8; 32]) -> Attached {
        let mut table = self.table();
        if let Some(kept) = table.kept.get(&id) {
            return Attached::Kept(kept.output.clone());
        }
        if let Some(receiver) = table.running.get(&id) {
            return Attached::Running(receiver.clone());
        }
        let (sender, receiver) = watch::channel(None);
        table.running.insert(id, receiver.clone());
        #[cfg(test)]
        {
            table.started += 1;
        }
        Attached::Started(
            Finish {
                operations: self.clone(),
                id,
                capability,
                sender: Some(sender),
            },
            receiver,
        )
    }
}

/// Completes one running operation. Dropped without an outcome (its task was
/// cancelled), it unregisters the operation and every waiter sees Reconcile.
struct Finish {
    operations: Arc<Operations>,
    id: OperationId,
    capability: [u8; 32],
    sender: Option<watch::Sender<Option<Output>>>,
}

impl Finish {
    fn complete(mut self, output: Output) {
        {
            let mut table = self.operations.table();
            table.running.remove(&self.id);
            // A refused capability keeps nothing: it cannot displace kept outcomes.
            if !matches!(
                output,
                Output::Error {
                    error: ErrorCode::Unauthorized
                }
            ) {
                table.sequence += 1;
                let sequence = table.sequence;
                table.kept.insert(
                    self.id,
                    Kept {
                        sequence,
                        capability: self.capability,
                        output: output.clone(),
                    },
                );
                while table.kept.len() > MAX_KEPT {
                    let oldest = table
                        .kept
                        .iter()
                        .min_by_key(|(_, kept)| kept.sequence)
                        .map(|(id, _)| *id)
                        .expect("a table above its bound is not empty");
                    table.kept.remove(&oldest);
                }
            }
        }
        if let Some(sender) = self.sender.take() {
            sender.send_replace(Some(output));
        }
    }
}

impl Drop for Finish {
    fn drop(&mut self) {
        if self.sender.is_some() {
            self.operations.table().running.remove(&self.id);
        }
    }
}

/// Only bounded messages cross threads. Door and all its child facades stay on
/// their owning thread, including browser-compatible Rc custody adapters.
#[derive(Clone)]
struct Owner(mpsc::Sender<Command>, Arc<Grants>);

/// The owner's current client grants (capability hash -> origin, expiry),
/// refreshed after every owner command. The operation protocol checks it
/// before serving an attached or kept outcome, without queueing behind the
/// running action: a revoked or expired capability gets nothing.
struct Grants {
    current: std::sync::Mutex<BTreeMap<[u8; 32], (String, u64)>>,
    clock: Arc<dyn Clock>,
}

impl Grants {
    fn refresh(&self, door: Option<&Door>) {
        let current = door.map_or_else(BTreeMap::new, |door| {
            door.grants
                .iter()
                .map(|(key, grant)| (*key, (grant.origin.clone(), grant.expires)))
                .collect()
        });
        *self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = current;
    }

    fn valid(&self, origin: &str, capability: &[u8; 32]) -> bool {
        let now = self.clock.now();
        self.current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(capability)
            .is_some_and(|(granted, expires)| granted == origin && now < *expires)
    }
}
enum Command {
    Authenticate {
        origin: String,
        token: Zeroizing<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    Invoke {
        origin: String,
        token: Zeroizing<String>,
        envelope: Vec<u8>,
        reply: oneshot::Sender<Output>,
        permit: OwnedSemaphorePermit,
    },
    /// The paired client's device restart (its global session expired): close the old Door,
    /// build a fresh one through the start's path and pair the client again.
    Restart {
        origin: String,
        token: Zeroizing<String>,
        reply: oneshot::Sender<Result<ClientToken>>,
    },
    Stop,
}

/// A device restart: rebuild the Door through the start's path and pair the same client
/// again (a fresh capability; nothing of the old Door is carried over).
fn restart_paired(rebuild: Rebuild, pairing: Pairing, clock: Arc<dyn Clock>) -> Restart {
    std::rc::Rc::new(move || {
        let (rebuild, pairing, clock) = (rebuild.clone(), pairing.clone(), clock.clone());
        Box::pin(async move {
            let (mut door, composer) = rebuild().await?;
            let now = clock.now();
            let paired = now
                .checked_add(pairing.lifetime_seconds)
                .ok_or(ErrorCode::Clock)
                .and_then(|expires| {
                    door.pair_client(&pairing.origin, pairing.role, pairing.actions, now, expires)
                });
            match paired {
                Ok(token) => Ok((door, token, Some(composer))),
                Err(error) => {
                    let _ = drain_composer(&mut Some(composer)).await;
                    door.close_owned().await;
                    Err(error)
                }
            }
        })
    })
}

/// Drain once, even after a dispatcher panic. A failed cleanup is never success;
/// Drop still closes the actual lifetime and the LocalSet drains before exit.
async fn drain_composer(composer: &mut Option<Box<dyn VaultComposer>>) -> Result<()> {
    let Some(mut composer) = composer.take() else {
        return Ok(());
    };
    AssertUnwindSafe(async {
        composer.close();
        composer.drain().await
    })
    .catch_unwind()
    .await
    .unwrap_or(Err(ErrorCode::Reconcile))
}

/// One courier per bound Mesh of the Door, started after the dispatch that bound
/// the Mesh (the login) and ended with it.
#[derive(Default)]
struct Couriers(
    Vec<(
        String,
        std::rc::Rc<super::courier::Shared>,
        super::courier::Courier,
    )>,
);

impl Couriers {
    async fn sync(&mut self, door: &super::courier::SharedDoor) {
        let bound = door.lock().await.courier_shareds();
        self.0.retain(|(origin, shared, _)| {
            bound
                .iter()
                .any(|(o, s)| o == origin && std::rc::Rc::ptr_eq(s, shared))
        });
        for (origin, shared) in bound {
            if self
                .0
                .iter()
                .any(|(o, s, _)| *o == origin && std::rc::Rc::ptr_eq(s, &shared))
            {
                continue;
            }
            let courier =
                super::courier::spawn(door.clone(), &origin, super::courier::Config::default());
            #[cfg(feature = "native-prover")]
            if let Some(job) = door.lock().await.record_job(&origin) {
                let closed = shared.clone();
                tokio::task::spawn_local(super::record_job::run(
                    door.clone(),
                    origin.clone(),
                    job,
                    std::rc::Rc::new(move || closed.closed.get()),
                    super::record_job::Cadence::default(),
                ));
            }
            if let Some(worker) = door.lock().await.wave_worker(&origin) {
                let closed = shared.clone();
                tokio::task::spawn_local(super::wave_job::run(
                    door.clone(),
                    origin.clone(),
                    worker,
                    std::rc::Rc::new(move || closed.closed.get()),
                    super::wave_job::Cadence::default(),
                ));
            }
            self.0.push((origin, shared, courier));
        }
    }

    async fn stop(&mut self, door: &super::courier::SharedDoor) {
        door.lock().await.stop_couriers();
        for (_, _, courier) in self.0.drain(..) {
            let _ = courier.finished().await;
        }
    }
}

impl Owner {
    async fn start<F, Fut, T>(
        initialize: F,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, T, std::thread::JoinHandle<Result<()>>)>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, T)>> + 'static,
        T: Send + 'static,
    {
        Self::start_retained(
            move || async move {
                let (door, value) = initialize().await?;
                Ok((door, value, (), None, None))
            },
            clock,
        )
        .await
    }

    async fn start_retained<F, Fut, T, G>(
        initialize: F,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, T, std::thread::JoinHandle<Result<()>>)>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, T, G, Option<Box<dyn VaultComposer>>, Option<Restart>)>>
            + 'static,
        T: Send + 'static,
        G: 'static,
    {
        let (sender, mut receiver) = mpsc::channel(MAX_CLIENTS);
        let grants = Arc::new(Grants {
            current: std::sync::Mutex::default(),
            clock: clock.clone(),
        });
        let owner_grants = grants.clone();
        let (ready, initialized) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("cmsg-owner".into())
            .spawn(move || {
                let initialized = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                }));
                let Ok(Ok(runtime)) = initialized else {
                    let _ = ready.send(Err(ErrorCode::Unavailable));
                    return Err(ErrorCode::Unavailable);
                };
                runtime.block_on(async move {
                    let local = tokio::task::LocalSet::new();
                    let result = local
                        .run_until(async move {
                            let initialized = AssertUnwindSafe(async { initialize().await })
                                .catch_unwind()
                                .await;
                            let (door, value, retained, mut composer, restart) = match initialized {
                                Ok(Ok(value)) => value,
                                Ok(Err(error)) => {
                                    let _ = ready.send(Err(error));
                                    return Err(error);
                                }
                                Err(__cause) => { crate::door::cause::print(file!(), line!(), "let _ ready send Err ErrorCode::Unavailable return Err ErrorCode", &__cause); {
                                    let _ = ready.send(Err(ErrorCode::Unavailable));
                                    return Err(ErrorCode::Unavailable);
                                } }};
                            let mut retained = Some(retained);
                            owner_grants.refresh(Some(&door));
                            if ready.send(Ok(value)).is_err() {
                                let _ = drain_composer(&mut composer).await;
                                door.close_owned().await;
                                return Err(ErrorCode::Unavailable);
                            }
                            // The Door is shared with the couriers of its bound Meshes.
                            let door = std::rc::Rc::new(tokio::sync::Mutex::new(door));
                            let mut couriers = Couriers::default();
                            let mut failed = false;
                            while let Some(command) = receiver.recv().await {
                                match command {
                                    Command::Stop => receiver.close(),
                                    Command::Restart {
                                        origin,
                                        token,
                                        reply,
                                    } => {
                                        let restarted = match &restart {
                                            Some(restart) if !failed => {
                                                // Only the paired client restarts its device.
                                                let paired = door
                                                    .lock()
                                                    .await
                                                    .authenticate(&origin, &token, clock.now())
                                                    .map(|_| ());
                                                match paired {
                                                    Err(error) => Err(error),
                                                    Ok(()) => {
                                                        // The old Door closes first; its authority
                                                        // is never used again.
                                                        let _ = drain_composer(&mut composer).await;
                                                        couriers.stop(&door).await;
                                                        door.lock().await.close_in_place().await;
                                                        match AssertUnwindSafe(restart())
                                                            .catch_unwind()
                                                            .await
                                                        {
                                                            Ok(Ok((
                                                                fresh,
                                                                token,
                                                                fresh_composer,
                                                            ))) => {
                                                                *door.lock().await = fresh;
                                                                composer = fresh_composer;
                                                                Ok(token)
                                                            }
                                                            Ok(Err(_)) => {
                                                                Err(ErrorCode::SessionExpired)
                                                            }
                                                            Err(_) => {
                                                                failed = true;
                                                                drop(retained.take());
                                                                Err(ErrorCode::Unavailable)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            _ => Err(ErrorCode::SessionExpired),
                                        };
                                        if failed {
                                            owner_grants.refresh(None);
                                        } else {
                                            owner_grants.refresh(Some(&*door.lock().await));
                                        }
                                        let _ = reply.send(restarted);
                                    }
                                    Command::Authenticate {
                                        origin,
                                        token,
                                        reply,
                                    } => {
                                        let checked = if failed {
                                            Err(ErrorCode::Unavailable)
                                        } else {
                                            let mut guard = door.lock().await;
                                            match std::panic::catch_unwind(AssertUnwindSafe(|| {
                                                guard
                                                    .authenticate(&origin, &token, clock.now())
                                                    .map(|_| ())
                                            })) {
                                                Ok(result) => result,
                                                Err(__cause) => { crate::door::cause::print(file!(), line!(), "failed true let _ drain_composer mut composer await drop retaine", &__cause); {
                                                    failed = true;
                                                    let _ = drain_composer(&mut composer).await;
                                                    drop(retained.take());
                                                    Err(ErrorCode::Unavailable)
                                                } }}
                                        };
                                        if failed {
                                            owner_grants.refresh(None);
                                        } else {
                                            owner_grants.refresh(Some(&*door.lock().await));
                                        }
                                        let _ = reply.send(checked);
                                    }
                                    Command::Invoke {
                                        origin,
                                        token,
                                        envelope,
                                        reply,
                                        permit,
                                    } => {
                                        let _permit = permit;
                                        let output = if failed {
                                            Output::Error {
                                                error: ErrorCode::Unavailable,
                                            }
                                        } else {
                                            // Even a lost HTTP waiter cannot cancel this future.
                                            // A panic may follow a durable child effect: reconcile,
                                            // then refuse every later request on this runtime.
                                            match AssertUnwindSafe(async {
                                                let token = ClientToken(token);
                                                let action =
                                                    serde_json::from_slice::<Invocation>(&envelope)
                                                        .map(|request| request.action)
                                                        .unwrap_or_default();
                                                let mut output = door
                                                    .lock()
                                                    .await
                                                    .dispatch(
                                                        &origin,
                                                        token.expose_for_transport(),
                                                        &envelope,
                                                        clock.now(),
                                                    )
                                                    .await;
                                                if let Some(composer) = composer.as_mut() {
                                                    let refusal = match &output {
                                                        Output::Error { error } => Some(*error),
                                                        Output::Ok { .. } => None,
                                                    };
                                                    let composed = composer
                                                        .after_dispatch(
                                                            &mut *door.lock().await,
                                                            &origin,
                                                            &token,
                                                            &action,
                                                            &mut output,
                                                            clock.now(),
                                                        )
                                                        .await;
                                                    if let Err(error) = composed {
                                                        composer.close();
                                                        output = Output::Error { error };
                                                    }
                                                    // Even a faulty composer cannot turn the original
                                                    // dispatcher refusal into successful custody.
                                                    if let Some(error) = refusal {
                                                        output = Output::Error { error };
                                                    }
                                                }
                                                couriers.sync(&door).await;
                                                output
                                            })
                                            .catch_unwind()
                                            .await
                                            {
                                                Ok(output) => output,
                                                Err(__cause) => { crate::door::cause::print(file!(), line!(), "failed true let _ drain_composer mut composer await drop retaine", &__cause); {
                                                    failed = true;
                                                    let _ = drain_composer(&mut composer).await;
                                                    drop(retained.take());
                                                    Output::Error {
                                                        error: ErrorCode::Reconcile,
                                                    }
                                                } }}
                                        };
                                        if failed {
                                            owner_grants.refresh(None);
                                        } else {
                                            owner_grants.refresh(Some(&*door.lock().await));
                                        }
                                        let _ = reply.send(output);
                                    }
                                }
                            }
                            let drained = drain_composer(&mut composer).await;
                            couriers.stop(&door).await;
                            if failed {
                                // Never call domain methods on a panic-fenced owner.
                                // Dropping its state cannot grant another request access.
                                return Err(ErrorCode::Reconcile);
                            }
                            match std::rc::Rc::try_unwrap(door) {
                                Ok(door) => door.into_inner().close_owned().await,
                                Err(_) => return Err(ErrorCode::Reconcile),
                            }
                            drained
                        })
                        .await;
                    // A dropped/cancelled initializer can already have scheduled
                    // independent local cleanup. Keep its executor alive until
                    // those actual tasks finish, including on panic/refusal.
                    local.await;
                    result
                })
            })
            .map_err(|__cause| crate::door::cause::emit(file!(), line!(), "ErrorCode::Unavailable", ErrorCode::Unavailable, &__cause))?;
        match initialized.await {
            Ok(Ok(value)) => Ok((Self(sender, grants), value, thread)),
            failure => {
                // Failed construction must finish its independent cleanup before
                // its caller can discard storage or start another owner.
                drop(sender);
                let joined = tokio::task::spawn_blocking(move || thread.join()).await;
                if !matches!(joined, Ok(Ok(_))) {
                    return Err(ErrorCode::Reconcile);
                }
                Err(match failure {
                    Ok(Err(error)) => error,
                    _ => ErrorCode::Unavailable,
                })
            }
        }
    }

    async fn authenticate(&self, origin: &str, token: &str) -> Result<()> {
        let (reply, receive) = oneshot::channel();
        self.0
            .send(Command::Authenticate {
                origin: origin.into(),
                token: Zeroizing::new(token.into()),
                reply,
            })
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        receive.await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?
    }

    async fn restart(&self, origin: &str, token: &str) -> Result<ClientToken> {
        let (reply, receive) = oneshot::channel();
        self.0
            .send(Command::Restart {
                origin: origin.into(),
                token: Zeroizing::new(token.into()),
                reply,
            })
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        receive.await.map_err(|_| ErrorCode::Unavailable)?
    }

    async fn invoke(
        &self,
        origin: String,
        token: Zeroizing<String>,
        envelope: Vec<u8>,
        permit: OwnedSemaphorePermit,
    ) -> Output {
        let (reply, receive) = oneshot::channel();
        if self
            .0
            .send(Command::Invoke {
                origin,
                token,
                envelope,
                reply,
                permit,
            })
            .await
            .is_err()
        {
            return Output::Error {
                error: ErrorCode::Unavailable,
            };
        }
        // A vanished owner after admission may have committed. Never suggest retry.
        receive.await.unwrap_or(Output::Error {
            error: ErrorCode::Reconcile,
        })
    }
}

fn validate_hosts(hosts: &BTreeSet<String>) -> Result<()> {
    if hosts.is_empty()
        || hosts.len() > 8
        || hosts.iter().any(|host| {
            host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('@')
        })
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// Construct all facades inside a dedicated current-thread runtime. The factory
/// may produce a non-Send future and Door; only the factory crosses threads.
/// Dropping every router closes admission and drains admitted owner work.
pub async fn router<F, Fut>(
    initialize: F,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
) -> Result<Router>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<Door>> + 'static,
{
    router_with(
        move || async { Ok((initialize().await?, ())) },
        hosts,
        clock,
    )
    .await
    .map(|(router, ())| router)
}

/// Trusted initialization with one protected in-process startup result. This is
/// useful for host pairing; it is never exposed through an HTTP/JSON action.
/// Construct non-Send facades inside initialize, not before moving the factory.
pub async fn router_with<F, Fut, T>(
    initialize: F,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
) -> Result<(Router, T)>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(Door, T)>> + 'static,
    T: Send + 'static,
{
    validate_hosts(&hosts)?;
    let (runtime, value, _thread) = Owner::start(initialize, clock).await?;
    Ok((routes(HttpState::new(runtime, hosts)), value))
}

fn routes(state: HttpState) -> Router {
    Router::new()
        .route("/invoke", post(invoke))
        .route("/v1/{action}", post(call))
        .with_state(state)
        .fallback(|| async {
            response(Output::Error {
                error: ErrorCode::UnsupportedAction,
            })
        })
        .method_not_allowed_fallback(|| async {
            response(Output::Error {
                error: ErrorCode::InvalidRequest,
            })
        })
        .layer(middleware::map_response(no_store))
}

/// Trusted native pairing configuration. This is not an API request and grants
/// only local access; configured Foyer sessions supply remote authority.
#[derive(Clone)]
pub struct Pairing {
    pub origin: String,
    pub role: Role,
    pub actions: BTreeSet<String>,
    pub lifetime_seconds: u64,
}

/// Owns the listener, protected local client and facade thread. No capability is
/// exposed as JSON, environment data or a URL. Explicit shutdown drains admitted
/// owner work, including work whose HTTP request has already disappeared.
pub struct Embedded {
    client: Client,
    runtime: RuntimeHandle,
}

/// Owns the embedded listener and facade thread independently of its single
/// protected client. Explicit shutdown drains admitted owner work even after
/// the client or an HTTP waiter has disappeared. No endpoint or capability is
/// exposed by this handle.
#[must_use = "retain the runtime handle and await shutdown after its client finishes"]
pub struct RuntimeHandle {
    owner: Owner,
    stop: Option<oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    thread: std::thread::JoinHandle<Result<()>>,
}
/// Public deployment data. Native construction uses the same schema as the
/// browser; capabilities, authenticators and storage secrets are not fields.
pub use super::browser::Configuration as DeviceConfiguration;

impl Embedded {
    /// Configure an optional dormant native restore composer. Without Tor
    /// deployment settings this explicitly selects the existing partial host.
    #[cfg(feature = "native-tor")]
    pub async fn configured_restore_with(
        deployment: NativeDeployment,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
        setup: DeviceSetup,
    ) -> Result<Self> {
        deployment
            .start_with(
                lifetime_seconds,
                clock,
                deployment::DoorSource::Runtime(Some(setup)),
            )
            .await
    }

    /// Like [`Self::configured_restore_with`], but the embedder builds the whole Door (see
    /// [`DoorBuilder`]): the runtime configuration then only has to match the device settings.
    #[cfg(feature = "native-tor")]
    pub async fn configured_restore_built(
        deployment: NativeDeployment,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
        build: DoorBuilder,
    ) -> Result<Self> {
        deployment
            .start_with(
                lifetime_seconds,
                clock,
                deployment::DoorSource::Built(build),
            )
            .await
    }

    /// Configure an optional dormant native restore composer. Without Tor
    /// deployment settings this explicitly selects the existing partial host.
    #[cfg(feature = "native-tor")]
    pub async fn configured_restore(
        deployment: NativeDeployment,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        deployment.start(lifetime_seconds, clock).await
    }

    /// Construct configured actual Foyer/Board owners inside the dedicated
    /// thread. This partial startup keeps custody/login/Mesh unavailable until
    /// their real initializer is integrated; it never claims messaging readiness.
    pub async fn configured(
        configuration: DeviceConfiguration,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let pairing = Pairing {
            origin: configuration.origin.clone(),
            role: configuration.role,
            actions: catalog().into_iter().map(|action| action.action).collect(),
            lifetime_seconds,
        };
        Self::start(
            move || async move { configuration.construct() },
            pairing,
            clock,
        )
        .await
    }

    pub async fn start<F, Fut>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Door>> + 'static,
    {
        Self::start_retained(
            move || async move { Ok((initialize().await?, ())) },
            pairing,
            clock,
        )
        .await
    }

    /// Retain non-Send composition guards on the same LocalSet as Door. A
    /// transport guard can own its independently progressing credential task;
    /// it survives each action and is dropped after admitted work is drained.
    /// Session lock/revoke must still close its negative lifetime immediately.
    /// This hook grants no readiness or authority by itself.
    pub async fn start_retained<F, Fut, G>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, G)>> + 'static,
        G: 'static,
    {
        Self::start_owned(
            move || async move {
                let (door, guard) = initialize().await?;
                Ok((door, guard, None, None))
            },
            pairing,
            clock,
        )
        .await
    }

    /// Retain original custody composition on the Door's LocalSet. The factory
    /// builds a dormant composer; actual recovery begins only after a successful
    /// original login dispatch. Its close/drain always precedes Store teardown.
    pub async fn start_composed<F, Fut>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, Box<dyn VaultComposer>)>> + 'static,
    {
        Self::start_owned(
            move || async move {
                let (door, composer) = initialize().await?;
                Ok((door, (), Some(composer), None))
            },
            pairing,
            clock,
        )
        .await
    }

    /// [`Self::start_composed`] whose Door can be rebuilt on its thread: a device restart
    /// (the client's expired global session) closes the old Door and swaps in a fresh one.
    #[cfg(feature = "native-tor")]
    pub(super) async fn start_restartable<F, Fut>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, Box<dyn VaultComposer>, Option<Rebuild>)>> + 'static,
    {
        Self::start_owned(
            move || async move {
                let (door, composer, rebuild) = initialize().await?;
                Ok((door, (), Some(composer), rebuild))
            },
            pairing,
            clock,
        )
        .await
    }

    async fn start_owned<F, Fut, G>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, G, Option<Box<dyn VaultComposer>>, Option<Rebuild>)>>
            + 'static,
        G: 'static,
    {
        validate_origin(&pairing.origin)?;
        if pairing.lifetime_seconds == 0 || pairing.lifetime_seconds > MAX_GRANT_SECONDS {
            return Err(ErrorCode::InvalidRequest);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let address = listener.local_addr().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let origin = pairing.origin.clone();
        let pairing_clock = clock.clone();
        let (owner, token, thread) = Owner::start_retained(
            move || async move {
                let (mut door, retained, mut composer, rebuild) = initialize().await?;
                let restart = rebuild
                    .map(|rebuild| restart_paired(rebuild, pairing.clone(), pairing_clock.clone()));
                let paired = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    let now = pairing_clock.now();
                    let expires = now
                        .checked_add(pairing.lifetime_seconds)
                        .ok_or(ErrorCode::Clock)?;
                    door.pair_client(&pairing.origin, pairing.role, pairing.actions, now, expires)
                }));
                match paired {
                    Ok(Ok(token)) => Ok((door, token, retained, composer, restart)),
                    failure => {
                        let _ = drain_composer(&mut composer).await;
                        match failure {
                            Ok(Err(error)) => {
                                door.close_owned().await;
                                Err(error)
                            }
                            _ => Err(ErrorCode::Reconcile),
                        }
                    }
                }
            },
            clock,
        )
        .await?;
        let mut client = Client::new(&format!("http://{address}"), &origin, token)?;
        client.restart = Some(owner.clone());
        let app = routes(HttpState::new(
            owner.clone(),
            BTreeSet::from([address.to_string()]),
        ));
        let (stop, receive) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receive.await;
                })
                .await
        });
        Ok(Self {
            client,
            runtime: RuntimeHandle {
                owner,
                stop: Some(stop),
                server,
                thread,
            },
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Move the one protected client into an owned CLI/MCP consumer while the
    /// caller retains responsibility for draining the runtime. Neither value
    /// clones or exports its local capability.
    pub fn into_parts(self) -> (Client, RuntimeHandle) {
        (self.client, self.runtime)
    }

    pub async fn shutdown(self) -> Result<()> {
        let (client, runtime) = self.into_parts();
        drop(client);
        runtime.shutdown().await
    }
}

impl RuntimeHandle {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let server = self.server.await;
        // Stop closes the queue and drains it; HTTP graceful shutdown alone is
        // insufficient because cancelled waiters may already be gone.
        let _ = self.owner.0.send(Command::Stop).await;
        let joined = tokio::task::spawn_blocking(move || self.thread.join()).await;
        joined
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })?
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Reconcile",
                    ErrorCode::Reconcile,
                    &__cause,
                )
            })??;
        if !matches!(server, Ok(Ok(()))) {
            return Err(ErrorCode::Unavailable);
        }
        Ok(())
    }
}

// Never let different HTTP consumers choose different values for an authority
// header. Exact configured origins and hosts do not accept comma lists either.
fn unique_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

async fn call(
    State(state): State<HttpState>,
    Path(action): Path<String>,
    request: Request,
) -> Response {
    dispatch(state, Some(action), request).await
}

async fn invoke(State(state): State<HttpState>, request: Request) -> Response {
    dispatch(state, None, request).await
}

async fn dispatch(state: HttpState, action: Option<String>, request: Request) -> Response {
    let headers = request.headers();
    let host = unique_header(headers, header::HOST);
    let origin = unique_header(headers, header::ORIGIN);
    let token =
        unique_header(headers, header::AUTHORIZATION).and_then(|h| h.strip_prefix("Bearer "));
    let (Some(host), Some(origin), Some(token)) = (host, origin, token) else {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    };
    if !state.hosts.contains(host)
        || unique_header(headers, header::CONTENT_TYPE) != Some("application/json")
    {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    }
    let operation = match headers.get(&OPERATION) {
        None => None,
        Some(_) if unique_header(headers, OPERATION) == Some("1") => match acknowledged(headers) {
            Some(ids) => Some(ids),
            None => {
                return response(Output::Error {
                    error: ErrorCode::InvalidRequest,
                })
            }
        },
        Some(_) => {
            return response(Output::Error {
                error: ErrorCode::InvalidRequest,
            })
        }
    };
    let origin = origin.to_owned();
    let token = Zeroizing::new(token.to_owned());
    let Ok(permit) = state.requests.clone().try_acquire_owned() else {
        return response(Output::Error {
            error: ErrorCode::Capacity,
        });
    };
    if let Some(acknowledged) = operation {
        return operate(state, action, request, origin, token, permit, &acknowledged).await;
    }
    // Bound queued work before authentication; repeat authority after body and
    // channel waiting with fresh time inside the owner thread.
    let authorized = state.runtime.authenticate(&origin, &token).await;
    if let Err(error) = authorized {
        return response(Output::Error { error });
    }
    let envelope = match envelope(action, request).await {
        Ok(envelope) => envelope,
        Err(refused) => return *refused,
    };
    let output = state.runtime.invoke(origin, token, envelope, permit).await;
    response(output)
}

/// Acknowledged operation ids: absent, or one header with at most
/// `MAX_ACKNOWLEDGED` comma-separated ids. Anything else is refused.
fn acknowledged(headers: &HeaderMap) -> Option<Vec<OperationId>> {
    if headers.get(&ACKNOWLEDGE).is_none() {
        return Some(Vec::new());
    }
    let ids = unique_header(headers, ACKNOWLEDGE)?
        .split(',')
        .map(decode_operation)
        .collect::<Option<Vec<_>>>()?;
    (ids.len() <= MAX_ACKNOWLEDGED).then_some(ids)
}

/// Read the bounded body and build the exact invocation envelope.
async fn envelope(
    action: Option<String>,
    request: Request,
) -> std::result::Result<Vec<u8>, Box<Response>> {
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(__cause)) => {
            crate::door::cause::print(
                file!(),
                line!(),
                "return Err Box::new response Output::Error error: ErrorCode::Capacity",
                &__cause,
            );
            return Err(Box::new(response(Output::Error {
                error: ErrorCode::Capacity,
            })));
        }
        Err(__cause) => {
            crate::door::cause::print(
                file!(),
                line!(),
                "return Err Box::new response Output::Error error: ErrorCode::Una",
                &__cause,
            );
            {
                return Err(Box::new(response(Output::Error {
                    error: ErrorCode::Unavailable,
                })));
            }
        }
    };
    // Preserve the exact body bytes for the typed Serde decoder, including its
    // duplicate-field rejection. No Value round trip before authorization.
    Ok(if let Some(action) = action {
        let Ok(body) = std::str::from_utf8(&bytes) else {
            return Err(Box::new(response(Output::Error {
                error: ErrorCode::InvalidRequest,
            })));
        };
        let name = serde_json::to_string(&action).expect("a string always encodes as JSON");
        format!("{{\"action\":{name},\"version\":1,\"body\":{body}}}").into_bytes()
    } else {
        bytes.to_vec()
    })
}

/// One hop of the operation protocol. A new action runs in its own task
/// (authentication, then admitted execution) that no HTTP waiter can cancel;
/// the hop waits at most `hop_wait` for it. The permit bounds every waiter and
/// travels with a new action into the owner, as without the protocol.
async fn operate(
    state: HttpState,
    action: Option<String>,
    request: Request,
    origin: String,
    token: Zeroizing<String>,
    permit: OwnedSemaphorePermit,
    acknowledged: &[OperationId],
) -> Response {
    let envelope = match envelope(action, request).await {
        Ok(envelope) => envelope,
        Err(refused) => return *refused,
    };
    state.operations.acknowledge(acknowledged);
    let id = operation_id(&origin, &token, &envelope);
    let capability = token_hash(&token);
    let grants = state.runtime.1.clone();
    // An attached or kept outcome is served only to a capability that is still
    // valid; a revoked or expired one gets nothing and loses its kept outcomes.
    let refused = |operations: &Operations| {
        operations.forget(&capability);
        response(Output::Error {
            error: ErrorCode::Unauthorized,
        })
    };
    let (mut receiver, _permit, check) = match state.operations.attach(id, capability) {
        Attached::Kept(output) => {
            if !grants.valid(&origin, &capability) {
                return refused(&state.operations);
            }
            return operation_response(&id, Some(output));
        }
        Attached::Running(receiver) => {
            if !grants.valid(&origin, &capability) {
                return refused(&state.operations);
            }
            (receiver, Some(permit), true)
        }
        Attached::Started(finish, receiver) => {
            // This hop's own run authenticates inside its task.
            let runtime = state.runtime.clone();
            let origin = origin.clone();
            tokio::spawn(async move {
                let output = match runtime.authenticate(&origin, &token).await {
                    Err(error) => Output::Error { error },
                    Ok(()) => runtime.invoke(origin, token, envelope, permit).await,
                };
                finish.complete(output);
            });
            (receiver, None, false)
        }
    };
    let outcome = match tokio::time::timeout(
        state.hop_wait,
        receiver.wait_for(|outcome| outcome.is_some()),
    )
    .await
    {
        Ok(Ok(outcome)) => outcome.clone(),
        // The action's task ended without an outcome: it may have committed.
        Ok(Err(__cause)) => {
            crate::door::cause::print(
                file!(),
                line!(),
                "Some Output::Error error: ErrorCode::Reconcile",
                &__cause,
            );
            Some(Output::Error {
                error: ErrorCode::Reconcile,
            })
        }
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "None", &__cause);
            None
        }
    };
    if check && outcome.is_some() && !grants.valid(&origin, &capability) {
        return refused(&state.operations);
    }
    operation_response(&id, outcome)
}

/// A final outcome, or `pending` (202) while the action is still running.
fn operation_response(id: &OperationId, outcome: Option<Output>) -> Response {
    let mut answer = match outcome {
        Some(output) => response(output),
        None => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "status": "pending" })),
        )
            .into_response(),
    };
    answer.headers_mut().insert(
        OPERATION,
        HeaderValue::from_str(&encode_operation(id)).expect("base64url is a header value"),
    );
    answer
}

fn response(output: Output) -> Response {
    let code = match output {
        Output::Ok { .. } => StatusCode::OK,
        Output::Error {
            error: ErrorCode::Unauthorized,
        } => StatusCode::FORBIDDEN,
        Output::Error {
            error: ErrorCode::Capacity,
        } => StatusCode::PAYLOAD_TOO_LARGE,
        Output::Error {
            error: ErrorCode::Unavailable | ErrorCode::Reconcile,
        } => StatusCode::SERVICE_UNAVAILABLE,
        Output::Error { .. } => StatusCode::BAD_REQUEST,
    };
    (code, Json(output)).into_response()
}

// Includes routing and extraction refusals as well as domain responses.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Native paired-client transport for CLI/MCP/TUI. No Clone/Debug or credential
/// accessor exists. Pairing is performed by the trusted host, never by this client.
pub struct Client {
    http: reqwest::Client,
    endpoint: url::Url,
    origin: String,
    /// Replaced only by a device restart (a fresh pairing on the fresh Door).
    capability: std::sync::Mutex<ClientToken>,
    /// The embedded owner, for a device restart when the global session expired.
    restart: Option<Owner>,
    /// Outcomes this client has read, acknowledged on its next request.
    acknowledged: std::sync::Mutex<Vec<String>>,
}

/// What one hop of the operation protocol learned.
enum Hop {
    Final(Output, Option<String>),
    Pending,
    /// No answer within the hop (timeout, interrupted response): ask again.
    Lost,
    /// The device is not listening: nothing is running there any more.
    Gone,
    /// The device answered outside the protocol.
    Invalid,
}

impl Client {
    /// Consume an already paired local capability. Only literal loopback HTTP
    /// origins are allowed; neither DNS, redirects nor environment proxies can
    /// forward this capability to a different service. No cookie jar is used.
    pub fn new(base: &str, origin: &str, capability: ClientToken) -> Result<Self> {
        Self::with_hop(base, origin, capability, CLIENT_HOP)
    }

    /// `hop` bounds one request/response exchange, never an action.
    fn with_hop(base: &str, origin: &str, capability: ClientToken, hop: Duration) -> Result<Self> {
        validate_origin(origin)?;
        let mut endpoint = url::Url::parse(base).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if !loopback
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        endpoint.set_path("/invoke");
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(hop)
            .build()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        Ok(Self {
            http,
            endpoint,
            origin: origin.into(),
            capability: std::sync::Mutex::new(capability),
            restart: None,
            acknowledged: std::sync::Mutex::default(),
        })
    }

    /// Forward the original invocation bytes. There is no Value parse/reencode
    /// that could erase duplicate fields before the Door's typed decoder.
    /// The action runs as one device operation: a hop without an answer, or a
    /// `pending` answer, repeats the identical request, which attaches to the
    /// same operation and can never start the action twice. The result is the
    /// action's real outcome, however long it runs; Reconcile only when the
    /// device stops listening or answers outside the protocol. Valid owner
    /// refusals stay unchanged in Output. No redirect is ever followed.
    pub async fn invoke_bytes(&self, request: &[u8]) -> Result<Output> {
        let output = self.invoke_once(request).await?;
        let (
            Some(owner),
            Output::Error {
                error: ErrorCode::SessionExpired,
            },
        ) = (&self.restart, &output)
        else {
            return Ok(output);
        };
        // The device's global session expired: restart the device (a fresh Door through the
        // start's unchanged path), pair again and log in by the retained device login (no
        // ceremony). A join then repeats ONCE (each of its steps is an idempotent state); any
        // other operation reports `session_expired` and the app's next call succeeds.
        if self.restart_device(owner).await.is_err() {
            return Ok(output);
        }
        let repeat = serde_json::from_slice::<Invocation>(request)
            .is_ok_and(|invocation| invocation.action == REPEATED_AFTER_RESTART);
        if !repeat {
            return Ok(output);
        }
        self.invoke_once(request).await
    }

    async fn restart_device(&self, owner: &Owner) -> Result<()> {
        let current = self.bearer_token();
        let fresh = owner.restart(&self.origin, &current).await?;
        *self
            .capability
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = fresh;
        let login = serde_json::to_vec(&Invocation {
            action: "login.start".into(),
            version: 1,
            body: serde_json::json!({}),
        })
        .map_err(|_| ErrorCode::InvalidRequest)?;
        match self.invoke_once(&login).await? {
            Output::Ok { result, .. } if result["state"] == "complete" => Ok(()),
            Output::Ok { .. } => Err(ErrorCode::SessionExpired),
            Output::Error { error } => Err(error),
        }
    }

    fn bearer_token(&self) -> Zeroizing<String> {
        Zeroizing::new(
            self.capability
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .expose_for_transport()
                .to_owned(),
        )
    }

    async fn invoke_once(&self, request: &[u8]) -> Result<Output> {
        if request.len() > MAX_BODY_BYTES {
            return Err(ErrorCode::Capacity);
        }
        let bearer = Zeroizing::new(format!("Bearer {}", self.bearer_token().as_str()));
        // Capability encoding is fixed ASCII base64url from the owner constructor.
        let mut authorization =
            HeaderValue::from_str(&bearer).expect("paired capability is fixed ASCII base64url");
        authorization.set_sensitive(true);
        loop {
            let acknowledged = self.take_acknowledged();
            match self.hop(request, &authorization, &acknowledged).await {
                Hop::Final(output, id) => {
                    self.restore_acknowledged(id.into_iter().collect());
                    return Ok(output);
                }
                Hop::Pending => {}
                Hop::Lost => {
                    self.restore_acknowledged(acknowledged);
                    tokio::time::sleep(LOST_HOP_PAUSE).await;
                }
                Hop::Gone => {
                    self.restore_acknowledged(acknowledged);
                    return Err(ErrorCode::Reconcile);
                }
                Hop::Invalid => return Err(ErrorCode::Reconcile),
            }
        }
    }

    fn take_acknowledged(&self) -> Vec<String> {
        let mut pending = self
            .acknowledged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = pending.len().min(MAX_ACKNOWLEDGED);
        pending.drain(..count).collect()
    }

    fn restore_acknowledged(&self, ids: Vec<String>) {
        let mut pending = self
            .acknowledged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for id in ids {
            if !pending.contains(&id) {
                pending.push(id);
            }
        }
        // An unacknowledged outcome only waits for the device's own bound.
        let excess = pending.len().saturating_sub(MAX_KEPT);
        pending.drain(..excess);
    }

    async fn hop(
        &self,
        request: &[u8],
        authorization: &HeaderValue,
        acknowledged: &[String],
    ) -> Hop {
        let mut call = self
            .http
            .post(self.endpoint.clone())
            .header(header::ORIGIN, &self.origin)
            .header(header::AUTHORIZATION, authorization.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header(OPERATION, "1");
        if !acknowledged.is_empty() {
            call = call.header(ACKNOWLEDGE, acknowledged.join(","));
        }
        let mut response = match call.body(request.to_vec()).send().await {
            Ok(response) => response,
            Err(error) if error.is_connect() => return Hop::Gone,
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "return Hop::Lost", &__cause);
                return Hop::Lost;
            }
        };
        let status = response.status();
        let id = unique_header(response.headers(), OPERATION)
            .filter(|id| decode_operation(id).is_some())
            .map(str::to_owned);
        if unique_header(response.headers(), header::CONTENT_TYPE) != Some("application/json")
            || unique_header(response.headers(), header::CACHE_CONTROL) != Some("no-store")
        {
            return Hop::Invalid;
        }
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.len() > MAX_RESULT_BYTES - bytes.len() {
                        return Hop::Invalid;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(__cause) => {
                    crate::door::cause::print(file!(), line!(), "return Hop::Lost", &__cause);
                    return Hop::Lost;
                }
            }
        }
        if status == StatusCode::ACCEPTED {
            return match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(value)
                    if value == serde_json::json!({ "status": "pending" }) && id.is_some() =>
                {
                    Hop::Pending
                }
                _ => Hop::Invalid,
            };
        }
        let Ok(output) = serde_json::from_slice::<Output>(&bytes) else {
            return Hop::Invalid;
        };
        if status.is_success() != matches!(output, Output::Ok { .. }) {
            return Hop::Invalid;
        }
        Hop::Final(output, id)
    }
}

#[cfg(test)]
#[path = "../../tests/support/native.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/support/native_composition.rs"]
mod composition_tests;
