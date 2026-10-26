//! Native transport composition for an authenticated headless member.
//!
//! This is a trusted constructor, not a public action or a complete toy journey.
//! Original Records operations cross a bounded channel; transport custody stays
//! in an independently polled local task while Door awaits network/Store work.
use super::{custody, Door, ErrorCode};
use cdht::{
    rpc::{
        envelope::{
            AuthenticatedOperation, Envelope, EnvelopeCipher, TimeWindow, MAX_ENVELOPE_BYTES,
        },
        peers::{Advertisement, FindAnswer},
        Answer, Question, SignedOperation, Statement, UnverifiedPeerInfoBytes,
    },
    Error, NodeId,
};
use cmsh::tor_discovery::TorNodeIdentity;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Semaphore};

pub mod mesh;
pub mod network;
pub mod restore;

const REQUESTS: usize = 16;
type Session =
    ckmg::TransportSession<custody::SystemClock, custody::TransportAuthority<custody::SystemClock>>;

/// Send/Sync facade containing only public identity and bounded message senders.
/// No member/root/record signing capability is reachable through this facade.
#[derive(Clone)]
pub struct TransportClient {
    node: NodeId,
    requests: mpsc::Sender<Request>,
    pending: Arc<Semaphore>,
    // Construction identity only: prevent accidentally retaining a different
    // session's owner when composing the native network. This grants no keys.
    session: Arc<()>,
    window: TimeWindow,
}

/// Retain alongside the unlocked Vault for its entire lifetime. Dropping this
/// guard closes authority immediately and cancels the independent custody task.
/// It must also be closed on login cancellation, lock, revoke and failed restore.
#[must_use = "retain with Vault; closing it stops the original Tor engine"]
pub struct TransportOwner {
    lifetime: custody::CustodyLifetime,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    member: Option<custody::MemberAuthorityBuilder>,
    foyer: cfyr::policy::CurrentPolicy<super::foyer::Transport>,
    session: Arc<()>,
}

struct Lifetime(custody::CustodyLifetime);
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.close();
    }
}

enum Operation {
    Sign {
        bytes: Vec<u8>,
        destination: NodeId,
    },
    Seal {
        bytes: Vec<u8>,
        destination: NodeId,
        timestamp_us: u64,
    },
    Open {
        bytes: Vec<u8>,
    },
    Initialize {
        scope: ctrn::Scope,
    },
    Advertise {
        advertisement: Advertisement,
    },
}
enum Response {
    Signed(SignedOperation),
    Sealed(Vec<u8>),
    Opened(AuthenticatedOperation),
    Initializer(ckmg::NativeTorInitializer),
    Advertisement(UnverifiedPeerInfoBytes),
}
struct Request {
    operation: Operation,
    reply: oneshot::Sender<Result<Response, Error>>,
}

impl Door {
    /// Call within the native owner's LocalSet after actual passkey handover.
    /// `binding` is the original authenticated member binding, never a toy UUID
    /// or action field. No root, accepting authority or private key is supplied.
    ///
    /// Parent composition must retain the owner and its negative lifetime with
    /// Vault, and wire observed lineage removals to that same lifetime. This
    /// constructor neither binds Records/Mesh nor marks the member ready.
    pub fn prepare_native_transport(
        &self,
        origin: &str,
        prepared: &cvlt::PreparedOpen,
        binding: ckmg::Binding,
        window: TimeWindow,
    ) -> super::Result<(TransportClient, TransportOwner)> {
        let device = prepared.device().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let (authority, lifetime) =
            self.transport_authority(origin, binding.clone(), device, custody::SystemClock)?;
        let member = self.member_authority_builder(origin, &authority)?;
        let foyer = self.custody_current_policy(origin)?;
        let session = prepared
            .transport(binding, custody::SystemClock, authority)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        let node = *session
            .public_key()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .value();
        let (requests, receiver) = mpsc::channel(REQUESTS);
        let (stop, stopped) = oneshot::channel();
        let session_id = Arc::new(());
        let owned_lifetime = Lifetime(lifetime.clone());
        // Spawn directly on LocalSet. Never send this work through Door dispatch:
        // the serial Door may be waiting on the very Records RPC we must sign.
        let task = tokio::task::spawn_local(async move {
            let _lifetime = owned_lifetime;
            serve(session, receiver, stopped, window).await;
        });
        Ok((
            TransportClient {
                node,
                requests,
                pending: Arc::new(Semaphore::new(REQUESTS)),
                session: session_id.clone(),
                window,
            },
            TransportOwner {
                lifetime,
                stop: Some(stop),
                task: Some(task),
                member: Some(member),
                foyer,
                session: session_id,
            },
        ))
    }
}

impl TransportOwner {
    fn require_independent_initial(
        &self,
        initial: &cfyr::membership::InitialCreationLease<'_, super::foyer::Transport>,
    ) -> super::Result<()> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        initial
            .require_independent_owner(&self.foyer)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unauthorized",
                    ErrorCode::Unauthorized,
                    &__cause,
                )
            })
    }

    /// Consume the captured original Foyer ports once, after Records handles
    /// exist. This releases no key, lineage authority or bootstrap permission.
    pub fn take_member_authority(&mut self) -> super::Result<custody::MemberAuthorityBuilder> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        self.member.take().ok_or(ErrorCode::Unavailable)
    }

    /// Shared negative-only authority state. A caller closing this state must
    /// also call close/shutdown on the retained owner to stop idle engines.
    pub fn lifetime(&self) -> custody::CustodyLifetime {
        self.lifetime.clone()
    }

    /// Observe original verified lineage and immediately stop transport on
    /// refusal, including when there are no outstanding credential requests.
    pub fn observe_lineage(
        &mut self,
        observed: &cvlt::VerifiedLineageObservation<'_>,
        now: u64,
    ) -> Result<(), ckmg::Error> {
        let result = self.lifetime.observe_lineage(observed, now);
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Session lock/revoke/cancellation hook. No later request can obtain keys.
    pub fn close(&mut self) {
        self.lifetime.close();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }

    /// Cancel credential work and await custody destruction. This never waits
    /// for the serial Door receiver or for a blocked remote authority response.
    pub async fn shutdown(mut self) -> super::Result<()> {
        self.lifetime.close();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.task.take().expect("owned transport task").await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(__cause) => {
                crate::door::cause::print(file!(), line!(), "Err ErrorCode::Reconcile", &__cause);
                Err(ErrorCode::Reconcile)
            }
        }
    }
}
impl Drop for TransportOwner {
    fn drop(&mut self) {
        self.close();
    }
}

async fn serve(
    mut session: Session,
    mut requests: mpsc::Receiver<Request>,
    mut stopped: oneshot::Receiver<()>,
    window: TimeWindow,
) {
    loop {
        let request = tokio::select! {
            biased;
            _ = &mut stopped => break,
            request = requests.recv() => match request {
                Some(request) => request,
                None => break,
            },
        };
        let Request {
            operation,
            mut reply,
        } = request;
        if reply.is_closed() {
            continue;
        }
        let result = tokio::select! {
            biased;
            _ = &mut stopped => break,
            // Cancellation of an in-flight authority check locks Keys through
            // its original CheckGuard. End this session; never retry implicitly.
            _ = reply.closed() => break,
            result = execute(&mut session, operation, window) => result,
        };
        let _ = reply.send(result);
    }
    session.lock();
}

async fn execute(
    session: &mut Session,
    operation: Operation,
    window: TimeWindow,
) -> Result<Response, Error> {
    if let Operation::Initialize { scope } = operation {
        return session
            .native_initializer(scope)
            .await
            .map(Response::Initializer)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unavailable",
                    Error::Unavailable,
                    &__cause,
                )
            });
    }
    session
        .with_node(|signer, cipher| {
            let signer = Signer(signer);
            let cipher = Cipher(cipher);
            match operation {
                Operation::Advertise { advertisement } => {
                    UnverifiedPeerInfoBytes::sign_extension(advertisement, &signer)
                        .map(Response::Advertisement)
                }
                Operation::Sign { bytes, destination } => {
                    SignedOperation::sign(bytes, &destination, &signer).map(Response::Signed)
                }
                Operation::Seal {
                    bytes,
                    destination,
                    timestamp_us,
                } => {
                    // Preserve independently signed watcher operations. Authenticate
                    // their original destination binding before node envelope signing.
                    let checked = SignedOperation::verify_sender(bytes, &destination, &Verifier)?;
                    Envelope::seal(
                        checked.as_bytes(),
                        &destination,
                        timestamp_us,
                        &signer,
                        &cipher,
                    )
                    .map(Response::Sealed)
                }
                Operation::Open { bytes } => {
                    // Recheck after the fresh HTTPS await: queue time must not extend
                    // the original envelope's timestamp acceptance window.
                    let now = now_us()?;
                    let envelope =
                        Envelope::verify(bytes, cipher.0.public_key(), now, window, &Verifier)?;
                    envelope
                        .open_operation(&cipher, &Verifier)
                        .map(Response::Opened)
                }
                Operation::Initialize { .. } => unreachable!("initializer handled above"),
            }
        })
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })?
}

fn now_us() -> Result<u64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })?
        .as_micros()
        .try_into()
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })
}
struct Signer<'a>(ckmg::Vld0Signer<'a>);
impl cdht::Signer for Signer<'_> {
    fn public_key(&self) -> NodeId {
        *self.0.public_key()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        self.0.sign(bytes).map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "Error::Signer", Error::Signer, &__cause)
        })
    }
}
struct Cipher<'a>(ckmg::Vld0NodeCipher<'a>);
impl EnvelopeCipher for Cipher<'_> {
    fn node_id(&self) -> NodeId {
        *self.0.public_key()
    }
    fn crypt(
        &self,
        peer: &NodeId,
        nonce: &[u8; 24],
        bytes: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        self.0.crypt(peer, nonce, bytes).map_err(|__cause| {
            crate::door::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })
    }
}
/// Original strict Keys VLD0 verification, shared by native network owners.
#[derive(Clone, Copy)]
pub struct Verifier;
impl cdht::Verifier for Verifier {
    fn verify(&self, key: &NodeId, bytes: &[u8], signature: &[u8; 64]) -> bool {
        ckmg::verify(
            &ckmg::PublicKey::new(ckmg::VLD0, *key),
            bytes,
            &ckmg::Signature::new(ckmg::VLD0, *signature),
        )
        .is_ok()
    }
}

impl TransportClient {
    /// Sign the original node advertisement obtained from the actual listener.
    /// Runtime constructs its timestamp, capabilities and Tor dial information;
    /// this trusted port is never exposed as a member action or JSON input.
    pub async fn advertise(
        &self,
        advertisement: Advertisement,
    ) -> Result<UnverifiedPeerInfoBytes, Error> {
        // Bound owned channel memory without replacing the original publisher's
        // validation of protocol fields, duplicate entries or signing transcript.
        let words = advertisement
            .capabilities
            .len()
            .saturating_add(advertisement.outbound_protocols.len())
            .saturating_add(advertisement.address_types.len());
        let size = advertisement
            .dial_info
            .iter()
            .fold(words.saturating_mul(4), |size, dial| {
                size.saturating_add(std::mem::size_of_val(dial))
                    .saturating_add(dial.detail.len())
            });
        if size > MAX_ENVELOPE_BYTES {
            return Err(Error::ValueTooLarge);
        }
        match self
            .request(|| Operation::Advertise { advertisement })
            .await?
        {
            Response::Advertisement(value) => Ok(value),
            _ => Err(Error::Encoding),
        }
    }

    async fn request(&self, make: impl FnOnce() -> Operation) -> Result<Response, Error> {
        // Hold through reply consumption, bounding completed-but-unconsumed
        // replies as well as queued and actively executing requests.
        let _pending = self.pending.try_acquire().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })?;
        // Reserve before allocating/copying. Full queues refuse immediately;
        // waiting producer futures cannot accumulate unbounded owned packets.
        let receive = {
            let slot = self.requests.try_reserve().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "Error::Unavailable",
                    Error::Unavailable,
                    &__cause,
                )
            })?;
            let (reply, receive) = oneshot::channel();
            slot.send(Request {
                operation: make(),
                reply,
            });
            receive
        };
        receive.await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Error::Unavailable",
                Error::Unavailable,
                &__cause,
            )
        })?
    }
    async fn sign(&self, bytes: &[u8], destination: &NodeId) -> Result<SignedOperation, Error> {
        bounded(bytes)?;
        match self
            .request(|| Operation::Sign {
                bytes: bytes.to_vec(),
                destination: *destination,
            })
            .await?
        {
            Response::Signed(value) => Ok(value),
            _ => Err(Error::Encoding),
        }
    }
    /// Obtain only the original consume-once engine capability, then pass it to
    /// Door::bind_native_tor. Keep TransportOwner alive after initialization.
    pub async fn native_initializer(
        &self,
        scope: ctrn::Scope,
    ) -> super::Result<ckmg::NativeTorInitializer> {
        match self
            .request(|| Operation::Initialize { scope })
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })? {
            Response::Initializer(value) => Ok(value),
            _ => Err(ErrorCode::Unavailable),
        }
    }
}
fn bounded(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        Err(Error::ValueTooLarge)
    } else {
        Ok(())
    }
}
impl TorNodeIdentity for TransportClient {
    fn node_id(&self) -> NodeId {
        self.node
    }
    fn question<'a>(
        &'a self,
        question: &'a Question,
        destination: &'a NodeId,
    ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
        Box::pin(self.sign(question.as_bytes(), destination))
    }
    fn answer<'a>(
        &'a self,
        answer: &'a FindAnswer,
        destination: &'a NodeId,
    ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
        Box::pin(self.sign(answer.as_bytes(), destination))
    }
    fn record_answer<'a>(
        &'a self,
        answer: &'a Answer,
        destination: &'a NodeId,
    ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
        Box::pin(self.sign(answer.as_bytes(), destination))
    }
    fn statement<'a>(
        &'a self,
        statement: &'a Statement,
        destination: &'a NodeId,
    ) -> cmsh::BoxFuture<'a, Result<SignedOperation, Error>> {
        Box::pin(self.sign(statement.as_bytes(), destination))
    }
    fn seal<'a>(
        &'a self,
        operation: &'a SignedOperation,
        destination: &'a NodeId,
        timestamp_us: u64,
    ) -> cmsh::BoxFuture<'a, Result<Vec<u8>, Error>> {
        Box::pin(async move {
            bounded(operation.as_bytes())?;
            match self
                .request(|| Operation::Seal {
                    bytes: operation.as_bytes().to_vec(),
                    destination: *destination,
                    timestamp_us,
                })
                .await?
            {
                Response::Sealed(value) => Ok(value),
                _ => Err(Error::Encoding),
            }
        })
    }
    fn open<'a>(
        &'a self,
        envelope: &'a Envelope,
    ) -> cmsh::BoxFuture<'a, Result<AuthenticatedOperation, Error>> {
        Box::pin(async move {
            bounded(envelope.as_bytes())?;
            match self
                .request(|| Operation::Open {
                    bytes: envelope.as_bytes().to_vec(),
                })
                .await?
            {
                Response::Opened(value) => Ok(value),
                _ => Err(Error::Encoding),
            }
        })
    }
}
