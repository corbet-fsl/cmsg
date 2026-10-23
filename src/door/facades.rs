//! Bound actual owner facades. Type erasure here preserves their own methods;
//! no generic accepting domain driver or caller-supplied success is exposed.
use super::*;
mod group_custody;
mod inbox_custody;
mod lineage_custody;
mod pairing_custody;
pub use pairing_custody::PairApproved;
mod profile_custody;
mod room_sync;
mod shared;
use cbrd::clnk;
pub use group_custody::{
    GroupPeers, RemoveStep, RoomAdmitTask, RoomJoinTask, RoomJoined, RoomKeySealed, RoomKeyTask,
    RoomKeysStanding, RoomLeaveTask, RoomRemoveTask, RoomSecretsReceived, RoomSecretsTask,
    VaultGroupOwner, VerifiedPeers,
};
pub use room_sync::{RefusedJoins, ResyncReason, RoomSync, RoomSyncTask, RoomSynced};
pub use shared::{AccountPort, PortVault, VaultBoardOwner};
use std::{future::Future, pin::Pin};

pub(super) type OwnedFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Conversation is an owner-local key, never a caller-selected community/store.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    pub conversation: [u8; 32],
}
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub conversation: [u8; 32],
    pub peer: String,
}
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub conversation: [u8; 32],
    pub message: [u8; 32],
}

pub(super) trait BoundBoard {
    /// Structural owner availability only; this never grants domain authority.
    fn require_committed(&self) -> Result<()> {
        Err(ErrorCode::Unavailable)
    }
    fn attend(&mut self, _origin: &str, _expires: u64) -> OwnedFuture<'_, cbrd::Status> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn search(
        &mut self,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
        _expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn group_act(
        &mut self,
        _intent: cbrd::GroupIntent,
        _expires: u64,
    ) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn group_propose(
        &mut self,
        _intent: cbrd::GroupIntent,
        _expires: u64,
    ) -> OwnedFuture<'_, board::GroupProposed> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn group_message(
        &mut self,
        _from: String,
        _text: String,
        _expires: u64,
    ) -> OwnedFuture<'_, board::GroupInbound> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn group_answer(
        &mut self,
        _operation: [u8; 32],
        _accept: bool,
        _expires: u64,
    ) -> OwnedFuture<'_, board::GroupAnswered> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn group_welcome(
        &mut self,
        _operation: [u8; 32],
        _delivered: Vec<String>,
        _expires: u64,
    ) -> OwnedFuture<'_, board::GroupWelcomes> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn profile_publish(&mut self, _edit: cbrd::Edit, _expires: u64) -> OwnedFuture<'_, u64> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn discovery(&mut self, _expires: u64) -> OwnedFuture<'_, Vec<cbrd::Discovery>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn watch(
        &mut self,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
        _expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// One step of joining a member room (request, wait, join).
    fn room_join(
        &mut self,
        _join: board::RoomJoin,
        _expires: u64,
    ) -> OwnedFuture<'_, board::RoomJoinStatus> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Answer the room's pending join requests with this member's evidence.
    fn room_serve(
        &mut self,
        _room: board::RoomRef,
        _expires: u64,
    ) -> OwnedFuture<'_, board::RoomServed> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Admit the newcomers whose ordered external commits the room holds.
    fn room_admit(
        &mut self,
        _room: board::RoomRef,
        _expires: u64,
    ) -> OwnedFuture<'_, board::RoomAdmitted> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Leave a member room (Groups, Threads state, Attend in one commit).
    fn room_leave(
        &mut self,
        _room: board::RoomRef,
        _expires: u64,
    ) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Local group views from the committed Groups checkpoint; no Forum traffic.
    fn groups(&mut self, _expires: u64) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Whether this Board carries the anonymous room transport.
    #[allow(dead_code)] // consumed by the room actions that follow
    fn has_rooms(&self) -> bool {
        false
    }
    /// One command on the room transport (Assembly only; no membership).
    #[allow(dead_code)] // consumed by the room actions that follow
    fn execute_room(
        &self,
        _command: cbrd::clnk::cmbl::Request,
    ) -> rooms::RoomFuture<'_, cbrd::clnk::cmbl::Outcome> {
        Box::pin(async { Err(cbrd::clnk::ErrorCode::Rejected) })
    }
    /// Bring this device's listing keys of public rooms up to date and return
    /// what must be published and sent (see `board.room_listing`).
    fn room_listing(&mut self) -> OwnedFuture<'_, board::ListingPlan> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The public rooms this device holds the listing key of.
    fn room_refs(&mut self) -> OwnedFuture<'_, Vec<board::RoomRef>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The live connection of `room`, if this device has connected to it.
    fn room_connection(&self, _room: [u8; 16]) -> Result<[u8; 16]> {
        Err(ErrorCode::Unavailable)
    }
    fn room_prepare_epoch(&mut self, _nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        Err(ErrorCode::Unavailable)
    }
    fn room_receive_epoch(
        &mut self,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
    ) -> OwnedFuture<'_, ()> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn room_prepare_pass(
        &mut self,
        _room: [u8; 16],
        _operation: [u8; 16],
        _nonce: [u8; 16],
    ) -> Result<cbrd::Prepared> {
        Err(ErrorCode::Unavailable)
    }
    fn room_receive_pass(
        &mut self,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
    ) -> OwnedFuture<'_, [u8; 16]> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn status(&self) -> cbrd::Status;
    fn disconnect(&mut self) -> cbrd::Status;
    fn prepare(&mut self, request: cbrd::cfrm::Request, nonce: [u8; 16]) -> Result<cbrd::Prepared>;
    fn execute(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, cbrd::cfrm::Reply>;
}
pub(super) struct BoardBinding<T, R> {
    pub(super) board: cbrd::Board<T, R>,
    // Original owner request/session/nonce/signature retained after uncertainty.
    // It is never a wire result or an automatic retry instruction.
    pub(super) pending: Option<cbrd::cfrm::Request>,
}
impl<T: clnk::Transport, R: RoomLink> BoundBoard for BoardBinding<T, R> {
    fn has_rooms(&self) -> bool {
        R::ROOMS
    }
    fn execute_room(
        &self,
        command: cbrd::clnk::cmbl::Request,
    ) -> rooms::RoomFuture<'_, cbrd::clnk::cmbl::Outcome> {
        R::execute_room(&self.board, command)
    }
    fn room_connection(&self, room: [u8; 16]) -> Result<[u8; 16]> {
        R::room_connection(&self.board, room).map_err(board::before_send)
    }
    fn room_prepare_epoch(&mut self, nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        R::prepare_room_epoch(&self.board, nonce).map_err(board::before_send)
    }
    fn room_receive_epoch(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, ()> {
        Box::pin(async move {
            R::receive_room_epoch(&mut self.board, prepared, signature)
                .await
                .map_err(board::after_send)
        })
    }
    fn room_prepare_pass(
        &mut self,
        room: [u8; 16],
        operation: [u8; 16],
        nonce: [u8; 16],
    ) -> Result<cbrd::Prepared> {
        R::prepare_room_pass(&mut self.board, room, operation, nonce).map_err(board::before_send)
    }
    fn room_receive_pass(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, [u8; 16]> {
        Box::pin(async move {
            R::receive_room_pass(&mut self.board, prepared, signature)
                .await
                .map_err(board::after_send)
        })
    }
    fn status(&self) -> cbrd::Status {
        self.board.status()
    }
    fn disconnect(&mut self) -> cbrd::Status {
        self.board.disconnect();
        self.board.status()
    }
    fn prepare(&mut self, request: cbrd::cfrm::Request, nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        if self.pending.is_some() {
            return Err(ErrorCode::Reconcile);
        }
        self.board
            .prepare(request, nonce)
            .map_err(board::before_send)
    }
    fn execute(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, cbrd::cfrm::Reply> {
        Box::pin(async move {
            if self.pending.is_some() {
                return Err(ErrorCode::Reconcile);
            }
            let mut request = prepared.request().clone();
            request
                .possession_mut()
                .ok_or(ErrorCode::InvalidRequest)?
                .signature = signature.clone();
            self.pending = Some(request);
            let result = self
                .board
                .execute(prepared, signature)
                .await
                .map_err(board::after_send);
            if !matches!(result, Err(ErrorCode::Reconcile)) {
                self.pending = None;
            }
            result
        })
    }
}

pub(super) struct BoundMesh {
    // The Mesh, its listener, the address book and the send queue are shared
    // with the courier task of this origin (see `courier`).
    pub(super) shared: std::rc::Rc<courier::Shared>,
    _lifetime: Option<MeshLifetime>,
}
/// Retain the actual transport shutdown with Mesh, including failed startup,
/// dropped initialization, panic fencing and ordinary owner destruction.
pub(super) struct MeshLifetime(Option<Box<dyn FnOnce()>>);
impl MeshLifetime {
    #[cfg(any(
        all(feature = "native-tor", not(target_arch = "wasm32")),
        all(feature = "browser-tor", target_arch = "wasm32"),
    ))]
    pub(super) fn new(close: impl FnOnce() + 'static) -> Self {
        Self(Some(Box::new(close)))
    }
}
impl Drop for MeshLifetime {
    fn drop(&mut self) {
        if let Some(close) = self.0.take() {
            close();
        }
    }
}
impl BoundMesh {
    pub fn view(&self) -> Vec<cmsh::BackendView> {
        self.shared.mesh.view()
    }
    /// Stop the courier and release the Mesh. The listener (and with it the
    /// published reachability) ends when the courier drops its handle, which
    /// it does at its next wake-up.
    pub fn close(self) {
        self.shared.close();
    }
}

pub(super) struct SignedBoard {
    pub signature: Vec<u8>,
    pub admitted: ckmg::IntentGuard,
}

pub(super) struct VaultIdentity {
    pub binding: ckmg::Binding,
    pub device: ckmg::PublicKey,
}

pub(super) trait BoundVault {
    fn current_identity(&mut self) -> OwnedFuture<'_, VaultIdentity>;
    fn snapshot(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::ConversationView>;
    fn history(&mut self, request: Conversation) -> OwnedFuture<'_, Vec<cnbx::Message>>;
    fn relation(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::Relation>;
    fn delivery(&mut self, request: Delivery) -> OwnedFuture<'_, Option<cnbx::DeliveryStatus>>;
    /// Pin the verified key-chain head of this community beside its credential.
    fn store_pin(
        &mut self,
        _fingerprint: [u8; 32],
        _ring_revision: u64,
        _head: [u8; 32],
    ) -> OwnedFuture<'_, ()> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn blocking_rules(&mut self) -> OwnedFuture<'_, Vec<String>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The member's voucher custody record (link secrets, bonds, nonces).
    fn voucher_custody(&mut self) -> OwnedFuture<'_, Option<Zeroizing<Vec<u8>>>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Replace the voucher custody by compare-and-swap against `expected`.
    fn replace_voucher_custody<'a>(
        &'a mut self,
        _expected: Option<&'a [u8]>,
        _custody: &'a [u8],
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Sign an endorsement statement with the device key; the signature, the
    /// device public key and this member's signed community credential (the lineage
    /// evidence that travels with the endorsement; empty when none is held).
    fn sign_endorsement<'a>(
        &'a mut self,
        _message: &'a [u8],
        _origin: &'a str,
        _now: u64,
        _expires: u64,
    ) -> OwnedFuture<'a, (Vec<u8>, Vec<u8>, Vec<u8>)> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn contact_act(&mut self, _request: inbox::ContactAct) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Establish the contact a voucher admission created with `peer`, derived
    /// from the shared bond secret; returns the conversation id. Idempotent.
    fn contact_by_voucher<'a>(
        &'a mut self,
        _peer: &'a str,
        _bond: [u8; 32],
    ) -> OwnedFuture<'a, [u8; 32]> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The newcomer's single-use Threads key package for the thread of `conversation`.
    fn voucher_key_package<'a>(
        &'a mut self,
        _conversation: [u8; 32],
        _ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The sponsor's device creates the direct thread for `package` and returns
    /// its Welcome (the stored one when it already exists).
    fn voucher_create<'a>(
        &'a mut self,
        _peer: &'a str,
        _conversation: [u8; 32],
        _package: &'a [u8],
        _ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The newcomer's device joins the thread from the Welcome and sends what
    /// waited for it; returns the wires of those messages for the courier.
    fn voucher_join<'a>(
        &'a mut self,
        _peer: &'a str,
        _conversation: [u8; 32],
        _welcome: &'a [u8],
        _ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<Vec<u8>>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// One wave action over the member's Waves, Contacts and Threads. The ports
    /// are the Door-held capabilities of this member origin.
    fn waves<'a>(
        &'a mut self,
        _command: inbox_waves::Command,
        _ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_waves::Answer> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// One conversation action over a released direct conversation.
    fn conversation<'a>(
        &'a mut self,
        _command: inbox_conversation::Command,
        _ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_conversation::Answer> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn sign_board<'a>(
        &'a mut self,
        prepared: &'a cbrd::Prepared,
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, SignedBoard>;
    /// Existing-device pairing approval: add exactly the proven device named by `request`.
    /// Needs the member's explicit approval and a distinct single-use Pair admission.
    /// Sign the strictly next lineage record value for the pending approval receipt.
    fn revision_record<'a>(
        &'a mut self,
        _receipt: &'a ckmg::Receipt,
        _previous: &'a ckmg::Lineage,
        _canonical_evidence: &'a [u8],
        _origin: &'a str,
    ) -> OwnedFuture<'a, cdht::SignedValue> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn pair_device<'a>(
        &'a mut self,
        _request: &'a ckmg::PairingRequest,
        _origin: &'a str,
    ) -> OwnedFuture<'a, PairApproved> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// The member's current lineage (the anchor a pairing extends).
    fn pairing_anchor(&mut self) -> OwnedFuture<'_, ckmg::Lineage> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Retain the prepared evidence of the pending approval receipt, durably.
    fn retain_pairing_evidence<'a>(
        &'a mut self,
        _evidence: &'a cvlt::PreparedLineageEvidence,
        _receipt: &'a ckmg::Receipt,
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    /// Acknowledge the approval receipt after its revision is published.
    fn acknowledge_pairing<'a>(&'a mut self, _receipt: &'a ckmg::Receipt) -> OwnedFuture<'a, ()> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn lock(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + 'static>>;
}

struct Custody<B: cwst::backend::Backend, C, E, A, R, W> {
    vault: cvlt::Vault<B, C, E, A, R, W>,
    binding: ckmg::Binding,
    inbox: cnbx::Inbox,
    intent: Option<ckmg::IntentAdmission>,
}
impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    async fn view(&mut self, conversation: [u8; 32]) -> Result<cnbx::View> {
        // Acquire the actual transaction checkpoint first. The Vault owner's
        // ReadHandle lets Keys revalidate this same checkpoint without re-locking
        // it. Waiting must never carry an earlier authority check to disclosure.
        let storage = self.vault.storage().clone();
        let store = storage.lock().await;
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        if lineage.binding != self.binding {
            return Err(ErrorCode::Unauthorized);
        }
        if !store.is_scope(self.binding.community()) {
            return Err(ErrorCode::Unauthorized);
        }
        self.inbox
            .view(conversation, &store)
            .map_err(|_| ErrorCode::Refused)
    }
    async fn sign_transcript(
        &mut self,
        message: &[u8],
        origin: &str,
        now: u64,
        expires: u64,
    ) -> Result<SignedBoard> {
        let intent = self.intent.as_mut().ok_or(ErrorCode::Unavailable)?;
        let storage = self.vault.storage().clone();
        let store = storage.lock().await;
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        if lineage.binding != self.binding || !store.is_scope(self.binding.community()) {
            return Err(ErrorCode::Unauthorized);
        }
        let public = self
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(keys_error)?;
        let after = ckmg::Clock::now(&mut super::custody::SystemClock).map_err(keys_error)?;
        if after < now {
            return Err(ErrorCode::Clock);
        }
        if after >= expires {
            return Err(ErrorCode::Unauthorized);
        }
        let admitted = intent
            .admit(
                ckmg::AdmittedCommand {
                    binding: lineage.binding,
                    origin: origin.into(),
                    action: ckmg::Action::SignDeviceEd25519,
                    device: public,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: Some(message.to_vec()),
                    expires,
                },
                after,
            )
            .map_err(keys_error)?;
        // Keys authorizes and signs only these same immutable owner bytes.
        // Metadata access cannot consume this distinct exact signing intent,
        // and no general-purpose signer callback can change the transcript.
        let signature = self
            .vault
            .keys()
            .sign_device_ed25519(message, expires)
            .await
            .map_err(keys_error)?
            .to_vec();
        Ok(SignedBoard {
            signature,
            admitted,
        })
    }
}
impl<B, C, E, A, R, W> BoundVault for Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend + 'static,
    C: ckmg::Clock + 'static,
    E: ckmg::Entropy + 'static,
    A: ckmg::Authority + 'static,
    R: cvlt::Records + 'static,
    W: 'static,
{
    fn current_identity(&mut self) -> OwnedFuture<'_, VaultIdentity> {
        Box::pin(async move {
            let storage = self.vault.storage().clone();
            let store = storage.lock().await;
            let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
            let device = self
                .vault
                .keys()
                .device_public_key()
                .await
                .map_err(keys_error)?;
            if lineage.binding != self.binding || !store.is_scope(self.binding.community()) {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(VaultIdentity {
                binding: lineage.binding,
                device,
            })
        })
    }
    fn snapshot(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::ConversationView> {
        Box::pin(async move {
            self.view(request.conversation)
                .await?
                .snapshot(&request.peer)
                .map_err(|_| ErrorCode::Refused)
        })
    }
    fn history(&mut self, request: Conversation) -> OwnedFuture<'_, Vec<cnbx::Message>> {
        Box::pin(async move { Ok(self.view(request.conversation).await?.history().to_vec()) })
    }
    fn relation(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(async move {
            self.view(request.conversation)
                .await?
                .relation(&request.peer)
                .map_err(|_| ErrorCode::Refused)
        })
    }
    fn delivery(&mut self, request: Delivery) -> OwnedFuture<'_, Option<cnbx::DeliveryStatus>> {
        Box::pin(async move {
            Ok(self
                .view(request.conversation)
                .await?
                .delivery_status(&request.message))
        })
    }
    fn blocking_rules(&mut self) -> OwnedFuture<'_, Vec<String>> {
        Box::pin(self.blocking_rules_owned())
    }
    fn voucher_custody(&mut self) -> OwnedFuture<'_, Option<Zeroizing<Vec<u8>>>> {
        Box::pin(self.voucher_custody_owned())
    }
    fn replace_voucher_custody<'a>(
        &'a mut self,
        expected: Option<&'a [u8]>,
        custody: &'a [u8],
    ) -> OwnedFuture<'a, ()> {
        Box::pin(self.replace_voucher_custody_owned(expected, custody))
    }
    fn sign_endorsement<'a>(
        &'a mut self,
        message: &'a [u8],
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, (Vec<u8>, Vec<u8>, Vec<u8>)> {
        Box::pin(self.sign_endorsement_owned(message, origin, now, expires))
    }
    fn store_pin(
        &mut self,
        fingerprint: [u8; 32],
        ring_revision: u64,
        head: [u8; 32],
    ) -> OwnedFuture<'_, ()> {
        Box::pin(self.store_pin_owned(fingerprint, ring_revision, head))
    }
    fn waves<'a>(
        &'a mut self,
        command: inbox_waves::Command,
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_waves::Answer> {
        Box::pin(self.waves_owned(command, ports))
    }
    fn conversation<'a>(
        &'a mut self,
        command: inbox_conversation::Command,
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_conversation::Answer> {
        Box::pin(self.conversation_owned(command, ports))
    }
    fn contact_act(&mut self, request: inbox::ContactAct) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(self.contact_act_owned(request))
    }
    fn contact_by_voucher<'a>(
        &'a mut self,
        peer: &'a str,
        bond: [u8; 32],
    ) -> OwnedFuture<'a, [u8; 32]> {
        Box::pin(self.contact_by_voucher_owned(peer, bond))
    }
    fn voucher_key_package<'a>(
        &'a mut self,
        conversation: [u8; 32],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(self.with_env(ports, async move |env| {
            env.voucher_key_package(conversation).await
        }))
    }
    fn voucher_create<'a>(
        &'a mut self,
        peer: &'a str,
        conversation: [u8; 32],
        package: &'a [u8],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(self.with_env(ports, async move |env| {
            env.voucher_create(peer, conversation, package).await
        }))
    }
    fn voucher_join<'a>(
        &'a mut self,
        peer: &'a str,
        conversation: [u8; 32],
        welcome: &'a [u8],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<Vec<u8>>> {
        Box::pin(self.with_env(ports, async move |env| {
            env.voucher_join(peer, conversation, welcome).await
        }))
    }
    fn sign_board<'a>(
        &'a mut self,
        prepared: &'a cbrd::Prepared,
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, SignedBoard> {
        Box::pin(self.sign_transcript(prepared.message(), origin, now, expires))
    }

    fn pair_device<'a>(
        &'a mut self,
        request: &'a ckmg::PairingRequest,
        origin: &'a str,
    ) -> OwnedFuture<'a, PairApproved> {
        Box::pin(self.pair_owned(request, origin))
    }
    fn revision_record<'a>(
        &'a mut self,
        receipt: &'a ckmg::Receipt,
        previous: &'a ckmg::Lineage,
        canonical_evidence: &'a [u8],
        origin: &'a str,
    ) -> OwnedFuture<'a, cdht::SignedValue> {
        Box::pin(self.revision_record_owned(receipt, previous, canonical_evidence, origin))
    }
    fn pairing_anchor(&mut self) -> OwnedFuture<'_, ckmg::Lineage> {
        Box::pin(self.pairing_anchor_owned())
    }
    fn retain_pairing_evidence<'a>(
        &'a mut self,
        evidence: &'a cvlt::PreparedLineageEvidence,
        receipt: &'a ckmg::Receipt,
    ) -> OwnedFuture<'a, ()> {
        Box::pin(self.retain_pairing_evidence_owned(evidence, receipt))
    }
    fn acknowledge_pairing<'a>(&'a mut self, receipt: &'a ckmg::Receipt) -> OwnedFuture<'a, ()> {
        Box::pin(self.acknowledge_pairing_owned(receipt))
    }

    fn lock(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
        Box::pin(async move {
            self.vault.lock().await;
        })
    }
}

impl Door {
    /// Run only after admitted requests drain on a healthy owner. Explicit Vault
    /// lock revokes the original checkpoint even if another owner still holds a
    /// SharedStore clone; merely dropping this Door cannot provide that guarantee.
    pub(super) async fn close_owned(mut self) {
        super::login::session::drain(&mut self).await;
        self.grants.clear();
        for (_, mesh) in std::mem::take(&mut self.meshes) {
            mesh.close();
        }
        for (_, vault) in std::mem::take(&mut self.vaults) {
            vault.lock().await;
        }
    }

    /// Bind the actual sole Board for a configured member portal. Construction
    /// itself grants neither forum attendance nor readiness.
    pub fn bind_board<T: clnk::Transport + 'static, R: RoomLink>(
        &mut self,
        origin: &str,
        board: cbrd::Board<T, R>,
    ) -> Result<()> {
        self.member_origin(origin)?;
        if board.community() != self.config.community || self.boards.contains_key(origin) {
            return Err(ErrorCode::InvalidRequest);
        }
        self.boards.insert(
            origin.into(),
            Box::new(BoardBinding {
                board,
                pending: None,
            }),
        );
        Ok(())
    }

    /// Consume a real unlocked Vault after its Keys owner verifies current G3.
    /// Inbox uses this exact accepted member binding and encrypted checkpoint.
    /// The local caller never supplies a pseudonym, ready bit or authority verdict.
    pub async fn bind_vault<B, C, E, A, R, W>(
        &mut self,
        origin: &str,
        vault: cvlt::Vault<B, C, E, A, R, W>,
    ) -> Result<()>
    where
        B: cwst::backend::Backend + 'static,
        C: ckmg::Clock + 'static,
        E: ckmg::Entropy + 'static,
        A: ckmg::Authority + 'static,
        R: cvlt::Records + 'static,
        W: 'static,
    {
        self.bind_vault_inner(origin, vault, None).await
    }

    /// Move only the Door half of the actual authority's intent channel. The
    /// verifier must already belong to that Vault's concrete authority composer.
    pub async fn bind_vault_with_intent<B, C, E, A, R, W>(
        &mut self,
        origin: &str,
        vault: cvlt::Vault<B, C, E, A, R, W>,
        intent: ckmg::IntentAdmission,
    ) -> Result<()>
    where
        B: cwst::backend::Backend + 'static,
        C: ckmg::Clock + 'static,
        E: ckmg::Entropy + 'static,
        A: ckmg::Authority + 'static,
        R: cvlt::Records + 'static,
        W: 'static,
    {
        self.bind_vault_inner(origin, vault, Some(intent)).await
    }

    async fn bind_vault_inner<B, C, E, A, R, W>(
        &mut self,
        origin: &str,
        mut vault: cvlt::Vault<B, C, E, A, R, W>,
        intent: Option<ckmg::IntentAdmission>,
    ) -> Result<()>
    where
        B: cwst::backend::Backend + 'static,
        C: ckmg::Clock + 'static,
        E: ckmg::Entropy + 'static,
        A: ckmg::Authority + 'static,
        R: cvlt::Records + 'static,
        W: 'static,
    {
        self.member_origin(origin)?;
        if self.vaults.contains_key(origin) {
            return Err(ErrorCode::InvalidRequest);
        }
        let binding = vault.keys().lineage().await.map_err(keys_error)?.binding;
        if binding.community() != self.config.community
            || !vault
                .storage()
                .lock()
                .await
                .is_scope(&self.config.community)
        {
            return Err(ErrorCode::Unauthorized);
        }
        let inbox = cnbx::Inbox::new(binding.clone());
        self.vaults.insert(
            origin.into(),
            Box::new(Custody {
                vault,
                binding,
                inbox,
                intent,
            }),
        );
        Ok(())
    }

    /// Retain the actual Mesh and its live listener. The embedding supplies its
    /// already scoped backend owners; a caller cannot choose peer/network scope.
    /// This does not claim backend health or completed Inbox receive integration.
    pub async fn bind_mesh(&mut self, origin: &str, mesh: cmsh::Mesh) -> Result<()> {
        self.bind_mesh_owned(origin, mesh, None).await
    }

    pub(super) async fn bind_mesh_owned(
        &mut self,
        origin: &str,
        mesh: cmsh::Mesh,
        lifetime: Option<MeshLifetime>,
    ) -> Result<()> {
        self.member_origin(origin)?;
        if self.meshes.contains_key(origin) {
            return Err(ErrorCode::InvalidRequest);
        }
        let listener = mesh.listen().await.map_err(|_| ErrorCode::Unavailable)?;
        // One address must never be published for two memberships of this device:
        // peers could link the pseudonyms. Production gives every origin its own
        // onion key (derived per community); refuse a backend that does not.
        if self.meshes.values().any(|bound| {
            let own = bound.shared.own.borrow();
            listener.addresses().iter().any(|a| own.contains(a))
        }) {
            return Err(ErrorCode::InvalidRequest);
        }
        self.meshes.insert(
            origin.into(),
            BoundMesh {
                shared: std::rc::Rc::new(courier::Shared::new(mesh, listener)),
                _lifetime: lifetime,
            },
        );
        Ok(())
    }

    pub(super) fn member_origin(&self, origin: &str) -> Result<()> {
        if self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|origins| origins.contains(origin))
        {
            Ok(())
        } else {
            Err(ErrorCode::Unauthorized)
        }
    }
}

pub(super) fn keys_error(error: ckmg::Error) -> ErrorCode {
    match error {
        ckmg::Error::Reconcile | ckmg::Error::Pending => ErrorCode::Reconcile,
        ckmg::Error::Unauthorized | ckmg::Error::Revoked | ckmg::Error::Expired => {
            ErrorCode::Unauthorized
        }
        ckmg::Error::Limit => ErrorCode::Capacity,
        ckmg::Error::Clock => ErrorCode::Clock,
        ckmg::Error::Unavailable | ckmg::Error::Locked | ckmg::Error::MissingCheckpoint => {
            ErrorCode::Unavailable
        }
        _ => ErrorCode::Refused,
    }
}

#[cfg(test)]
#[path = "../../tests/support/facades.rs"]
mod tests;
