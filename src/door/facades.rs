//! Bound actual owner facades. Type erasure here preserves their own methods;
//! no generic accepting domain driver or caller-supplied success is exposed.
use super::*;
mod shared;
use cbrd::clnk;
pub use shared::VaultBoardOwner;
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
    /// Local group views from the committed Groups checkpoint; no Forum traffic.
    fn groups(&mut self, _expires: u64) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
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
impl<T: clnk::Transport, R> BoundBoard for BoardBinding<T, R> {
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
    mesh: cmsh::Mesh,
    listener: cmsh::Listening,
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
        self.mesh.view()
    }
    pub fn close(mut self) {
        self.listener.close();
        drop(self.mesh);
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
    fn sign_board<'a>(
        &'a mut self,
        prepared: &'a cbrd::Prepared,
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, SignedBoard>;
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
    fn sign_board<'a>(
        &'a mut self,
        prepared: &'a cbrd::Prepared,
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, SignedBoard> {
        Box::pin(self.sign_transcript(prepared.message(), origin, now, expires))
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
    pub fn bind_board<T: clnk::Transport + 'static, R: 'static>(
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
        self.meshes.insert(
            origin.into(),
            BoundMesh {
                mesh,
                listener,
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
