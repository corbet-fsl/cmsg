//! One actual Vault retained by its Door and the Board's scoped owner.
use super::group_custody::{self, GroupPeers};
use super::*;
use crate::door::{board, custody::CustodyLifetime};
use futures_util::lock::Mutex;
use std::rc::Rc;

type Retained<B, C, E, A, R, W> = Rc<Mutex<Option<Custody<B, C, E, A, R, W>>>>;

/// Trusted Board capability over the same Vault used by the Door. It contains
/// neither another Keys owner nor a snapshot that can outlive a lock/revocation.
/// Restricted contact-detail text remains refused until a real detector exists.
pub struct VaultBoardOwner<B: cwst::backend::Backend, C, E, A, R, W> {
    retained: Retained<B, C, E, A, R, W>,
    lifetime: CustodyLifetime,
    origin: String,
    /// Present only on the Board's own handle (never on the Door's clone).
    groups: Option<group_custody::VaultGroupOwner<B, C, E, A, R, W>>,
}
impl<B: cwst::backend::Backend, C, E, A, R, W> Clone for VaultBoardOwner<B, C, E, A, R, W> {
    fn clone(&self) -> Self {
        Self {
            retained: self.retained.clone(),
            lifetime: self.lifetime.clone(),
            origin: self.origin.clone(),
            groups: None,
        }
    }
}
impl<B: cwst::backend::Backend, C, E, A, R, W> VaultBoardOwner<B, C, E, A, R, W> {
    /// Give the Board its group owner. `peers` is the forced, Charter-verified
    /// lineage read of other members; without it only this member's own
    /// consents can be verified. Call once, right after binding.
    pub fn enable_groups(&mut self, peers: Option<Box<dyn GroupPeers>>) -> Result<()> {
        let member = {
            let retained = self.retained.try_lock().ok_or(ErrorCode::Reconcile)?;
            retained
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .binding
                .member()
                .to_owned()
        };
        self.groups = Some(group_custody::VaultGroupOwner::new(
            self.retained.clone(),
            self.lifetime.clone(),
            self.origin.clone(),
            member,
            peers,
        ));
        Ok(())
    }

    /// The production group owner: other members' lineage is read through the
    /// handle this member's Contacts journal retained and reverified against the
    /// community Charter (`policy`, the Door's weak current-policy read).
    pub fn enable_verified_groups<N>(
        &mut self,
        network: N,
        policy: cfyr::policy::CurrentPolicy<crate::door::foyer::Transport>,
    ) -> Result<()>
    where
        N: cdht::Network + Clone + 'static,
    {
        self.enable_groups(Some(Box::new(group_custody::VerifiedPeers::new(
            crate::door::inbox_lineage::TorHandleOpener::new(network),
            policy,
            || ckmg::Clock::now(&mut crate::door::custody::SystemClock).ok(),
        ))))
    }

    fn require_open(&self) -> Result<()> {
        if self.lifetime.is_closed() {
            Err(ErrorCode::Unauthorized)
        } else {
            Ok(())
        }
    }

    // A sibling closes the lifetime synchronously, even while this owner holds
    // the retained Vault. No value or signing intent may escape a completed wait
    // after that close; rejected values (including IntentGuard) drop here.
    fn after_wait<T>(&self, result: Result<T>) -> Result<T> {
        self.require_open()?;
        result
    }
}
impl<B, C, E, A, R, W> board::CommittedOwner for VaultBoardOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
    W: cvlt::RecordSlot,
{
    type Backend = B;
    fn groups(&mut self) -> Option<&mut dyn cbrd::GroupOwner> {
        self.groups
            .as_mut()
            .map(|groups| groups as &mut dyn cbrd::GroupOwner)
    }
    fn join_room<'a, T, L>(
        &'a mut self,
        board: &'a cbrd::Board<T, L>,
        task: super::RoomJoinTask<'a>,
    ) -> board::OwnerFuture<'a, cbrd::cgrp::Snapshot>
    where
        T: cbrd::clnk::Transport,
        L: crate::door::RoomLink,
    {
        Box::pin(async move {
            let groups = self.groups.as_mut().ok_or(ErrorCode::Unavailable)?;
            groups.join_room(board, task).await.map_err(room_error)
        })
    }
    fn leave_room<'a>(
        &'a mut self,
        task: super::RoomLeaveTask<'a>,
    ) -> board::OwnerFuture<'a, Option<cbrd::cgrp::Snapshot>> {
        Box::pin(async move {
            let groups = self.groups.as_mut().ok_or(ErrorCode::Unavailable)?;
            groups.leave_room(task).await.map_err(room_error)
        })
    }
    fn room_evidence<'a>(
        &'a mut self,
        group: cbrd::cgrp::Id,
        policy: &'a dyn cbrd::cgrp::PolicySource,
    ) -> board::OwnerFuture<'a, cthr::ParentEvidence> {
        Box::pin(async move {
            let groups = self.groups.as_mut().ok_or(ErrorCode::Unavailable)?;
            groups
                .room_evidence(group, policy)
                .await
                .map_err(room_error)
        })
    }
    fn with_current<'a, T: 'a, F>(&'a mut self, read: F) -> board::OwnerFuture<'a, T>
    where
        F: for<'read> FnOnce(board::CommittedRead<'read, B>) -> Result<T> + 'a,
    {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let custody = retained.as_mut().ok_or(ErrorCode::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let store = storage.lock().await;
            // Original ReadHandle checks this exact immutable checkpoint while
            // fresh member authority completes. No earlier lineage is reused.
            let lineage = custody.vault.keys().lineage().await.map_err(keys_error)?;
            if self.lifetime.is_closed()
                || lineage.binding != custody.binding
                || !store.is_scope(custody.binding.community())
            {
                return Err(ErrorCode::Unauthorized);
            }
            // This is a text detector, NOT the ctcs relationship journal. Its
            // unavailable result cannot approve a no-contact-details field.
            let contact = |_: &str| cshm::ContactCheck::Unavailable;
            // Same snapshot, same Use: the block list travels with the read.
            let blocked = custody
                .inbox
                .contacts(&store)
                .and_then(|contacts| contacts.blocking_rules())
                .map_err(|_| ErrorCode::Refused)?;
            read(board::CommittedRead {
                blocked: &blocked,
                store: &store,
                binding: &lineage.binding,
                contact: &contact,
            })
            // Nothing awaits after disclosure under this actual Store guard.
        })
    }
    fn with_profile<'a, T: 'a, F>(&'a mut self, prepare: F) -> board::OwnerFuture<'a, T>
    where
        F: for<'p> FnOnce(board::ProfileParts<'p, B>) -> Result<T> + 'a,
    {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .with_profile_owned(&self.origin, prepare)
                .await;
            // A sibling lock during the wait drops the authorized candidate.
            self.after_wait(result)
        })
    }
    fn commit_profile(
        &mut self,
        authorized: cbrd::cpfl::Authorized,
    ) -> board::OwnerFuture<'_, u64> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .commit_profile_owned(authorized)
                .await;
            self.after_wait(result)
        })
    }
    fn sign_attendance<'a>(
        &'a mut self,
        challenge: &'a clnk::Challenge,
        origin: &'a str,
        expires: u64,
    ) -> board::OwnerFuture<'a, board::SignedAttendance> {
        Box::pin(async move {
            if self.lifetime.is_closed() || origin != self.origin {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let custody = retained.as_mut().ok_or(ErrorCode::Unavailable)?;
            let now =
                ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(keys_error)?;
            let signed = custody
                .sign_transcript(challenge.message(), origin, now, expires)
                .await?;
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(board::SignedAttendance {
                signature: signed.signature,
                admitted: signed.admitted,
            })
        })
    }
    fn present_record<'a>(
        &'a mut self,
        challenge: &'a clnk::Challenge,
        epoch: &'a czkp::record::Epoch,
    ) -> board::OwnerFuture<'a, Vec<u8>> {
        Box::pin(async move {
            // Untrusted service bytes; the Wallet owner bounds them against the epoch.
            let context: czkp::record::Context =
                serde_json::from_slice(challenge.record_context()).map_err(|_| ErrorCode::Refused)?;
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let custody = retained.as_mut().ok_or(ErrorCode::Unavailable)?;
            let now =
                ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(keys_error)?;
            let presentation = custody
                .vault
                .present_record(epoch, &context, now)
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
            self.require_open()?;
            serde_json::to_vec(&presentation).map_err(|_| ErrorCode::Unavailable)
        })
    }
}

impl<B, C, E, A, R, W> VaultBoardOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Is `peer` blocked? Board consults this before it decrypts a Profile or
    /// Exchange input from that sender; the answer is read from the Contacts
    /// journal under fresh Use.
    pub async fn is_blocked(&mut self, peer: &str) -> Result<bool> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        let mut retained = self.retained.lock().await;
        self.require_open()?;
        let result = retained
            .as_mut()
            .ok_or(ErrorCode::Unavailable)?
            .is_blocked_owned(peer)
            .await;
        self.after_wait(result)
    }

    /// Pin the verified chain head of this community in the Vault.
    pub async fn store_pin(
        &mut self,
        fingerprint: [u8; 32],
        ring_revision: u64,
        head: [u8; 32],
    ) -> Result<()> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        let mut retained = self.retained.lock().await;
        self.require_open()?;
        let result = retained
            .as_mut()
            .ok_or(ErrorCode::Unavailable)?
            .store_pin_owned(fingerprint, ring_revision, head)
            .await;
        self.after_wait(result)
    }

    /// Trusted composition only: record the community credential the community
    /// issued to this device when joining. `expected` is the credential believed
    /// current (`None` the first time); a mismatch writes nothing.
    pub async fn store_community_credential(
        &mut self,
        expected: Option<&[u8]>,
        credential: &[u8],
    ) -> Result<cvlt::CredentialWrite> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        let mut retained = self.retained.lock().await;
        self.require_open()?;
        let result = retained
            .as_mut()
            .ok_or(ErrorCode::Unavailable)?
            .store_credential_owned(expected, credential)
            .await;
        self.after_wait(result)
    }
}
impl<B, C, E, A, R, W> BoundVault for VaultBoardOwner<B, C, E, A, R, W>
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
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let identity = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .current_identity()
                .await?;
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(identity)
        })
    }
    fn snapshot(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::ConversationView> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .snapshot(request)
                .await;
            self.after_wait(result)
        })
    }
    fn history(&mut self, request: Conversation) -> OwnedFuture<'_, Vec<cnbx::Message>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .history(request)
                .await;
            self.after_wait(result)
        })
    }
    fn thread(&mut self, request: Conversation) -> OwnedFuture<'_, Vec<ThreadEntry>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .thread(request)
                .await;
            self.after_wait(result)
        })
    }
    fn relation(&mut self, request: Relation) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .relation(request)
                .await;
            self.after_wait(result)
        })
    }
    fn store_pin(
        &mut self,
        fingerprint: [u8; 32],
        ring_revision: u64,
        head: [u8; 32],
    ) -> OwnedFuture<'_, ()> {
        Box::pin(VaultBoardOwner::store_pin(
            self,
            fingerprint,
            ring_revision,
            head,
        ))
    }
    fn blocking_rules(&mut self) -> OwnedFuture<'_, Vec<String>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .blocking_rules()
                .await;
            self.after_wait(result)
        })
    }
    fn voucher_custody(&mut self) -> OwnedFuture<'_, Option<Zeroizing<Vec<u8>>>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .voucher_custody_owned()
                .await;
            self.after_wait(result)
        })
    }
    fn replace_voucher_custody<'a>(
        &'a mut self,
        expected: Option<&'a [u8]>,
        custody: &'a [u8],
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .replace_voucher_custody_owned(expected, custody)
                .await;
            self.after_wait(result)
        })
    }
    fn sign_endorsement<'a>(
        &'a mut self,
        message: &'a [u8],
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, (Vec<u8>, Vec<u8>, Vec<u8>)> {
        Box::pin(async move {
            if self.lifetime.is_closed() || origin != self.origin {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .sign_endorsement_owned(message, origin, now, expires)
                .await;
            self.after_wait(result)
        })
    }
    fn waves<'a>(
        &'a mut self,
        command: inbox_waves::Command,
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_waves::Answer> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .waves(command, ports)
                .await;
            self.after_wait(result)
        })
    }
    fn conversation<'a>(
        &'a mut self,
        command: inbox_conversation::Command,
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, inbox_conversation::Answer> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .conversation(command, ports)
                .await;
            self.after_wait(result)
        })
    }
    fn contact_act(&mut self, request: inbox::ContactAct) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .contact_act(request)
                .await;
            self.after_wait(result)
        })
    }
    fn contact_by_voucher<'a>(
        &'a mut self,
        peer: &'a str,
        bond: [u8; 32],
    ) -> OwnedFuture<'a, [u8; 32]> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .contact_by_voucher(peer, bond)
                .await;
            self.after_wait(result)
        })
    }
    fn voucher_key_package<'a>(
        &'a mut self,
        conversation: [u8; 32],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .voucher_key_package(conversation, ports)
                .await;
            self.after_wait(result)
        })
    }
    fn voucher_create<'a>(
        &'a mut self,
        peer: &'a str,
        conversation: [u8; 32],
        package: &'a [u8],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .voucher_create(peer, conversation, package, ports)
                .await;
            self.after_wait(result)
        })
    }
    fn voucher_join<'a>(
        &'a mut self,
        peer: &'a str,
        conversation: [u8; 32],
        welcome: &'a [u8],
        ports: &'a dyn inbox_waves::WavePorts,
    ) -> OwnedFuture<'a, Vec<Vec<u8>>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .voucher_join(peer, conversation, welcome, ports)
                .await;
            self.after_wait(result)
        })
    }
    fn delivery(&mut self, request: Delivery) -> OwnedFuture<'_, Option<cnbx::DeliveryStatus>> {
        Box::pin(async move {
            if self.lifetime.is_closed() {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .delivery(request)
                .await;
            self.after_wait(result)
        })
    }
    fn sign_board<'a>(
        &'a mut self,
        prepared: &'a cbrd::Prepared,
        origin: &'a str,
        now: u64,
        expires: u64,
    ) -> OwnedFuture<'a, SignedBoard> {
        Box::pin(async move {
            if self.lifetime.is_closed() || origin != self.origin {
                return Err(ErrorCode::Unauthorized);
            }
            let mut retained = self.retained.lock().await;
            self.require_open()?;
            let result = retained
                .as_mut()
                .ok_or(ErrorCode::Unavailable)?
                .sign_board(prepared, origin, now, expires)
                .await;
            self.after_wait(result)
        })
    }
    fn lock(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + 'static>> {
        // Close immediately, before the returned future can wait or be cancelled.
        self.lifetime.close();
        Box::pin(async move {
            let custody = self.retained.lock().await.take();
            if let Some(mut custody) = custody {
                if let Some(intent) = custody.intent.as_mut() {
                    intent.cancel();
                }
                custody.vault.lock().await;
            }
        })
    }
}

impl Door {
    /// Retain the one real Vault and return its narrow Board capability. Obtain
    /// `intent` and `lifetime` from this same session's actual authority/transport
    /// construction. No generated action can install any of these owners.
    pub async fn bind_vault_with_board_owner<B, C, E, A, R, W>(
        &mut self,
        origin: &str,
        mut vault: cvlt::Vault<B, C, E, A, R, W>,
        intent: ckmg::IntentAdmission,
        lifetime: CustodyLifetime,
    ) -> Result<VaultBoardOwner<B, C, E, A, R, W>>
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
        let device = vault.keys().device_public_key().await.map_err(keys_error)?;
        lifetime.check_owner(&binding, device).map_err(keys_error)?;
        if binding.community() != self.config.community
            || !vault
                .storage()
                .lock()
                .await
                .is_scope(&self.config.community)
        {
            return Err(ErrorCode::Unauthorized);
        }
        lifetime.check_owner(&binding, device).map_err(keys_error)?;
        let inbox = cnbx::Inbox::new(binding.clone());
        let owner = VaultBoardOwner {
            retained: Rc::new(Mutex::new(Some(Custody {
                vault,
                binding,
                inbox,
                intent: Some(intent),
            }))),
            lifetime,
            origin: origin.into(),
            groups: None,
        };
        self.vaults.insert(origin.into(), Box::new(owner.clone()));
        Ok(owner)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/support/shared_vault.rs"]
mod tests;

/// The door's code for a room join or evidence failure; nothing of the cause
/// beyond its class crosses the boundary.
pub(crate) fn room_error(error: ctnd::Error) -> ErrorCode {
    match error {
        ctnd::Error::Invalid => ErrorCode::InvalidRequest,
        ctnd::Error::Authority => ErrorCode::Unauthorized,
        ctnd::Error::Unavailable => ErrorCode::Unavailable,
        ctnd::Error::Reconcile | ctnd::Error::Storage => ErrorCode::Reconcile,
    }
}

/// The community account actor's port on the Door's one Vault. It owns no Vault,
/// Store or Keys: each use takes the same retained lock as the Board and every
/// other owner, so the Store has exactly one owner on a device. While a use is
/// open the member authority spends the account's own signing channels.
pub struct AccountPort<B: cwst::backend::Backend, C, E, A, R> {
    retained: Retained<B, C, E, A, R, cvlt::WalletCustody>,
    lifetime: CustodyLifetime,
    arm: crate::door::custody::AccountArm,
}

/// The Door's Vault borrowed through the port for one use.
pub struct PortVault<'a, B: cwst::backend::Backend, C, E, A, R> {
    guard: futures_util::lock::MutexGuard<'a, Option<Custody<B, C, E, A, R, cvlt::WalletCustody>>>,
    _arm: crate::door::custody::ArmGuard,
}

impl<B: cwst::backend::Backend, C, E, A, R> std::ops::Deref for PortVault<'_, B, C, E, A, R> {
    type Target = cvlt::Vault<B, C, E, A, R, cvlt::WalletCustody>;
    fn deref(&self) -> &Self::Target {
        // Presence is checked when the port hands this out and the lock is held since.
        &self.guard.as_ref().expect("checked at open").vault
    }
}
impl<B: cwst::backend::Backend, C, E, A, R> std::ops::DerefMut for PortVault<'_, B, C, E, A, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard.as_mut().expect("checked at open").vault
    }
}

impl<B: cwst::backend::Backend, C, E, A, R> AccountPort<B, C, E, A, R> {
    pub(crate) async fn vault(&mut self) -> Result<PortVault<'_, B, C, E, A, R>> {
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        let guard = self.retained.lock().await;
        if self.lifetime.is_closed() {
            return Err(ErrorCode::Unauthorized);
        }
        if guard.is_none() {
            return Err(ErrorCode::Unavailable);
        }
        Ok(PortVault {
            guard,
            _arm: self.arm.arm(),
        })
    }
}

impl<B: cwst::backend::Backend, C, E, A, R> VaultBoardOwner<B, C, E, A, R, cvlt::WalletCustody> {
    /// The account actor's port on this Vault. `arm` is the handle the member
    /// authority of this same Vault gave out with its account channels.
    pub fn account_port(&self, arm: crate::door::custody::AccountArm) -> AccountPort<B, C, E, A, R> {
        AccountPort {
            retained: self.retained.clone(),
            lifetime: self.lifetime.clone(),
            arm,
        }
    }
}
