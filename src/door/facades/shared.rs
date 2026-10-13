//! One actual Vault retained by its Door and the Board's scoped owner.
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
}
impl<B: cwst::backend::Backend, C, E, A, R, W> Clone for VaultBoardOwner<B, C, E, A, R, W> {
    fn clone(&self) -> Self {
        Self {
            retained: self.retained.clone(),
            lifetime: self.lifetime.clone(),
            origin: self.origin.clone(),
        }
    }
}
impl<B: cwst::backend::Backend, C, E, A, R, W> VaultBoardOwner<B, C, E, A, R, W> {
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
{
    type Backend = B;
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
        };
        self.vaults.insert(origin.into(), Box::new(owner.clone()));
        Ok(owner)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/support/shared_vault.rs"]
mod tests;
