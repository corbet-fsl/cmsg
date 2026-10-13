//! Profile publication custody on the bound Vault. The device signer and the
//! Envelope custody exist only inside one synchronous Keys callback after a
//! distinct, single-use admission; the committed Store read, the community
//! credential and the Contacts block list come from that same Store snapshot.
//! The later commit is a Store version-fenced write: a lost race is Reconcile
//! and never overwrites.
use super::inbox_custody::contact_error;
use super::*;
use crate::door::board::{CommittedRead, ProfileParts};

/// How long the single-use custody admission stays valid, in seconds. The
/// callback runs synchronously right after admission; this only bounds waits.
const PROFILE_CUSTODY_SECONDS: u64 = 30;

fn credential_error(error: cvlt::CredentialError) -> ErrorCode {
    match error {
        cvlt::CredentialError::Keys(error) => keys_error(error),
        cvlt::CredentialError::Scope | cvlt::CredentialError::Foreign => ErrorCode::Unauthorized,
        cvlt::CredentialError::Invalid => ErrorCode::InvalidRequest,
        // An uncertain or conflicting write is reconciled, never retried blindly.
        cvlt::CredentialError::Conflict | cvlt::CredentialError::Storage => ErrorCode::Reconcile,
    }
}

impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Lend the Profile parts to one synchronous callback. Order matters: the
    /// credential read takes the Store lock itself, so it comes first; then the
    /// Store, fresh lineage and the Contacts journal are read under one guard,
    /// and only then is custody admitted and lent.
    pub(super) async fn with_profile_owned<T>(
        &mut self,
        origin: &str,
        prepare: impl for<'p> FnOnce(ProfileParts<'p, B>) -> Result<T>,
    ) -> Result<T> {
        let credential = self
            .vault
            .community_credential()
            .await
            .map_err(credential_error)?
            .map(|credential| credential.to_vec());
        let storage = self.vault.storage().clone();
        let store = storage.lock().await;
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        if lineage.binding != self.binding || !store.is_scope(self.binding.community()) {
            return Err(ErrorCode::Unauthorized);
        }
        // Same snapshot, same Use: a blocked member becomes a never-match rule.
        let blocked = self
            .inbox
            .contacts(&store)
            .and_then(|contacts| contacts.blocking_rules())
            .map_err(contact_error)?;
        let device = self
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(keys_error)?;
        let now = ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(keys_error)?;
        let intent = self.intent.as_mut().ok_or(ErrorCode::Unavailable)?;
        let admitted = intent
            .admit(
                ckmg::AdmittedCommand {
                    binding: lineage.binding.clone(),
                    origin: origin.into(),
                    action: ckmg::Action::LendProfileCustody,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: None,
                    expires: now.saturating_add(PROFILE_CUSTODY_SECONDS),
                },
                now,
            )
            .map_err(keys_error)?;
        let binding = lineage.binding;
        let contact = |_: &str| cshm::ContactCheck::Unavailable;
        let blocked_view = blocked.clone();
        let lent = self
            .vault
            .keys()
            .with_profile_custody(|signer, custody| {
                prepare(ProfileParts {
                    read: CommittedRead {
                        store: &store,
                        binding: &binding,
                        contact: &contact,
                        blocked: &blocked_view,
                    },
                    signer,
                    custody,
                    credential,
                    blocked,
                })
            })
            .await
            .map_err(keys_error);
        drop(admitted);
        lent?
    }

    /// Commit an authorized publication under the Store version fence. A lost
    /// race or uncertain write is Reconcile; nothing is overwritten or retried.
    pub(super) async fn commit_profile_owned(
        &mut self,
        authorized: cbrd::cpfl::Authorized,
    ) -> Result<u64> {
        let storage = self.vault.storage().clone();
        let mut store = storage.lock().await;
        self.check_scope(&store).await?;
        let mut operation = [0; 32];
        getrandom::fill(&mut operation).map_err(|_| ErrorCode::Unavailable)?;
        cbrd::commit_profile(authorized, &mut store, operation)
            .await
            .map_err(|_| ErrorCode::Reconcile)
    }

    /// Store or replace the member's community credential (compare-and-swap).
    pub(super) async fn store_credential_owned(
        &mut self,
        expected: Option<&[u8]>,
        credential: &[u8],
    ) -> Result<cvlt::CredentialWrite> {
        self.vault
            .replace_community_credential(expected, credential)
            .await
            .map_err(credential_error)
    }

    /// Pin the verified chain head of this membership's community in the Vault,
    /// beside the community credential. Only a first pin or a forward move is
    /// written; anything else is refused and writes nothing.
    pub(super) async fn store_pin_owned(
        &mut self,
        fingerprint: [u8; 32],
        ring_revision: u64,
        head: [u8; 32],
    ) -> Result<()> {
        use crate::door::identity::{self, Fingerprint, Head};
        let current = self.vault.community_pin().await.map_err(credential_error)?;
        let head = Head {
            ring_revision,
            digest: Fingerprint(head),
        };
        match identity::next_pin(current.as_ref(), &Fingerprint(fingerprint), head) {
            Ok(None) => Ok(()),
            Ok(Some(pin)) => self
                .vault
                .write_community_pin(current.as_ref(), &pin, None)
                .await
                .map(|_| ())
                .map_err(credential_error),
            Err(_) => Err(ErrorCode::Refused),
        }
    }

    /// Is this peer blocked in the Contacts journal? Read under fresh Use in the
    /// same Store snapshot, so a Profile or Exchange input from a blocked sender
    /// can be refused before any decryption.
    pub(super) async fn is_blocked_owned(&mut self, peer: &str) -> Result<bool> {
        let storage = self.vault.storage().clone();
        let store = storage.lock().await;
        self.check_scope(&store).await?;
        self.inbox
            .contacts(&store)
            .and_then(|contacts| contacts.blocking_rules())
            .map(|blocked| blocked.iter().any(|blocked| blocked == peer))
            .map_err(contact_error)
    }
}
