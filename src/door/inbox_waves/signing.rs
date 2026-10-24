//! The engine's account-key signer: the wave's three signatures, each through
//! `Keys::sign_account_digest`.
//!
//! The ports compute the digest from the account witness; this signer only passes the
//! committed account-key capsule. Keys keeps the one-digest-per-slot-and-phase ledger
//! inside its own checkpoint and releases a signature only after that checkpoint
//! committed, so no key, engine or ledger leaves custody here. A retry of the same
//! digest re-signs identical bytes (deterministic, low-S); a different digest for the
//! same wave slot and phase is refused. The desk's former ledger is imported into Keys
//! once (add-only) before the first signature.
use super::super::{facades::OwnedFuture, ErrorCode, Result};
use super::ports::AccountSigner;
use ckmg::{Authority, Clock, Entropy, Keys, SecureStore, SigningLedger, SigningPhase};
use cwst::{backend::Backend, Store};
use futures_util::lock::Mutex;
use std::cell::RefCell;

/// How long (seconds) one signing admission may take.
const ADMISSION_SECONDS: u64 = 60;

pub(crate) struct EngineSigner<'k, 's, S, C, R, A, B: Backend> {
    keys: Mutex<&'k mut Keys<S, C, R, A>>,
    store: &'s Store<B>,
    scope: String,
    /// The desk's legacy ledger until Keys imported it.
    legacy: RefCell<SigningLedger>,
}

impl<'k, 's, S, C, R, A, B> EngineSigner<'k, 's, S, C, R, A, B>
where
    S: SecureStore,
    C: Clock,
    R: Entropy,
    A: Authority,
    B: Backend,
{
    pub(crate) fn new(
        keys: &'k mut Keys<S, C, R, A>,
        store: &'s Store<B>,
        scope: &str,
        legacy: SigningLedger,
    ) -> Self {
        Self {
            keys: Mutex::new(keys),
            store,
            scope: scope.into(),
            legacy: RefCell::new(legacy),
        }
    }

    /// The part of the desk's legacy ledger Keys has not imported yet (empty once it
    /// has); the caller stores it back in the desk.
    pub(crate) fn into_legacy(self) -> SigningLedger {
        self.legacy.into_inner()
    }
}

impl<S, C, R, A, B> AccountSigner for EngineSigner<'_, '_, S, C, R, A, B>
where
    S: SecureStore,
    C: Clock,
    R: Entropy,
    A: Authority,
    B: Backend,
{
    fn sign<'a>(
        &'a self,
        phase: SigningPhase,
        slot: [u8; 32],
        digest: [u8; 32],
    ) -> OwnedFuture<'a, [u8; 64]> {
        Box::pin(async move {
            let mut keys = self.keys.lock().await;
            let legacy = self.legacy.borrow().clone();
            if !legacy.is_empty() {
                let bytes = legacy.to_bytes().map_err(|_| ErrorCode::Unavailable)?;
                keys.import_signing_ledger(&bytes)
                    .await
                    .map_err(unavailable)?;
                *self.legacy.borrow_mut() = SigningLedger::new();
            }
            let sealed =
                cwlt::account_owner::DurableAccountOwner::committed_sealed(self.store, &self.scope)
                    .map_err(|_| ErrorCode::Unavailable)?;
            let expires = Clock::now(&mut super::super::custody::SystemClock)
                .map_err(|_| ErrorCode::Clock)?
                .saturating_add(ADMISSION_SECONDS);
            keys.sign_account_digest(phase, slot, digest, &sealed, expires)
                .await
                .map_err(|error| match error {
                    ckmg::Error::Expired => ErrorCode::Clock,
                    _ => ErrorCode::Unauthorized,
                })
        })
    }
}

fn unavailable(_: ckmg::Error) -> ErrorCode {
    ErrorCode::Unavailable
}
