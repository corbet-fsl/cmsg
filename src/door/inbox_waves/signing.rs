//! The engine's account-key signer: the exact-digest Keys admissions behind the wave's
//! three signatures, with the persisted [`SigningLedger`].
//!
//! The ports compute the digest from the account witness; this signer is the only thing
//! that touches the key. A repeated digest returns the stored signature without touching
//! custody, a different digest for the same wave slot and phase is refused. The ledger
//! travels in the desk, so it is committed in the same checkpoint that stores the
//! signature in the session, before anything is sent.
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
    ledger: RefCell<SigningLedger>,
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
        ledger: SigningLedger,
    ) -> Self {
        Self {
            keys: Mutex::new(keys),
            store,
            scope: scope.into(),
            ledger: RefCell::new(ledger),
        }
    }

    /// The ledger after the signatures made so far; the caller commits it.
    pub(crate) fn into_ledger(self) -> SigningLedger {
        self.ledger.into_inner()
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
            let stored = self
                .ledger
                .borrow()
                .lookup(&slot, phase, &digest)
                .map_err(|_| ErrorCode::Refused)?;
            if let Some(stored) = stored {
                return Ok(stored.0);
            }
            let mut keys = self.keys.lock().await;
            let opening = keys.wallet_engine().await.map_err(unavailable)?;
            let signing = keys.wallet_engine().await.map_err(unavailable)?;
            let owner = cwlt::account_owner::DurableAccountOwner::open(
                opening,
                self.store,
                &self.scope,
            )
            .map_err(|_| ErrorCode::Unavailable)?;
            let expires = Clock::now(&mut super::super::custody::SystemClock)
                .map_err(|_| ErrorCode::Clock)?
                .saturating_add(ADMISSION_SECONDS);
            let mut ledger = self.ledger.borrow().clone();
            let signature = keys
                .sign_account_digest(&mut ledger, phase, slot, digest, owner.key(), &signing, expires)
                .await
                .map_err(|error| match error {
                    ckmg::Error::Expired => ErrorCode::Clock,
                    _ => ErrorCode::Unauthorized,
                })?;
            *self.ledger.borrow_mut() = ledger;
            Ok(signature)
        })
    }
}

fn unavailable(_: ckmg::Error) -> ErrorCode {
    ErrorCode::Unavailable
}
