//! Transient refusals of idempotent actions are absorbed here, inside the
//! operation's own deadline (decision 2026-10-27, journey row 16).
//!
//! Only an action whose server effect is idempotent may run through
//! [`absorb`]: an exact repeat after a partly applied attempt yields the same
//! state and consumes nothing twice. `community_join` is the one such action
//! today: the voucher link answers a known member `Known` without taking a use
//! (cvch `Link::apply`), the ledger answers an exact genesis repeat with its
//! cached acceptance (cblc `AccountLedger::apply`), the record recipient
//! registers once and repeats idempotently, and the client resumes its durable
//! state A by re-sending the identical bytes (`account_reopen`).
//!
//! Only `Unavailable` and `Reconcile` are transient. A deterministic refusal
//! (unauthorized, refused, …) is never repeated: it is a bug at its cause. The
//! budget is the origin's account session: a repeat whose pause would not end
//! before that session's deadline is not started, and the last typed error is
//! returned. Nothing here locks a key.
use super::{Door, ErrorCode, Result};

/// At most this many attempts of one operation (the first one included).
pub(super) const ATTEMPTS: u32 = 4;
/// The pause before the second attempt; it doubles for every further one.
pub(super) const FIRST_PAUSE_SECONDS: u64 = 1;

/// Run `attempt` and repeat it on a transient error while the budget lasts.
pub(super) async fn absorb<T>(
    door: &mut Door,
    origin: &str,
    mut attempt: impl AsyncFnMut(&mut Door) -> Result<T>,
) -> Result<T> {
    let mut pause = FIRST_PAUSE_SECONDS;
    let mut attempts = 1;
    loop {
        let error = match attempt(door).await {
            Err(error @ (ErrorCode::Unavailable | ErrorCode::Reconcile)) => error,
            done => return done,
        };
        if attempts >= ATTEMPTS || !runway(door, origin, pause) || !wait(pause).await {
            return Err(error);
        }
        attempts += 1;
        pause = pause.saturating_mul(2);
    }
}

/// Whether the origin's live account session still runs after `pause`. Without
/// a live session there is no deadline to repeat inside.
fn runway(door: &Door, origin: &str, pause: u64) -> bool {
    door.accounts
        .get(origin)
        .is_some_and(|actor| !actor.ended() && actor.lifetime().0 > pause)
}

#[cfg(not(target_arch = "wasm32"))]
async fn wait(seconds: u64) -> bool {
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
    true
}

/// The browser has no account actor (native devices only): nothing repeats.
#[cfg(target_arch = "wasm32")]
async fn wait(_: u64) -> bool {
    false
}
