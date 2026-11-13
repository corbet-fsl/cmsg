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
        super::cause::mark("absorb attempt", &format!("start {attempts}"));
        let result = attempt(door).await;
        super::cause::mark(
            "absorb attempt",
            &format!("end {attempts} {:?}", result.as_ref().err()),
        );
        let error = match result {
            Err(error @ (ErrorCode::Unavailable | ErrorCode::Reconcile)) => error,
            done => return done,
        };
        if attempts >= ATTEMPTS || !runway(door, origin, pause) || !wait(pause).await {
            return Err(error);
        }
        // Development gate only: name the absorbed kind, never a value.
        super::cause::print(file!(), line!(), "transient repeated", &error);
        attempts += 1;
        pause = pause.saturating_mul(2);
    }
}

/// At most this many attempts of the community vault opening at device start (the
/// first one included): 1 s and 2 s of pause, 3 s in all.
pub(super) const START_ATTEMPTS: u32 = 3;

/// Device start (decision 2026-11-13, journey row 13): a `503` from the vault means
/// the device retries (cvld `error.rs`), so one start step is repeated while its
/// error is transient. `transient` names the one transient kind of the step's typed
/// error, `Unavailable`; every other error returns at once. The pause starts at
/// [`FIRST_PAUSE_SECONDS`] and doubles. Every attempt starts from nothing (its own
/// session, lease and recovery): a failed lease is never reused. After the last
/// attempt its error returns unchanged. Nothing here locks a key.
pub(super) async fn repeat_start<T, E: std::fmt::Debug>(
    transient: impl Fn(&E) -> bool,
    mut attempt: impl AsyncFnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut pause = FIRST_PAUSE_SECONDS;
    let mut attempts = 1;
    loop {
        let error = match attempt().await {
            Err(error) if transient(&error) => error,
            done => return done,
        };
        if attempts >= START_ATTEMPTS || !wait(pause).await {
            return Err(error);
        }
        // Development gate only: name the repeated kind, never a value.
        super::cause::print(file!(), line!(), "start transient repeated", &error);
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod start_tests {
    use super::*;
    use std::cell::Cell;

    /// A vault that answers `Unavailable` twice and then opens: the start repeats
    /// and succeeds, after the 1 s and 2 s pauses.
    #[tokio::test(start_paused = true)]
    async fn a_transient_unavailable_is_repeated_until_the_vault_opens() {
        let calls = Cell::new(0u32);
        let started = tokio::time::Instant::now();
        let opened = repeat_start(
            |error: &ErrorCode| *error == ErrorCode::Unavailable,
            async || {
                calls.set(calls.get() + 1);
                if calls.get() <= 2 {
                    Err(ErrorCode::Unavailable)
                } else {
                    Ok("vault")
                }
            },
        )
        .await;
        assert_eq!(opened, Ok("vault"));
        assert_eq!(calls.get(), 3);
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(3));
    }

    /// A vault that stays `Unavailable`: bounded, the last error returns unchanged.
    #[tokio::test(start_paused = true)]
    async fn a_lasting_unavailable_ends_after_the_last_attempt_with_the_same_error() {
        let calls = Cell::new(0u32);
        let opened: std::result::Result<(), ErrorCode> = repeat_start(
            |error: &ErrorCode| *error == ErrorCode::Unavailable,
            async || {
                calls.set(calls.get() + 1);
                Err(ErrorCode::Unavailable)
            },
        )
        .await;
        assert_eq!(opened, Err(ErrorCode::Unavailable));
        assert_eq!(calls.get(), START_ATTEMPTS);
    }

    /// A genuine denial is never repeated: one attempt, its error at once.
    #[tokio::test(start_paused = true)]
    async fn an_unauthorized_or_refused_start_fails_at_once_without_a_repeat() {
        for denial in [
            ErrorCode::Unauthorized,
            ErrorCode::Refused,
            ErrorCode::Reconcile,
        ] {
            let calls = Cell::new(0u32);
            let started = tokio::time::Instant::now();
            let opened: std::result::Result<(), ErrorCode> = repeat_start(
                |error: &ErrorCode| *error == ErrorCode::Unavailable,
                async || {
                    calls.set(calls.get() + 1);
                    Err(denial)
                },
            )
            .await;
            assert_eq!(opened, Err(denial));
            assert_eq!(calls.get(), 1);
            assert_eq!(started.elapsed(), std::time::Duration::ZERO);
        }
    }
}
