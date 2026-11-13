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

/// A start step's typed error as [`repeat_start`] sees and logs it. `step` and `kind`
/// are fixed names (the step, the error's variant), never a value, key, token, member
/// identifier or record content.
pub(super) trait StartError: std::fmt::Debug {
    /// Whether the step repeats on this error: its `Unavailable` only.
    fn transient(&self) -> bool;
    /// The start step that failed.
    fn step(&self) -> &'static str;
    /// The error's variant name.
    fn kind(&self) -> String;
}

/// Device start (decision 2026-11-13, journey row 13; L20261113a): a `503` from the vault
/// means the device retries (cvld `error.rs`), so one start step is repeated while its
/// error is transient ([`StartError::transient`]); every other error returns at once. The
/// pause starts at [`FIRST_PAUSE_SECONDS`] and doubles. Every attempt starts from nothing
/// (its own session, lease and recovery): a failed lease is never reused. After the last
/// attempt its error returns unchanged. Every absorbed error is logged in every build
/// ([`warn`]): one line per repeat, and one more when an attempt after a repeat still
/// fails. Nothing here locks a key.
pub(super) async fn repeat_start<T, E: StartError>(
    attempt: impl AsyncFnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    repeat_start_logged(warn, attempt).await
}

/// [`repeat_start`] with its log sink as a parameter (the tests read the lines).
async fn repeat_start_logged<T, E: StartError>(
    mut log: impl FnMut(&str),
    mut attempt: impl AsyncFnMut() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut pause = FIRST_PAUSE_SECONDS;
    let mut attempts = 1;
    loop {
        let error = match attempt().await {
            Ok(done) => return Ok(done),
            Err(error) if error.transient() && attempts < START_ATTEMPTS => error,
            Err(error) => {
                if attempts > 1 {
                    log(&failed_line(&error, attempts));
                }
                return Err(error);
            }
        };
        log(&repeat_line(&error, attempts, pause));
        // Development gate only: name the repeated kind, never a value.
        super::cause::print(file!(), line!(), "start transient repeated", &error);
        start_pause(pause).await;
        attempts += 1;
        pause = pause.saturating_mul(2);
    }
}

/// The warn line of one repeat: step, attempt n of N, error kind and the pause before
/// the next attempt. Fixed names and counters only.
fn repeat_line(error: &impl StartError, attempt: u32, wait: u64) -> String {
    format!(
        "warn: start step repeated: step=\"{}\" attempt={attempt}/{START_ATTEMPTS} kind={} wait={wait}s",
        error.step(),
        error.kind()
    )
}

/// The warn line of a start that still fails after at least one repeat.
fn failed_line(error: &impl StartError, attempt: u32) -> String {
    format!(
        "warn: start step failed after repeats: step=\"{}\" attempt={attempt}/{START_ATTEMPTS} kind={}",
        error.step(),
        error.kind()
    )
}

/// The crate's log of a device: stderr natively, as in every other device line.
#[cfg(not(target_arch = "wasm32"))]
fn warn(line: &str) {
    eprintln!("{line}");
}

/// The crate's log in the browser: the console's warn level, as the wallet frame's errors.
#[cfg(target_arch = "wasm32")]
fn warn(line: &str) {
    web_sys::console::warn_1(&wasm_bindgen::JsValue::from_str(line));
}

#[cfg(not(target_arch = "wasm32"))]
async fn start_pause(seconds: u64) {
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
}

/// The browser pauses on the page's timer (the start path is async there too).
#[cfg(target_arch = "wasm32")]
async fn start_pause(seconds: u64) {
    gloo_timers::future::TimeoutFuture::new(
        seconds.saturating_mul(1000).min(u32::MAX as u64) as u32
    )
    .await;
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
    use std::cell::{Cell, RefCell};

    /// A start step's error; `Unavailable` carries a value that must never be logged.
    #[derive(Clone, Debug, PartialEq)]
    enum Probe {
        Unavailable(String),
        Unauthorized,
        Refused,
        Reconcile,
    }

    impl StartError for Probe {
        fn transient(&self) -> bool {
            matches!(self, Self::Unavailable(_))
        }
        fn step(&self) -> &'static str {
            "community vault"
        }
        fn kind(&self) -> String {
            super::super::cause::kind(self)
        }
    }

    fn unavailable() -> Probe {
        Probe::Unavailable("hunter2-member-record".into())
    }

    /// A vault that answers `Unavailable` twice and then opens: the start repeats and
    /// succeeds after the 1 s and 2 s pauses, with one warn line per repeat.
    #[tokio::test(start_paused = true)]
    async fn a_transient_unavailable_is_repeated_until_the_vault_opens() {
        let calls = Cell::new(0u32);
        let lines = RefCell::new(Vec::new());
        let started = tokio::time::Instant::now();
        let opened = repeat_start_logged(
            |line: &str| lines.borrow_mut().push(line.to_owned()),
            async || {
                calls.set(calls.get() + 1);
                if calls.get() <= 2 {
                    Err(unavailable())
                } else {
                    Ok("vault")
                }
            },
        )
        .await;
        assert_eq!(opened, Ok("vault"));
        assert_eq!(calls.get(), 3);
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(3));
        assert_eq!(
            lines.into_inner(),
            [
                "warn: start step repeated: step=\"community vault\" attempt=1/3 kind=Unavailable wait=1s",
                "warn: start step repeated: step=\"community vault\" attempt=2/3 kind=Unavailable wait=2s",
            ]
        );
    }

    /// A vault that stays `Unavailable`: bounded, the last error returns unchanged, and
    /// the final failure is logged once. No line carries the error's value.
    #[tokio::test(start_paused = true)]
    async fn a_lasting_unavailable_ends_after_the_last_attempt_with_the_same_error() {
        let calls = Cell::new(0u32);
        let lines = RefCell::new(Vec::new());
        let opened: std::result::Result<(), Probe> = repeat_start_logged(
            |line: &str| lines.borrow_mut().push(line.to_owned()),
            async || {
                calls.set(calls.get() + 1);
                Err(unavailable())
            },
        )
        .await;
        assert_eq!(opened, Err(unavailable()));
        assert_eq!(calls.get(), START_ATTEMPTS);
        let lines = lines.into_inner();
        assert_eq!(
            lines,
            [
                "warn: start step repeated: step=\"community vault\" attempt=1/3 kind=Unavailable wait=1s",
                "warn: start step repeated: step=\"community vault\" attempt=2/3 kind=Unavailable wait=2s",
                "warn: start step failed after repeats: step=\"community vault\" attempt=3/3 kind=Unavailable",
            ]
        );
        assert!(lines.iter().all(|line| !line.contains("hunter2")));
    }

    /// A genuine denial is never repeated: one attempt, its error at once, nothing logged.
    #[tokio::test(start_paused = true)]
    async fn an_unauthorized_or_refused_start_fails_at_once_without_a_repeat() {
        for denial in [Probe::Unauthorized, Probe::Refused, Probe::Reconcile] {
            let calls = Cell::new(0u32);
            let lines = RefCell::new(Vec::<String>::new());
            let started = tokio::time::Instant::now();
            let opened: std::result::Result<(), Probe> = repeat_start_logged(
                |line: &str| lines.borrow_mut().push(line.to_owned()),
                async || {
                    calls.set(calls.get() + 1);
                    Err(denial.clone())
                },
            )
            .await;
            assert_eq!(opened, Err(denial));
            assert_eq!(calls.get(), 1);
            assert_eq!(started.elapsed(), std::time::Duration::ZERO);
            assert!(lines.into_inner().is_empty());
        }
    }

    /// A denial after a repeat ends the start at once; the repeat and the failure are logged.
    #[tokio::test(start_paused = true)]
    async fn a_denial_after_a_repeat_ends_the_start_and_is_logged() {
        let calls = Cell::new(0u32);
        let lines = RefCell::new(Vec::new());
        let opened: std::result::Result<(), Probe> = repeat_start_logged(
            |line: &str| lines.borrow_mut().push(line.to_owned()),
            async || {
                calls.set(calls.get() + 1);
                Err(if calls.get() == 1 {
                    unavailable()
                } else {
                    Probe::Unauthorized
                })
            },
        )
        .await;
        assert_eq!(opened, Err(Probe::Unauthorized));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            lines.into_inner(),
            [
                "warn: start step repeated: step=\"community vault\" attempt=1/3 kind=Unavailable wait=1s",
                "warn: start step failed after repeats: step=\"community vault\" attempt=2/3 kind=Unauthorized",
            ]
        );
    }

    /// The child half of `every_build_logs_a_repeat_on_stderr`: the real sink.
    #[tokio::test(start_paused = true)]
    async fn repeat_log_child() {
        if std::env::var_os("CMSG_REPEAT_LOG_CHILD").is_none() {
            return;
        }
        let calls = Cell::new(0u32);
        let opened = repeat_start(async || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Err(unavailable())
            } else {
                Ok(())
            }
        })
        .await;
        assert_eq!(opened, Ok(()));
    }

    /// The repeat line reaches stderr in this build whatever its features (not only the
    /// development gate), and never with the error's value.
    #[test]
    fn every_build_logs_a_repeat_on_stderr() {
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "door::transient::start_tests::repeat_log_child",
                "--nocapture",
            ])
            .env("CMSG_REPEAT_LOG_CHILD", "1")
            .output()
            .expect("run the child test");
        assert!(out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!err.contains("hunter2"), "a value was logged: {err}");
        assert!(
            err.contains(
                "warn: start step repeated: step=\"community vault\" attempt=1/3 kind=Unavailable wait=1s"
            ),
            "the repeat line is missing: {err}"
        );
    }
}
