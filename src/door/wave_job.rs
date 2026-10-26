//! The background wave proof worker: while the device runs, every recorded wave job
//! (reserve, activate, prove the evidence; settle, prove the outcome) is taken from the
//! Door's journal, proven WITHOUT holding the Door, and handed back. It runs beside the
//! courier of a bound community and ends with it, like the record job.
//!
//! The Door is locked only for the short journal calls (`inbox.wave_job_next`,
//! `inbox.wave_job_done`) through an internal lease that grants exactly those actions;
//! the wallet's own account-actor calls (update, settle) lock it again per call. The
//! courier owns start-up recovery (`inbox.wave_jobs_recover` once per start), so the
//! worker waits a moment before its first round and never re-offers a job it holds.
//!
//! What builds the wallet of a round is the embedding's [`WaveWorker`]: the native
//! device composes it from the account witness in Vault custody, the extension group's
//! provers and the D2 actor (`inbox_waves::native`). Nothing here is visible to the
//! person; a failed round is simply retried, and the member's action stays recorded.
use super::{
    courier::SharedDoor,
    inbox_waves::{
        production::{drain, WalletProver, WaveJobs, WaveWallet},
        JobDone, JobOffer, JobResult, ProveJob, Proved,
    },
    Door, ErrorCode, Grant, Result,
};
use serde_json::{json, Value};
use std::{future::Future, pin::Pin, rc::Rc, time::Duration};

/// One round of the worker for one origin: drain the job journal with a freshly built
/// wallet. Returns how many proved jobs were handed back.
pub trait WaveWorker {
    fn round(
        &self,
        door: SharedDoor,
        origin: String,
    ) -> Pin<Box<dyn Future<Output = Result<usize>>>>;
}

/// A worker from a wallet builder: each round builds the wallet from the device's
/// current custody and trust, then drains the journal with it.
pub struct WalletWorker<F>(pub F);

impl<F, Fut, W> WaveWorker for WalletWorker<F>
where
    F: Fn(SharedDoor, String) -> Fut,
    Fut: Future<Output = Result<W>> + 'static,
    W: WaveWallet + 'static,
{
    fn round(
        &self,
        door: SharedDoor,
        origin: String,
    ) -> Pin<Box<dyn Future<Output = Result<usize>>>> {
        let wallet = (self.0)(door.clone(), origin.clone());
        Box::pin(async move {
            let mut prover = WalletProver(wallet.await?);
            let mut jobs = LeaseJobs { door, origin };
            drain(&mut jobs, &mut prover, false).await
        })
    }
}

/// The journal actions the worker's lease grants; nothing else.
const ACTIONS: &[&str] = &[
    "inbox.wave_job_next",
    "inbox.wave_job_done",
    "inbox.wave_jobs_recover",
];

/// Seconds a lease lives; it is closed after each call anyway.
const LEASE_SECONDS: u64 = 60;

fn now() -> Result<u64> {
    ckmg::Clock::now(&mut super::custody::SystemClock).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Clock",
            ErrorCode::Clock,
            &__cause,
        )
    })
}

/// One journal call through a short internal grant of `origin`, exactly as a paired
/// client's call would be authorized (same handler, same origin and expiry checks).
async fn call(door: &mut Door, origin: &str, action: &str, body: Value) -> Result<Value> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    door.grants.insert(
        key,
        Grant {
            origin: origin.to_owned(),
            actions: ACTIONS.iter().map(|a| (*a).to_owned()).collect(),
            expires: now()?.saturating_add(LEASE_SECONDS),
        },
    );
    let outcome = match super::registry::action(action) {
        Some(found) => (found.handler)(door, &key, &body.to_string())
            .await
            .map(|(value, _)| value),
        None => Err(ErrorCode::UnsupportedAction),
    };
    door.grants.remove(&key);
    outcome
}

/// The Door's job journal as the worker sees it, one short lock per call.
pub struct LeaseJobs {
    pub door: SharedDoor,
    pub origin: String,
}

impl WaveJobs for LeaseJobs {
    async fn recover(&mut self) -> Result<()> {
        let mut door = self.door.lock().await;
        call(
            &mut door,
            &self.origin,
            "inbox.wave_jobs_recover",
            json!({}),
        )
        .await
        .map(|_| ())
    }
    async fn next(&mut self) -> Result<Option<ProveJob>> {
        let value = {
            let mut door = self.door.lock().await;
            call(&mut door, &self.origin, "inbox.wave_job_next", json!({})).await?
        };
        let offer: JobOffer = serde_json::from_value(value).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        Ok(offer.job)
    }
    async fn finish(&mut self, job: &ProveJob, proved: Option<Proved>) -> Result<()> {
        let result = match proved {
            Some(proved) => JobResult::Proved { proved },
            None => JobResult::Failed,
        };
        let body = serde_json::to_value(JobDone { id: job.id, result }).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let mut door = self.door.lock().await;
        call(&mut door, &self.origin, "inbox.wave_job_done", body)
            .await
            .map(|_| ())
    }
}

/// Cadence of the worker, in seconds.
#[derive(Clone, Copy, Debug)]
pub struct Cadence {
    /// Before the first round: the courier's start-up recovery runs first.
    pub start: u64,
    /// Between rounds that found nothing or finished.
    pub check: u64,
    /// First retry after a failed round; doubles up to `ceiling`.
    pub retry: u64,
    pub ceiling: u64,
}
impl Default for Cadence {
    fn default() -> Self {
        Self {
            start: 5,
            check: 15,
            retry: 30,
            ceiling: 300,
        }
    }
}

/// Run the worker for `origin` until `closed` reports the courier ended.
pub async fn run(
    door: SharedDoor,
    origin: String,
    worker: Rc<dyn WaveWorker>,
    closed: Rc<dyn Fn() -> bool>,
    cadence: Cadence,
) {
    let mut wait = cadence.start;
    let mut retry = cadence.retry.max(1);
    loop {
        let mut slept = 0;
        while slept < wait {
            if closed() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            slept += 1;
        }
        if closed() {
            return;
        }
        wait = match worker.round(door.clone(), origin.clone()).await {
            Ok(_) => {
                retry = cadence.retry.max(1);
                cadence.check.max(1)
            }
            Err(__cause) => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "let now retry retry retry 2 min cadence ceiling max 1 now",
                    &__cause,
                );
                {
                    let now = retry;
                    retry = (retry * 2).min(cadence.ceiling.max(1));
                    now
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::{Configuration, Role};
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
    };

    const ORIGIN: &str = "https://omega.example.test";

    fn door() -> SharedDoor {
        let configuration = Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
        )
        .unwrap();
        Rc::new(tokio::sync::Mutex::new(Door::new(configuration)))
    }

    /// A wallet that must never be asked: no job reaches it.
    struct Never;
    impl WaveWallet for Never {
        async fn prove_job(&mut self, _: &ProveJob) -> Result<Proved> {
            panic!("no job was recorded");
        }
    }

    #[tokio::test]
    async fn a_round_without_a_bound_inbox_fails_and_leaves_no_grant() {
        let door = door();
        let worker = WalletWorker(|_: SharedDoor, _: String| async { Ok(Never) });
        let outcome = worker.round(door.clone(), ORIGIN.to_owned()).await;
        assert!(
            outcome.is_err(),
            "no Inbox is bound, the journal is unavailable"
        );
        assert!(
            door.lock().await.grants.is_empty(),
            "the lease is closed after the call"
        );
    }

    #[tokio::test]
    async fn a_wallet_that_cannot_be_built_fails_the_round_before_any_call() {
        let door = door();
        let worker = WalletWorker(|_: SharedDoor, _: String| async {
            Err::<Never, _>(ErrorCode::Unavailable)
        });
        assert_eq!(
            worker.round(door, ORIGIN.to_owned()).await.err(),
            Some(ErrorCode::Unavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_worker_backs_off_after_failures_and_ends_with_the_courier() {
        struct Counting(Rc<Cell<u32>>);
        impl WaveWorker for Counting {
            fn round(
                &self,
                _: SharedDoor,
                _: String,
            ) -> Pin<Box<dyn Future<Output = Result<usize>>>> {
                self.0.set(self.0.get() + 1);
                Box::pin(async { Err(ErrorCode::Unavailable) })
            }
        }
        let rounds = Rc::new(Cell::new(0));
        let closed = Rc::new(Cell::new(false));
        let stop = closed.clone();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let task = tokio::task::spawn_local(run(
                    door(),
                    ORIGIN.to_owned(),
                    Rc::new(Counting(rounds.clone())),
                    Rc::new(move || stop.get()),
                    Cadence {
                        start: 1,
                        check: 5,
                        retry: 2,
                        ceiling: 8,
                    },
                ));
                // Rounds at 1, 3 (retry 2), 7 (retry 4), 15 (retry 8), 23 (ceiling 8).
                tokio::time::sleep(Duration::from_secs(24)).await;
                assert_eq!(rounds.get(), 5);
                closed.set(true);
                tokio::time::sleep(Duration::from_secs(2)).await;
                assert!(task.is_finished(), "a closed courier ends the worker");
                assert_eq!(rounds.get(), 5);
            })
            .await;
    }
}
