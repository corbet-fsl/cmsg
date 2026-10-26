//! The background record job (decided 2026-10-05): once per epoch, while the device
//! runs, the member's epoch record is proven and cached in the Vault, so entering a
//! Forum never waits for a proof. It runs beside the courier of a bound community
//! and ends with it. The two account-actor steps are short; the proof itself runs on
//! a blocking worker without the Door, the actor or the Store. Nothing here is
//! visible to the person: a failure or a restart simply runs the epoch again (the
//! epoch key is durable before proving, the cache is committed only when verified).
use super::{
    account::{Answer, Command, Shared},
    courier::SharedDoor,
    record::RecordJob,
    ErrorCode, Result,
};
use std::{cell::Cell, rc::Rc, time::Duration};

/// Cadence of the job, in seconds.
#[derive(Clone, Copy, Debug)]
pub struct Cadence {
    /// After a cached or freshly proven epoch: look for the next epoch.
    pub check: u64,
    /// First retry after a failure; doubles up to `check`.
    pub retry: u64,
}
impl Default for Cadence {
    fn default() -> Self {
        Self {
            check: 600,
            retry: 30,
        }
    }
}

/// What one run did.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// The current epoch's record was already cached.
    Cached,
    /// The current epoch's record was proven and is cached now.
    Proven,
}

/// One run: begin through the account actor (or learn it is cached), prove off
/// everything, commit through the actor. The Door is held only for the two calls.
/// Only a cached (or freshly committed) record of the current epoch marks G2.
pub async fn step(door: &SharedDoor, origin: &str, job: &Shared<RecordJob>) -> Result<Step> {
    let answer = {
        let mut guard = door.lock().await;
        super::registry::account_call_at(&mut guard, origin, Command::RecordPrepare(job.clone()))
            .await?
    };
    let Answer::RecordWork(window, work) = answer else {
        return Err(ErrorCode::Unavailable);
    };
    let Some(work) = work.and_then(|work| work.take()) else {
        job.current.mark(window);
        return Ok(Step::Cached);
    };
    let proof = tokio::task::spawn_blocking(move || work.prove())
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })??;
    let mut guard = door.lock().await;
    match super::registry::account_call_at(
        &mut guard,
        origin,
        Command::RecordFinish(Shared::new(Cell::new(Some(proof)))),
    )
    .await?
    {
        Answer::RecordCached => {
            job.current.mark(window);
            Ok(Step::Proven)
        }
        _ => Err(ErrorCode::Unavailable),
    }
}

/// Run the job for `origin` until `closed` reports the courier ended.
pub async fn run(
    door: SharedDoor,
    origin: String,
    job: Shared<RecordJob>,
    closed: Rc<dyn Fn() -> bool>,
    cadence: Cadence,
) {
    let mut wait = 0;
    let mut retry = cadence.retry.max(1);
    loop {
        // Sleep in short slices so a closed courier ends the job promptly.
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
        wait = match step(&door, &origin, &job).await {
            Ok(_) => {
                retry = cadence.retry.max(1);
                cadence.check
            }
            Err(__cause) => {
                crate::door::cause::print(
                    file!(),
                    line!(),
                    "let now retry retry retry 2 min cadence check max 1 now",
                    &__cause,
                );
                {
                    let now = retry;
                    retry = (retry * 2).min(cadence.check.max(1));
                    now
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::{Configuration, Door, Role};
    use std::collections::{BTreeMap, BTreeSet};

    fn door() -> SharedDoor {
        let configuration = Configuration::new(
            "omega".into(),
            BTreeMap::from([(
                Role::Member,
                BTreeSet::from(["https://omega.example.test".to_owned()]),
            )]),
        )
        .unwrap();
        Rc::new(tokio::sync::Mutex::new(Door::new(configuration)))
    }

    #[test]
    fn the_default_cadence_checks_every_ten_minutes_and_retries_sooner() {
        let cadence = Cadence::default();
        assert_eq!(cadence.check, 600);
        assert!(cadence.retry < cadence.check);
    }

    #[tokio::test]
    async fn an_origin_without_an_account_actor_answers_unavailable() {
        let door = door();
        let mut guard = door.lock().await;
        let answer = crate::door::registry::account_call_at(
            &mut guard,
            "https://omega.example.test",
            Command::Resume,
        )
        .await;
        assert_eq!(answer.err(), Some(ErrorCode::Unavailable));
    }
}
