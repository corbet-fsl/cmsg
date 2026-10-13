//! The host side of the background proof worker. The host owns the wallet
//! openings and the prover; the Door never proves and never waits for a proof.
//!
//! One round is three steps and the Door is borrowed only for the short first
//! and last ones, so the member's other actions are never held up by a proof:
//!
//! ```text
//! let job = next(&mut door, origin, token, now).await?;       // short
//! let proved = prover.prove(&job).await;                       // long, no Door borrow
//! finish(&mut door, origin, token, now, &job, proved).await?;  // short
//! ```
//! The calls go through the same bounded dispatcher as every other client, so
//! the worker needs a grant for exactly `inbox.wave_job_next` and
//! `inbox.wave_job_done`.
use super::super::{Door, ErrorCode, Invocation, Output, Result};
use super::types::*;

/// The wallet side: builds the witness and proves. Holds the openings.
#[allow(async_fn_in_trait)]
pub trait Prover {
    /// `None` is a failed or uncertain build; the job stays recorded.
    async fn prove(&mut self, job: &ProveJob) -> Option<Proved>;
}

async fn call<T: serde::de::DeserializeOwned>(
    door: &mut Door,
    origin: &str,
    token: &str,
    now: u64,
    action: &str,
    body: serde_json::Value,
) -> Result<T> {
    let invocation = Invocation {
        action: action.into(),
        version: 1,
        body,
    };
    let bytes = serde_json::to_vec(&invocation).map_err(|_| ErrorCode::InvalidRequest)?;
    match door.dispatch(origin, token, &bytes, now).await {
        Output::Ok { result, .. } => {
            serde_json::from_value(result).map_err(|_| ErrorCode::Unavailable)
        }
        Output::Error { error } => Err(error),
    }
}

/// Take the next recorded job, if any.
pub async fn next(
    door: &mut Door,
    origin: &str,
    token: &str,
    now: u64,
) -> Result<Option<ProveJob>> {
    let offer: JobOffer = call(
        door,
        origin,
        token,
        now,
        "inbox.wave_job_next",
        serde_json::json!({}),
    )
    .await?;
    Ok(offer.job)
}

/// Hand the result back. A missing proof reports failure and never loses the job.
pub async fn finish(
    door: &mut Door,
    origin: &str,
    token: &str,
    now: u64,
    job: &ProveJob,
    proved: Option<Proved>,
) -> Result<WaveStatus> {
    let result = match proved {
        Some(proved) => JobResult::Proved { proved },
        None => JobResult::Failed,
    };
    let body = serde_json::to_value(JobDone { id: job.id, result })
        .map_err(|_| ErrorCode::InvalidRequest)?;
    call(door, origin, token, now, "inbox.wave_job_done", body).await
}
