//! Production wave capabilities and the proof worker loop.
//!
//! [`ProductionPorts`] is the [`WavePorts`] bundle a device installs per member origin
//! (`Door::bind_waves`). It owns no policy, key or proof system itself: every part is a
//! small capability supplied by the trusted embedding runtime, and every one refuses when
//! its source is missing or stale (nothing here answers permissively):
//!
//! | Port method | Source |
//! |---|---|
//! | `policy`, `verify_*` | [`WaveTrust`]: the verified community material (never unverified configuration or a peer's presentation) |
//! | `terms` | [`WaveTerms`]: the member's own wallet authority and a fresh one-use challenge |
//! | `verify_*` | cwlt [`WaveVerifier`] built per call from the trusted policy and window |
//! | `own_record` (G2) | [`OwnRecordCheck`] |
//! | `peer_lineage` | [`PeerLineageRead`]: a forced read, never a cache |
//!
//! [`drain`] is the host-side worker loop: recover interrupted jobs once, then take a job,
//! prove it WITHOUT holding the Door, hand the result back, until the queue is empty.
use super::super::{facades::OwnedFuture, Door, ErrorCode, Result};
use super::{
    ports::{verify_outcome_with, verify_reservation_with},
    types::{ProveJob, Proved, Terms},
    worker, Policy, WavePorts,
};
use ckmg::{Binding, Lineage};
use cwlt::wave::{
    ProofCheck, VerifiedWaveOutcome, VerifiedWaveReservation, WaveContext, WaveOutcome,
    WaveOutcomeStatement, WavePolicy, WaveStatement, WaveVerifier,
};

/// What the verified community material currently allows. `authority_until` is the
/// exclusive end of the authenticated policy lease.
#[derive(Clone, Debug)]
pub struct Trust {
    pub policy: Policy,
    pub wave: WavePolicy,
    pub authority_until: u64,
}

/// The verified, current wave terms. Until the published material carries the wave
/// policy derivation (cblc `PublicVerifierMaterial::wave_policy`), an implementation
/// reads the same verified feed material the device already holds.
pub trait WaveTrust {
    /// `Unavailable` when no verified material covers `now`.
    fn current(&self, now: u64) -> Result<Trust>;
}

/// The recipient's own terms for a wave it was offered.
pub trait WaveTerms {
    fn terms(&self, nonce: &[u8; 32], now: u64) -> Result<Terms>;
}

/// G2: this member's record matches the newest epoch commitment.
pub trait OwnRecordCheck {
    fn check<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, ()>;
}

/// The current lineage of a peer, read afresh every time.
pub trait PeerLineageRead {
    fn read<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, Lineage>;
}

/// Builds the counterpart verifier for one trusted policy and instant. The native build
/// returns `WaveVerifier::native(..)` over the retained wave artifact group; a browser
/// build returns the wasm backend. A failure refuses the wave.
pub type VerifierFactory<C> = Box<dyn Fn(WavePolicy, u64, u64) -> Result<WaveVerifier<C>>>;

pub struct ProductionPorts<C: ProofCheck> {
    trust: Box<dyn WaveTrust>,
    terms: Box<dyn WaveTerms>,
    record: Box<dyn OwnRecordCheck>,
    lineage: Box<dyn PeerLineageRead>,
    verifier: VerifierFactory<C>,
    clock: Box<dyn Fn() -> Option<u64>>,
}

impl<C: ProofCheck> ProductionPorts<C> {
    pub fn new(
        trust: Box<dyn WaveTrust>,
        terms: Box<dyn WaveTerms>,
        record: Box<dyn OwnRecordCheck>,
        lineage: Box<dyn PeerLineageRead>,
        verifier: VerifierFactory<C>,
        clock: Box<dyn Fn() -> Option<u64>>,
    ) -> Self {
        Self {
            trust,
            terms,
            record,
            lineage,
            verifier,
            clock,
        }
    }

    /// The verifier for the CURRENT trusted policy; a caller-supplied `now` that disagrees
    /// with the device clock is refused, so a peer message cannot move the window.
    fn verifier(&self, now: u64) -> Result<WaveVerifier<C>> {
        let local = (self.clock)().ok_or(ErrorCode::Unavailable)?;
        if local.abs_diff(now) > 300 {
            return Err(ErrorCode::Unavailable);
        }
        let trust = self.trust.current(now)?;
        trust.wave.validate().map_err(|_| ErrorCode::Unavailable)?;
        (self.verifier)(trust.wave, now, trust.authority_until)
    }
}

impl<C: ProofCheck + 'static> WavePorts for ProductionPorts<C> {
    fn policy(&self, now: u64) -> Result<Policy> {
        Ok(self.trust.current(now)?.policy)
    }
    fn terms(&self, nonce: &[u8; 32], now: u64) -> Result<Terms> {
        self.terms.terms(nonce, now)
    }
    fn verify_reservation<'a>(
        &'a self,
        statement: &'a WaveStatement,
        proof: &'a [u8],
        expected: &'a WaveContext,
        now: u64,
    ) -> OwnedFuture<'a, VerifiedWaveReservation> {
        Box::pin(async move {
            let verifier = self.verifier(now)?;
            verify_reservation_with(&verifier, statement, proof, expected, now).await
        })
    }
    fn verify_outcome<'a>(
        &'a self,
        statement: &'a WaveOutcomeStatement,
        proof: &'a [u8],
        expected: &'a WaveContext,
        outcome: WaveOutcome,
        receipt_digest: &'a [u8; 32],
        now: u64,
    ) -> OwnedFuture<'a, VerifiedWaveOutcome> {
        Box::pin(async move {
            let verifier = self.verifier(now)?;
            verify_outcome_with(
                &verifier,
                statement,
                proof,
                expected,
                outcome,
                receipt_digest,
                now,
            )
            .await
        })
    }
    fn own_record<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, ()> {
        self.record.check(binding)
    }
    fn peer_lineage<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, Lineage> {
        self.lineage.read(binding)
    }
}

/// The wallet side of one job: builds the update, sends it for acceptance, builds the
/// evidence and proves it. It holds the account witness and the prover; nothing it
/// returns is secret. `Err` is a failed or uncertain build: the job stays recorded.
#[allow(async_fn_in_trait)]
pub trait WaveWallet {
    async fn prove_job(&mut self, job: &ProveJob) -> Result<Proved>;
}

/// Adapter so any [`WaveWallet`] is the worker's `Prover`.
pub struct WalletProver<W>(pub W);
impl<W: WaveWallet> worker::Prover for WalletProver<W> {
    async fn prove(&mut self, job: &ProveJob) -> Option<Proved> {
        self.0.prove_job(job).await.ok()
    }
}

/// Run the worker until the queue is empty and report how many jobs were handed back.
/// `recover` is called once first so a job interrupted by a restart is offered again. A
/// refused result is the Door's decision (it already reverts the claim); the loop goes on
/// with the next job, but stops on a Door error that is not a per-job refusal.
pub async fn drain<P: worker::Prover>(
    door: &mut Door,
    origin: &str,
    token: &str,
    now: impl Fn() -> u64,
    prover: &mut P,
    recover: bool,
) -> Result<usize> {
    if recover {
        worker::recover(door, origin, token, now()).await?;
    }
    let mut handed = 0;
    // Bounded by the Door's own job journal; each job is offered until it is settled.
    while let Some(job) = worker::next(door, origin, token, now()).await? {
        let proved = prover.prove(&job).await;
        let failed = proved.is_none();
        match worker::finish(door, origin, token, now(), &job, proved).await {
            Ok(_) => handed += 1,
            Err(ErrorCode::Refused | ErrorCode::InvalidRequest | ErrorCode::Unauthorized) => {}
            Err(error) => return Err(error),
        }
        if failed {
            // A failed build returns the job to the queue; do not spin on it.
            break;
        }
    }
    Ok(handed)
}
