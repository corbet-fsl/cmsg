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

/// The job journal as the worker sees it. The Door implements it through the three short
/// calls ([`DoorJobs`]); tests implement it with a scripted queue.
#[allow(async_fn_in_trait)]
pub trait WaveJobs {
    async fn recover(&mut self) -> Result<()>;
    async fn next(&mut self) -> Result<Option<ProveJob>>;
    async fn finish(&mut self, job: &ProveJob, proved: Option<Proved>) -> Result<()>;
}

/// The Door's job journal, reached through the bounded dispatcher with a grant for
/// exactly `inbox.wave_job_next`, `inbox.wave_job_done` and `inbox.wave_jobs_recover`.
pub struct DoorJobs<'a, N: Fn() -> u64> {
    pub door: &'a mut Door,
    pub origin: &'a str,
    pub token: &'a str,
    pub now: N,
}
impl<N: Fn() -> u64> WaveJobs for DoorJobs<'_, N> {
    async fn recover(&mut self) -> Result<()> {
        worker::recover(self.door, self.origin, self.token, (self.now)()).await
    }
    async fn next(&mut self) -> Result<Option<ProveJob>> {
        worker::next(self.door, self.origin, self.token, (self.now)()).await
    }
    async fn finish(&mut self, job: &ProveJob, proved: Option<Proved>) -> Result<()> {
        worker::finish(self.door, self.origin, self.token, (self.now)(), job, proved)
            .await
            .map(|_| ())
    }
}

/// Run the worker until the queue is empty and report how many proved jobs were handed
/// back. `recover` is called once first so a job interrupted by a restart is offered
/// again. A refused result is the Door's decision (it already reverts the claim); the
/// loop goes on, but stops on a failed build (the job returns to the queue; no spinning)
/// and on any Door error that is not a per-job refusal.
pub async fn drain<J: WaveJobs, P: worker::Prover>(
    jobs: &mut J,
    prover: &mut P,
    recover: bool,
) -> Result<usize> {
    if recover {
        jobs.recover().await?;
    }
    let mut handed = 0;
    while let Some(job) = jobs.next().await? {
        let proved = prover.prove(&job).await;
        let failed = proved.is_none();
        match jobs.finish(&job, proved).await {
            Ok(()) if !failed => handed += 1,
            Ok(()) => {}
            Err(ErrorCode::Refused | ErrorCode::InvalidRequest | ErrorCode::Unauthorized) => {}
            Err(error) => return Err(error),
        }
        if failed {
            break;
        }
    }
    Ok(handed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::door::inbox_waves::types::{Blob, Work};
    use cwlt::wave::{ExtensionPolicy, PublicField};
    use std::{cell::RefCell, rc::Rc};

    const NOW: u64 = 1_000_000;

    /// A checker that accepts only the proof bytes `good`.
    struct Fixed {
        calls: Rc<RefCell<u32>>,
    }
    impl ProofCheck for Fixed {
        async fn check(&self, _: &[PublicField], proof: &[u8]) -> std::result::Result<(), czkp::Error> {
            *self.calls.borrow_mut() += 1;
            if proof == b"good" {
                Ok(())
            } else {
                Err(czkp::Error::InvalidInput)
            }
        }
    }

    fn wave_policy() -> WavePolicy {
        WavePolicy {
            community: [1; 32],
            extension: ExtensionPolicy {
                revision: 1,
                public_record_quorum: 1,
                change_token_cost: 1,
                deposit_delay_seconds: 1,
                minimum_deposit_batch: 2,
                standing_policy_digest: [2; 32],
            },
            proof_scope: czkp::ProofScope {
                circuit_digest: [3; 32],
                verifying_key_digest: [4; 32],
            },
            certificate_key: vec![5; 64],
            manifest_sha256: [6; 32],
            state_policy: [7; 32],
            valid_from: NOW - 1000,
            valid_until: NOW + 1000,
        }
    }
    fn context(role: u8) -> WaveContext {
        WaveContext {
            community: [1; 32],
            owner: [8; 32],
            peer: [9; 32],
            role,
            nonce: [10; 32],
            group: [11; 32],
            contact_policy: [12; 32],
            history: [13; 32],
            challenge: [14; 32],
            opened_at: NOW - 10,
            expires_at: NOW + 500,
            owner_authority: [0; 32],
            peer_authority: [0; 32],
        }
    }
    fn statement() -> WaveStatement {
        WaveStatement {
            context: context(0),
            state_policy: [7; 32],
            version: 1,
            state: [0; 32],
            accepted_at: NOW - 5,
            binding: [0; 32],
            certificate: vec![0; 64],
        }
    }

    struct Trusted(Option<Trust>);
    impl WaveTrust for Trusted {
        fn current(&self, _: u64) -> Result<Trust> {
            self.0.clone().ok_or(ErrorCode::Unavailable)
        }
    }
    struct NoTerms;
    impl WaveTerms for NoTerms {
        fn terms(&self, _: &[u8; 32], _: u64) -> Result<Terms> {
            Err(ErrorCode::Unavailable)
        }
    }
    struct NoRecord;
    impl OwnRecordCheck for NoRecord {
        fn check<'a>(&'a self, _: &'a Binding) -> OwnedFuture<'a, ()> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
    }
    struct NoLineage;
    impl PeerLineageRead for NoLineage {
        fn read<'a>(&'a self, _: &'a Binding) -> OwnedFuture<'a, Lineage> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
    }

    fn trust() -> Trust {
        Trust {
            policy: Policy {
                group: [1; 32],
                contact_policy: [2; 32],
                history: [3; 32],
                authority: [4; 32],
                lifetime: 3600,
            },
            wave: wave_policy(),
            authority_until: NOW + 500,
        }
    }
    fn ports(
        trust: Option<Trust>,
        clock: Option<u64>,
        calls: Rc<RefCell<u32>>,
        built: Rc<RefCell<Vec<(u64, u64)>>>,
    ) -> ProductionPorts<Fixed> {
        ProductionPorts::new(
            Box::new(Trusted(trust)),
            Box::new(NoTerms),
            Box::new(NoRecord),
            Box::new(NoLineage),
            Box::new(move |policy, now, until| {
                built.borrow_mut().push((now, until));
                WaveVerifier::new(
                    policy,
                    now,
                    until,
                    Fixed { calls: calls.clone() },
                    Fixed { calls: calls.clone() },
                )
                .map_err(|_| ErrorCode::Unavailable)
            }),
            Box::new(move || clock),
        )
    }

    #[tokio::test]
    async fn a_tampered_reservation_is_refused_and_never_accepted() {
        let calls = Rc::new(RefCell::new(0));
        let built = Rc::new(RefCell::new(Vec::new()));
        let p = ports(Some(trust()), Some(NOW), calls.clone(), built.clone());
        let expected = context(0);
        for proof in [&b"bad"[..], &b""[..], &b"goodx"[..]] {
            let verdict = p.verify_reservation(&statement(), proof, &expected, NOW).await;
            assert!(verdict.is_err(), "a tampered proof must not verify");
        }
        // A statement for another community is refused even with the "good" proof.
        let mut foreign = statement();
        foreign.context.community = [99; 32];
        assert!(p
            .verify_reservation(&foreign, b"good", &expected, NOW)
            .await
            .is_err());
        // The verifier was built from the trusted policy and window, once per call.
        assert_eq!(built.borrow().len(), 4);
        assert!(built.borrow().iter().all(|b| *b == (NOW, NOW + 500)));
    }

    #[tokio::test]
    async fn a_stale_or_missing_clock_or_trust_refuses_everything() {
        let calls = Rc::new(RefCell::new(0));
        let built = Rc::new(RefCell::new(Vec::new()));
        let expected = context(0);
        // Clock 301 s apart from the caller's `now`: refused before any verifier exists.
        for clock in [Some(NOW + 301), Some(NOW - 301), None] {
            let p = ports(Some(trust()), clock, calls.clone(), built.clone());
            assert_eq!(
                p.verify_reservation(&statement(), b"good", &expected, NOW).await.err(),
                Some(ErrorCode::Unavailable)
            );
        }
        // No verified material: the policy and the verifier are both unavailable.
        let p = ports(None, Some(NOW), calls.clone(), built.clone());
        assert_eq!(p.policy(NOW).err(), Some(ErrorCode::Unavailable));
        assert_eq!(
            p.verify_reservation(&statement(), b"good", &expected, NOW).await.err(),
            Some(ErrorCode::Unavailable)
        );
        // An expired authority lease: the verifier cannot be built.
        let mut expired = trust();
        expired.authority_until = NOW;
        let p = ports(Some(expired), Some(NOW), calls.clone(), built.clone());
        assert!(p
            .verify_reservation(&statement(), b"good", &expected, NOW)
            .await
            .is_err());
        assert_eq!(*calls.borrow(), 0, "no proof was ever checked");
        // The default recipient terms and G2 refuse as well.
        assert!(p.terms(&[0; 32], NOW).is_err());
    }

    /// A scripted job journal: a job stays until it is finished with a proof.
    struct Queue {
        jobs: Vec<ProveJob>,
        recovered: u32,
        done: Vec<[u8; 32]>,
    }
    impl WaveJobs for Queue {
        async fn recover(&mut self) -> Result<()> {
            self.recovered += 1;
            Ok(())
        }
        async fn next(&mut self) -> Result<Option<ProveJob>> {
            Ok(self.jobs.first().cloned())
        }
        async fn finish(&mut self, job: &ProveJob, proved: Option<Proved>) -> Result<()> {
            if proved.is_some() {
                self.jobs.retain(|j| j.id != job.id);
                self.done.push(job.id);
            }
            Ok(())
        }
    }
    struct Script(Vec<bool>);
    impl worker::Prover for Script {
        async fn prove(&mut self, _: &ProveJob) -> Option<Proved> {
            self.0.remove(0).then(|| Proved {
                blob: Blob { statement: vec![], proof: vec![] },
                receipt_digest: None,
                wallet: vec![],
            })
        }
    }
    fn job(byte: u8) -> ProveJob {
        ProveJob {
            id: [byte; 32],
            nonce: [byte; 32],
            work: Work::ReserveSender,
            sender: context(0),
            recipient: context(1),
            receipt_digest: None,
        }
    }
    #[tokio::test]
    async fn recovery_after_a_crash_resumes_each_job_exactly_once() {
        let mut queue = Queue { jobs: vec![job(1), job(2)], recovered: 0, done: vec![] };
        // First run: the build for job 1 fails (crash); nothing is handed back, no spin.
        let handed = drain(&mut queue, &mut Script(vec![false]), true).await.unwrap();
        assert_eq!((handed, queue.jobs.len(), queue.recovered), (0, 2, 1));
        // After the restart the same jobs are offered again, each proved exactly once.
        let handed = drain(&mut queue, &mut Script(vec![true, true]), true).await.unwrap();
        assert_eq!((handed, queue.jobs.len(), queue.recovered), (2, 0, 2));
        assert_eq!(queue.done, vec![[1; 32], [2; 32]]);
        // A further run finds nothing and hands back nothing.
        let handed = drain(&mut queue, &mut Script(vec![]), false).await.unwrap();
        assert_eq!(handed, 0);
    }
}
