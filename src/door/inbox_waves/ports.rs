//! The owner capabilities the wave actions consume. The Door holds one bundle
//! per member origin, installed by the trusted embedding runtime (like the
//! account actor): no client can supply or replace it. Every method either
//! answers from the real owner or refuses; none has a permissive default.
use super::super::{facades::OwnedFuture, Result};
use super::types::Terms;
use ckmg::Binding;
use cwlt::wave::{
    VerifiedWaveOutcome, VerifiedWaveReservation, WaveContext, WaveOutcome, WaveOutcomeStatement,
    WaveStatement,
};

/// Public policy terms a new wave needs, read from the community's current
/// signed settings by the embedding runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub group: [u8; 32],
    pub contact_policy: [u8; 32],
    pub history: [u8; 32],
    /// This member's wallet authority field for the community.
    pub authority: [u8; 32],
    /// Seconds the offer stays open.
    pub lifetime: u64,
}

/// Methods take `&self`: an implementation keeps its own interior mutability,
/// so one bundle can serve the verifier, Contacts and Threads adapters at once.
pub trait WavePorts {
    /// Current policy terms; `Unavailable` if the signed trust is stale.
    fn policy(&self, now: u64) -> Result<Policy>;
    /// The recipient's own terms for a wave it was offered.
    fn terms(&self, nonce: &[u8; 32], now: u64) -> Result<Terms>;
    /// Counterpart check of a reservation (cwlt `WaveVerifier::verify`).
    fn verify_reservation<'a>(
        &'a self,
        statement: &'a WaveStatement,
        proof: &'a [u8],
        expected: &'a WaveContext,
        now: u64,
    ) -> OwnedFuture<'a, VerifiedWaveReservation>;
    /// Check of a settled outcome (cwlt `WaveVerifier::verify_outcome`).
    #[allow(clippy::too_many_arguments)]
    fn verify_outcome<'a>(
        &'a self,
        statement: &'a WaveOutcomeStatement,
        proof: &'a [u8],
        expected: &'a WaveContext,
        outcome: WaveOutcome,
        receipt_digest: &'a [u8; 32],
        now: u64,
    ) -> OwnedFuture<'a, VerifiedWaveOutcome>;
    /// G2: this member's record matches the newest epoch commitment.
    fn own_record<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, ()>;
    /// The CURRENT lineage of a peer (forced read, never cached).
    fn peer_lineage<'a>(&'a self, binding: &'a Binding) -> OwnedFuture<'a, ckmg::Lineage>;
}

/// The cwlt verifier is the production implementation of the proof-verifier
/// half of the port. A composition forwards `verify_*` to it.
pub async fn verify_reservation_with<C: cwlt::wave::ProofCheck>(
    verifier: &cwlt::wave::WaveVerifier<C>,
    statement: &WaveStatement,
    proof: &[u8],
    expected: &WaveContext,
    now: u64,
) -> Result<VerifiedWaveReservation> {
    verifier
        .verify(statement, proof, expected, now)
        .await
        .map_err(|_| super::super::ErrorCode::Refused)
}

/// See [`verify_reservation_with`].
pub async fn verify_outcome_with<C: cwlt::wave::ProofCheck>(
    verifier: &cwlt::wave::WaveVerifier<C>,
    statement: &WaveOutcomeStatement,
    proof: &[u8],
    expected: &WaveContext,
    outcome: WaveOutcome,
    receipt_digest: &[u8; 32],
    now: u64,
) -> Result<VerifiedWaveOutcome> {
    verifier
        .verify_outcome(statement, proof, expected, outcome, receipt_digest, now)
        .await
        .map_err(|_| super::super::ErrorCode::Refused)
}
