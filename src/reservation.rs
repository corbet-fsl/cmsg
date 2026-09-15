//! Trusted-host verification boundary for private peer reservation presentations.
use crate::Error;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationPolicy {
    pub state_policy_digest: [u8; 32],
    pub opened_at: u64,
    pub abandon_after: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationExpectation {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub peer: [u8; 32],
    pub role: u8,
    pub nonce: [u8; 32],
    pub group: [u8; 32],
    pub contact_policy_digest: [u8; 32],
    pub history_digest: [u8; 32],
    pub phase: u8,
    pub opened_at: u64,
    pub expires_at: u64,
    pub challenge: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationContext {
    pub now: u64,
    pub device_public_key: [u8; 32],
    pub expected: ReservationExpectation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationContexts {
    pub outgoing: ReservationContext,
    pub incoming: ReservationContext,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedReservation {
    #[serde(flatten)]
    pub expected: ReservationExpectation,
    pub state_policy_digest: [u8; 32],
    pub state_version: u64,
    pub state_commitment: [u8; 32],
    pub presentation_binding: [u8; 32],
    pub owner_authority: [u8; 32],
    /// Trusted verifier metadata; not a peer proof public input.
    pub valid_until: u64,
}
/// Implemented by a trusted embedding, never by interpreting a peer's boolean.
/// Both methods must verify the actual proof under pinned circuit/VK and the
/// signed operator acceptance. The local method additionally checks the host's
/// latest accepted own state still contains this Active obligation. A remote
/// certificate proves an accepted state, not that it has never been superseded.
pub trait ReservationVerifier {
    fn verify_remote(
        &mut self,
        evidence: &[u8],
        context: &ReservationContext,
    ) -> Result<VerifiedReservation, Error>;
    fn verify_current_local(
        &mut self,
        evidence: &[u8],
        context: &ReservationContext,
    ) -> Result<VerifiedReservation, Error>;
}
