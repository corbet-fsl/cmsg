//! The wave trust from the community's verified feed: the wave policy is built on the
//! device from the signed Balance (decided 2026-10-14), never from a peer's
//! presentation or from configuration.
//!
//! [`derive`] reads the authenticated public verifier material of the current charter
//! and projects the portable wave verifier descriptor (the accounting owner publishes
//! it and its own validation recomputes it from the material, so it cannot differ) plus
//! the public terms a new wave needs. [`FeedTrust`] keeps the newest derivation for the
//! ports: the ports run while the Door is locked and cannot read the charter
//! themselves, so the wave worker refreshes it, and it lapses on its own at the end of
//! its authenticated lease.
//!
//! The three opaque wave fields are fixed, domain-separated digests: a 1:1 wave
//! belongs to no group, is made under the community's current economic policy, and is
//! a first contact. Both devices bind the sender's values into every contact digest and
//! proof, so the recipient never has to recompute them.
use super::super::{ErrorCode, Result};
use super::production::{Trust, WaveTrust};
use super::Policy;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc};

const GROUP: &[u8] = b"cmsg.wave.direct-group.v1\0";
const CONTACT_POLICY: &[u8] = b"cmsg.wave.contact-policy.v1\0";
const HISTORY: &[u8] = b"cmsg.wave.first-contact.v1\0";

/// SHA-256 over a tag and length-prefixed parts.
fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(tag);
    for part in parts {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

/// The public wave terms of `community` under the economic policy `policy_digest`.
/// `authority` is this member's wallet authority field (its enrollment leaf).
pub fn terms(
    community: &str,
    policy_digest: &[u8; 32],
    authority: [u8; 32],
    lifetime: u64,
    window: u64,
) -> Policy {
    Policy {
        group: tagged(GROUP, &[community.as_bytes()]),
        contact_policy: tagged(CONTACT_POLICY, &[community.as_bytes(), policy_digest]),
        history: tagged(HISTORY, &[community.as_bytes()]),
        authority,
        lifetime,
        window,
    }
}

/// Derive the current wave trust from the verified charter at `now`. Refuses when the
/// Balance is missing, stale, of another revision or epoch, or carries no wave verifier
/// descriptor.
pub fn derive(charter: &cchr::VerifiedCharter, authority: [u8; 32], now: u64) -> Result<Trust> {
    let balance = charter.balance().ok_or(ErrorCode::Unavailable)?;
    if now >= balance.valid_until() || now >= charter.valid_until() {
        return Err(ErrorCode::Unavailable);
    }
    let material: cblc::publication::PublicVerifierMaterial =
        serde_json::from_slice(balance.payload()).map_err(|_| ErrorCode::Unauthorized)?;
    material
        .validate_at(charter.community(), now)
        .map_err(|_| ErrorCode::Unauthorized)?;
    if material.revision != balance.revision() || material.policy_epoch != charter.policy_epoch() {
        return Err(ErrorCode::Unauthorized);
    }
    let descriptor = material
        .wave_verifier
        .as_ref()
        .ok_or(ErrorCode::Unavailable)?;
    let wave: cwlt::wave::WavePolicy = serde_json::to_value(descriptor)
        .and_then(serde_json::from_value)
        .map_err(|_| ErrorCode::Unauthorized)?;
    wave.validate().map_err(|_| ErrorCode::Unauthorized)?;
    if now < wave.valid_from || now >= wave.valid_until {
        return Err(ErrorCode::Unavailable);
    }
    let authority_until = balance
        .valid_until()
        .min(charter.valid_until())
        .min(wave.valid_until);
    let account = &material.policy.account;
    Ok(Trust {
        policy: terms(
            charter.community(),
            &material.policy_digest,
            authority,
            account.abandon_after,
            account.rate_window,
        ),
        wave,
        authority_until,
    })
}

/// The newest derived trust. Clones share one value.
#[derive(Clone, Default)]
pub struct FeedTrust(Rc<RefCell<Option<Trust>>>);

impl FeedTrust {
    /// Replace the trust with a fresh derivation (the worker, after reading the feed).
    pub fn set(&self, trust: Trust) {
        *self.0.borrow_mut() = Some(trust);
    }
}

impl WaveTrust for FeedTrust {
    fn current(&self, now: u64) -> Result<Trust> {
        let trust = self.0.borrow().clone().ok_or(ErrorCode::Unavailable)?;
        if now >= trust.authority_until || now < trust.wave.valid_from {
            return Err(ErrorCode::Unavailable);
        }
        Ok(trust)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wave_terms_are_fixed_per_community_and_policy_and_domain_separated() {
        let a = terms("omega", &[1; 32], [9; 32], 3600, 300);
        assert_eq!(a, terms("omega", &[1; 32], [9; 32], 3600, 300));
        assert_ne!(a.group, terms("alpha", &[1; 32], [9; 32], 3600, 300).group);
        assert_ne!(
            a.contact_policy,
            terms("omega", &[2; 32], [9; 32], 3600, 300).contact_policy
        );
        // The policy digest changes only the contact policy.
        assert_eq!(a.group, terms("omega", &[2; 32], [9; 32], 3600, 300).group);
        assert_eq!(
            a.history,
            terms("omega", &[2; 32], [9; 32], 3600, 300).history
        );
        // The three fields never coincide.
        assert!(
            a.group != a.contact_policy && a.group != a.history && a.contact_policy != a.history
        );
        assert_eq!((a.authority, a.lifetime, a.window), ([9; 32], 3600, 300));
    }

    #[test]
    fn an_empty_or_lapsed_trust_is_unavailable() {
        let trust = FeedTrust::default();
        assert_eq!(trust.current(10).err(), Some(ErrorCode::Unavailable));
    }
}
