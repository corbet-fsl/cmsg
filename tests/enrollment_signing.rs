mod common;

use cmsg::{AdmissionGrant, Clock, Error, Member, SemaphoreEnrollmentChallenge};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

// Canonical field fixtures only: this suite does not claim Semaphore-key possession.
const WALLET_COMMITMENT: &str = "123456789";
const FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const FIELD_MAX: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn admitted(id: u8) -> (Member, AdmissionGrant, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let mut member = Member::new_with_clock(clock.clone()).unwrap();
    let mut grant = common::grant(&member.chat_public_key(), id);
    grant.issued_at = 50;
    grant.expires_at = 400;
    common::sign(&mut grant);
    member
        .bind_admission(grant.clone(), common::trust(), 100)
        .unwrap();
    (member, grant, clock)
}

fn challenge(grant: &AdmissionGrant) -> SemaphoreEnrollmentChallenge {
    SemaphoreEnrollmentChallenge {
        community_id: grant.community_id.clone(),
        member_id: grant.member_id.clone(),
        chat_public_key: grant.chat_public_key.clone(),
        commitment: WALLET_COMMITMENT.into(),
        challenge_id: B64.encode(&[41; 32]),
        issued_at: 90,
        expires_at: 150,
    }
}

fn cfrm_bytes(c: &SemaphoreEnrollmentChallenge, domain: &str) -> Vec<u8> {
    // Independent statement construction mirrors cfrm enrollmentBytes, not a Rust helper.
    serde_json::to_vec(&serde_json::json!([
        domain,
        c.community_id,
        c.member_id,
        c.chat_public_key,
        c.commitment,
        c.challenge_id,
        c.issued_at,
        c.expires_at
    ]))
    .unwrap()
}

fn verifies(member: &Member, bytes: &[u8], signature: &str) -> bool {
    let key: [u8; 32] = member.chat_public_key().try_into().unwrap();
    let raw = B64.decode(signature.as_bytes()).unwrap();
    assert_eq!(B64.encode(&raw), signature);
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(bytes, &Signature::from_slice(&raw).unwrap())
        .is_ok()
}

#[test]
fn enrollment_signature_matches_cfrm_bytes_and_binds_the_exact_fixed_domain() {
    let (member, grant, _) = admitted(1);
    let c = challenge(&grant);
    let signature = member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .unwrap();
    assert_eq!(signature.len(), 86);
    assert!(verifies(
        &member,
        &cfrm_bytes(&c, "cfrm.semaphore.enroll.v1"),
        &signature
    ));
    assert!(!verifies(
        &member,
        &cfrm_bytes(&c, "cfrm.semaphore.enroll.v2"),
        &signature
    ));
    let mut changed = c.clone();
    changed.challenge_id = B64.encode(&[42; 32]);
    assert!(!verifies(
        &member,
        &cfrm_bytes(&changed, "cfrm.semaphore.enroll.v1"),
        &signature
    ));
}

#[test]
fn server_proposed_commitment_must_match_the_separate_client_wallet_input() {
    let (member, grant, _) = admitted(1);
    let mut c = challenge(&grant);
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_ok());
    c.commitment = "123456790".into();
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_err());
    c.commitment = WALLET_COMMITMENT.into();
    for unexpected in ["", "123456790", "0123456789", "123456789 "] {
        assert!(member.sign_semaphore_enrollment(&c, unexpected).is_err());
    }
}

#[test]
fn copied_member_key_community_and_noncanonical_nonce_challenges_are_refused() {
    let (member, grant, _) = admitted(1);
    let c = challenge(&grant);
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_ok());
    for field in 0..7 {
        let mut bad = c.clone();
        match field {
            0 => bad.member_id = B64.encode(&[2; 32]),
            1 => bad.chat_public_key = B64.encode(&[3; 32]),
            2 => bad.community_id.push('x'),
            3 => bad.challenge_id.push('='),
            4 => bad.challenge_id = B64.encode(&[4; 31]),
            5 => bad.challenge_id = "A".repeat(42) + "B",
            _ => bad.challenge_id.clear(),
        }
        assert!(member
            .sign_semaphore_enrollment(&bad, WALLET_COMMITMENT)
            .is_err());
    }
    let unadmitted = Member::new().unwrap();
    assert!(unadmitted
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_err());
}

#[test]
fn commitments_are_nonzero_canonical_decimal_field_elements() {
    let (member, grant, _) = admitted(1);
    let mut c = challenge(&grant);
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_ok());
    for valid in ["1", FIELD_MAX] {
        c.commitment = valid.into();
        assert!(member.sign_semaphore_enrollment(&c, valid).is_ok());
    }
    for invalid in [
        "",
        "0",
        "01",
        "+1",
        "-1",
        "1.0",
        "1e2",
        " 1",
        "1 ",
        "١",
        FIELD_MODULUS,
    ] {
        c.commitment = invalid.into();
        assert!(member.sign_semaphore_enrollment(&c, invalid).is_err());
    }
    let oversized = "9".repeat(79);
    c.commitment = oversized.clone();
    assert!(member.sign_semaphore_enrollment(&c, &oversized).is_err());
}

#[test]
fn trusted_clock_and_current_grant_bound_the_complete_challenge_window() {
    let (member, grant, clock) = admitted(1);
    let c = challenge(&grant);
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_ok());
    let mut maximum = c.clone();
    maximum.expires_at = maximum.issued_at + 300;
    assert!(member
        .sign_semaphore_enrollment(&maximum, WALLET_COMMITMENT)
        .is_ok());
    for (issued, expires) in [
        (0, 150),
        (49, 150),
        (101, 150),
        (90, 90),
        (90, 89),
        (90, 100),
        (90, 391),
        (100, 401),
        (90, 9_007_199_254_740_992),
    ] {
        let mut bad = c.clone();
        bad.issued_at = issued;
        bad.expires_at = expires;
        assert!(member
            .sign_semaphore_enrollment(&bad, WALLET_COMMITMENT)
            .is_err());
    }
    for now in [89, 150, 400] {
        clock.0.store(now, Ordering::SeqCst);
        assert!(member
            .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
            .is_err());
    }
}

#[test]
fn changed_certified_chat_key_can_authorize_the_same_client_wallet_commitment() {
    let (first, first_grant, _) = admitted(1);
    let (second, second_grant, _) = admitted(1);
    let first_challenge = challenge(&first_grant);
    let first_signature = first
        .sign_semaphore_enrollment(&first_challenge, WALLET_COMMITMENT)
        .unwrap();
    let second_challenge = challenge(&second_grant);
    let second_signature = second
        .sign_semaphore_enrollment(&second_challenge, WALLET_COMMITMENT)
        .unwrap();
    assert_eq!(first_grant.member_id, second_grant.member_id);
    assert_ne!(first_grant.chat_public_key, second_grant.chat_public_key);
    assert!(verifies(
        &first,
        &cfrm_bytes(&first_challenge, "cfrm.semaphore.enroll.v1"),
        &first_signature
    ));
    assert!(verifies(
        &second,
        &cfrm_bytes(&second_challenge, "cfrm.semaphore.enroll.v1"),
        &second_signature
    ));
    assert!(second
        .sign_semaphore_enrollment(&first_challenge, WALLET_COMMITMENT)
        .is_err());
}

#[test]
fn portable_challenge_has_exact_camel_case_fields_and_no_numeric_commitment() {
    let (member, grant, _) = admitted(1);
    let c = challenge(&grant);
    assert!(member
        .sign_semaphore_enrollment(&c, WALLET_COMMITMENT)
        .is_ok());
    let json = serde_json::json!({
        "communityId": c.community_id,
        "memberId": c.member_id,
        "chatPublicKey": c.chat_public_key,
        "commitment": c.commitment,
        "challengeId": c.challenge_id,
        "issuedAt": c.issued_at,
        "expiresAt": c.expires_at
    });
    assert_eq!(serde_json::to_value(&c).unwrap(), json);
    assert!(serde_json::from_value::<SemaphoreEnrollmentChallenge>(json.clone()).is_ok());
    let mut extra = json.clone();
    extra["policyDigest"] = serde_json::json!(grant.policy_digest);
    assert!(serde_json::from_value::<SemaphoreEnrollmentChallenge>(extra).is_err());
    let mut numeric = json.clone();
    numeric["commitment"] = serde_json::json!(123456789);
    assert!(serde_json::from_value::<SemaphoreEnrollmentChallenge>(numeric).is_err());
    let mut fractional = json;
    fractional["issuedAt"] = serde_json::json!(90.5);
    assert!(serde_json::from_value::<SemaphoreEnrollmentChallenge>(fractional).is_err());
}
