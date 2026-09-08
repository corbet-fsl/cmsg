mod common;

use cmsg::{
    AdmissionGrant, Clock, DirectionalReceiveAuthorization, DirectionalSendAuthorization, Error,
    Member, ReleaseAuthorizationTiming, ReleaseContext, ReleasePreflight, ReleaseReceipt,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn test_member(id: u8) -> (Member, AdmissionGrant, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let mut member = Member::new_with_clock(clock.clone()).unwrap();
    let grant = common::grant(&member.chat_public_key(), id);
    member
        .bind_admission(grant.clone(), common::trust(), 100)
        .unwrap();
    (member, grant, clock)
}

fn context() -> ReleaseContext {
    ReleaseContext {
        community_id: common::trust().community_id,
        policy_digest: common::trust().policy_digest,
        cohort_id: "synthetic-release-cohort".into(),
        not_before: 90,
        expires_at: 1000,
    }
}

fn timing() -> ReleaseAuthorizationTiming {
    ReleaseAuthorizationTiming {
        nonce: B64.encode(&[51; 32]),
        expires_at: 150,
    }
}

fn receipt(grant: &AdmissionGrant, release_nonce: &str) -> ReleaseReceipt {
    // Shape/ownership fixture only. Real blind RSA validation belongs to cfrm;
    // the client authorizer must not claim these synthetic bytes are spendable.
    let mut message = [11; 160];
    message[64..96].copy_from_slice(&B64.decode(grant.member_id.as_bytes()).unwrap());
    message[128..160].copy_from_slice(&B64.decode(release_nonce.as_bytes()).unwrap());
    ReleaseReceipt {
        message: B64.encode(&message),
        signature: B64.encode(&[12; 384]),
    }
}

fn sender_bytes(a: &DirectionalSendAuthorization) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.directional.authorize.v1",
        a.community_id,
        a.policy_digest,
        a.cohort_id,
        a.sender_id,
        a.request_hash,
        a.nonce,
        a.issued_at,
        a.expires_at
    ]))
    .unwrap()
}

fn receiver_bytes(a: &DirectionalReceiveAuthorization) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.directional.redeem.v1",
        a.community_id,
        a.policy_digest,
        a.cohort_id,
        a.member_id,
        a.receipt_hash,
        a.nonce,
        a.issued_at,
        a.expires_at
    ]))
    .unwrap()
}

fn preflight_bytes(p: &ReleasePreflight) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cmsg.release.preflight.v1",
        p.context.community_id,
        p.context.policy_digest,
        p.context.cohort_id,
        p.context.not_before,
        p.context.expires_at,
        p.sender.member_id,
        p.sender.chat_public_key,
        p.recipient.member_id,
        p.recipient.chat_public_key,
        p.release_nonce,
        p.issued_at,
        p.expires_at
    ]))
    .unwrap()
}

fn verify(member: &Member, bytes: &[u8], signature: &str) {
    let key: [u8; 32] = member.chat_public_key().try_into().unwrap();
    let signature = Signature::from_slice(&B64.decode(signature.as_bytes()).unwrap()).unwrap();
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(bytes, &signature)
        .unwrap();
}

#[test]
fn sender_authorization_matches_cfrm_statement_and_hashes_actual_blinded_bytes() {
    let (member, grant, _) = test_member(1);
    let blinded = [33; 384];
    let auth = member
        .authorize_release_send(&context(), &blinded, &timing())
        .unwrap();
    assert_eq!(auth.version, 1);
    assert_eq!(auth.purpose, "authorized-send");
    assert_eq!(auth.sender_id, grant.member_id);
    assert_eq!(auth.request_hash, B64.encode(&Sha256::digest(blinded)));
    assert_eq!(auth.issued_at, 100);
    assert_eq!(auth.expires_at, 150);
    verify(&member, &sender_bytes(&auth), &auth.signature);
}

#[test]
fn sender_refuses_wrong_context_unbounded_inputs_and_invalid_authorization_time() {
    let (member, _, _) = test_member(1);
    assert!(member
        .authorize_release_send(&context(), &[33; 384], &timing())
        .is_ok());
    for field in 0..8 {
        let mut c = context();
        match field {
            0 => c.community_id.push('x'),
            1 => c.policy_digest = B64.encode(&[9; 32]),
            2 => c.cohort_id.clear(),
            3 => c.cohort_id = "x".repeat(129),
            4 => c.not_before = 101,
            5 => c.expires_at = 100,
            6 => c.not_before = 0,
            _ => c.expires_at = 9_007_199_254_740_992,
        }
        assert!(member
            .authorize_release_send(&c, &[33; 384], &timing())
            .is_err());
    }
    for len in [0, 383, 385] {
        assert!(member
            .authorize_release_send(&context(), &vec![33; len], &timing())
            .is_err());
    }
    for nonce in [
        String::new(),
        B64.encode(&[1; 31]),
        format!("{}=", timing().nonce),
    ] {
        let t = ReleaseAuthorizationTiming { nonce, ..timing() };
        assert!(member
            .authorize_release_send(&context(), &[33; 384], &t)
            .is_err());
    }
    for expires_at in [0, 99, 100, 401, 1001] {
        let t = ReleaseAuthorizationTiming {
            expires_at,
            ..timing()
        };
        assert!(member
            .authorize_release_send(&context(), &[33; 384], &t)
            .is_err());
    }
}

#[test]
fn receive_authorization_hashes_canonical_receipt_and_names_only_current_owner() {
    let (member, grant, _) = test_member(2);
    let nonce = B64.encode(&[41; 32]);
    let receipt = receipt(&grant, &nonce);
    let auth = member
        .authorize_release_receive(&context(), &receipt, &nonce, &timing())
        .unwrap();
    let bytes =
        serde_json::to_vec(&serde_json::json!([receipt.message, receipt.signature])).unwrap();
    assert_eq!(auth.version, 1);
    assert_eq!(auth.purpose, "acknowledged-receive");
    assert_eq!(auth.member_id, grant.member_id);
    assert_eq!(auth.receipt_hash, B64.encode(&Sha256::digest(bytes)));
    verify(&member, &receiver_bytes(&auth), &auth.signature);
}

#[test]
fn receive_signing_rejects_other_owners_old_formats_and_wrong_private_challenges() {
    let (member, grant, _) = test_member(2);
    let (_, other, _) = test_member(3);
    let nonce = B64.encode(&[41; 32]);
    let valid = receipt(&grant, &nonce);
    assert!(member
        .authorize_release_receive(&context(), &valid, &nonce, &timing())
        .is_ok());
    assert!(member
        .authorize_release_receive(&context(), &receipt(&other, &nonce), &nonce, &timing())
        .is_err());
    assert!(member
        .authorize_release_receive(&context(), &valid, &B64.encode(&[42; 32]), &timing())
        .is_err());
    for len in [0, 128, 159, 161] {
        let bad = ReleaseReceipt {
            message: B64.encode(&vec![11; len]),
            ..valid.clone()
        };
        assert!(member
            .authorize_release_receive(&context(), &bad, &nonce, &timing())
            .is_err());
    }
    for signature in [
        B64.encode(&[12; 383]),
        B64.encode(&[12; 385]),
        format!("{}=", valid.signature),
    ] {
        let bad = ReleaseReceipt {
            signature,
            ..valid.clone()
        };
        assert!(member
            .authorize_release_receive(&context(), &bad, &nonce, &timing())
            .is_err());
    }
    let mut wrong_policy = context();
    wrong_policy.policy_digest = B64.encode(&[8; 32]);
    assert!(member
        .authorize_release_receive(&wrong_policy, &valid, &nonce, &timing())
        .is_err());
}

#[test]
fn private_preflight_authenticates_both_actual_certified_chat_keys_and_challenge() {
    let (sender, s_grant, _) = test_member(1);
    let (recipient, r_grant, _) = test_member(2);
    let nonce = B64.encode(&[41; 32]);
    let p = sender
        .sign_release_preflight(&context(), &r_grant, &nonce, 150)
        .unwrap();
    assert_eq!(p.version, 1);
    assert_eq!(p.sender.member_id, s_grant.member_id);
    assert_eq!(p.sender.chat_public_key, s_grant.chat_public_key);
    assert_eq!(p.recipient.member_id, r_grant.member_id);
    assert_eq!(p.recipient.chat_public_key, r_grant.chat_public_key);
    assert_eq!(p.release_nonce, nonce);
    verify(&sender, &preflight_bytes(&p), &p.signature);
    recipient.verify_release_preflight(&p, &s_grant).unwrap();
}

#[test]
fn preflight_rejects_forged_cross_context_expired_or_self_recipient_credentials() {
    let (sender, s_grant, _) = test_member(1);
    let (_, r_grant, _) = test_member(2);
    let nonce = B64.encode(&[41; 32]);
    assert!(sender
        .sign_release_preflight(&context(), &r_grant, &nonce, 150)
        .is_ok());
    for field in 0..4 {
        let mut bad = r_grant.clone();
        match field {
            0 => bad.community_id.push('x'),
            1 => bad.policy_digest = B64.encode(&[7; 32]),
            2 => bad.expires_at = 99,
            _ => bad.signature.clear(),
        }
        if field != 3 {
            common::sign(&mut bad);
        }
        assert!(sender
            .sign_release_preflight(&context(), &bad, &nonce, 150)
            .is_err());
    }
    assert!(sender
        .sign_release_preflight(&context(), &s_grant, &nonce, 150)
        .is_err());
    assert!(sender
        .sign_release_preflight(&context(), &r_grant, &format!("{nonce}="), 150)
        .is_err());
    assert!(sender
        .sign_release_preflight(&context(), &r_grant, &nonce, 401)
        .is_err());
}

#[test]
fn addressed_preflight_cannot_be_substituted_to_another_current_member_or_key() {
    let (sender, s_grant, _) = test_member(1);
    let (recipient, r_grant, _) = test_member(2);
    let (other, _, _) = test_member(3);
    let p = sender
        .sign_release_preflight(&context(), &r_grant, &B64.encode(&[41; 32]), 150)
        .unwrap();
    recipient.verify_release_preflight(&p, &s_grant).unwrap();
    assert!(other.verify_release_preflight(&p, &s_grant).is_err());
    let mut different_key = r_grant.clone();
    different_key.chat_public_key = B64.encode(&other.chat_public_key());
    common::sign(&mut different_key);
    let p2 = sender
        .sign_release_preflight(&context(), &different_key, &B64.encode(&[41; 32]), 150)
        .unwrap();
    assert!(recipient.verify_release_preflight(&p2, &s_grant).is_err());
    let (_, wrong_sender_grant, _) = test_member(4);
    assert!(recipient
        .verify_release_preflight(&p, &wrong_sender_grant)
        .is_err());
    for field in 0..7 {
        let mut changed = p.clone();
        match field {
            0 => changed.release_nonce = B64.encode(&[42; 32]),
            1 => changed.context.cohort_id.push('x'),
            2 => changed.recipient.member_id = B64.encode(&[3; 32]),
            3 => changed.sender.chat_public_key = B64.encode(&other.chat_public_key()),
            4 => changed.issued_at = 101,
            5 => changed.version = 2,
            _ => changed.signature.push('='),
        }
        assert!(recipient
            .verify_release_preflight(&changed, &s_grant)
            .is_err());
    }
}

#[test]
fn trusted_clock_controls_signature_timestamps_expiry_and_current_admission() {
    let (sender, s_grant, s_clock) = test_member(1);
    let (recipient, r_grant, r_clock) = test_member(2);
    s_clock.0.store(120, Ordering::SeqCst);
    let auth = sender
        .authorize_release_send(&context(), &[33; 384], &timing())
        .unwrap();
    assert_eq!(auth.issued_at, 120);
    let p = sender
        .sign_release_preflight(&context(), &r_grant, &B64.encode(&[41; 32]), 150)
        .unwrap();
    r_clock.0.store(120, Ordering::SeqCst);
    recipient.verify_release_preflight(&p, &s_grant).unwrap();
    r_clock.0.store(150, Ordering::SeqCst);
    assert!(recipient.verify_release_preflight(&p, &s_grant).is_err());
    // Keep every other time boundary current to isolate the expired own grant.
    let expired = s_grant.expires_at;
    let late_context = ReleaseContext {
        not_before: expired - 10,
        expires_at: expired + 100,
        ..context()
    };
    let late_timing = ReleaseAuthorizationTiming {
        expires_at: expired + 50,
        ..timing()
    };
    let mut renewed_recipient = r_grant.clone();
    renewed_recipient.issued_at = expired - 10;
    renewed_recipient.expires_at = expired + 100;
    common::sign(&mut renewed_recipient);
    s_clock.0.store(s_grant.expires_at, Ordering::SeqCst);
    assert!(sender
        .authorize_release_send(&late_context, &[33; 384], &late_timing)
        .is_err());
    assert!(sender
        .sign_release_preflight(
            &late_context,
            &renewed_recipient,
            &B64.encode(&[41; 32]),
            expired + 50
        )
        .is_err());
    r_clock.0.store(r_grant.expires_at, Ordering::SeqCst);
    let nonce = B64.encode(&[41; 32]);
    assert!(recipient
        .authorize_release_receive(
            &late_context,
            &receipt(&r_grant, &nonce),
            &nonce,
            &late_timing
        )
        .is_err());
}

#[test]
fn operator_authorizations_do_not_carry_private_preflight_or_correspondent_fields() {
    let (sender, s_grant, _) = test_member(1);
    let (recipient, r_grant, _) = test_member(2);
    let nonce = B64.encode(&[41; 32]);
    let p = sender
        .sign_release_preflight(&context(), &r_grant, &nonce, 150)
        .unwrap();
    let s = sender
        .authorize_release_send(&context(), &[33; 384], &timing())
        .unwrap();
    let r_timing = ReleaseAuthorizationTiming {
        nonce: B64.encode(&[52; 32]),
        ..timing()
    };
    let r = recipient
        .authorize_release_receive(&context(), &receipt(&r_grant, &nonce), &nonce, &r_timing)
        .unwrap();
    let s_wire = serde_json::to_string(&s).unwrap();
    let r_wire = serde_json::to_string(&r).unwrap();
    for private in [
        &r_grant.member_id,
        &r_grant.chat_public_key,
        &nonce,
        &p.signature,
    ] {
        assert!(!s_wire.contains(private));
    }
    for private in [
        &s_grant.member_id,
        &s_grant.chat_public_key,
        &s.nonce,
        &s.request_hash,
        &p.signature,
    ] {
        assert!(!r_wire.contains(private));
    }
    let mut bad_sender = serde_json::to_value(&s).unwrap();
    bad_sender["recipientId"] = r_grant.member_id.into();
    assert!(serde_json::from_value::<DirectionalSendAuthorization>(bad_sender).is_err());
    let mut bad_recipient = serde_json::to_value(&r).unwrap();
    bad_recipient["senderId"] = s_grant.member_id.into();
    assert!(serde_json::from_value::<DirectionalReceiveAuthorization>(bad_recipient).is_err());
}

#[test]
fn signatures_are_not_interchangeable_between_private_preflight_and_debit_roles() {
    let (sender, s_grant, _) = test_member(1);
    let (recipient, r_grant, _) = test_member(2);
    let mut p = sender
        .sign_release_preflight(&context(), &r_grant, &B64.encode(&[41; 32]), 150)
        .unwrap();
    let auth = sender
        .authorize_release_send(&context(), &[33; 384], &timing())
        .unwrap();
    recipient.verify_release_preflight(&p, &s_grant).unwrap();
    let key: [u8; 32] = sender.chat_public_key().try_into().unwrap();
    let signature = Signature::from_slice(&B64.decode(p.signature.as_bytes()).unwrap()).unwrap();
    assert!(VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&sender_bytes(&auth), &signature)
        .is_err());
    p.signature = auth.signature;
    assert!(recipient.verify_release_preflight(&p, &s_grant).is_err());
}
