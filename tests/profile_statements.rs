mod common;

use cmsg::{Clock, Error, Member, MemberIdentity};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::Relaxed))
    }
}

fn device() -> (Member, Arc<Time>) {
    let clock = Arc::new(Time(AtomicU64::new(100)));
    let root = MemberIdentity::new(&common::trust().community_id).unwrap();
    let mut member = Member::new_with_clock(clock.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    grant.issued_at = 50;
    grant.expires_at = 400;
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            root.authorize_device(&key, 80, 300).unwrap(),
            100,
        )
        .unwrap();
    (member, clock)
}

fn encoded(size: usize) -> String {
    B64.encode(&vec![9; size])
}

fn wrapping_key() -> String {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    B64.encode(key.verifying_key().to_encoded_point(false).as_bytes())
}

fn fixtures(member: &Member) -> Vec<Value> {
    let community = common::trust().community_id;
    let policy = common::trust().policy_digest;
    let owner = member.member_id().unwrap();
    let device = B64.encode(&member.chat_public_key());
    let delegation = json!([
        "cfrm.profile-holder.v1",
        community,
        owner,
        device,
        encoded(32),
        encoded(32),
        wrapping_key(),
        encoded(32),
        100,
        150
    ]);
    let bytes = serde_json::to_vec(&delegation).unwrap();
    let signature = member.sign_profile_statement(&bytes).unwrap();
    vec![
        json!([
            "cfrm.cached-profile.v1",
            community,
            owner,
            device,
            encoded(32),
            1,
            100,
            150,
            encoded(12),
            encoded(32),
            [["ageBand", 6], ["region", 2]]
        ]),
        json!(["cfrm.discovery-request.v1", community, policy, owner, device, encoded(32), encoded(32), 100, 150, {"kind": "query", "filters": [], "limit": 5}]),
        json!([
            "cfrm.key-access.issue.v1",
            community,
            owner,
            device,
            encoded(32),
            encoded(32),
            encoded(32),
            100,
            150
        ]),
        json!([
            "cfrm.profile-holder-key.v1",
            community,
            owner,
            device,
            wrapping_key(),
            100,
            150
        ]),
        delegation,
        json!([
            "cfrm.profile-holder-seed.v1",
            B64.encode(&bytes),
            signature,
            wrapping_key(),
            encoded(12),
            encoded(48)
        ]),
        json!([
            "cfrm.profile-key-challenge.v1",
            community,
            policy,
            encoded(32),
            owner,
            device,
            encoded(32),
            encoded(32),
            wrapping_key(),
            encoded(32),
            100,
            150
        ]),
        json!([
            "cfrm.profile-key-grant.v1",
            encoded(32),
            150,
            wrapping_key(),
            encoded(12),
            encoded(48)
        ]),
    ]
}

fn sign(member: &Member, value: &Value) -> Result<String, Error> {
    member.sign_profile_statement(&serde_json::to_vec(value).unwrap())
}

#[test]
fn supported_profile_domains_sign_with_the_certified_device_key() {
    let (member, _) = device();
    let key: [u8; 32] = member.chat_public_key().try_into().unwrap();
    let key = VerifyingKey::from_bytes(&key).unwrap();
    for value in fixtures(&member) {
        let bytes = serde_json::to_vec(&value).unwrap();
        let signature = B64
            .decode(sign(&member, &value).unwrap().as_bytes())
            .unwrap();
        let signature = Signature::from_slice(&signature).unwrap();
        key.verify_strict(&bytes, &signature).unwrap();
        assert!(key
            .verify_strict(b"MLS 1.0 FramedContentTBS", &signature)
            .is_err());
        let mut bad = value.clone();
        bad[0] = "cfrm.unrecognized.v1".into();
        assert!(sign(&member, &bad).is_err());
        bad = value;
        bad.as_array_mut().unwrap().push(Value::Null);
        assert!(sign(&member, &bad).is_err());
    }
}

#[test]
fn statements_cannot_substitute_owner_device_community_or_policy() {
    let (member, _) = device();
    let all = fixtures(&member);
    for (fixture, indexes) in [
        (0, vec![1, 2, 3]),
        (1, vec![1, 2, 3, 4]),
        (2, vec![1, 2, 3]),
        (3, vec![1, 2, 3]),
        (4, vec![1, 2, 3]),
        (6, vec![1, 2, 4, 5]),
    ] {
        for index in indexes {
            let mut bad = all[fixture].clone();
            bad[index] = encoded(32).into();
            assert!(sign(&member, &bad).is_err());
        }
    }
    let mut bad = all[5].clone();
    bad[2] = B64.encode(&[0; 64]).into();
    assert!(
        sign(&member, &bad).is_err(),
        "seed requires the owner's actual delegation signature"
    );
    bad = all[5].clone();
    bad[1] = B64.encode(&serde_json::to_vec(&all[7]).unwrap()).into();
    assert!(
        sign(&member, &bad).is_err(),
        "seed cannot nest an unrelated signing domain"
    );
}

#[test]
fn current_root_authority_bounds_every_signature_including_digest_only_grants() {
    let (member, clock) = device();
    let all = fixtures(&member);
    for value in &all {
        assert!(sign(&member, value).is_ok());
    }
    for (fixture, issued, expires) in [
        (0, Some(6), 7),
        (1, Some(7), 8),
        (2, Some(7), 8),
        (3, Some(5), 6),
        (4, Some(8), 9),
        (6, Some(10), 11),
        (7, None, 2),
    ] {
        let mut bad = all[fixture].clone();
        bad[expires] = 301.into();
        assert!(
            sign(&member, &bad).is_err(),
            "issuer validity cannot extend root authority"
        );
        if let Some(issued) = issued {
            bad = all[fixture].clone();
            bad[issued] = 79.into();
            assert!(
                sign(&member, &bad).is_err(),
                "root authorization lower bound"
            );
            bad[issued] = 101.into();
            assert!(sign(&member, &bad).is_err(), "future issuance");
        }
    }
    clock.0.store(150, Ordering::Relaxed);
    for value in &all {
        assert!(sign(&member, value).is_err());
    }
    clock.0.store(301, Ordering::Relaxed);
    let mut grant = all[7].clone();
    grant[2] = 350.into();
    assert!(
        sign(&member, &grant).is_err(),
        "currently expired root fails despite a future transcript expiry"
    );
    assert!(
        sign(&common::member(), &grant).is_err(),
        "issuer-only legacy membership has no root authority"
    );
}

#[test]
fn malformed_or_noncanonical_statements_are_never_a_signing_oracle() {
    let (member, _) = device();
    for bytes in [
        b"MLS 1.0 FramedContentTBS".as_slice(),
        b"[]",
        b"{}",
        b"null",
        b"[\"cfrm.profile-key-grant.v1\"]",
        &[255],
    ] {
        assert!(member.sign_profile_statement(bytes).is_err());
    }
    assert!(member
        .sign_profile_statement(&vec![b' '; cmsg::MAX_WIRE_BYTES + 1])
        .is_err());
    let all = fixtures(&member);
    let canonical = serde_json::to_vec(&all[0]).unwrap();
    let mut spaced = vec![b' '];
    spaced.extend_from_slice(&canonical);
    assert!(member.sign_profile_statement(&spaced).is_err());
    let duplicate = serde_json::to_string(&all[1]).unwrap().replace(
        "\"kind\":\"query\"",
        "\"kind\":\"fetch\",\"kind\":\"query\"",
    );
    assert!(member.sign_profile_statement(duplicate.as_bytes()).is_err());
    for invalid in [
        json!([["z", 1], ["a", 2]]),
        json!([["a", 1], ["a", 2]]),
        json!([["a", -1]]),
        json!([["a", 4294967296u64]]),
        json!([["arbitrary text", 1]]),
    ] {
        let mut bad = all[0].clone();
        bad[10] = invalid;
        assert!(sign(&member, &bad).is_err());
    }
    let mut bad = all[2].clone();
    bad[5] = B64.encode(&[0; 32]).into();
    assert!(sign(&member, &bad).is_err());
    bad = all[3].clone();
    bad[4] = encoded(65).into();
    assert!(sign(&member, &bad).is_err(), "invalid wrapping curve point");
}
