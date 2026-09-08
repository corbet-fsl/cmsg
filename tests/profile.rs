mod common;
use cmsg::{Member, ProfileChallenge};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

fn challenge(member: &Member) -> ProfileChallenge {
    let key = [42; 32];
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(key);
    hash.update([3]);
    let digest = hash.finalize();
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&digest[..2]);
    bytes.push(3);
    ProfileChallenge {
        version: 1,
        community_id: common::trust().community_id,
        owner_member_id: member.member_id().unwrap(),
        owner_chat_public_key: BASE64URL_NOPAD.encode(&member.chat_public_key()),
        onion_host: format!(
            "{}.onion",
            data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
        ),
        onion_port: 80,
        session_id: BASE64URL_NOPAD.encode(&[1; 32]),
        reader_nonce: BASE64URL_NOPAD.encode(&[2; 32]),
        owner_nonce: BASE64URL_NOPAD.encode(&[3; 32]),
        policy_digest: common::trust().policy_digest,
        issued_at: 10,
        expires_at: 310,
    }
}
fn signed_bytes(c: &ProfileChallenge) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.profile.v1",
        "challenge",
        c.community_id,
        c.owner_member_id,
        c.owner_chat_public_key,
        c.onion_host,
        c.onion_port,
        c.session_id,
        c.reader_nonce,
        c.owner_nonce,
        c.policy_digest,
        c.issued_at,
        c.expires_at
    ]))
    .unwrap()
}
fn verify(member: &Member, bytes: &[u8], signature: &str) {
    let key = VerifyingKey::from_bytes(&member.chat_public_key().try_into().unwrap()).unwrap();
    let signature =
        Signature::from_slice(&BASE64URL_NOPAD.decode(signature.as_bytes()).unwrap()).unwrap();
    key.verify_strict(bytes, &signature).unwrap();
    assert!(key
        .verify_strict(b"unrelated signing request", &signature)
        .is_err());
}
#[test]
fn owner_signs_exact_profile_challenge_and_response_without_new_identity() {
    let member = common::member();
    let c = challenge(&member);
    let bytes = signed_bytes(&c);
    let signature = member.sign_profile_challenge(&c, 100).unwrap();
    verify(&member, &bytes, &signature);
    let profile = BASE64URL_NOPAD.encode(&Sha256::digest(b"synthetic plain profile"));
    let signature = member.sign_profile_response(&c, &profile, 100).unwrap();
    let response_bytes = serde_json::to_vec(&serde_json::json!([
        "cfrm.profile.v1",
        "response",
        BASE64URL_NOPAD.encode(&Sha256::digest(&bytes)),
        profile
    ]))
    .unwrap();
    verify(&member, &response_bytes, &signature);
}
#[test]
fn owner_refuses_wrong_identity_policy_route_nonce_time_and_version() {
    let member = common::member();
    let original = challenge(&member);
    let profile = BASE64URL_NOPAD.encode(&[4; 32]);
    let reject = |c: &ProfileChallenge, now| {
        assert!(member.sign_profile_challenge(c, now).is_err());
        assert!(member.sign_profile_response(c, &profile, now).is_err());
    };
    reject(&original, 9);
    reject(&original, 310);
    for field in [
        "communityId",
        "ownerMemberId",
        "ownerChatPublicKey",
        "policyDigest",
        "sessionId",
        "readerNonce",
        "ownerNonce",
        "onionHost",
    ] {
        let mut json = serde_json::to_value(&original).unwrap();
        json[field] = "invalid".into();
        reject(&serde_json::from_value(json).unwrap(), 100);
    }
    let mut bad = original.clone();
    bad.expires_at = 311;
    reject(&bad, 100);
    bad = original.clone();
    bad.version = 2;
    reject(&bad, 100);
    bad = original.clone();
    bad.onion_port = 0;
    reject(&bad, 100);
    assert!(member
        .sign_profile_response(&original, "not-a-digest", 100)
        .is_err());
}
#[test]
fn profile_challenge_cannot_outlive_its_owners_admission() {
    let mut member = Member::new().unwrap();
    let mut grant = common::grant(&member.chat_public_key(), 251);
    grant.expires_at = 200;
    common::sign(&mut grant);
    let c = ProfileChallenge {
        owner_member_id: grant.member_id.clone(),
        owner_chat_public_key: grant.chat_public_key.clone(),
        ..challenge(&common::member())
    };
    member.bind_admission(grant, common::trust(), 100).unwrap();
    assert!(member.sign_profile_challenge(&c, 100).is_err());
    assert!(member
        .sign_profile_response(&c, &BASE64URL_NOPAD.encode(&[4; 32]), 100)
        .is_err());
}
