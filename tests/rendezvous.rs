mod common;
use cmsg::{RendezvousChallenge, RendezvousEndpoint};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha3::{Digest, Sha3_256};
fn endpoint() -> String {
    let key = [42; 32];
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(key);
    hash.update([3]);
    let digest = hash.finalize();
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&digest[..2]);
    bytes.push(3);
    format!(
        "{}.onion",
        data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
    )
}
fn challenge(member: &cmsg::Member) -> RendezvousChallenge {
    RendezvousChallenge {
        community_id: common::trust().community_id,
        member_id: member.member_id().unwrap(),
        chat_public_key: BASE64URL_NOPAD.encode(&member.chat_public_key()),
        endpoint: RendezvousEndpoint {
            host: endpoint(),
            port: 80,
        },
        challenge_id: BASE64URL_NOPAD.encode(&[9; 32]),
        issued_at: 10,
        expires_at: 200,
    }
}
#[test]
fn certified_chat_key_signs_only_the_exact_rendezvous_statement() {
    let member = common::member();
    let challenge = challenge(&member);
    let signature = member.sign_rendezvous(&challenge, 100).unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!([
        "cfrm.rendezvous.v1",
        "register",
        challenge.community_id,
        challenge.member_id,
        challenge.chat_public_key,
        challenge.endpoint.host,
        challenge.endpoint.port,
        challenge.challenge_id,
        challenge.issued_at,
        challenge.expires_at
    ]))
    .unwrap();
    let key = VerifyingKey::from_bytes(&member.chat_public_key().try_into().unwrap()).unwrap();
    let signature =
        Signature::from_slice(&BASE64URL_NOPAD.decode(signature.as_bytes()).unwrap()).unwrap();
    key.verify_strict(&bytes, &signature).unwrap();
    assert!(key
        .verify_strict(b"an unrelated signing challenge", &signature)
        .is_err());
}
#[test]
fn challenge_cannot_change_identity_community_key_expiry_or_route() {
    let member = common::member();
    let original = challenge(&member);
    assert!(member.sign_rendezvous(&original, 200).is_err());
    assert!(member.sign_rendezvous(&original, 0).is_err());
    for endpoint in [
        "http://127.0.0.1",
        "https://example.com",
        "http://a.onion",
        "http://example.onion/?redirect=evil",
    ] {
        let mut bad = original.clone();
        bad.endpoint.host = endpoint.into();
        assert!(member.sign_rendezvous(&bad, 100).is_err());
    }
    let mut bad = original.clone();
    bad.member_id = BASE64URL_NOPAD.encode(&[99; 32]);
    assert!(member.sign_rendezvous(&bad, 100).is_err());
    bad = original.clone();
    bad.chat_public_key = BASE64URL_NOPAD.encode(&[99; 32]);
    assert!(member.sign_rendezvous(&bad, 100).is_err());
    bad = original.clone();
    bad.community_id = "other-community".into();
    assert!(member.sign_rendezvous(&bad, 100).is_err());
    bad = original;
    bad.expires_at = 9_000_000_001;
    assert!(member.sign_rendezvous(&bad, 100).is_err());
}
