#![allow(dead_code)]
pub mod accounting;
use cmsg::{AdmissionGrant, AdmissionTrust};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub fn trust() -> AdmissionTrust {
    let signer = SigningKey::from_bytes(&[17u8; 32]);
    AdmissionTrust {
        community_id: "synthetic-community".into(),
        policy_digest: BASE64URL_NOPAD.encode(&[42u8; 32]),
        issuer_public_key: signer.verifying_key().to_bytes(),
    }
}
pub fn grant(chat_key: &[u8], member: u8) -> AdmissionGrant {
    let trust = trust();
    let mut grant = AdmissionGrant {
        version: 1,
        issuer_key_id: BASE64URL_NOPAD.encode(&Sha256::digest(trust.issuer_public_key)),
        community_id: trust.community_id,
        member_id: BASE64URL_NOPAD.encode(&[member; 32]),
        chat_public_key: BASE64URL_NOPAD.encode(chat_key),
        policy_digest: trust.policy_digest,
        issued_at: 1,
        expires_at: 9_000_000_000,
        signature: String::new(),
    };
    sign(&mut grant);
    grant
}
pub fn sign(grant: &mut AdmissionGrant) {
    let data = serde_json::to_vec(&serde_json::json!([
        "cvld.admission.v1",
        grant.issuer_key_id,
        grant.community_id,
        grant.member_id,
        grant.chat_public_key,
        grant.policy_digest,
        grant.issued_at,
        grant.expires_at
    ]))
    .unwrap();
    grant.signature =
        BASE64URL_NOPAD.encode(&SigningKey::from_bytes(&[17u8; 32]).sign(&data).to_bytes());
}
pub fn member() -> cmsg::Member {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    let mut member = cmsg::Member::new().unwrap();
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    member
        .bind_admission(grant(&member.chat_public_key(), id), trust(), 100)
        .unwrap();
    member
}

pub fn root_device(identity: &cmsg::MemberIdentity) -> cmsg::Member {
    let mut member = cmsg::Member::new().unwrap();
    let key = member.chat_public_key();
    let mut certificate = grant(&key, 1);
    certificate.member_id = identity.member_id().to_owned();
    sign(&mut certificate);
    member
        .bind_device_admission(
            certificate,
            trust(),
            identity.authorize_device(&key, 1, 9_000_000_000).unwrap(),
            100,
        )
        .unwrap();
    member
}
