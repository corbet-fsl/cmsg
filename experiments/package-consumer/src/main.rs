//! Synthetic external-package consumer. No network or production credentials.
//! This checks the Member primitive; real cfrm gating has a separate experiment.
use cmsg::{verify_admission, AdmissionGrant, AdmissionTrust, Clock, Error, Member, Received};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;

struct SyntheticClock;
impl Clock for SyntheticClock {
    fn now(&self) -> Result<u64, Error> {
        Ok(100)
    }
}

fn certify(member: &mut Member, identity: u8) -> String {
    // Public synthetic test seed; never use this issuer outside the experiment.
    let signer = SigningKey::from_bytes(&[17; 32]);
    let trust = AdmissionTrust {
        community_id: "synthetic-package-consumer".into(),
        policy_digest: BASE64URL_NOPAD.encode(&[42; 32]),
        issuer_public_key: signer.verifying_key().to_bytes(),
    };
    let mut grant = AdmissionGrant {
        version: 1,
        issuer_key_id: BASE64URL_NOPAD.encode(&Sha256::digest(trust.issuer_public_key)),
        community_id: trust.community_id.clone(),
        member_id: BASE64URL_NOPAD.encode(&[identity; 32]),
        chat_public_key: BASE64URL_NOPAD.encode(&member.chat_public_key()),
        policy_digest: trust.policy_digest.clone(),
        issued_at: 1,
        expires_at: 1_000,
        signature: String::new(),
    };
    let bytes = serde_json::to_vec(&serde_json::json!([
        "cvld.admission.v1",
        grant.issuer_key_id,
        grant.community_id,
        grant.member_id,
        grant.chat_public_key,
        grant.policy_digest,
        grant.issued_at,
        grant.expires_at
    ]))
    .expect("synthetic admission encoding");
    grant.signature = BASE64URL_NOPAD.encode(&signer.sign(&bytes).to_bytes());
    let id = verify_admission(&grant, &trust, &member.chat_public_key(), 100)
        .expect("real synthetic admission signature");
    member
        .bind_admission(grant, trust, 100)
        .expect("certified identity binding");
    id
}

fn main() {
    let clock: Arc<dyn Clock> = Arc::new(SyntheticClock);
    let mut alice = Member::new_with_clock(clock.clone()).expect("first member");
    let mut bob = Member::new_with_clock(clock.clone()).expect("second member");
    let alice_id = certify(&mut alice, 1);
    let bob_id = certify(&mut bob, 2);
    alice.create_group().expect("group creation");
    let invitation = alice
        .add(&bob.key_package().expect("key package"))
        .expect("certified invitation");
    bob.join(&invitation.welcome).expect("primitive Welcome");

    let roster = bob.participants().expect("authenticated local roster");
    assert_eq!(roster.len(), 2);
    assert!(roster
        .iter()
        .any(|p| p.member_id == alice_id && p.chat_public_key == alice.chat_public_key()));
    assert!(roster
        .iter()
        .any(|p| p.member_id == bob_id && p.chat_public_key == bob.chat_public_key()));

    let text = "synthetic package conversation: Καλημέρα 🦀";
    let wire = alice.send(text.as_bytes()).expect("encrypted send");
    assert!(!wire.windows(text.len()).any(|w| w == text.as_bytes()));
    assert!(matches!(
        bob.receive(&wire).expect("authenticated receive"),
        Received::Text(t) if t.member_id == alice_id && t.text == text
    ));

    // Caller-owned synthetic wrapping material substitutes only at the PRF seam.
    let key = [23; 32];
    let context = b"synthetic-package-consumer.wallet";
    let snapshot = bob.snapshot(&key, context).expect("encrypted snapshot");
    assert!(!snapshot.windows(text.len()).any(|w| w == text.as_bytes()));
    drop(bob);
    let mut restored = Member::restore_with_clock(&snapshot, &key, context, clock)
        .expect("encrypted state restored");
    assert_eq!(restored.member_id().expect("restored identity"), bob_id);
    assert_eq!(restored.history()[0].text, text);
    assert!(restored.receive(&wire).is_err());
    let reply = restored
        .send(b"reply after restore")
        .expect("restored send");
    assert!(matches!(
        alice.receive(&reply).expect("reply receive"),
        Received::Text(t) if t.member_id == bob_id && t.text == "reply after restore"
    ));
    println!("{{\"certified_pair\":true,\"stable_roster\":true,\"encrypted_restore\":true,\"replay_rejected\":true,\"continued_exchange\":true}}");
}
