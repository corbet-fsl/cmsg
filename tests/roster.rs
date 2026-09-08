mod common;
use cmsg::{Member, ParticipantHandle, Received};
use data_encoding::BASE64URL_NOPAD;

fn member(id: u8) -> Member {
    let mut m = Member::new().unwrap();
    m.bind_admission(
        common::grant(&m.chat_public_key(), id),
        common::trust(),
        100,
    )
    .unwrap();
    m
}
fn pair() -> (Member, Member) {
    let mut a = member(1);
    let mut b = member(2);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    (a, b)
}
fn handle(owner: &Member, target: &Member) -> ParticipantHandle {
    owner
        .participants()
        .unwrap()
        .iter()
        .find(|p| p.member_id == target.member_id().unwrap())
        .unwrap()
        .handle
        .clone()
}
#[test]
fn roster_exposes_all_authenticated_participants_and_redacts_debug_output() {
    let (a, b) = pair();
    let roster = a.participants().unwrap();
    assert_eq!(roster.len(), 2);
    for member in [&a, &b] {
        let id = member.member_id().unwrap();
        let entry = roster.iter().find(|p| p.member_id == id).unwrap();
        assert_eq!(entry.chat_public_key, member.chat_public_key());
        assert!(!format!("{entry:?}").contains(&id));
        assert!(!format!("{:?}", entry.handle).contains(&id));
    }
    assert!(Member::new().unwrap().participants().is_err());
}
#[test]
fn handles_fail_after_epoch_changes_and_leaf_reuse_without_targeting_a_replacement() {
    let (mut a, mut b) = pair();
    let stale_b = handle(&a, &b);
    let mut c = member(3);
    let invitation = a.add(&c.key_package().unwrap()).unwrap();
    b.receive(&invitation.commit).unwrap();
    c.join(&invitation.welcome).unwrap();
    assert!(a.remove_participant(&stale_b).is_err());
    let current_b = handle(&a, &b);
    let removal = a.remove_participant(&current_b).unwrap();
    c.receive(&removal).unwrap();
    let mut d = member(4);
    let invitation = a.add(&d.key_package().unwrap()).unwrap();
    c.receive(&invitation.commit).unwrap();
    d.join(&invitation.welcome).unwrap();
    assert!(a.remove_participant(&current_b).is_err());
    let wire = a.send(b"replacement remains in the group").unwrap();
    assert!(
        matches!(d.receive(&wire).unwrap(), Received::Text(t) if t.text == "replacement remains in the group")
    );
}
#[test]
fn handles_cannot_cross_conversations_even_at_the_same_epoch_and_leaf() {
    let (a, b) = pair();
    let foreign = handle(&a, &b);
    let (mut other, target) = pair();
    assert!(other.remove_participant(&foreign).is_err());
    let legitimate = handle(&other, &target);
    other.remove_participant(&legitimate).unwrap();
}
#[test]
fn duplicate_ids_are_rejected_before_local_addition_advances_the_epoch() {
    let (mut a, mut b) = pair();
    let duplicate_b = member(2);
    assert!(a.add(&duplicate_b.key_package().unwrap()).is_err());
    let c = member(3);
    let duplicate_c = member(3);
    assert!(a
        .add_many(&[c.key_package().unwrap(), duplicate_c.key_package().unwrap()])
        .is_err());
    assert!(matches!(
        b.receive(&a.send(b"no rejected epoch advance").unwrap())
            .unwrap(),
        Received::Text(_)
    ));
}

struct RawGroup {
    provider: openmls_rust_crypto::OpenMlsRustCrypto,
    signer: openmls_basic_credential::SignatureKeyPair,
    group: openmls::prelude::MlsGroup,
}
impl RawGroup {
    fn new() -> Self {
        use openmls::prelude::*;
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let signer =
            openmls_basic_credential::SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                serde_json::to_vec(&common::grant(&signer.to_public_vec(), 10)).unwrap(),
            )
            .into(),
            signature_key: signer.to_public_vec().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        let group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
        Self {
            provider,
            signer,
            group,
        }
    }
    fn add(&mut self, packages: &[Vec<u8>]) -> cmsg::Invitation {
        use openmls::prelude::{KeyPackageIn, ProtocolVersion};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::{Deserialize, Serialize};
        let packages: Vec<_> = packages
            .iter()
            .map(|bytes| {
                KeyPackageIn::tls_deserialize_exact(bytes)
                    .unwrap()
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .unwrap()
            })
            .collect();
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, &self.signer, &packages)
            .unwrap();
        self.group.merge_pending_commit(&self.provider).unwrap();
        cmsg::Invitation {
            commit: commit.tls_serialize_detached().unwrap(),
            welcome: welcome.tls_serialize_detached().unwrap(),
        }
    }
}
#[test]
fn duplicate_identity_in_a_welcome_is_rejected_without_consuming_another_invitation() {
    let mut recipient = member(20);
    let duplicate = member(20);
    let package = recipient.key_package().unwrap();
    let mut honest = member(21);
    honest.create_group().unwrap();
    let good = honest.add(&package).unwrap().welcome;
    let mut malicious = RawGroup::new();
    let bad = malicious
        .add(&[package, duplicate.key_package().unwrap()])
        .welcome;
    assert!(recipient.join(&bad).is_err());
    recipient.join(&good).unwrap();
}
#[test]
fn duplicate_identity_commit_is_rejected_and_legitimate_control_can_still_follow() {
    use openmls_traits::OpenMlsProvider;
    let mut recipient = member(20);
    let duplicate = member(20);
    let mut owner = RawGroup::new();
    recipient
        .join(&owner.add(&[recipient.key_package().unwrap()]).welcome)
        .unwrap();
    let saved = owner.provider.storage().values.read().unwrap().clone();
    let group_id = owner.group.group_id().clone();
    let invalid = owner.add(&[duplicate.key_package().unwrap()]).commit;
    assert!(recipient.receive(&invalid).is_err());
    *owner.provider.storage().values.write().unwrap() = saved;
    owner.group = openmls::prelude::MlsGroup::load(owner.provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    let legitimate = member(21);
    let valid = owner.add(&[legitimate.key_package().unwrap()]).commit;
    assert!(matches!(
        recipient.receive(&valid).unwrap(),
        Received::MembershipChanged
    ));
}
#[test]
fn expired_members_remain_identifiable_but_future_issued_rosters_are_rejected() {
    use cmsg::{Clock, Error};
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
    let time = Arc::new(Time(AtomicU64::new(100)));
    let mut a = Member::new_with_clock(time.clone()).unwrap();
    let mut cert = common::grant(&a.chat_public_key(), 30);
    cert.expires_at = 200;
    common::sign(&mut cert);
    a.bind_admission(cert, common::trust(), 100).unwrap();
    a.create_group().unwrap();
    let key = [44; 32];
    let saved = a.snapshot(&key, b"roster").unwrap();
    time.0.store(300, Ordering::Relaxed);
    let restored = Member::restore_with_clock(&saved, &key, b"roster", time.clone()).unwrap();
    assert!(restored.member_id().is_err());
    let roster = restored.participants().unwrap();
    assert_eq!(roster[0].member_id, BASE64URL_NOPAD.encode(&[30; 32]));
    time.0.store(200, Ordering::Relaxed);
    let mut future = Member::new_with_clock(time.clone()).unwrap();
    let mut certificate = common::grant(&future.chat_public_key(), 31);
    certificate.issued_at = 150;
    certificate.expires_at = 400;
    common::sign(&mut certificate);
    future
        .bind_admission(certificate, common::trust(), 200)
        .unwrap();
    future.create_group().unwrap();
    time.0.store(100, Ordering::Relaxed);
    assert!(future.participants().is_err());
}
