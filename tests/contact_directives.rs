mod common;
use cmsg::{
    Clock, ContactDirective, ContactDirectiveKind as Kind, Error, FirstContactPolicy, Member,
    MemberIdentity,
};
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

fn device(root: &MemberIdentity, time: &Arc<Time>, expiry: u64) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            root.authorize_device(&key, 1, expiry).unwrap(),
            100,
        )
        .unwrap();
    member
}

#[test]
fn every_reopening_scope_is_authenticated_and_the_peer_cannot_impersonate_the_blocker() {
    let clock = Arc::new(Time(AtomicU64::new(100)));
    let alice_root = MemberIdentity::new("synthetic-community").unwrap();
    let bob_root = MemberIdentity::new("synthetic-community").unwrap();
    let outsider_root = MemberIdentity::new("synthetic-community").unwrap();
    let alice = device(&alice_root, &clock, 1000);
    let bob = device(&bob_root, &clock, 1000);
    let outsider = device(&outsider_root, &clock, 1000);
    let policy = FirstContactPolicy {
        response_deadline: 500,
        max_intro_bytes: 512,
    };
    let original = alice
        .sign_contact_directive(
            bob_root.member_id(),
            2,
            &[9; 32],
            &[8; 32],
            Kind::FreshInitiative,
            &[7; 32],
            alice_root.member_id(),
            b"fresh-mls-group",
            Some(policy),
            None,
        )
        .unwrap();
    bob.verify_contact_directive(&original, alice_root.member_id())
        .unwrap();
    alice
        .verify_contact_directive(&original, alice_root.member_id())
        .unwrap();
    assert!(outsider
        .verify_contact_directive(&original, alice_root.member_id())
        .is_err());
    assert!(bob
        .verify_contact_directive(&original, bob_root.member_id())
        .is_err());
    let serialized = serde_json::to_value(&original).unwrap();
    let changes = [
        ("communityId", serde_json::json!("another-community")),
        ("ownerId", serde_json::json!(outsider_root.member_id())),
        ("peerId", serde_json::json!(outsider_root.member_id())),
        ("revision", serde_json::json!(3)),
        ("previousDigest", serde_json::json!([6; 32].to_vec())),
        ("peerDigest", serde_json::json!([5; 32].to_vec())),
        ("introductionId", serde_json::json!([4; 32].to_vec())),
        ("initiatorId", serde_json::json!(bob_root.member_id())),
        ("groupId", serde_json::json!(b"old-mls-group".to_vec())),
        (
            "policy",
            serde_json::json!({"response_deadline":501,"max_intro_bytes":512}),
        ),
        ("issuedAt", serde_json::json!(99)),
    ];
    for (field, value) in changes {
        let mut changed = serialized.clone();
        changed[field] = value;
        let changed: ContactDirective = serde_json::from_value(changed).unwrap();
        assert!(
            bob.verify_contact_directive(&changed, alice_root.member_id())
                .is_err(),
            "{field}"
        );
        assert_ne!(
            original.digest().unwrap(),
            changed.digest().unwrap(),
            "{field}"
        );
    }
    let mut forged = bob
        .sign_contact_directive(
            alice_root.member_id(),
            1,
            &[0; 32],
            &[0; 32],
            Kind::Block,
            &[0; 32],
            "",
            b"",
            None,
            None,
        )
        .unwrap();
    forged.owner_id = alice_root.member_id().to_owned();
    forged.peer_id = bob_root.member_id().to_owned();
    assert!(bob
        .verify_contact_directive(&forged, alice_root.member_id())
        .is_err());
    assert_eq!(format!("{original:?}"), "ContactDirective([redacted])");
}

#[test]
fn block_expiry_is_signed_and_does_not_extend_expired_device_authority() {
    let clock = Arc::new(Time(AtomicU64::new(100)));
    let alice_root = MemberIdentity::new("synthetic-community").unwrap();
    let bob_root = MemberIdentity::new("synthetic-community").unwrap();
    let alice = device(&alice_root, &clock, 300);
    let bob = device(&bob_root, &clock, 1000);
    let directive = alice
        .sign_contact_directive(
            bob_root.member_id(),
            1,
            &[0; 32],
            &[0; 32],
            Kind::Block,
            &[0; 32],
            "",
            b"",
            None,
            Some(200),
        )
        .unwrap();
    bob.verify_contact_directive(&directive, alice_root.member_id())
        .unwrap();
    let mut changed = directive.clone();
    changed.until = None;
    assert!(bob
        .verify_contact_directive(&changed, alice_root.member_id())
        .is_err());
    changed.until = Some(250);
    assert!(bob
        .verify_contact_directive(&changed, alice_root.member_id())
        .is_err());
    clock.0.store(250, Ordering::Relaxed);
    // An expired block still authenticates its owner's retained history. Inbox
    // decides whether a fresh request may begin; verification does not unblock.
    bob.verify_contact_directive(&directive, alice_root.member_id())
        .unwrap();
    clock.0.store(301, Ordering::Relaxed);
    assert!(bob
        .verify_contact_directive(&directive, alice_root.member_id())
        .is_err());
}

#[test]
fn signers_reject_ambiguous_timer_chain_and_conversation_shapes() {
    let clock = Arc::new(Time(AtomicU64::new(100)));
    let alice_root = MemberIdentity::new("synthetic-community").unwrap();
    let bob_root = MemberIdentity::new("synthetic-community").unwrap();
    let alice = device(&alice_root, &clock, 1000);
    for (revision, predecessor, until) in [
        (0, [0; 32], None),
        (1, [1; 32], None),
        (2, [0; 32], None),
        (1, [0; 32], Some(100)),
        (1, [0; 32], Some(u64::MAX)),
    ] {
        assert!(alice
            .sign_contact_directive(
                bob_root.member_id(),
                revision,
                &predecessor,
                &[0; 32],
                Kind::Block,
                &[0; 32],
                "",
                b"",
                None,
                until
            )
            .is_err());
    }
    let policy = FirstContactPolicy {
        response_deadline: 500,
        max_intro_bytes: 512,
    };
    for (intro, group, candidate_policy, until) in [
        ([0; 32], b"group".as_slice(), Some(policy), None),
        ([1; 32], b"".as_slice(), Some(policy), None),
        ([1; 32], b"group".as_slice(), None, None),
        ([1; 32], b"group".as_slice(), Some(policy), Some(200)),
        (
            [1; 32],
            b"group".as_slice(),
            Some(FirstContactPolicy {
                response_deadline: 100,
                ..policy
            }),
            None,
        ),
        (
            [1; 32],
            b"group".as_slice(),
            Some(FirstContactPolicy {
                max_intro_bytes: 0,
                ..policy
            }),
            None,
        ),
    ] {
        assert!(alice
            .sign_contact_directive(
                bob_root.member_id(),
                1,
                &[0; 32],
                &[0; 32],
                Kind::FreshInitiative,
                &intro,
                alice_root.member_id(),
                group,
                candidate_policy,
                until
            )
            .is_err());
    }
}
