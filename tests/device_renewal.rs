mod common;
use cmsg::{Clock, Error, Member, MemberIdentity, Received};
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

fn device(root: &MemberIdentity, time: &Arc<Time>, device_expiry: u64) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            root.authorize_device(&key, 1, device_expiry).unwrap(),
            100,
        )
        .unwrap();
    member
}

#[test]
fn expired_device_authorization_renews_with_same_root_and_key_without_rotating_identity() {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let alice_root = MemberIdentity::new("synthetic-community").unwrap();
    let bob_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut alice = device(&alice_root, &time, 200);
    let mut bob = device(&bob_root, &time, 1000);
    alice.create_group().unwrap();
    bob.join(&alice.add(&bob.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    time.0.store(300, Ordering::Relaxed);
    assert!(alice.send(b"expired authorization").is_err());
    let key = alice.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = alice_root.member_id().to_owned();
    common::sign(&mut grant);
    let renewal = alice_root.authorize_device(&key, 300, 900).unwrap();
    assert!(alice
        .renew_device_admission(grant.clone(), renewal.clone(), |_, _| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(
        alice.member_id().is_err(),
        "failed durable write cannot install a root renewal"
    );
    let mut invalid = renewal.clone();
    invalid.expires_at = 950;
    assert!(alice
        .renew_device_admission(grant.clone(), invalid, |_, _| panic!("invalid signature"))
        .is_err());
    let wrong_root = bob_root.authorize_device(&key, 300, 900).unwrap();
    assert!(alice
        .renew_device_admission(grant.clone(), wrong_root, |_, _| panic!("wrong root"))
        .is_err());
    let wrong_key = alice_root
        .authorize_device(&bob.chat_public_key(), 300, 900)
        .unwrap();
    assert!(alice
        .renew_device_admission(grant.clone(), wrong_key, |_, _| panic!("wrong device"))
        .is_err());
    let control = alice
        .renew_device_admission(grant, renewal, |_, _| Ok(()))
        .unwrap();
    assert!(matches!(
        bob.receive(&control).unwrap(),
        Received::MembershipChanged
    ));
    assert_eq!(alice.member_id().unwrap(), alice_root.member_id());
    assert_eq!(alice.chat_public_key(), key);
    assert!(
        matches!(bob.receive(&alice.send(b"root renewed").unwrap()).unwrap(), Received::Text(message)
        if message.member_id == alice_root.member_id() && message.text == "root renewed")
    );
}

#[test]
fn delayed_expired_close_is_refreshed_after_joint_renewal_without_reopening_contact() {
    use cmsg::{ContactResolution, FirstContactPolicy, FirstContactRole as Role, Inbox};
    const KEY: [u8; 32] = [56; 32];
    const CONTEXT: &[u8] = b"synthetic-delayed-close";
    const NONCE: [u8; 32] = [45; 32];
    let time = Arc::new(Time(AtomicU64::new(100)));
    let a_root = MemberIdentity::new("synthetic-community").unwrap();
    let b_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&a_root, &time, 1000);
    let mut b = device(&b_root, &time, 200);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    let policy = FirstContactPolicy {
        response_deadline: 600,
        max_intro_bytes: 128,
    };
    ai.begin_first_contact(
        b_root.member_id(),
        &NONCE,
        Role::Initiator,
        policy,
        &a,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    bi.begin_first_contact(
        a_root.member_id(),
        &NONCE,
        Role::Recipient,
        policy,
        &b,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    let first = ai
        .send_contact(&mut a, b"introduction", &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    bi.receive_contact(&mut b, &first, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let delayed = bi
        .close_contact(&mut b, &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    let old_receipt = bi
        .outbound_resolution_receipt(a_root.member_id())
        .unwrap()
        .to_vec();
    assert!(bi
        .refresh_outbound_resolution(a_root.member_id(), &b, &KEY, CONTEXT, |_| panic!(
            "still-current receipt cannot reset close transmission"
        ))
        .is_err());
    time.0.store(700, Ordering::Relaxed);
    assert!(ai
        .receive_contact(&mut a, &delayed, &KEY, CONTEXT, |_| Ok(()))
        .is_err());
    assert!(ai.is_closed(b_root.member_id()));
    assert!(
        ai.awaiting_peer_resolution(b_root.member_id()),
        "local timeout is not a peer response"
    );
    let mut grant = common::grant(&b.chat_public_key(), 1);
    grant.member_id = b_root.member_id().to_owned();
    common::sign(&mut grant);
    let authorization = b_root
        .authorize_device(&b.chat_public_key(), 700, 900)
        .unwrap();
    let renewal = b
        .renew_device_admission(grant, authorization, |_, _| Ok(()))
        .unwrap();
    assert!(matches!(
        ai.receive_contact(&mut a, &renewal, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::MembershipChanged
    ));
    let old: ContactResolution = serde_json::from_slice(&old_receipt).unwrap();
    assert!(a
        .verify_contact_resolution(&old, b_root.member_id(), &NONCE)
        .is_err());
    assert!(bi
        .refresh_outbound_resolution(a_root.member_id(), &b, &KEY, CONTEXT, |_| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert_eq!(
        bi.outbound_resolution_receipt(a_root.member_id()).unwrap(),
        old_receipt
    );
    let refreshed = bi
        .refresh_outbound_resolution(a_root.member_id(), &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let new: ContactResolution = serde_json::from_slice(&refreshed).unwrap();
    assert_eq!(new.kind, old.kind);
    assert_eq!(new.introduction_id, old.introduction_id);
    assert_eq!(new.responder_id, old.responder_id);
    assert_eq!(new.peer_id, old.peer_id);
    a.verify_contact_resolution(&new, b_root.member_id(), &NONCE)
        .unwrap();
    assert!(bi.is_closed(a_root.member_id()));
    let retransmission = bi
        .close_contact(&mut b, &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(matches!(
        ai.receive_contact(&mut a, &retransmission, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactClosed
    ));
    assert!(!ai.awaiting_peer_resolution(b_root.member_id()));
    assert_eq!(
        ai.inbound_resolution_receipt(b_root.member_id()).unwrap(),
        refreshed
    );
    assert!(bi
        .close_contact(&mut b, &KEY, CONTEXT, |_, _| panic!(
            "one transmission per refreshed decision"
        ))
        .is_err());
}

#[test]
fn refreshed_inbound_evidence_persists_and_syncs_without_a_second_resolution() {
    use cmsg::{ContactResolution, ContactResolutionKind as Kind, Inbox};
    const KEY: [u8; 32] = [57; 32];
    const CONTEXT: &[u8] = b"synthetic-refreshed-evidence";
    const NONCE: [u8; 32] = [46; 32];
    let time = Arc::new(Time(AtomicU64::new(100)));
    let a_root = MemberIdentity::new("synthetic-community").unwrap();
    let b_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&a_root, &time, 1000);
    let sibling = device(&a_root, &time, 1000);
    let mut b = device(&b_root, &time, 200);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    ai.begin_introduction(b_root.member_id(), &NONCE, &a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    bi.begin_introduction(a_root.member_id(), &NONCE, &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let old_bytes = bi
        .resolve_introduction(
            a_root.member_id(),
            Kind::ClosedForever,
            &b,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    let old: ContactResolution = serde_json::from_slice(&old_bytes).unwrap();
    assert!(ai
        .apply_resolution(&old, &a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap());
    time.0.store(300, Ordering::Relaxed);
    assert!(ai
        .apply_resolution(&old, &a, &KEY, CONTEXT, |_| panic!(
            "expired receipt still rejects"
        ))
        .is_err());
    let stale_evidence = ai.export_contact_sync(&a).unwrap();
    sibling_inbox
        .merge_contact_sync(&stale_evidence, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut grant = common::grant(&b.chat_public_key(), 1);
    grant.member_id = b_root.member_id().to_owned();
    common::sign(&mut grant);
    let authorization = b_root
        .authorize_device(&b.chat_public_key(), 300, 900)
        .unwrap();
    let renewal = b
        .renew_device_admission(grant, authorization, |_, _| Ok(()))
        .unwrap();
    a.receive(&renewal).unwrap();
    let fresh_bytes = bi
        .refresh_outbound_resolution(a_root.member_id(), &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let fresh: ContactResolution = serde_json::from_slice(&fresh_bytes).unwrap();
    assert!(ai
        .apply_resolution(&fresh, &a, &KEY, CONTEXT, |_| Err(Error::InvalidStore))
        .is_err());
    assert_eq!(
        ai.inbound_resolution_receipt(b_root.member_id()).unwrap(),
        old_bytes
    );
    let mut saved = Vec::new();
    assert!(
        !ai.apply_resolution(&fresh, &a, &KEY, CONTEXT, |state| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap(),
        "renewed evidence is not a second resolution"
    );
    let (mut restored, a) = Inbox::restore_with_clock(&saved, &KEY, CONTEXT, time.clone()).unwrap();
    assert!(restored.is_closed(b_root.member_id()));
    assert_eq!(
        restored
            .inbound_resolution_receipt(b_root.member_id())
            .unwrap(),
        fresh_bytes
    );
    assert!(!restored
        .apply_resolution(&fresh, &a, &KEY, CONTEXT, |_| panic!(
            "exact replay changes nothing"
        ))
        .unwrap());
    let fresh_evidence = restored.export_contact_sync(&a).unwrap();
    sibling_inbox
        .merge_contact_sync(&fresh_evidence, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    sibling_inbox
        .merge_contact_sync(&stale_evidence, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(sibling_inbox.is_closed(b_root.member_id()));
    assert_eq!(
        sibling_inbox
            .inbound_resolution_receipt(b_root.member_id())
            .unwrap(),
        fresh_bytes,
        "stale sibling evidence cannot replace the renewed receipt"
    );
}
