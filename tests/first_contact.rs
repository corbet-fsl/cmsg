mod common;
use cmsg::{
    Clock, ContactResolutionKind, Error, FirstContactPolicy, FirstContactRole as Role, Inbox,
    Member, MemberIdentity, Received,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const KEY: [u8; 32] = [55; 32];
const CONTEXT: &[u8] = b"synthetic-strict-first-contact";
const INTRO: [u8; 32] = [32; 32];
const POLICY: FirstContactPolicy = FirstContactPolicy {
    response_deadline: 300,
    max_intro_bytes: 128,
};

struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::Relaxed))
    }
}

fn device(root: &MemberIdentity, time: &Arc<Time>) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let mut grant = common::grant(&member.chat_public_key(), 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            root.authorize_device(&member.chat_public_key(), 1, 1000)
                .unwrap(),
            100,
        )
        .unwrap();
    member
}

struct Pair {
    time: Arc<Time>,
    a_root: MemberIdentity,
    a: Member,
    b: Member,
    ai: Inbox,
    bi: Inbox,
}

fn pair() -> Pair {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let a_root = MemberIdentity::new("synthetic-community").unwrap();
    let b_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&a_root, &time);
    let mut b = device(&b_root, &time);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    ai.begin_first_contact(
        b_root.member_id(),
        &INTRO,
        Role::Initiator,
        POLICY,
        &a,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    bi.begin_first_contact(
        a_root.member_id(),
        &INTRO,
        Role::Recipient,
        POLICY,
        &b,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    Pair {
        time,
        a_root,
        a,
        b,
        ai,
        bi,
    }
}

#[test]
fn one_bounded_introduction_waits_for_an_actual_reply_and_generic_apis_cannot_bypass_it() {
    let mut p = pair();
    assert!(p.ai.send(&mut p.a, b"generic bypass").is_err());
    assert!(p.ai.send_bytes(&mut p.a, b"binary bypass").is_err());
    assert!(p
        .ai
        .send_contact(&mut p.a, &[b'x'; 129], &KEY, CONTEXT, |_, _| panic!(
            "oversize intro"
        ))
        .is_err());
    let wire =
        p.ai.send_contact(&mut p.a, b"first introduction", &KEY, CONTEXT, |_, wire| {
            assert!(!wire.is_empty());
            Ok(())
        })
        .unwrap();
    assert!(p
        .ai
        .send_contact(
            &mut p.a,
            b"repeat before reply",
            &KEY,
            CONTEXT,
            |_, _| panic!("one intro only")
        )
        .is_err());
    assert!(p.bi.receive(&mut p.b, &wire).is_err());
    assert!(
        matches!(p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(message) if message.text == "first introduction")
    );
    let malicious_repeat = p.a.send(b"sender bypassed its own policy").unwrap();
    assert!(p
        .bi
        .receive_contact(&mut p.b, &malicious_repeat, &KEY, CONTEXT, |_| panic!(
            "receiver independently refuses repeated intro"
        ))
        .is_err());
    assert_eq!(p.b.history().len(), 1);
    assert!(p
        .ai
        .resolve_introduction(
            &p.b.member_id().unwrap(),
            ContactResolutionKind::Answered,
            &p.a,
            &KEY,
            CONTEXT,
            |_| panic!("initiator cannot self-answer")
        )
        .is_err());
    let false_answer =
        p.b.sign_contact_resolution(
            &p.a.member_id().unwrap(),
            &INTRO,
            ContactResolutionKind::Answered,
        )
        .unwrap();
    assert!(p
        .ai
        .apply_resolution(&false_answer, &p.a, &KEY, CONTEXT, |_| panic!(
            "a signed declaration cannot replace actual reply data"
        ))
        .is_err());
    let reply =
        p.bi.send_contact(&mut p.b, b"actual answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(
        matches!(p.ai.receive_contact(&mut p.a, &reply, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(message) if message.text == "actual answer")
    );
    let followup =
        p.ai.send_contact_bytes(&mut p.a, b"established data", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(
        matches!(p.bi.receive_contact(&mut p.b, &followup, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Bytes(message) if message.bytes == b"established data")
    );
}

#[test]
fn failed_send_receive_and_reply_persistence_leave_ratchets_and_obligations_unchanged() {
    let mut p = pair();
    assert!(p
        .ai
        .send_contact(&mut p.a, b"write fails", &KEY, CONTEXT, |_, _| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(p.a.history().is_empty());
    let wire =
        p.ai.send_contact(&mut p.a, b"durable intro", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(p
        .bi
        .receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Err(Error::InvalidStore))
        .is_err());
    assert!(p.b.history().is_empty());
    p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p
        .bi
        .send_contact(&mut p.b, b"reply write fails", &KEY, CONTEXT, |_, _| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(p.bi.needs_resolution(&p.a.member_id().unwrap()));
    assert_eq!(p.b.history().len(), 1);
    let answer =
        p.bi.send_contact(&mut p.b, b"durable reply", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.awaiting_peer_resolution(&p.b.member_id().unwrap()));
}

#[test]
fn sender_cancellation_does_not_self_resolve_and_recipient_close_is_encrypted_permanent_and_one_shot(
) {
    let mut p = pair();
    let first =
        p.ai.send_contact(&mut p.a, b"introduction", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &first, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let cancel =
        p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(
        p.ai.awaiting_peer_resolution(&p.b.member_id().unwrap()),
        "local close cannot recycle sender allowance"
    );
    assert!(matches!(
        p.bi.receive_contact(&mut p.b, &cancel, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactClosed
    ));
    assert!(p
        .ai
        .close_contact(&mut p.a, &KEY, CONTEXT, |_, _| panic!(
            "repeated close control"
        ))
        .is_err());
    let closed =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, wire| {
            assert!(!wire
                .windows(b"closed-forever".len())
                .any(|part| part == b"closed-forever"));
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        p.ai.receive_contact(&mut p.a, &closed, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactClosed
    ));
    assert!(!p.ai.awaiting_peer_resolution(&p.b.member_id().unwrap()));
    assert!(p
        .ai
        .send_contact(&mut p.a, b"cannot reopen", &KEY, CONTEXT, |_, _| panic!(
            "permanent close"
        ))
        .is_err());
    assert!(p
        .ai
        .begin_first_contact(
            &p.b.member_id().unwrap(),
            &[33; 32],
            Role::Initiator,
            POLICY,
            &p.a,
            &KEY,
            CONTEXT,
            |_| panic!("new thread cannot reopen")
        )
        .is_err());
}

#[test]
fn configured_deadline_closes_durably_and_restore_cannot_reset_it() {
    let mut p = pair();
    let first =
        p.ai.send_contact(&mut p.a, b"deadline intro", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &first, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.time.0.store(300, Ordering::Relaxed);
    assert!(p
        .bi
        .apply_deadlines(&p.b, &KEY, CONTEXT, |_| Err(Error::InvalidStore))
        .is_err());
    assert!(!p.bi.is_closed(&p.a.member_id().unwrap()));
    let mut saved = Vec::new();
    assert_eq!(
        p.bi.apply_deadlines(&p.b, &KEY, CONTEXT, |state| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap(),
        1
    );
    let (mut restored, mut member) =
        Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert!(restored.is_closed(&p.a.member_id().unwrap()));
    assert_eq!(
        restored
            .apply_deadlines(&member, &KEY, CONTEXT, |_| panic!(
                "deadline already applied"
            ))
            .unwrap(),
        0
    );
    assert!(restored
        .send_contact(&mut member, b"too late", &KEY, CONTEXT, |_, _| panic!(
            "cannot reopen after deadline"
        ))
        .is_err());
    let close = restored
        .close_contact(&mut member, &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(matches!(
        p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactClosed
    ));
}

#[test]
fn sibling_sync_preserves_the_single_initial_writer_and_message_progress() {
    let mut p = pair();
    let mut sibling = device(&p.a_root, &p.time);
    let added = p.a.add(&sibling.key_package().unwrap()).unwrap();
    p.b.receive(&added.commit).unwrap();
    sibling.join(&added.welcome).unwrap();
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    let pending = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox
        .merge_contact_sync(&pending, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(sibling_inbox
        .send_contact(
            &mut sibling,
            b"parallel initial send",
            &KEY,
            CONTEXT,
            |_, _| panic!("one designated initial writer")
        )
        .is_err());
    let intro =
        p.ai.send_contact(
            &mut p.a,
            b"the single initial send",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let sent = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox
        .merge_contact_sync(&sent, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    sibling_inbox
        .merge_contact_sync(&pending, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let reply =
        p.bi.send_contact(&mut p.b, b"reply for the member", &KEY, CONTEXT, |_, _| {
            Ok(())
        })
        .unwrap();
    sibling_inbox
        .receive_contact(&mut sibling, &reply, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let followup = sibling_inbox
        .send_contact(
            &mut sibling,
            b"sibling after answer",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(
        matches!(p.bi.receive_contact(&mut p.b, &followup, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(message)
        if message.member_id == p.a_root.member_id())
    );
}

#[test]
fn admission_expiring_during_external_redemption_keeps_the_exact_spent_attempt_pending() {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let sender_root = MemberIdentity::new("synthetic-community").unwrap();
    let recipient_root = MemberIdentity::new("synthetic-community").unwrap();
    let mut sender = device(&sender_root, &time);
    let mut recipient = device(&recipient_root, &time);
    sender.create_group().unwrap();
    let welcome = sender
        .add(&recipient.key_package().unwrap())
        .unwrap()
        .welcome;
    let mut inbox = Inbox::new(&recipient).unwrap();
    let mut saved = Vec::new();
    let mut debits = 0;
    let result = inbox
        .accept(
            &mut recipient,
            &welcome,
            Some(b"exact already-spent claim"),
            &KEY,
            CONTEXT,
            |state| {
                saved = state.to_vec();
                Ok(())
            },
            |_| {
                debits += 1;
                time.0.store(1000, Ordering::Relaxed);
                cmsg::Redemption::Accepted
            },
        )
        .unwrap();
    assert_eq!(result, cmsg::Acceptance::Pending);
    assert_eq!(debits, 1);
    assert!(!inbox.is_known(sender_root.member_id()));
    assert!(recipient.send(b"not joined after expiry").is_err());
    assert_eq!(inbox.pending_welcome(), Some(welcome.as_slice()));
    let (mut restored, mut recipient) =
        Inbox::restore_with_clock(&saved, &KEY, CONTEXT, time).unwrap();
    assert_eq!(restored.pending_welcome(), Some(welcome.as_slice()));
    assert!(restored
        .accept(
            &mut recipient,
            &welcome,
            None,
            &KEY,
            CONTEXT,
            |_| panic!("expired admission cannot publish"),
            |_| panic!("no new debit or claim")
        )
        .is_err());
}
