mod common;
use cmsg::{
    Clock, ContactResolution, Error, FirstContactPolicy, FirstContactRole as Role, Inbox, Member,
    MemberIdentity, Received,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const KEY: [u8; 32] = [71; 32];
const CONTEXT: &[u8] = b"synthetic-directional-contact";
const INITIAL: [u8; 32] = [72; 32];
const FRESH: [u8; 32] = [73; 32];

struct Time(AtomicU64);
impl Clock for Time {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::Relaxed))
    }
}
fn device(root: &MemberIdentity, time: &Arc<Time>) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member
        .bind_device_admission(
            grant,
            common::trust(),
            root.authorize_device(&key, 1, 10_000).unwrap(),
            100,
        )
        .unwrap();
    member
}
fn policy() -> FirstContactPolicy {
    FirstContactPolicy {
        response_deadline: 5000,
        max_intro_bytes: 128,
    }
}
fn chain(inbox: &Inbox, member: &Member, peer: &str) -> Vec<cmsg::ContactDirective> {
    let state: serde_json::Value =
        serde_json::from_slice(&inbox.export_contact_sync(member).unwrap()).unwrap();
    serde_json::from_value(state["directional"][peer]["local"].clone()).unwrap()
}
fn malicious_control(member: &mut Member, chain: &[cmsg::ContactDirective]) -> Vec<u8> {
    let mut bytes = b"cmsg.contact-directive.v1\0".to_vec();
    bytes.extend_from_slice(
        &serde_json::to_vec(&serde_json::json!({"chain":chain,"receipt":null})).unwrap(),
    );
    member.send_bytes(&bytes).unwrap()
}
struct Pair {
    a: Member,
    b: Member,
    ai: Inbox,
    bi: Inbox,
    ar: MemberIdentity,
    br: MemberIdentity,
    time: Arc<Time>,
}
fn configured() -> Pair {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let ar = MemberIdentity::new("synthetic-community").unwrap();
    let br = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&ar, &time);
    let mut b = device(&br, &time);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    ai.begin_first_contact(
        br.member_id(),
        &INITIAL,
        Role::Initiator,
        policy(),
        &a,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    bi.begin_first_contact(
        ar.member_id(),
        &INITIAL,
        Role::Recipient,
        policy(),
        &b,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    Pair {
        a,
        b,
        ai,
        bi,
        ar,
        br,
        time,
    }
}

fn pending() -> Pair {
    let mut p = configured();
    let intro =
        p.ai.send_contact(&mut p.a, b"initial introduction", &KEY, CONTEXT, |_, _| {
            Ok(())
        })
        .unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p
}

fn established() -> Pair {
    let mut p = pending();
    let answer =
        p.bi.send_contact(&mut p.b, b"initial answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p
}

#[test]
fn only_block_owner_restarts_with_a_fresh_gate_and_old_data_and_receipts_stay_closed() {
    let mut p = established();
    let delayed =
        p.ai.send_contact(&mut p.a, b"old queued data", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    let close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    let old_receipt: ContactResolution =
        serde_json::from_slice(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap())
            .unwrap();
    assert!(matches!(
        p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactClosed
    ));
    assert!(p
        .ai
        .initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!(
            "blocked peer cannot initiate"
        ))
        .is_err());
    assert!(p
        .bi
        .initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let stale = p.bi.export_contact_sync(&p.b).unwrap();
    let mut saved = Vec::new();
    let initiative =
        p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |state, _| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    assert!(matches!(
        p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::ContactPolicyChanged
    ));
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(p
        .ai
        .send_contact(&mut p.a, b"premature reply", &KEY, CONTEXT, |_, _| panic!(
            "fresh introduction required"
        ))
        .is_err());
    assert!(!p
        .ai
        .apply_resolution(&old_receipt, &p.a, &KEY, CONTEXT, |_| panic!(
            "duplicate archived receipt needs no write"
        ))
        .unwrap());
    assert!(
        !p.ai.is_closed(p.br.member_id()),
        "old receipt cannot alter the current nonce"
    );
    assert!(p
        .bi
        .receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!(
            "old plaintext must not escape"
        ))
        .is_err());
    let (mut restored, mut b) =
        Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    restored
        .merge_contact_sync(&stale, &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        !restored.is_closed(p.ar.member_id()),
        "a stale chain prefix cannot undo the owner's newer initiative"
    );
    let intro = restored
        .send_contact(&mut b, b"fresh introduction", &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(restored
        .send_contact(
            &mut b,
            b"duplicate fresh introduction",
            &KEY,
            CONTEXT,
            |_, _| panic!("one only")
        )
        .is_err());
    assert!(
        matches!(p.ai.receive_contact(&mut p.a, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh introduction")
    );
    let answer =
        p.ai.send_contact(&mut p.a, b"fresh answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(
        matches!(restored.receive_contact(&mut b, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh answer")
    );
    assert!(p
        .ai
        .receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| panic!("replay"))
        .is_err());
}

#[test]
fn both_members_must_consent_to_the_same_fresh_initiative() {
    let mut p = established();
    let a_close =
        p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let b_close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let offer =
        p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert!(p.ai.is_closed(p.br.member_id()));
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    assert!(p
        .ai
        .send_contact(&mut p.a, b"without consent", &KEY, CONTEXT, |_, _| panic!(
            "peer still blocks"
        ))
        .is_err());
    assert!(p
        .bi
        .consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Err(Error::InvalidStore))
        .is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let consent =
        p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro =
        p.ai.send_contact(&mut p.a, b"mutually reopened", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let answer =
        p.bi.send_contact(&mut p.b, b"accepted", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
}

#[test]
fn optional_block_expiry_allows_only_a_new_authenticated_introduction() {
    let mut p = established();
    let delayed =
        p.ai.send_contact(
            &mut p.a,
            b"queued before timed block",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    let block =
        p.bi.close_contact_until(&mut p.b, Some(200), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &block, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.time.0.store(199, Ordering::Relaxed);
    assert!(p
        .ai
        .initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!(
            "not expired"
        ))
        .is_err());
    p.time.0.store(201, Ordering::Relaxed);
    assert!(
        p.ai.is_closed(p.br.member_id()),
        "time alone cannot reopen old state"
    );
    assert!(p
        .bi
        .receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!(
            "old queued data remains blocked"
        ))
        .is_err());
    let initiative =
        p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &initiative, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro =
        p.ai.send_contact(
            &mut p.a,
            b"after configured expiry",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
}

#[test]
fn competing_same_owner_device_histories_persist_a_conflict_and_fail_closed() {
    let mut p = established();
    let sibling = device(&p.br, &p.time);
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    sibling_inbox
        .block_member_until(p.ar.member_id(), Some(400), &sibling, &KEY, CONTEXT, |_| {
            Ok(())
        })
        .unwrap();
    p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let conflicting = sibling_inbox.export_contact_sync(&sibling).unwrap();
    let mut saved = Vec::new();
    p.bi.merge_contact_sync(&conflicting, &p.b, &KEY, CONTEXT, |state| {
        saved = state.to_vec();
        Ok(())
    })
    .unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    let (mut restored, mut b) =
        Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert!(restored
        .initiate_contact(&mut b, &[74; 32], policy(), &KEY, CONTEXT, |_, _| panic!(
            "fork requires reconciliation"
        ))
        .is_err());
    assert!(restored
        .send_contact(
            &mut b,
            b"conflict must stay closed",
            &KEY,
            CONTEXT,
            |_, _| panic!("closed")
        )
        .is_err());
}

#[test]
fn direct_close_after_reopening_survives_sibling_sync_until_its_owner_initiates_again() {
    let mut p = established();
    let sibling = device(&p.ar, &p.time);
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    let close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let fresh =
        p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &fresh, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let intro =
        p.bi.send_contact(
            &mut p.b,
            b"fresh introduction",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.ai.receive_contact(&mut p.a, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let answer =
        p.ai.send_contact(&mut p.a, b"fresh answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    sibling_inbox
        .merge_contact_sync(
            &p.ai.export_contact_sync(&p.a).unwrap(),
            &sibling,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let receipt =
        p.b.sign_contact_resolution(
            p.ar.member_id(),
            &FRESH,
            cmsg::ContactResolutionKind::ClosedForever,
        )
        .unwrap();
    assert!(!p
        .ai
        .apply_resolution(&receipt, &p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap());
    let closed = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox
        .merge_contact_sync(&closed, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        sibling_inbox.is_closed(p.br.member_id()),
        "a prior initiative does not erase a later direct close"
    );
    let next =
        p.bi.initiate_contact(&mut p.b, &[75; 32], policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &next, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let reopened = p.ai.export_contact_sync(&p.a).unwrap();
    sibling_inbox
        .merge_contact_sync(&reopened, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    sibling_inbox
        .merge_contact_sync(&closed, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        !sibling_inbox.is_closed(p.br.member_id()),
        "only the owner's subsequent chained initiative supersedes that close"
    );
}

#[test]
fn authentic_unsolicited_fresh_directive_cannot_replace_an_existing_gate() {
    let mut p = established();
    p.ai.block_member_until(p.br.member_id(), None, &p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let group = chain(&p.ai, &p.a, p.br.member_id())[0].group_id.clone();
    let illicit =
        p.a.sign_contact_directive(
            p.br.member_id(),
            1,
            &[0; 32],
            &[0; 32],
            cmsg::ContactDirectiveKind::FreshInitiative,
            &FRESH,
            p.ar.member_id(),
            &group,
            Some(policy()),
            None,
        )
        .unwrap();
    let wire = malicious_control(&mut p.a, &[illicit]);
    assert!(p
        .bi
        .receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| panic!(
            "a valid signature does not authorize a fresh gate"
        ))
        .is_err());
}

#[test]
fn sender_self_block_then_fresh_cannot_erase_a_received_unanswered_introduction() {
    for deliver_cancellation in [false, true] {
        let mut p = established();
        let close =
            p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
                .unwrap();
        p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let initiative =
            p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
                .unwrap();
        p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let introduction =
            p.bi.send_contact(&mut p.b, b"still unanswered", &KEY, CONTEXT, |_, _| Ok(()))
                .unwrap();
        p.ai.receive_contact(&mut p.a, &introduction, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        if deliver_cancellation {
            let cancellation =
                p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
                    .unwrap();
            p.ai.receive_contact(&mut p.a, &cancellation, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
        } else {
            p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(()))
                .unwrap();
        }
        assert!(p.bi.awaiting_peer_resolution(p.ar.member_id()));
        assert!(p
            .bi
            .initiate_contact(&mut p.b, &[76; 32], policy(), &KEY, CONTEXT, |_, _| panic!(
                "honest sender cannot self-refund"
            ))
            .is_err());
        let mut history = chain(&p.bi, &p.b, p.ar.member_id());
        let previous = history.last().unwrap();
        let illicit =
            p.b.sign_contact_directive(
                p.ar.member_id(),
                previous.revision + 1,
                &previous.digest().unwrap(),
                &[0; 32],
                cmsg::ContactDirectiveKind::FreshInitiative,
                &[76; 32],
                p.br.member_id(),
                &previous.group_id,
                Some(policy()),
                None,
            )
            .unwrap();
        history.push(illicit);
        let wire = malicious_control(&mut p.b, &history);
        let before = p.a.history().len();
        assert!(p
            .ai
            .receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| panic!(
                "peer cancellation cannot replace recipient answer or close"
            ))
            .is_err());
        let mut payload = b"cmsg.contact-data.v2\0".to_vec();
        payload.extend_from_slice(&[76; 32]);
        payload.push(1);
        payload.extend_from_slice(b"another unsolicited introduction");
        let bypass = p.b.send_bytes(&payload).unwrap();
        assert!(p
            .ai
            .receive_contact(&mut p.a, &bypass, &KEY, CONTEXT, |_| panic!(
                "new data must stay blocked"
            ))
            .is_err());
        assert_eq!(p.a.history().len(), before);
    }
}

#[test]
fn a_valid_peer_signature_cannot_change_the_initiative_it_claims_to_accept() {
    let mut p = established();
    let a_close =
        p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let b_close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let offer =
        p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let owner_chain = chain(&p.ai, &p.a, p.br.member_id());
    let acknowledgement = owner_chain.last().unwrap().digest().unwrap();
    for mutation in 0..6 {
        let mut history = chain(&p.bi, &p.b, p.ar.member_id());
        let previous = history.last().unwrap();
        let nonce = if mutation == 0 || mutation == 5 {
            [77; 32]
        } else {
            FRESH
        };
        let mut limits = policy();
        if mutation == 1 || mutation == 5 {
            limits.response_deadline += 1;
        }
        if mutation == 2 {
            limits.max_intro_bytes -= 1;
        }
        let group = if mutation == 3 {
            vec![9; 32]
        } else {
            previous.group_id.clone()
        };
        let initiator = if mutation == 4 || mutation == 5 {
            p.br.member_id()
        } else {
            p.ar.member_id()
        };
        let forged =
            p.b.sign_contact_directive(
                p.ar.member_id(),
                previous.revision + 1,
                &previous.digest().unwrap(),
                &acknowledgement,
                cmsg::ContactDirectiveKind::FreshInitiative,
                &nonce,
                initiator,
                &group,
                Some(limits),
                None,
            )
            .unwrap();
        history.push(forged);
        let wire = malicious_control(&mut p.b, &history);
        assert!(p
            .ai
            .receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| panic!(
                "consent must match exactly"
            ))
            .is_err());
    }
    let consent =
        p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
}

#[test]
fn stale_signed_archives_cannot_erase_an_unresolved_sent_introduction() {
    let mut p = configured();
    let before_send = p.ai.snapshot(&p.a, &KEY, CONTEXT).unwrap();
    let first =
        p.ai.send_contact(
            &mut p.a,
            b"an outstanding introduction",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.bi.receive_contact(&mut p.b, &first, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    // The recipient's private decision allows its own new initiative, but its
    // separate resolution receipt has not yet reached the original sender.
    let newer =
        p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &newer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p.ai.awaiting_peer_resolution(p.br.member_id()));
    let (mut stale, mut old_a) =
        Inbox::restore_with_clock(&before_send, &KEY, CONTEXT, p.time.clone()).unwrap();
    stale
        .receive_contact(&mut old_a, &newer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        !stale.awaiting_peer_resolution(p.br.member_id()),
        "an old authentic snapshot lacks the later send"
    );
    let stale_sync = stale.export_contact_sync(&old_a).unwrap();
    let current_sync = p.ai.export_contact_sync(&p.a).unwrap();
    p.ai.merge_contact_sync(&stale_sync, &p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        p.ai.awaiting_peer_resolution(p.br.member_id()),
        "archive merge must preserve sent=true"
    );
    stale
        .merge_contact_sync(&current_sync, &old_a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        stale.awaiting_peer_resolution(p.br.member_id()),
        "current peer evidence heals the rolled-back send floor"
    );
}

#[test]
fn delayed_sender_cancellation_preserves_the_recipients_own_close_provenance() {
    let mut p = pending();
    let b_close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    let own_close =
        p.bi.outbound_resolution_receipt(p.ar.member_id())
            .unwrap()
            .to_vec();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let a_close =
        p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    let receipt: ContactResolution =
        serde_json::from_slice(p.ai.outbound_resolution_receipt(p.br.member_id()).unwrap())
            .unwrap();
    assert!(!p
        .bi
        .apply_resolution(&receipt, &p.b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap());
    assert_eq!(
        p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap(),
        own_close
    );
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(
        p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap(),
        own_close
    );
    let offer =
        p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let consent =
        p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
}

#[test]
fn delayed_archived_resolution_is_durable_and_cannot_change_the_fresh_gate() {
    for already_answered in [false, true] {
        let mut p = if already_answered {
            established()
        } else {
            pending()
        };
        p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let receipt: ContactResolution =
            serde_json::from_slice(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap())
                .unwrap();
        // The authenticated owner initiative arrives before its separate receipt.
        let fresh =
            p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(()))
                .unwrap();
        p.ai.receive_contact(&mut p.a, &fresh, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        assert_eq!(
            p.ai.awaiting_peer_resolution(p.br.member_id()),
            !already_answered
        );
        let before: serde_json::Value =
            serde_json::from_slice(&p.ai.export_contact_sync(&p.a).unwrap()).unwrap();

        let unknown =
            p.b.sign_contact_resolution(
                p.ar.member_id(),
                &[99; 32],
                cmsg::ContactResolutionKind::ClosedForever,
            )
            .unwrap();
        assert!(p
            .ai
            .apply_resolution(&unknown, &p.a, &KEY, CONTEXT, |_| panic!(
                "unknown nonce must not persist"
            ))
            .is_err());
        if !already_answered {
            let claimed_answer =
                p.b.sign_contact_resolution(
                    p.ar.member_id(),
                    &INITIAL,
                    cmsg::ContactResolutionKind::Answered,
                )
                .unwrap();
            assert!(p
                .ai
                .apply_resolution(&claimed_answer, &p.a, &KEY, CONTEXT, |_| panic!(
                    "a claim cannot replace the actual answer"
                ))
                .is_err());
        }
        assert!(p
            .ai
            .apply_resolution(&receipt, &p.a, &KEY, CONTEXT, |_| Err(Error::InvalidStore))
            .is_err());
        assert_eq!(
            p.ai.awaiting_peer_resolution(p.br.member_id()),
            !already_answered
        );
        let after_failure: serde_json::Value =
            serde_json::from_slice(&p.ai.export_contact_sync(&p.a).unwrap()).unwrap();
        assert_eq!(
            before, after_failure,
            "failed persistence leaves all evidence unchanged"
        );

        let mut saved = Vec::new();
        assert_eq!(
            p.ai.apply_resolution(&receipt, &p.a, &KEY, CONTEXT, |state| {
                saved = state.to_vec();
                Ok(())
            })
            .unwrap(),
            !already_answered
        );
        assert!(!p.ai.awaiting_peer_resolution(p.br.member_id()));
        assert!(!p.ai.is_closed(p.br.member_id()));
        let after: serde_json::Value =
            serde_json::from_slice(&p.ai.export_contact_sync(&p.a).unwrap()).unwrap();
        assert_eq!(before["introductions"], after["introductions"]);
        assert_eq!(before["directional"], after["directional"]);
        assert!(!p
            .ai
            .apply_resolution(&receipt, &p.a, &KEY, CONTEXT, |_| panic!(
                "receipt replay must not persist"
            ))
            .unwrap());
        let reversed =
            p.b.sign_contact_resolution(
                p.ar.member_id(),
                &INITIAL,
                cmsg::ContactResolutionKind::Answered,
            )
            .unwrap();
        assert!(p
            .ai
            .apply_resolution(&reversed, &p.a, &KEY, CONTEXT, |_| panic!(
                "closed archive cannot reverse"
            ))
            .is_err());

        let (mut restored, mut a) =
            Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
        assert!(!restored.awaiting_peer_resolution(p.br.member_id()));
        assert!(!restored.is_closed(p.br.member_id()));
        assert!(restored
            .send_contact(
                &mut a,
                b"old resolution is not a new introduction",
                &KEY,
                CONTEXT,
                |_, _| panic!("fresh introduction still required")
            )
            .is_err());
        let intro =
            p.bi.send_contact(
                &mut p.b,
                b"a genuinely fresh introduction",
                &KEY,
                CONTEXT,
                |_, _| Ok(()),
            )
            .unwrap();
        restored
            .receive_contact(&mut a, &intro, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
        let answer = restored
            .send_contact(&mut a, b"answer to the new nonce", &KEY, CONTEXT, |_, _| {
                Ok(())
            })
            .unwrap();
        p.bi.receive_contact(&mut p.b, &answer, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    }
}

#[test]
fn internal_contact_envelopes_cannot_escape_generic_receive_or_consume_its_keys() {
    let mut p = established();
    assert!(p
        .ai
        .send_contact_bytes(&mut p.a, &[], &KEY, CONTEXT, |_, _| panic!(
            "strict contact requires nonempty data"
        ))
        .is_err());
    for payload in [vec![0], vec![42; cmsg::MAX_DATA_BYTES]] {
        let wire =
            p.ai.send_contact_bytes(&mut p.a, &payload, &KEY, CONTEXT, |_, _| Ok(()))
                .unwrap();
        assert!(
            p.b.receive(&wire).is_err(),
            "generic byte delivery must reject internal kind 2"
        );
        assert!(p.b.receive_control(&wire).is_err());
        let generic = Inbox::new(&p.b).unwrap();
        assert!(generic.receive(&mut p.b, &wire).is_err());
        assert!(
            matches!(p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(())).unwrap(),
            Received::Bytes(message) if message.bytes == payload && message.member_id == p.ar.member_id())
        );
        assert!(p
            .bi
            .receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| panic!("guarded replay"))
            .is_err());
    }
    assert!(p
        .ai
        .send_contact_bytes(
            &mut p.a,
            &vec![0; cmsg::MAX_DATA_BYTES + 1],
            &KEY,
            CONTEXT,
            |_, _| panic!("payload limit applies before persistence")
        )
        .is_err());
}

#[test]
fn owner_reopens_in_a_replacement_group_with_fresh_admission_and_no_old_group_bypass() {
    let mut p = established();
    let close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut a = device(&p.ar, &p.time);
    let mut b = device(&p.br, &p.time);
    let package = a.key_package().unwrap();
    assert!(p
        .bi
        .initiate_replacement(&mut b, &package, &FRESH, policy(), &KEY, CONTEXT, |_, _| {
            Err(Error::InvalidStore)
        })
        .is_err());
    assert!(b.participants().is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let bundle =
        p.bi.initiate_replacement(
            &mut b,
            &package,
            &FRESH,
            policy(),
            &KEY,
            CONTEXT,
            |_, frames| {
                assert!(!frames.welcome.is_empty() && !frames.control.is_empty());
                Ok(())
            },
        )
        .unwrap();
    let key_before_preview = a.chat_public_key();
    let preview =
        p.ai.preview_replacement(&a, &bundle.welcome, &bundle.control)
            .unwrap();
    assert_eq!(preview.inviter, p.br.member_id());
    assert_eq!(preview.introduction_id, FRESH);
    assert_eq!(preview.policy, policy());
    assert!(!preview.group_id.is_empty());
    assert_eq!(format!("{preview:?}"), "ReplacementPreview([redacted])");
    assert_eq!(a.chat_public_key(), key_before_preview);
    assert!(a.participants().is_err(), "preview does not join");
    assert!(
        p.ai.is_closed(p.br.member_id()),
        "preview does not change contact policy"
    );
    assert_eq!(
        p.ai.accept_replacement(
            &mut a,
            &bundle.welcome,
            &bundle.control,
            None,
            &KEY,
            CONTEXT,
            |_| panic!("no admission claim"),
            |_| panic!("no admission claim")
        )
        .unwrap(),
        cmsg::Acceptance::NeedsPermit
    );
    let mut altered = bundle.control.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(p
        .ai
        .preview_replacement(&a, &bundle.welcome, &altered)
        .is_err());
    assert!(p
        .ai
        .accept_replacement(
            &mut a,
            &bundle.welcome,
            &altered,
            Some(b"private recipient claim"),
            &KEY,
            CONTEXT,
            |_| panic!("authenticate before persistence"),
            |_| panic!("authenticate before spending")
        )
        .is_err());
    assert_eq!(
        p.ai.accept_replacement(
            &mut a,
            &bundle.welcome,
            &bundle.control,
            Some(b"private recipient claim"),
            &KEY,
            CONTEXT,
            |_| Ok(()),
            |_| cmsg::Redemption::Accepted
        )
        .unwrap(),
        cmsg::Acceptance::Joined
    );
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(p.ai.is_known(p.br.member_id()));
    assert!(p
        .ai
        .send_contact(&mut a, b"no implicit answer", &KEY, CONTEXT, |_, _| panic!(
            "fresh intro required"
        ))
        .is_err());

    // A legitimate old device still has a valid MLS signing key and ratchet.
    // The new nonce alone must not authorize it to use the discarded group.
    let mut old_record = b"cmsg.contact-data.v2\0".to_vec();
    old_record.extend_from_slice(&FRESH);
    old_record.push(0);
    old_record.extend_from_slice(b"new nonce in old group");
    let old_wire = p.b.send_bytes(&old_record).unwrap();
    assert!(p
        .ai
        .receive_contact(&mut p.a, &old_wire, &KEY, CONTEXT, |_| panic!(
            "old group cannot carry the replacement nonce"
        ))
        .is_err());
    assert!(p
        .bi
        .send_contact_bytes(&mut p.b, b"old owner device", &KEY, CONTEXT, |_, _| panic!(
            "selected group must match"
        ))
        .is_err());
    let intro =
        p.bi.send_contact(
            &mut b,
            b"recovered owner introduction",
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.ai.receive_contact(&mut a, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let answer =
        p.ai.send_contact(&mut a, b"new group answer", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut b, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();

    // A second replacement remains subject to new admission even though known.
    let close =
        p.bi.close_contact(&mut b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut a, &close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut a_next = device(&p.ar, &p.time);
    let mut b_next = device(&p.br, &p.time);
    let next =
        p.bi.initiate_replacement(
            &mut b_next,
            &a_next.key_package().unwrap(),
            &[80; 32],
            policy(),
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(
        p.ai.accept_replacement(
            &mut a_next,
            &next.welcome,
            &next.control,
            None,
            &KEY,
            CONTEXT,
            |_| panic!("known does not bypass replacement admission"),
            |_| panic!("claim required")
        )
        .unwrap(),
        cmsg::Acceptance::NeedsPermit
    );
}

#[test]
fn replacement_group_preserves_both_owners_consent() {
    let mut p = established();
    let a_close =
        p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let b_close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut a = device(&p.ar, &p.time);
    let mut b = device(&p.br, &p.time);
    let bundle =
        p.bi.initiate_replacement(
            &mut b,
            &a.key_package().unwrap(),
            &FRESH,
            policy(),
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(
        p.ai.accept_replacement(
            &mut a,
            &bundle.welcome,
            &bundle.control,
            Some(b"recipient-bound claim"),
            &KEY,
            CONTEXT,
            |_| Ok(()),
            |_| cmsg::Redemption::Accepted
        )
        .unwrap(),
        cmsg::Acceptance::Joined
    );
    assert!(p.ai.is_closed(p.br.member_id()));
    assert!(p.bi.is_closed(p.ar.member_id()));
    assert!(p
        .bi
        .send_contact(
            &mut b,
            b"without second owner consent",
            &KEY,
            CONTEXT,
            |_, _| panic!("blocked")
        )
        .is_err());
    let consent =
        p.ai.consent_contact(&mut a, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut b, &consent, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let intro =
        p.bi.send_contact(&mut b, b"both owners consented", &KEY, CONTEXT, |_, _| {
            Ok(())
        })
        .unwrap();
    p.ai.receive_contact(&mut a, &intro, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
}

#[test]
fn replacement_pending_survives_storage_failure_ambiguity_and_expiry_without_new_spending() {
    let mut p = established();
    let close =
        p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut a = device(&p.ar, &p.time);
    let mut b = device(&p.br, &p.time);
    let bundle =
        p.bi.initiate_replacement(
            &mut b,
            &a.key_package().unwrap(),
            &FRESH,
            policy(),
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(p
        .ai
        .accept_replacement(
            &mut a,
            &bundle.welcome,
            &bundle.control,
            Some(b"one durable private claim"),
            &KEY,
            CONTEXT,
            |_| Err(Error::InvalidStore),
            |_| panic!("failed pending write prevents spending")
        )
        .is_err());
    assert!(a.participants().is_err());
    let mut pending = Vec::new();
    assert_eq!(
        p.ai.accept_replacement(
            &mut a,
            &bundle.welcome,
            &bundle.control,
            None,
            &KEY,
            CONTEXT,
            |state| {
                pending = state.to_vec();
                Ok(())
            },
            |claim| {
                assert_eq!(claim, b"one durable private claim");
                cmsg::Redemption::Indeterminate
            }
        )
        .unwrap(),
        cmsg::Acceptance::Pending
    );
    let (mut restored, mut a) =
        Inbox::restore_with_clock(&pending, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert_eq!(
        restored.pending_replacement_control().unwrap(),
        bundle.control
    );
    assert_eq!(
        restored
            .accept_replacement(
                &mut a,
                &bundle.welcome,
                &bundle.control,
                Some(b"replacement claim"),
                &KEY,
                CONTEXT,
                |_| panic!("claim cannot change"),
                |_| panic!("claim cannot change")
            )
            .unwrap(),
        cmsg::Acceptance::Busy
    );
    let mut writes = 0;
    assert_eq!(
        restored
            .accept_replacement(
                &mut a,
                &bundle.welcome,
                &bundle.control,
                None,
                &KEY,
                CONTEXT,
                |_| {
                    writes += 1;
                    if writes == 2 {
                        Err(Error::InvalidStore)
                    } else {
                        Ok(())
                    }
                },
                |_| cmsg::Redemption::Accepted
            )
            .unwrap(),
        cmsg::Acceptance::Pending
    );
    assert!(a.participants().is_err());
    assert!(restored.is_closed(p.br.member_id()));
    assert_eq!(
        restored
            .accept_replacement(
                &mut a,
                &bundle.welcome,
                &bundle.control,
                None,
                &KEY,
                CONTEXT,
                |state| {
                    pending = state.to_vec();
                    Ok(())
                },
                |_| {
                    p.time.0.store(10_001, Ordering::Relaxed);
                    cmsg::Redemption::Accepted
                }
            )
            .unwrap(),
        cmsg::Acceptance::Pending
    );
    let (mut expired, mut a) =
        Inbox::restore_with_clock(&pending, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert_eq!(
        expired.pending_replacement_control().unwrap(),
        bundle.control
    );
    assert_eq!(
        expired
            .accept_replacement(
                &mut a,
                &bundle.welcome,
                &bundle.control,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("expired pending cannot be reauthorized"),
                |_| panic!("no new spending while expired")
            )
            .unwrap(),
        cmsg::Acceptance::Pending
    );
    expired
        .cancel_pending(&a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(expired.pending_replacement_control().is_none());
}

#[test]
fn malicious_sender_cannot_reset_unanswered_introduction_by_minting_a_replacement_group() {
    let mut p = pending();
    let mut a = device(&p.ar, &p.time);
    let mut b = device(&p.br, &p.time);
    let package = b.key_package().unwrap();
    p.ai.block_member_until(p.br.member_id(), None, &p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p
        .ai
        .initiate_replacement(
            &mut a,
            &package,
            &FRESH,
            policy(),
            &KEY,
            CONTEXT,
            |_, _| panic!("sender cancellation creates no fresh reach")
        )
        .is_err());
    a.create_group().unwrap();
    let welcome = a.add(&package).unwrap().welcome;
    p.ai.block_member_until(p.br.member_id(), None, &a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut directives = chain(&p.ai, &a, p.br.member_id());
    let previous = directives.last().unwrap();
    let forged_initiative = a
        .sign_contact_directive(
            p.br.member_id(),
            directives.len() as u64 + 1,
            &previous.digest().unwrap(),
            &[0; 32],
            cmsg::ContactDirectiveKind::FreshInitiative,
            &FRESH,
            p.ar.member_id(),
            &previous.group_id,
            Some(policy()),
            None,
        )
        .unwrap();
    directives.push(forged_initiative);
    let control = malicious_control(&mut a, &directives);
    assert!(p
        .bi
        .accept_replacement(
            &mut b,
            &welcome,
            &control,
            Some(b"even a fresh permit is insufficient"),
            &KEY,
            CONTEXT,
            |_| panic!("receiver must preserve unresolved incoming"),
            |_| panic!("reject before spending")
        )
        .is_err());
    assert!(b.participants().is_err());
    assert!(p.ai.awaiting_peer_resolution(p.br.member_id()));
}
