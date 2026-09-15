mod common;
use cmsg::{Clock, ContactResolution, Error, FirstContactPolicy, FirstContactRole as Role, Inbox, Member, MemberIdentity, Received};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

const KEY: [u8; 32] = [71; 32];
const CONTEXT: &[u8] = b"synthetic-directional-contact";
const INITIAL: [u8; 32] = [72; 32];
const FRESH: [u8; 32] = [73; 32];

struct Time(AtomicU64);
impl Clock for Time { fn now(&self) -> Result<u64, Error> { Ok(self.0.load(Ordering::Relaxed)) } }
fn device(root: &MemberIdentity, time: &Arc<Time>) -> Member {
    let mut member = Member::new_with_clock(time.clone()).unwrap();
    let key = member.chat_public_key();
    let mut grant = common::grant(&key, 1);
    grant.member_id = root.member_id().to_owned();
    common::sign(&mut grant);
    member.bind_device_admission(grant, common::trust(), root.authorize_device(&key, 1, 10_000).unwrap(), 100).unwrap();
    member
}
fn policy() -> FirstContactPolicy { FirstContactPolicy { response_deadline: 5000, max_intro_bytes: 128 } }
struct Pair {
    a: Member, b: Member, ai: Inbox, bi: Inbox,
    ar: MemberIdentity, br: MemberIdentity, time: Arc<Time>,
}
fn established() -> Pair {
    let time = Arc::new(Time(AtomicU64::new(100)));
    let ar = MemberIdentity::new("synthetic-community").unwrap();
    let br = MemberIdentity::new("synthetic-community").unwrap();
    let mut a = device(&ar, &time);
    let mut b = device(&br, &time);
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome).unwrap();
    let mut ai = Inbox::new(&a).unwrap();
    let mut bi = Inbox::new(&b).unwrap();
    ai.begin_first_contact(br.member_id(), &INITIAL, Role::Initiator, policy(), &a, &KEY, CONTEXT, |_| Ok(())).unwrap();
    bi.begin_first_contact(ar.member_id(), &INITIAL, Role::Recipient, policy(), &b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let intro = ai.send_contact(&mut a, b"initial introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    bi.receive_contact(&mut b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let answer = bi.send_contact(&mut b, b"initial answer", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    ai.receive_contact(&mut a, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    Pair { a, b, ai, bi, ar, br, time }
}

#[test]
fn only_block_owner_restarts_with_a_fresh_gate_and_old_data_and_receipts_stay_closed() {
    let mut p = established();
    let delayed = p.ai.send_contact(&mut p.a, b"old queued data", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let old_receipt: ContactResolution = serde_json::from_slice(p.bi.outbound_resolution_receipt(p.ar.member_id()).unwrap()).unwrap();
    assert!(matches!(p.ai.receive_contact(&mut p.a, &close, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::ContactClosed));
    assert!(p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!("blocked peer cannot initiate")).is_err());
    assert!(p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Err(Error::InvalidStore)).is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let stale = p.bi.export_contact_sync(&p.b).unwrap();
    let mut saved = Vec::new();
    let initiative = p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT,
        |state, _| { saved = state.to_vec(); Ok(()) }).unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    assert!(matches!(p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::ContactPolicyChanged));
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(p.ai.send_contact(&mut p.a, b"premature reply", &KEY, CONTEXT, |_, _| panic!("fresh introduction required")).is_err());
    assert!(p.ai.apply_resolution(&old_receipt, &p.a, &KEY, CONTEXT, |_| panic!("old receipt cannot alter current nonce")).is_err());
    assert!(p.bi.receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!("old plaintext must not escape")).is_err());
    let (mut restored, mut b) = Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    restored.merge_contact_sync(&stale, &b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!restored.is_closed(p.ar.member_id()), "a stale chain prefix cannot undo the owner's newer initiative");
    let intro = restored.send_contact(&mut b, b"fresh introduction", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(restored.send_contact(&mut b, b"duplicate fresh introduction", &KEY, CONTEXT, |_, _| panic!("one only")).is_err());
    assert!(matches!(p.ai.receive_contact(&mut p.a, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh introduction"));
    let answer = p.ai.send_contact(&mut p.a, b"fresh answer", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(matches!(restored.receive_contact(&mut b, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap(), Received::Text(m) if m.text == "fresh answer"));
    assert!(p.ai.receive_contact(&mut p.a, &initiative, &KEY, CONTEXT, |_| panic!("replay")).is_err());
}

#[test]
fn both_members_must_consent_to_the_same_fresh_initiative() {
    let mut p = established();
    let a_close = p.ai.close_contact(&mut p.a, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &a_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let b_close = p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &b_close, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let offer = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(p.ai.is_closed(p.br.member_id()));
    p.bi.receive_contact(&mut p.b, &offer, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    assert!(p.ai.send_contact(&mut p.a, b"without consent", &KEY, CONTEXT, |_, _| panic!("peer still blocks")).is_err());
    assert!(p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Err(Error::InvalidStore)).is_err());
    assert!(p.bi.is_closed(p.ar.member_id()));
    let consent = p.bi.consent_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &consent, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro = p.ai.send_contact(&mut p.a, b"mutually reopened", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
    let answer = p.bi.send_contact(&mut p.b, b"accepted", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(())).unwrap();
}

#[test]
fn optional_block_expiry_allows_only_a_new_authenticated_introduction() {
    let mut p = established();
    let delayed = p.ai.send_contact(&mut p.a, b"queued before timed block", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    let block = p.bi.close_contact_until(&mut p.b, Some(200), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.ai.receive_contact(&mut p.a, &block, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.time.0.store(199, Ordering::Relaxed);
    assert!(p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| panic!("not expired")).is_err());
    p.time.0.store(201, Ordering::Relaxed);
    assert!(p.ai.is_closed(p.br.member_id()), "time alone cannot reopen old state");
    assert!(p.bi.receive_contact(&mut p.b, &delayed, &KEY, CONTEXT, |_| panic!("old queued data remains blocked")).is_err());
    let initiative = p.ai.initiate_contact(&mut p.a, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &initiative, &KEY, CONTEXT, |_| Ok(())).unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let intro = p.ai.send_contact(&mut p.a, b"after configured expiry", &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    p.bi.receive_contact(&mut p.b, &intro, &KEY, CONTEXT, |_| Ok(())).unwrap();
}

#[test]
fn competing_same_owner_device_histories_persist_a_conflict_and_fail_closed() {
    let mut p = established();
    let sibling = device(&p.br, &p.time);
    let mut sibling_inbox = Inbox::new(&sibling).unwrap();
    p.bi.block_member_until(p.ar.member_id(), None, &p.b, &KEY, CONTEXT, |_| Ok(())).unwrap();
    sibling_inbox.block_member_until(p.ar.member_id(), Some(400), &sibling, &KEY, CONTEXT, |_| Ok(())).unwrap();
    p.bi.initiate_contact(&mut p.b, &FRESH, policy(), &KEY, CONTEXT, |_, _| Ok(())).unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    let conflicting = sibling_inbox.export_contact_sync(&sibling).unwrap();
    let mut saved = Vec::new();
    p.bi.merge_contact_sync(&conflicting, &p.b, &KEY, CONTEXT, |state| { saved = state.to_vec(); Ok(()) }).unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
    let (mut restored, mut b) = Inbox::restore_with_clock(&saved, &KEY, CONTEXT, p.time.clone()).unwrap();
    assert!(restored.initiate_contact(&mut b, &[74; 32], policy(), &KEY, CONTEXT, |_, _| panic!("fork requires reconciliation")).is_err());
    assert!(restored.send_contact(&mut b, b"conflict must stay closed", &KEY, CONTEXT, |_, _| panic!("closed")).is_err());
}
