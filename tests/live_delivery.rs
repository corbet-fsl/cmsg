mod common;
use cmsg::{DeliveryStatus, Error, FirstContactPolicy, FirstContactRole, Inbox, Received};
use common::accounting::{Pair, CONTEXT, KEY};
fn configured() -> Pair {
    let mut p = Pair::configured(10_000);
    p.ai = Inbox::new_live(&p.a).unwrap();
    p.bi = Inbox::new_live(&p.b).unwrap();
    let policy = FirstContactPolicy {
        response_deadline: 5000,
        max_intro_bytes: 128,
    };
    p.ai.begin_first_contact(
        p.br.member_id(),
        &[84; 32],
        FirstContactRole::Initiator,
        policy,
        &p.a,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    p.bi.begin_first_contact(
        p.ar.member_id(),
        &[84; 32],
        FirstContactRole::Recipient,
        policy,
        &p.b,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    p
}
fn controls(from: &mut Inbox, member: &cmsg::Member) -> Vec<Vec<u8>> {
    let wires = from.pending_live_controls();
    from.clear_live_controls(member, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    wires
}
fn handshake(p: &mut Pair) {
    let a =
        p.ai.begin_live_session(
            &mut p.a,
            &p.b.chat_public_key(),
            1000,
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    let b =
        p.bi.begin_live_session(
            &mut p.b,
            &p.a.chat_public_key(),
            1000,
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    assert!(matches!(
        p.ai.receive_contact(&mut p.a, &b, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::LiveControl
    ));
    assert!(matches!(
        p.bi.receive_contact(&mut p.b, &a, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        Received::LiveControl
    ));
    for wire in controls(&mut p.ai, &p.a) {
        p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    }
    for wire in controls(&mut p.bi, &p.b) {
        p.ai.receive_contact(&mut p.a, &wire, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    }
    assert_eq!(p.ai.live_sessions(), p.bi.live_sessions());
}
fn accept_acks(from: &mut Inbox, fm: &cmsg::Member, to: &mut Inbox, tm: &mut cmsg::Member) {
    for wire in controls(from, fm) {
        to.receive_contact(tm, &wire, &KEY, CONTEXT, |_| Ok(()))
            .unwrap();
    }
}
#[test]
fn ordinary_live_entry_points_require_mutual_session_and_actual_answer_acceptance() {
    let mut p = configured();
    assert!(p
        .ai
        .send_contact(&mut p.a, b"no session", &KEY, CONTEXT, |_, _| panic!(
            "no publication"
        ))
        .is_err());
    handshake(&mut p);
    p.send_intro();
    accept_acks(&mut p.bi, &p.b, &mut p.ai, &mut p.a);
    let answer = p.send_answer();
    assert!(p.bi.needs_resolution(p.ar.member_id()));
    assert!(
        p.bi.accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
            .is_err(),
        "queued Answer is not accepted"
    );
    p.ai.receive_contact(&mut p.a, &answer, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(
        p.bi.needs_resolution(p.ar.member_id()),
        "receiver acceptance has not yet reached recipient"
    );
    accept_acks(&mut p.ai, &p.a, &mut p.bi, &mut p.b);
    assert!(!p.bi.needs_resolution(p.ar.member_id()));
    assert!(p
        .bi
        .accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
        .is_ok());
}
#[test]
fn canceled_queued_answer_can_close_and_never_reappears_after_reconnect() {
    let mut p = configured();
    handshake(&mut p);
    p.send_intro();
    accept_acks(&mut p.bi, &p.b, &mut p.ai, &mut p.a);
    let old = p.send_answer();
    let sid = p.bi.live_sessions()[0];
    p.bi.lose_live_session(&p.b, &sid, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.ai.lose_live_session(&p.a, &sid, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.bi.is_closed(p.ar.member_id()));
    assert!(!p.bi.can_transmit_live_wire(&old, &p.b).unwrap());
    assert!(p
        .bi
        .live_deliveries()
        .iter()
        .any(|r| r.outgoing && r.status == DeliveryStatus::CanceledUnconfirmed));
    handshake(&mut p);
    assert!(p
        .ai
        .receive_contact(&mut p.a, &old, &KEY, CONTEXT, |_| panic!(
            "old session cannot expose payload"
        ))
        .is_err());
    p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(p.bi.is_closed(p.ar.member_id()));
}
#[test]
fn lost_ack_preserves_accepted_history_and_late_evidence_without_resending_data() {
    let mut p = configured();
    handshake(&mut p);
    let wire =
        p.ai.send_contact(&mut p.a, b"delivered once", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let ack = controls(&mut p.bi, &p.b).pop().unwrap();
    let sid = p.ai.live_sessions()[0];
    p.ai.lose_live_session(&p.a, &sid, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(
        p.ai.live_deliveries()[0].status,
        DeliveryStatus::CanceledUnconfirmed
    );
    assert_eq!(p.bi.accepted_live_history()[0].bytes, b"delivered once");
    p.ai.receive_contact(&mut p.a, &ack, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(p.ai.live_deliveries()[0].status, DeliveryStatus::Accepted);
    assert!(!p.ai.can_transmit_live_wire(&wire, &p.a).unwrap());
    assert!(
        p.ai.awaiting_peer_resolution(p.br.member_id()),
        "introduction receipt is not an Answer/refund"
    );
}
#[test]
fn restore_cancels_outbox_and_keeps_history_control_recovery_and_failed_write_retry() {
    let mut p = configured();
    handshake(&mut p);
    let wire =
        p.ai.send_contact(&mut p.a, b"history", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    assert_eq!(
        p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Err(Error::InvalidStore))
            .err(),
        Some(Error::InvalidStore)
    );
    assert!(p.bi.accepted_live_history().is_empty());
    p.bi.receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let pending = p.ai.snapshot(&p.a, &KEY, CONTEXT).unwrap();
    let (ai, a) = Inbox::restore_with_clock(&pending, &KEY, CONTEXT, p.time.clone()).unwrap();
    p.ai = ai;
    p.a = a;
    assert!(p.ai.live_sessions().is_empty());
    assert!(!p.ai.can_transmit_live_wire(&wire, &p.a).unwrap());
    assert_eq!(
        p.ai.live_deliveries()[0].status,
        DeliveryStatus::CanceledUnconfirmed
    );
    let accepted = p.bi.snapshot(&p.b, &KEY, CONTEXT).unwrap();
    let (bi, b) = Inbox::restore_with_clock(&accepted, &KEY, CONTEXT, p.time.clone()).unwrap();
    p.bi = bi;
    p.b = b;
    assert_eq!(p.bi.accepted_live_history()[0].bytes, b"history");
    let message = p.bi.live_deliveries()[0].message_id;
    let ack =
        p.bi.retransmit_live_ack(&mut p.b, &message, &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.ai.receive_contact(&mut p.a, &ack, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(p.ai.live_deliveries()[0].status, DeliveryStatus::Accepted);
}
#[test]
fn unguarded_legacy_payload_and_failed_handshake_persistence_do_not_open_live_inbox() {
    let mut p = configured();
    let peerkey = p.b.chat_public_key();
    assert!(p
        .ai
        .begin_live_session(&mut p.a, &peerkey, 1000, &KEY, CONTEXT, |_, _| Err(
            Error::InvalidStore
        ))
        .is_err());
    assert!(p.ai.live_sessions().is_empty());
    handshake(&mut p);
    let mut raw = b"cmsg.contact-data.v2\0".to_vec();
    raw.extend_from_slice(&[84; 32]);
    raw.push(0);
    raw.extend_from_slice(b"legacy bypass");
    let wire = p.a.send_bytes(&raw).unwrap();
    assert!(p
        .bi
        .receive_contact(&mut p.b, &wire, &KEY, CONTEXT, |_| panic!(
            "no legacy publication"
        ))
        .is_err());
}
#[test]
fn same_owner_sync_retains_only_authenticated_accepted_live_history() {
    let mut p = configured();
    handshake(&mut p);
    p.send_intro();
    let sibling = common::accounting::device(&p.br, &p.time, 10_000);
    let mut inbox = Inbox::new_live(&sibling).unwrap();
    let sync = p.bi.export_contact_sync(&p.b).unwrap();
    inbox
        .merge_contact_sync(&sync, &sibling, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(inbox.accepted_live_history()[0].bytes, b"introduction");
    assert!(inbox.live_sessions().is_empty());
    let mut forged = sync.clone();
    let position = forged.iter().position(|b| *b == b'i').unwrap();
    forged[position] ^= 1;
    assert!(inbox
        .merge_contact_sync(&forged, &sibling, &KEY, CONTEXT, |_| panic!(
            "forged history"
        ))
        .is_err());
}
#[test]
fn bounded_session_expiry_cancels_pending_without_closing_member_or_refunding_intro() {
    let mut p = configured();
    handshake(&mut p);
    let pending =
        p.ai.send_contact(&mut p.a, b"ambiguous", &KEY, CONTEXT, |_, _| Ok(()))
            .unwrap();
    p.time.0.store(1000, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        p.ai.apply_deadlines(&p.a, &KEY, CONTEXT, |_| Ok(()))
            .unwrap(),
        1
    );
    assert!(!p.ai.is_closed(p.br.member_id()));
    assert!(p.ai.awaiting_peer_resolution(p.br.member_id()));
    assert_eq!(
        p.ai.live_deliveries()[0].status,
        DeliveryStatus::CanceledUnconfirmed
    );
    assert!(!p.ai.can_transmit_live_wire(&pending, &p.a).unwrap());
    assert!(p
        .bi
        .receive_contact(&mut p.b, &pending, &KEY, CONTEXT, |_| Ok(()))
        .is_err());
}
#[test]
fn losing_one_device_session_keeps_another_authenticated_device_live() {
    let mut p = configured();
    let mut sibling = common::accounting::device(&p.br, &p.time, 10_000);
    let invitation = p.a.add(&sibling.key_package().unwrap()).unwrap();
    p.b.receive(&invitation.commit).unwrap();
    sibling.join(&invitation.welcome).unwrap();
    let mut si = Inbox::new_live(&sibling).unwrap();
    si.merge_contact_sync(
        &p.bi.export_contact_sync(&p.b).unwrap(),
        &sibling,
        &KEY,
        CONTEXT,
        |_| Ok(()),
    )
    .unwrap();
    handshake(&mut p);
    let first = p.ai.live_sessions()[0];
    let ah =
        p.ai.begin_live_session(
            &mut p.a,
            &sibling.chat_public_key(),
            1000,
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    let sh = si
        .begin_live_session(
            &mut sibling,
            &p.a.chat_public_key(),
            1000,
            &KEY,
            CONTEXT,
            |_, _| Ok(()),
        )
        .unwrap();
    p.ai.receive_contact(&mut p.a, &sh, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    si.receive_contact(&mut sibling, &ah, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    accept_acks(&mut p.ai, &p.a, &mut si, &mut sibling);
    accept_acks(&mut si, &sibling, &mut p.ai, &mut p.a);
    assert_eq!(p.ai.live_sessions().len(), 2);
    let second = si.live_sessions()[0];
    p.ai.lose_live_session(&p.a, &first, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(p.ai.live_sessions(), vec![second]);
    let intro =
        p.ai.send_live_bytes(&mut p.a, &second, b"other device", &KEY, CONTEXT, |_, _| {
            Ok(())
        })
        .unwrap();
    assert!(
        matches!(si.receive_contact(&mut sibling,&intro,&KEY,CONTEXT,|_|Ok(())).unwrap(),Received::Bytes(m) if m.bytes==b"other device")
    );
    let stale = p.ai.export_contact_sync(&p.a).unwrap();
    p.ai.lose_live_session(&p.a, &second, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.ai.merge_contact_sync(&stale, &p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(p.ai.live_sessions().is_empty());
    assert!(!p.ai.can_transmit_live_wire(&intro, &p.a).unwrap());
}
#[test]
fn silence_at_response_deadline_never_fabricates_close_or_refund_evidence() {
    let mut p = configured();
    handshake(&mut p);
    p.send_intro();
    p.time.0.store(5000, std::sync::atomic::Ordering::Relaxed);
    p.ai.apply_deadlines(&p.a, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    p.bi.apply_deadlines(&p.b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(!p.ai.is_closed(p.br.member_id()) && !p.bi.is_closed(p.ar.member_id()));
    assert!(
        p.ai.awaiting_peer_resolution(p.br.member_id()) && p.bi.needs_resolution(p.ar.member_id())
    );
    assert!(p.bi.outbound_resolution_receipt(p.ar.member_id()).is_none());
    assert!(p.ai.outbound_resolution_receipt(p.br.member_id()).is_none());
    assert!(p
        .bi
        .accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
        .is_err());
    assert!(p
        .bi
        .send_contact(&mut p.b, b"late Answer", &KEY, CONTEXT, |_, _| panic!(
            "expired contact cannot answer"
        ))
        .is_err());
    p.bi.close_contact(&mut p.b, &KEY, CONTEXT, |_, _| Ok(()))
        .unwrap();
    assert!(
        p.bi.is_closed(p.ar.member_id()),
        "explicit owner Close remains possible after expiry"
    );
    assert!(p
        .bi
        .accounting_receipt(p.ar.member_id(), &p.b, &p.bk, &p.bd)
        .is_ok());
}
