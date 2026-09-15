mod common;
use cmsg::{ContactResolution, ContactResolutionKind as Kind, Error, Inbox, MemberIdentity};

const KEY: [u8; 32] = [54; 32];
const CONTEXT: &[u8] = b"synthetic-introduction-resolution";
const NONCE: [u8; 32] = [21; 32];

#[test]
fn exact_first_introduction_is_resolved_once_and_close_survives_new_thread_attempts() {
    for decision in [Kind::Answered, Kind::ClosedForever] {
        let alice_id = MemberIdentity::new("synthetic-community").unwrap();
        let bob_id = MemberIdentity::new("synthetic-community").unwrap();
        let alice = common::root_device(&alice_id);
        let bob = common::root_device(&bob_id);
        let mut alice_inbox = Inbox::new(&alice).unwrap();
        let mut bob_inbox = Inbox::new(&bob).unwrap();
        alice_inbox
            .begin_introduction(
                bob_id.member_id(),
                &NONCE,
                &alice,
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        bob_inbox
            .begin_introduction(
                alice_id.member_id(),
                &NONCE,
                &bob,
                &KEY,
                CONTEXT,
                |_| Ok(()),
            )
            .unwrap();
        assert!(alice_inbox.needs_resolution(bob_id.member_id()));
        assert!(bob_inbox.needs_resolution(alice_id.member_id()));
        assert!(alice_inbox
            .begin_introduction(
                bob_id.member_id(),
                &[22; 32],
                &alice,
                &KEY,
                CONTEXT,
                |_| panic!("a new nonce cannot replace unresolved state")
            )
            .is_err());
        let mut saved_bob = Vec::new();
        let wire = bob_inbox
            .resolve_introduction(
                alice_id.member_id(),
                decision,
                &bob,
                &KEY,
                CONTEXT,
                |state| {
                    saved_bob = state.to_vec();
                    Ok(())
                },
            )
            .unwrap();
        assert!(!bob_inbox.needs_resolution(alice_id.member_id()));
        let (mut restored_bob, bob) = Inbox::restore(&saved_bob, &KEY, CONTEXT).unwrap();
        assert_eq!(
            restored_bob
                .resolve_introduction(
                    alice_id.member_id(),
                    decision,
                    &bob,
                    &KEY,
                    CONTEXT,
                    |_| panic!("retry returns the exact durable outbox receipt")
                )
                .unwrap(),
            wire
        );
        let receipt: ContactResolution = serde_json::from_slice(&wire).unwrap();
        let mut saved_alice = Vec::new();
        assert!(alice_inbox
            .apply_resolution(&receipt, &alice, &KEY, CONTEXT, |state| {
                saved_alice = state.to_vec();
                Ok(())
            })
            .unwrap());
        let (mut restored_alice, alice) = Inbox::restore(&saved_alice, &KEY, CONTEXT).unwrap();
        assert!(!restored_alice.needs_resolution(bob_id.member_id()));
        assert!(!restored_alice
            .apply_resolution(&receipt, &alice, &KEY, CONTEXT, |_| panic!(
                "replay cannot transition again"
            ))
            .unwrap());
        if decision == Kind::ClosedForever {
            assert!(restored_alice.is_closed(bob_id.member_id()));
            assert!(restored_bob.is_closed(alice_id.member_id()));
            assert!(restored_alice
                .begin_introduction(
                    bob_id.member_id(),
                    &[99; 32],
                    &alice,
                    &KEY,
                    CONTEXT,
                    |_| panic!("closed pair cannot restart")
                )
                .is_err());
            let contradicting = bob
                .sign_contact_resolution(alice_id.member_id(), &NONCE, Kind::Answered)
                .unwrap();
            assert!(restored_alice
                .apply_resolution(&contradicting, &alice, &KEY, CONTEXT, |_| panic!(
                    "answer cannot reverse closure"
                ))
                .is_err());
        }
    }
}

#[test]
fn failed_persistence_cannot_resolve_or_close_and_unrelated_receipts_are_rejected() {
    let alice_id = MemberIdentity::new("synthetic-community").unwrap();
    let bob_id = MemberIdentity::new("synthetic-community").unwrap();
    let alice = common::root_device(&alice_id);
    let bob = common::root_device(&bob_id);
    let mut inbox = Inbox::new(&alice).unwrap();
    inbox
        .begin_introduction(
            bob_id.member_id(),
            &NONCE,
            &alice,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    let mut receipt = bob
        .sign_contact_resolution(alice_id.member_id(), &NONCE, Kind::ClosedForever)
        .unwrap();
    assert_eq!(
        inbox.apply_resolution(&receipt, &alice, &KEY, CONTEXT, |_| Err(
            Error::InvalidStore
        )),
        Err(Error::InvalidStore)
    );
    assert!(!inbox.is_closed(bob_id.member_id()));
    assert!(inbox.needs_resolution(bob_id.member_id()));
    receipt.introduction_id = [24; 32];
    assert!(inbox
        .apply_resolution(&receipt, &alice, &KEY, CONTEXT, |_| panic!(
            "wrong introduction"
        ))
        .is_err());
    receipt.introduction_id = NONCE;
    receipt.kind = Kind::Answered;
    assert!(inbox
        .apply_resolution(&receipt, &alice, &KEY, CONTEXT, |_| panic!(
            "tampered decision"
        ))
        .is_err());
    receipt.kind = Kind::ClosedForever;
    assert!(inbox
        .apply_resolution(&receipt, &alice, &KEY, CONTEXT, |_| Ok(()))
        .unwrap());
    assert_eq!(format!("{receipt:?}"), "ContactResolution([redacted])");
}

#[test]
fn a_later_verified_close_is_terminal_without_another_first_resolution_and_evidence_survives_restore(
) {
    let alice_id = MemberIdentity::new("synthetic-community").unwrap();
    let bob_id = MemberIdentity::new("synthetic-community").unwrap();
    let alice = common::root_device(&alice_id);
    let bob = common::root_device(&bob_id);
    let mut inbox = Inbox::new(&alice).unwrap();
    inbox
        .begin_introduction(
            bob_id.member_id(),
            &NONCE,
            &alice,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    let answer = bob
        .sign_contact_resolution(alice_id.member_id(), &NONCE, Kind::Answered)
        .unwrap();
    assert!(inbox
        .apply_resolution(&answer, &alice, &KEY, CONTEXT, |_| Ok(()))
        .unwrap());
    let close = bob
        .sign_contact_resolution(alice_id.member_id(), &NONCE, Kind::ClosedForever)
        .unwrap();
    let mut saved = Vec::new();
    assert!(
        !inbox
            .apply_resolution(&close, &alice, &KEY, CONTEXT, |state| {
                saved = state.to_vec();
                Ok(())
            })
            .unwrap(),
        "closing an answered contact is not another first resolution"
    );
    assert!(inbox.is_closed(bob_id.member_id()));
    let (mut restored, alice) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    let stored: ContactResolution = serde_json::from_slice(
        restored
            .inbound_resolution_receipt(bob_id.member_id())
            .unwrap(),
    )
    .unwrap();
    alice
        .verify_contact_resolution(&stored, bob_id.member_id(), &NONCE)
        .unwrap();
    assert_eq!(stored.kind, Kind::ClosedForever);
    assert!(!restored
        .apply_resolution(&close, &alice, &KEY, CONTEXT, |_| panic!(
            "exact replay changes nothing"
        ))
        .unwrap());
    assert!(restored
        .apply_resolution(&answer, &alice, &KEY, CONTEXT, |_| panic!("cannot reopen"))
        .is_err());
}
