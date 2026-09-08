mod common;
use cmsg::{Acceptance, Error, Inbox, Member, Received, Redemption};
use std::cell::RefCell;
const KEY: [u8; 32] = [31; 32];
const CONTEXT: &[u8] = b"synthetic-inbox";
fn invitation() -> (Member, Member, Vec<u8>) {
    let mut a = common::member();
    let b = common::member();
    a.create_group().unwrap();
    let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
    (a, b, welcome)
}
#[test]
fn unknown_sender_requires_a_permit_after_full_invitation_validation() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("no state to persist"),
                |_| panic!("no debit allowed")
            )
            .unwrap(),
        Acceptance::NeedsPermit
    );
    assert!(inbox
        .accept(
            &mut b,
            b"malformed",
            Some(b"recipient-generated opaque attempt"),
            &KEY,
            CONTEXT,
            |_| panic!("bad invitation cannot persist"),
            |_| panic!("bad invitation cannot spend")
        )
        .is_err());
}
#[test]
fn persist_pending_then_redeem_then_commit_before_delivering() {
    let (mut a, mut b, welcome) = invitation();
    let sender = a.member_id().unwrap();
    let mut inbox = Inbox::new(&b).unwrap();
    let order = RefCell::new(Vec::new());
    let saved = RefCell::new(Vec::new());
    let result = inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"private-recipient-claim-with-permit"),
            &KEY,
            CONTEXT,
            |state| {
                order.borrow_mut().push("persist");
                *saved.borrow_mut() = state.to_vec();
                Ok(())
            },
            |attempt| {
                assert_eq!(attempt, b"private-recipient-claim-with-permit");
                order.borrow_mut().push("redeem");
                Redemption::Accepted
            },
        )
        .unwrap();
    assert_eq!(result, Acceptance::Joined);
    assert_eq!(*order.borrow(), vec!["persist", "redeem", "persist"]);
    assert!(inbox.is_known(&sender));
    let saved = saved.into_inner();
    assert!(!saved.windows(sender.len()).any(|b| b == sender.as_bytes()));
    let (restored, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert!(restored.is_known(&sender));
    assert!(
        matches!(b.receive(&a.send(b"accepted").unwrap()).unwrap(),Received::Text(t) if t.text=="accepted")
    );
}
#[test]
fn failed_pending_persistence_cannot_spend() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert!(inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"opaque-attempt"),
            &KEY,
            CONTEXT,
            |_| Err(Error::InvalidStore),
            |_| panic!("no durable intent")
        )
        .is_err());
    assert!(b.send(b"not joined").is_err());
}
#[test]
fn ambiguous_redemption_restores_exact_attempt_and_does_not_replenish_it() {
    let (a, mut b, welcome) = invitation();
    let sender = a.member_id().unwrap();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"same-private-claim"),
                &KEY,
                CONTEXT,
                |state| {
                    saved = state.to_vec();
                    Ok(())
                },
                |_| Redemption::Indeterminate
            )
            .unwrap(),
        Acceptance::Pending
    );
    assert!(!inbox.is_known(&sender));
    assert!(b.send(b"not accepted").is_err());
    let (mut inbox, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"replacement-claim"),
                &KEY,
                CONTEXT,
                |_| panic!("cannot replace"),
                |_| panic!("cannot replace")
            )
            .unwrap(),
        Acceptance::Busy
    );
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |attempt| {
                    assert_eq!(attempt, b"same-private-claim");
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
}
#[test]
fn failed_final_write_keeps_pending_and_idempotent_retry_can_finish() {
    let (a, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    let mut writes = 0;
    let result = inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"durable-private-claim"),
            &KEY,
            CONTEXT,
            |state| {
                writes += 1;
                if writes == 1 {
                    saved = state.to_vec();
                    Ok(())
                } else {
                    Err(Error::InvalidStore)
                }
            },
            |_| Redemption::Accepted,
        )
        .unwrap();
    assert_eq!(result, Acceptance::Pending);
    assert!(!inbox.is_known(&a.member_id().unwrap()));
    assert!(b.send(b"not committed").is_err());
    let (mut inbox, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |attempt| {
                    assert_eq!(attempt, b"durable-private-claim");
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
}
#[test]
fn rejected_permit_never_joins_or_establishes_a_known_contact() {
    let (a, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"spent-under-another-claim"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| Redemption::Rejected
            )
            .unwrap(),
        Acceptance::Rejected
    );
    assert!(!inbox.is_known(&a.member_id().unwrap()));
    assert!(b.send(b"blocked").is_err());
}
fn member_with_id(id: u8) -> Member {
    let mut member = Member::new().unwrap();
    member
        .bind_admission(
            common::grant(&member.chat_public_key(), id),
            common::trust(),
            100,
        )
        .unwrap();
    member
}
#[test]
fn known_counterpart_survives_encrypted_restore_and_new_chat_keys_without_another_debit() {
    let mut a = member_with_id(240);
    let mut b = member_with_id(241);
    a.create_group().unwrap();
    let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"first-recipient-claim"),
                &KEY,
                CONTEXT,
                |state| {
                    saved = state.to_vec();
                    Ok(())
                },
                |_| Redemption::Accepted
            )
            .unwrap(),
        Acceptance::Joined
    );
    let (mut inbox, _) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    let mut new_a = member_with_id(240);
    let mut new_b = member_with_id(241);
    new_a.create_group().unwrap();
    let welcome = new_a.add(&new_b.key_package().unwrap()).unwrap().welcome;
    assert_eq!(
        inbox
            .accept(
                &mut new_b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| panic!("known counterpart must not spend again")
            )
            .unwrap(),
        Acceptance::Joined
    );
    assert!(Inbox::restore(&saved, &[32; 32], CONTEXT).is_err());
}
#[test]
fn one_group_invitation_charges_only_its_authenticated_inviter() {
    let mut a = common::member();
    let mut b = common::member();
    let mut c = common::member();
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let welcome = a.add(&c.key_package().unwrap()).unwrap().welcome;
    let mut inbox = Inbox::new(&c).unwrap();
    let mut debits = 0;
    assert_eq!(
        inbox
            .accept(
                &mut c,
                &welcome,
                Some(b"one-invitation-claim"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| {
                    debits += 1;
                    Redemption::Accepted
                }
            )
            .unwrap(),
        Acceptance::Joined
    );
    assert_eq!(debits, 1);
    assert!(inbox.is_known(&a.member_id().unwrap()));
    assert!(!inbox.is_known(&b.member_id().unwrap()));
}
#[test]
fn pending_spend_cannot_be_reassigned_to_a_different_valid_welcome() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"pending-claim"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| Redemption::Indeterminate
            )
            .unwrap(),
        Acceptance::Pending
    );
    let mut other = common::member();
    other.create_group().unwrap();
    let replacement = other.add(&b.key_package().unwrap()).unwrap().welcome;
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &replacement,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("no replacement"),
                |_| panic!("no replacement")
            )
            .unwrap(),
        Acceptance::Busy
    );
}
#[test]
fn an_inbox_cannot_be_reused_by_another_recipient() {
    let (_, mut b, welcome) = invitation();
    let other = common::member();
    let mut inbox = Inbox::new(&other).unwrap();
    assert!(inbox
        .accept(
            &mut b,
            &welcome,
            Some(b"attempt"),
            &KEY,
            CONTEXT,
            |_| panic!("wrong recipient"),
            |_| panic!("wrong recipient")
        )
        .is_err());
}
#[test]
fn local_cancel_durably_clears_pending_without_a_refund_or_redemption_call() {
    let (_, mut b, welcome) = invitation();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"indeterminate-claim"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| Redemption::Indeterminate
            )
            .unwrap(),
        Acceptance::Pending
    );
    inbox
        .cancel_pending(&b, &KEY, CONTEXT, |state| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap();
    assert!(inbox.pending_welcome().is_none());
    let (restored, _) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert!(restored.pending_welcome().is_none());
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("new permit required"),
                |_| panic!("no refund")
            )
            .unwrap(),
        Acceptance::NeedsPermit
    );
}
#[test]
fn local_blocks_persist_and_stop_unknown_and_previously_known_inviters_before_spending() {
    let mut a = member_with_id(230);
    let mut b = member_with_id(231);
    a.create_group().unwrap();
    let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
    let sender = a.member_id().unwrap();
    let mut inbox = Inbox::new(&b).unwrap();
    let mut saved = Vec::new();
    inbox
        .set_blocked(&sender, true, &b, &KEY, CONTEXT, |state| {
            saved = state.to_vec();
            Ok(())
        })
        .unwrap();
    let (mut inbox, mut b) = Inbox::restore(&saved, &KEY, CONTEXT).unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"unused-permit"),
                &KEY,
                CONTEXT,
                |_| panic!("blocked"),
                |_| panic!("blocked")
            )
            .unwrap(),
        Acceptance::Blocked
    );
    inbox
        .set_blocked(&sender, false, &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"first-attempt"),
                &KEY,
                CONTEXT,
                |_| Ok(()),
                |_| Redemption::Accepted
            )
            .unwrap(),
        Acceptance::Joined
    );
    assert!(inbox.is_known(&sender));
    inbox
        .set_blocked(&sender, true, &b, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    let mut a = member_with_id(230);
    let mut b = member_with_id(231);
    a.create_group().unwrap();
    let welcome = a.add(&b.key_package().unwrap()).unwrap().welcome;
    assert_eq!(
        inbox
            .accept(
                &mut b,
                &welcome,
                None,
                &KEY,
                CONTEXT,
                |_| panic!("known but blocked"),
                |_| panic!("known but blocked")
            )
            .unwrap(),
        Acceptance::Blocked
    );
}

#[test]
fn inbox_accepts_the_same_context_lengths_as_member_and_binds_restore_context() {
    for length in [1, 128] {
        let (_, mut b, welcome) = invitation();
        let mut inbox = Inbox::new(&b).unwrap();
        let context = vec![44; length];
        assert!(b.snapshot(&KEY, &context).is_ok());
        let mut saved = Vec::new();
        assert_eq!(
            inbox
                .accept(
                    &mut b,
                    &welcome,
                    Some(b"recipient-claim"),
                    &KEY,
                    &context,
                    |state| {
                        saved = state.to_vec();
                        Ok(())
                    },
                    |_| Redemption::Accepted
                )
                .unwrap(),
            Acceptance::Joined
        );
        assert!(Inbox::restore(&saved, &KEY, &context).is_ok());
        assert!(Inbox::restore(&saved, &KEY, &vec![45; length]).is_err());
    }
    for length in [0, 129] {
        let (_, mut b, welcome) = invitation();
        let mut inbox = Inbox::new(&b).unwrap();
        let context = vec![44; length];
        assert!(b.snapshot(&KEY, &context).is_err());
        assert!(inbox
            .accept(
                &mut b,
                &welcome,
                Some(b"recipient-claim"),
                &KEY,
                &context,
                |_| panic!("invalid context cannot persist"),
                |_| panic!("invalid context cannot spend")
            )
            .is_err());
    }
}
