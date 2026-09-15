mod common;
use cmsg::{Acceptance, Error, Inbox, Member, Received, Redemption};

const KEY: [u8; 32] = [51; 32];
const CONTEXT: &[u8] = b"synthetic-permanent-closure";

fn device(identity: u8) -> Member {
    let mut member = Member::new().unwrap();
    member
        .bind_admission(
            common::grant(&member.chat_public_key(), identity),
            common::trust(),
            100,
        )
        .unwrap();
    member
}

fn pair() -> (Member, Member, Inbox) {
    let mut sender = device(1);
    let mut recipient = device(2);
    sender.create_group().unwrap();
    recipient
        .join(
            &sender
                .add(&recipient.key_package().unwrap())
                .unwrap()
                .welcome,
        )
        .unwrap();
    let inbox = Inbox::new(&recipient).unwrap();
    (sender, recipient, inbox)
}

#[test]
fn permanent_closure_survives_restore_unblock_new_thread_and_new_device_keys() {
    let (sender, recipient, mut inbox) = pair();
    let identity = sender.member_id().unwrap();
    let mut checkpoint = Vec::new();
    inbox
        .close_forever(&identity, &recipient, &KEY, CONTEXT, |sealed| {
            checkpoint = sealed.to_vec();
            Ok(())
        })
        .unwrap();
    let (mut inbox, recipient) = Inbox::restore(&checkpoint, &KEY, CONTEXT).unwrap();
    inbox
        .set_blocked(&identity, false, &recipient, &KEY, CONTEXT, |_| Ok(()))
        .unwrap();
    assert!(inbox.is_closed(&identity));
    for _ in 0..3 {
        let mut renewed_sender = device(1);
        let mut renewed_recipient = device(2);
        renewed_sender.create_group().unwrap();
        let welcome = renewed_sender
            .add(&renewed_recipient.key_package().unwrap())
            .unwrap()
            .welcome;
        assert_eq!(
            inbox
                .accept(
                    &mut renewed_recipient,
                    &welcome,
                    Some(b"fresh quota cannot override close"),
                    &KEY,
                    CONTEXT,
                    |_| panic!("closed contact must not write"),
                    |_| panic!("closed contact must not spend")
                )
                .unwrap(),
            Acceptance::Blocked
        );
    }
}

#[test]
fn closed_peers_cannot_expose_plaintext_or_write_history_in_an_existing_group() {
    let (mut sender, mut recipient, mut inbox) = pair();
    let before_close = sender.send(b"in flight when closed").unwrap();
    inbox
        .close_forever(
            &sender.member_id().unwrap(),
            &recipient,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    assert!(inbox.receive(&mut recipient, &before_close).is_err());
    assert!(inbox.send(&mut recipient, b"not released").is_err());
    assert!(inbox.send_bytes(&mut recipient, b"not released").is_err());
    assert!(recipient.history().is_empty());
    // The lower-level MLS primitive has no application contact policy. This
    // check also establishes that rejection did not consume its receive key.
    assert!(
        matches!(recipient.receive(&before_close).unwrap(), Received::Text(message) if message.text == "in flight when closed")
    );
}

#[test]
fn failed_close_write_keeps_the_previous_contact_policy() {
    let (mut sender, mut recipient, mut inbox) = pair();
    let identity = sender.member_id().unwrap();
    assert_eq!(
        inbox.close_forever(&identity, &recipient, &KEY, CONTEXT, |_| Err(
            Error::InvalidStore
        )),
        Err(Error::InvalidStore)
    );
    assert!(!inbox.is_closed(&identity));
    assert!(matches!(
        inbox
            .receive(&mut recipient, &sender.send(b"write failed").unwrap())
            .unwrap(),
        Received::Text(_)
    ));
    assert!(inbox
        .close_forever(
            &recipient.member_id().unwrap(),
            &recipient,
            &KEY,
            CONTEXT,
            |_| panic!("cannot close own identity")
        )
        .is_err());
}

#[test]
fn another_inviter_cannot_smuggle_a_closed_member_into_a_group() {
    let mut inviter = device(3);
    let mut closed = device(1);
    let mut recipient = device(2);
    inviter.create_group().unwrap();
    closed
        .join(&inviter.add(&closed.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let welcome = inviter
        .add(&recipient.key_package().unwrap())
        .unwrap()
        .welcome;
    let mut inbox = Inbox::new(&recipient).unwrap();
    inbox
        .close_forever(
            &closed.member_id().unwrap(),
            &recipient,
            &KEY,
            CONTEXT,
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        inbox
            .accept(
                &mut recipient,
                &welcome,
                Some(b"valid looking intro"),
                &KEY,
                CONTEXT,
                |_| panic!("no hidden closed participant"),
                |_| Redemption::Accepted
            )
            .unwrap(),
        Acceptance::Blocked
    );
}
