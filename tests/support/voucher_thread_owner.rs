//! The direct thread of a vouching between two real member Vaults: the contact
//! exists from the bond alone, a message written before the thread exists waits
//! on the newcomer's device, the sponsor's Welcome creates the thread once, and
//! both sides chat right after the admission.
use super::inbox_waves_tests::{member, Ports};
use super::profile_owner_tests::{open_as, ProfileOwner};
use super::*;
use crate::door::inbox_conversation::{Answer, Command, ConversationSend, Wired};

async fn lineage_of(owner: &ProfileOwner) -> ckmg::Lineage {
    owner
        .retained
        .lock()
        .await
        .as_mut()
        .unwrap()
        .vault
        .keys()
        .lineage()
        .await
        .unwrap()
}

async fn say(
    owner: &mut ProfileOwner,
    ports: &Ports,
    peer: &str,
    conversation: [u8; 32],
    text: &str,
) -> crate::door::inbox_conversation::Sent {
    let command = Command::Send(ConversationSend {
        peer: peer.into(),
        conversation,
        text: text.into(),
    });
    match owner.conversation(command, ports).await.unwrap() {
        Answer::Sent(sent) => sent,
        _ => panic!("a sent message"),
    }
}

/// Deliver `wire` to `to`, hand the receipt back to `from`; returns the text.
async fn deliver(
    from: (&mut ProfileOwner, &Ports, &str),
    to: (&mut ProfileOwner, &Ports, &str),
    conversation: [u8; 32],
    wire: Vec<u8>,
) -> Vec<u8> {
    let received = to
        .0
        .conversation(
            Command::Receive(Wired {
                peer: from.2.into(),
                conversation,
                wire,
            }),
            to.1,
        )
        .await
        .unwrap();
    let Answer::Received(received) = received else {
        panic!("a received message")
    };
    let message = received.message.expect("a new message");
    from.0
        .conversation(
            Command::Ack(Wired {
                peer: to.2.into(),
                conversation,
                wire: received.receipt,
            }),
            from.1,
        )
        .await
        .unwrap();
    message.bytes
}

#[tokio::test]
async fn sponsor_and_newcomer_chat_right_after_the_admission() {
    let (sponsor_id, newcomer_id) = (member("ab"), member("cd"));
    let (mut sponsor, _, _) = open_as(&sponsor_id, false).await;
    let (mut newcomer, _, _) = open_as(&newcomer_id, false).await;
    let sponsor_ports = Ports {
        lineage: lineage_of(&newcomer).await,
    };
    let newcomer_ports = Ports {
        lineage: lineage_of(&sponsor).await,
    };
    let bond = [7; 32];

    // Admission: each device derives the same contact from the bond alone, and
    // repeating the step writes nothing.
    let conversation = sponsor.contact_by_voucher(&newcomer_id, bond).await.unwrap();
    assert_eq!(
        newcomer.contact_by_voucher(&sponsor_id, bond).await.unwrap(),
        conversation
    );
    assert_eq!(
        sponsor.contact_by_voucher(&newcomer_id, bond).await.unwrap(),
        conversation
    );

    // The newcomer never waits: a message written before the Welcome arrives is
    // kept on the device.
    let package = newcomer
        .voucher_key_package(conversation, &newcomer_ports)
        .await
        .unwrap();
    let early = say(&mut newcomer, &newcomer_ports, &sponsor_id, conversation, "hello early").await;
    assert!(early.queued && early.wire.is_empty());

    // The sponsor's device creates the thread once; a repeat returns the same Welcome.
    let welcome = sponsor
        .voucher_create(&newcomer_id, conversation, &package, &sponsor_ports)
        .await
        .unwrap();
    assert_eq!(
        sponsor
            .voucher_create(&newcomer_id, conversation, &package, &sponsor_ports)
            .await
            .unwrap(),
        welcome
    );

    // The newcomer joins from the Welcome and the early message goes out; a
    // repeated join changes nothing.
    let early_wires = newcomer
        .voucher_join(&sponsor_id, conversation, &welcome, &newcomer_ports)
        .await
        .unwrap();
    assert_eq!(early_wires.len(), 1);
    assert!(newcomer
        .voucher_join(&sponsor_id, conversation, &welcome, &newcomer_ports)
        .await
        .unwrap()
        .is_empty());
    let text = deliver(
        (&mut newcomer, &newcomer_ports, &newcomer_id),
        (&mut sponsor, &sponsor_ports, &sponsor_id),
        conversation,
        early_wires[0].clone(),
    )
    .await;
    assert_eq!(text, b"hello early");

    // Chat both ways.
    let sent = say(&mut sponsor, &sponsor_ports, &newcomer_id, conversation, "welcome aboard").await;
    assert!(!sent.queued);
    let text = deliver(
        (&mut sponsor, &sponsor_ports, &sponsor_id),
        (&mut newcomer, &newcomer_ports, &newcomer_id),
        conversation,
        sent.wire,
    )
    .await;
    assert_eq!(text, b"welcome aboard");
    let sent = say(&mut newcomer, &newcomer_ports, &sponsor_id, conversation, "thank you").await;
    let text = deliver(
        (&mut newcomer, &newcomer_ports, &newcomer_id),
        (&mut sponsor, &sponsor_ports, &sponsor_id),
        conversation,
        sent.wire,
    )
    .await;
    assert_eq!(text, b"thank you");
}

/// A kill between the flushed send and the queue delete: the entry finds its own
/// message in the thread after the restart, so the early message is written
/// once, and its wire still goes out through the pending retry.
#[tokio::test]
async fn a_kill_between_the_flushed_send_and_the_queue_delete_sends_once() {
    let (sponsor_id, newcomer_id) = (member("ab"), member("cd"));
    let (mut sponsor, _, _) = open_as(&sponsor_id, false).await;
    let (mut newcomer, _, _) = open_as(&newcomer_id, false).await;
    let sponsor_ports = Ports {
        lineage: lineage_of(&newcomer).await,
    };
    let newcomer_ports = Ports {
        lineage: lineage_of(&sponsor).await,
    };
    let bond = [9; 32];
    let conversation = sponsor.contact_by_voucher(&newcomer_id, bond).await.unwrap();
    newcomer.contact_by_voucher(&sponsor_id, bond).await.unwrap();
    let package = newcomer
        .voucher_key_package(conversation, &newcomer_ports)
        .await
        .unwrap();
    let early = say(&mut newcomer, &newcomer_ports, &sponsor_id, conversation, "once only").await;
    assert!(early.queued);
    let welcome = sponsor
        .voucher_create(&newcomer_id, conversation, &package, &sponsor_ports)
        .await
        .unwrap();

    // The process dies after the send was committed and before the queue entry
    // was deleted.
    crate::door::voucher_thread::tests_kill::arm();
    assert!(newcomer
        .voucher_join(&sponsor_id, conversation, &welcome, &newcomer_ports)
        .await
        .is_err());
    // The queue entry left in the same transaction as the send. After the
    // restart the join repeats: nothing is written a second time.
    assert!(newcomer
        .voucher_join(&sponsor_id, conversation, &welcome, &newcomer_ports)
        .await
        .unwrap()
        .is_empty());

    // The one message is still Pending and leaves through the retry.
    let Answer::Retried(retried) = newcomer
        .conversation(
            Command::Retry(crate::door::inbox_conversation::ConversationRetry {
                peer: sponsor_id.clone(),
                conversation,
                message: crate::door::voucher_thread::tests_kill::sent(),
            }),
            &newcomer_ports,
        )
        .await
        .unwrap()
    else {
        panic!("a retried message")
    };
    let text = deliver(
        (&mut newcomer, &newcomer_ports, &newcomer_id),
        (&mut sponsor, &sponsor_ports, &sponsor_id),
        conversation,
        retried.wire,
    )
    .await;
    assert_eq!(text, b"once only");
    let received = sponsor
        .history(crate::door::facades::Conversation { conversation })
        .await
        .unwrap();
    assert_eq!(received.len(), 1);
    // Another restart changes nothing.
    assert!(newcomer
        .voucher_join(&sponsor_id, conversation, &welcome, &newcomer_ports)
        .await
        .unwrap()
        .is_empty());
}
