mod common;
use cmsg::{Member, Received, MAX_DATA_BYTES};

fn pair() -> (Member, Member) {
    let mut sender = common::member();
    let mut receiver = common::member();
    sender.create_group().unwrap();
    receiver
        .join(
            &sender
                .add(&receiver.key_package().unwrap())
                .unwrap()
                .welcome,
        )
        .unwrap();
    (sender, receiver)
}

#[test]
fn binary_payloads_are_authenticated_bounded_and_distinct_from_text() {
    let (mut sender, mut receiver) = pair();
    for payload in [
        vec![],
        vec![0, 255, 128, 1],
        b"UTF-8 remains bytes".to_vec(),
        vec![42; MAX_DATA_BYTES],
    ] {
        let wire = sender.send_bytes(&payload).unwrap();
        let received = receiver.receive(&wire).unwrap();
        assert_eq!(format!("{received:?}"), "Bytes([redacted])");
        assert!(matches!(received, Received::Bytes(message)
            if message.bytes == payload && message.member_id == sender.member_id().unwrap()));
        assert!(receiver.receive(&wire).is_err(), "binary replay must fail");
    }
    assert!(sender.send_bytes(&vec![0; MAX_DATA_BYTES + 1]).is_err());
    assert!(sender.history().is_empty());
    assert!(receiver.history().is_empty());
    assert!(
        matches!(receiver.receive(&sender.send(b"typed text").unwrap()).unwrap(),
        Received::Text(message) if message.text == "typed text")
    );
}

#[test]
fn a_tampered_binary_message_cannot_consume_the_authentic_receive_key() {
    let (mut sender, mut receiver) = pair();
    let payload = b"sensitive opaque protocol material";
    let wire = sender.send_bytes(payload).unwrap();
    assert!(!wire.windows(payload.len()).any(|part| part == payload));
    let mut altered = wire.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(receiver.receive(&altered).is_err());
    assert!(
        matches!(receiver.receive(&wire).unwrap(), Received::Bytes(message) if message.bytes == payload)
    );
}
