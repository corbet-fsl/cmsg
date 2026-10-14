use super::*;

fn address(byte: u8) -> Address {
    Address::new(Scheme::new("tor").unwrap(), vec![byte; 8]).unwrap()
}

#[test]
fn reachability_round_trips_and_drops_garbage() {
    let own = vec![address(1), address(2)];
    assert_eq!(decode_reachability(&encode_reachability(&own)), own);
    assert!(decode_reachability(b"not json").is_empty());
    assert!(decode_reachability(br#"[{"scheme":"BAD!","address":"AA"}]"#).is_empty());
    let many: Vec<Address> = (0..20).map(address).collect();
    assert_eq!(decode_reachability(&encode_reachability(&many)).len(), MAX_ADDRESSES);
}

#[test]
fn the_book_keeps_the_latest_and_ignores_empty_updates() {
    let mut book = Book::default();
    book.learn("bob", &encode_reachability(&[address(1)]));
    book.learn("bob", &encode_reachability(&[address(2)]));
    assert_eq!(book.get("bob"), Some(&vec![address(2)]));
    book.learn("bob", b"junk");
    assert_eq!(book.get("bob"), Some(&vec![address(2)]));
}

#[test]
fn frames_are_versioned_and_strict() {
    let frame = Frame {
        version: FRAME_VERSION,
        reach: vec![1],
        body: Body::WaveAck { nonce: [7; 32], kind: "hello".into() },
    };
    let bytes = serde_json::to_vec(&frame).unwrap();
    assert_eq!(serde_json::from_slice::<Frame>(&bytes).unwrap(), frame);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["extra"] = json!(1);
    assert!(serde_json::from_value::<Frame>(value).is_err());
    let chat = Frame {
        version: 2,
        reach: vec![],
        body: Body::Chat { conversation: [1; 32], wire: vec![9] },
    };
    // A future version still parses; the receiver drops it by version.
    let parsed: Frame = serde_json::from_slice(&serde_json::to_vec(&chat).unwrap()).unwrap();
    assert_ne!(parsed.version, FRAME_VERSION);
}

#[test]
fn defaults_keep_presence_inside_a_short_lease() {
    let config = Config::default();
    assert!(config.heartbeat <= 30 && config.resend > config.tick);
}
