mod common;
use cmsg::{validate_text, Error, Member, OnionEndpoint, OnionTransport, Received, MAX_TEXT_BYTES};

fn pair() -> (Member, Member) {
    let mut a = common::member();
    let mut b = common::member();
    a.create_group().unwrap();
    let invitation = a.add(&b.key_package().unwrap()).unwrap();
    b.join(&invitation.welcome).unwrap();
    (a, b)
}
fn text(member: &mut Member, wire: &[u8]) -> String {
    match member.receive(wire).unwrap() {
        Received::Text(text) => text.text.clone(),
        _ => panic!("expected application message"),
    }
}
#[test]
fn two_members_exchange_utf8_without_plaintext_on_wire() {
    let (mut a, mut b) = pair();
    let sender_id = a.member_id().unwrap();
    let secret = "private synthetic message: Καλημέρα 🦀";
    let wire = a.send(secret.as_bytes()).unwrap();
    assert!(!wire.windows(secret.len()).any(|w| w == secret.as_bytes()));
    let received = b.receive(&wire).unwrap();
    assert!(matches!(received, Received::Text(t) if t.text == secret && t.member_id == sender_id));
    assert_eq!(text(&mut a, &b.send(b"reply").unwrap()), "reply");
}
#[test]
fn three_member_group_and_new_member_cannot_read_old_epoch() {
    let (mut a, mut b) = pair();
    let old = a.send(b"before joining").unwrap();
    let mut c = common::member();
    let invitation = a.add(&c.key_package().unwrap()).unwrap();
    assert!(matches!(
        b.receive(&invitation.commit).unwrap(),
        Received::MembershipChanged
    ));
    c.join(&invitation.welcome).unwrap();
    assert!(c.receive(&old).is_err());
    let wire = c.send(b"three members").unwrap();
    assert_eq!(text(&mut a, &wire), "three members");
    assert_eq!(text(&mut b, &wire), "three members");
}
#[test]
fn removed_member_cannot_decrypt_new_epoch() {
    let (mut a, mut b) = pair();
    let mut c = common::member();
    let invitation = a.add(&c.key_package().unwrap()).unwrap();
    b.receive(&invitation.commit).unwrap();
    c.join(&invitation.welcome).unwrap();
    let removal = a.remove(2).unwrap();
    b.receive(&removal).unwrap();
    let _ = c.receive(&removal);
    let wire = a.send(b"after removal").unwrap();
    assert_eq!(text(&mut b, &wire), "after removal");
    assert!(c.receive(&wire).is_err());
}
#[test]
fn replay_fails_but_out_of_order_messages_work_once() {
    let (mut a, mut b) = pair();
    let first = a.send(b"first").unwrap();
    let second = a.send(b"second").unwrap();
    assert_eq!(text(&mut b, &second), "second");
    assert_eq!(text(&mut b, &first), "first");
    assert!(b.receive(&first).is_err());
    assert!(b.receive(&second).is_err());
}
#[test]
fn tampered_and_cross_group_ciphertexts_fail() {
    let (mut a, mut b) = pair();
    let (_, mut outsider) = pair();
    let wire = a.send(b"authentic").unwrap();
    assert!(outsider.receive(&wire).is_err());
    let mut bad = wire.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(b.receive(&bad).is_err());
    assert_eq!(text(&mut b, &wire), "authentic");
    let mut trailing = a.send(b"framing").unwrap();
    trailing.push(0);
    assert!(b.receive(&trailing).is_err());
}
#[test]
fn text_limits_are_bytes_and_urls_are_inert_text() {
    assert!(validate_text(b"hello").is_ok());
    assert_eq!(validate_text(&[0xff]), Err(Error::InvalidText));
    assert_eq!(validate_text(b""), Err(Error::InvalidText));
    assert!(validate_text(&vec![b'x'; MAX_TEXT_BYTES]).is_ok());
    assert_eq!(
        validate_text(&vec![b'x'; MAX_TEXT_BYTES + 1]),
        Err(Error::InvalidText)
    );
    assert_eq!(
        validate_text(&"🦀".repeat(MAX_TEXT_BYTES / 4 + 1).into_bytes()),
        Err(Error::InvalidText)
    );
    let (mut a, mut b) = pair();
    let inert = "<img src='http://127.0.0.1:9/trap'> ![image](https://example.invalid/image)";
    assert_eq!(text(&mut b, &a.send(inert.as_bytes()).unwrap()), inert);
    assert!(a.send(&[0xff]).is_err());
}
#[test]
fn encrypted_snapshot_restores_ratchet_and_replay_state() {
    let (mut a, mut b) = pair();
    let wire = a.send(b"seen before backup").unwrap();
    text(&mut b, &wire);
    let key = [23u8; 32];
    let saved = b.snapshot(&key, b"synthetic-wallet-1").unwrap();
    assert!(!saved
        .windows(b"seen before backup".len())
        .any(|w| w == b"seen before backup"));
    let mut restored = Member::restore(&saved, &key, b"synthetic-wallet-1").unwrap();
    assert_eq!(restored.history()[0].text, "seen before backup");
    assert!(restored.receive(&wire).is_err());
    assert_eq!(
        text(&mut restored, &a.send(b"after restore").unwrap()),
        "after restore"
    );
    assert_eq!(
        text(&mut a, &restored.send(b"restored reply").unwrap()),
        "restored reply"
    );
}
#[test]
fn wrong_key_context_and_altered_snapshot_fail_closed() {
    let (a, _) = pair();
    let saved = a.snapshot(&[11; 32], b"wallet-a").unwrap();
    assert!(Member::restore(&saved, &[12; 32], b"wallet-a").is_err());
    assert!(Member::restore(&saved, &[11; 32], b"wallet-b").is_err());
    assert_ne!(saved, a.snapshot(&[11; 32], b"wallet-a").unwrap());
    for index in [0, 8, saved.len() - 1] {
        let mut changed = saved.clone();
        changed[index] ^= 1;
        assert!(Member::restore(&changed, &[11; 32], b"wallet-a").is_err());
    }
    assert!(Member::restore(b"plaintext", &[11; 32], b"wallet-a").is_err());
}
#[test]
fn arbitrary_peers_cannot_choose_clearnet_routes() {
    for host in [
        "127.0.0.1",
        "example.com",
        "https://example.com",
        "a.onion",
        "evil.onion.example.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
    ] {
        assert!(OnionEndpoint::parse(host, 80).is_err(), "accepted {host}");
    }
    assert!(OnionTransport::new("1.2.3.4:9050".parse().unwrap()).is_err());
    assert!(OnionTransport::new("127.0.0.1:9050".parse().unwrap()).is_ok());
}
#[tokio::test]
async fn missing_proxy_fails_closed() {
    // A valid v3 address synthesized from public key material; no Tor connection.
    use sha3::{Digest, Sha3_256};
    let key = [42u8; 32];
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(key);
    hash.update([3]);
    let digest = hash.finalize();
    let mut address = key.to_vec();
    address.extend_from_slice(&digest[..2]);
    address.push(3);
    let host = format!(
        "{}.onion",
        data_encoding::BASE32_NOPAD.encode(&address).to_lowercase()
    );
    let endpoint = OnionEndpoint::parse(&host, 80).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let transport = OnionTransport::new(addr).unwrap();
    assert!(transport.connect(&endpoint).await.is_err());
}
