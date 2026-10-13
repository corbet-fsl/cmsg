//! Key selection of the Oblivious HTTP endpoint: the verified community feed
//! replaces the configured keys, windows are enforced, and an older
//! publication never rolls keys back.
use cblv::keys::{Directory, KeySource, PublishedKey};
use cmsg::door::ohttp::{Keys, OhttpEndpoint};

/// X25519 key config (RFC 9458) with one HKDF-SHA256 / ChaCha20-Poly1305 suite.
fn config(id: u8) -> Vec<u8> {
    let mut bytes = vec![id, 0x00, 0x20];
    bytes.extend([id.wrapping_add(1); 32]);
    bytes.extend([0x00, 0x04, 0x00, 0x01, 0x00, 0x03]);
    bytes
}

fn directory(id: u8, from: u64, to: u64) -> Directory {
    Directory {
        relay: "https://relay.example".into(),
        keys: vec![PublishedKey {
            service: "gw.example".into(),
            key_id: id,
            config: config(id),
            not_before: from,
            not_after: to,
        }],
    }
}

fn endpoint(id: u8) -> OhttpEndpoint {
    let key = &directory(id, 0, 1000).keys[0];
    serde_json::from_value(serde_json::json!({
        "relay": "https://relay.example",
        "keys": [{
            "service": key.service,
            "key_id": key.key_id,
            "config": key.config,
            "not_before": key.not_before,
            "not_after": key.not_after,
        }],
    }))
    .unwrap()
}

fn key_id(keys: &Keys, now: u64) -> Option<u8> {
    keys.current("gw.example", now).map(|(_, key)| key.key_id)
}

#[test]
fn verified_feed_replaces_configured_keys() {
    let endpoint = endpoint(9);
    let keys = endpoint.keys().unwrap();
    assert_eq!(key_id(&keys, 5), Some(9));
    let feed = endpoint.feed();
    feed.install_snapshot(1, Some(directory(1, 0, 100).verify().unwrap()))
        .unwrap();
    assert_eq!(key_id(&keys, 5), Some(1));
    // A publication without the entry leaves no key and never falls back.
    feed.install_snapshot(2, None).unwrap();
    assert_eq!(key_id(&keys, 5), None);
    // A clone of the endpoint shares the same feed.
    assert_eq!(key_id(&endpoint.clone().keys().unwrap(), 5), None);
}

#[test]
fn keys_outside_their_window_are_never_used() {
    let endpoint = endpoint(9);
    let keys = endpoint.keys().unwrap();
    endpoint
        .feed()
        .install_snapshot(1, Some(directory(1, 10, 20).verify().unwrap()))
        .unwrap();
    assert_eq!(key_id(&keys, 9), None);
    assert_eq!(key_id(&keys, 10), Some(1));
    assert_eq!(key_id(&keys, 20), None);
}

#[test]
fn an_older_publication_never_rolls_keys_back() {
    let endpoint = endpoint(9);
    let keys = endpoint.keys().unwrap();
    let feed = endpoint.feed();
    feed.install_snapshot(5, Some(directory(2, 0, 100).verify().unwrap()))
        .unwrap();
    for revision in [4, 5] {
        assert!(feed
            .install_snapshot(revision, Some(directory(1, 0, 100).verify().unwrap()))
            .is_err());
    }
    assert_eq!(key_id(&keys, 5), Some(2));
}
