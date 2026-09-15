#![cfg(target_arch = "wasm32")]
//! Executed in a real browser by wasm-bindgen-test. This is crypto/ABI evidence,
//! not evidence of Tor connectivity or a browser-hosted onion service.
mod common;
use cmsg::browser::{BrowserFrameCodec, BrowserIdentity, BrowserMember, BrowserOnionEndpoint};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn member(id: u8) -> BrowserMember {
    let mut member = BrowserMember::new().unwrap();
    let identity = BrowserIdentity::new(&common::trust().community_id).unwrap();
    let mut grant = common::grant(&member.chat_public_key(), id);
    grant.member_id = identity.member_id();
    common::sign(&mut grant);
    let authorization = identity
        .authorize_device(&member.chat_public_key(), 1.0, 9_000_000_000.0)
        .unwrap();
    member
        .bind_device_admission(
            &serde_json::to_string(&grant).unwrap(),
            &serde_json::to_string(&common::trust()).unwrap(),
            &authorization,
        )
        .unwrap();
    member
}

#[wasm_bindgen_test]
fn browser_root_identity_restores_without_exporting_a_private_key() {
    let identity = BrowserIdentity::new("synthetic-community").unwrap();
    let id = identity.member_id();
    let public = identity.public_key();
    let key = [9u8; 32];
    let sealed = identity.seal(&key, b"identity-fixture").unwrap();
    let restored = BrowserIdentity::restore(
        &sealed,
        &key,
        "synthetic-community",
        &id,
        b"identity-fixture",
    )
    .unwrap();
    assert_eq!(restored.member_id(), id);
    assert_eq!(restored.public_key(), public);
    assert!(BrowserIdentity::restore(
        &sealed,
        &[10u8; 32],
        "synthetic-community",
        &id,
        b"identity-fixture",
    )
    .is_err());
}

#[wasm_bindgen_test]
fn browser_mls_roundtrip_keeps_arbitrary_bytes_and_text_distinct() {
    let mut alice = member(11);
    let mut bob = member(12);
    alice.create_group().unwrap();
    let invitation = alice.add(&bob.key_package().unwrap()).unwrap();
    bob.join(&invitation.welcome()).unwrap();
    let bytes = [0, 255, 128, 10, 0];
    let wire = alice.send_bytes(&bytes).unwrap();
    let received = bob.receive(&wire).unwrap();
    assert_eq!(received.kind(), "bytes");
    assert_eq!(received.bytes(), bytes);
    assert_eq!(received.member_id().unwrap(), alice.member_id().unwrap());
    assert_eq!(received.text(), None);
    assert!(bob.receive(&wire).is_err());
    let received = alice
        .receive(&bob.send_text("literal <tag> 🦀").unwrap())
        .unwrap();
    assert_eq!(received.kind(), "text");
    assert_eq!(received.text().as_deref(), Some("literal <tag> 🦀"));
}

#[wasm_bindgen_test]
fn browser_snapshot_restores_session_and_rejects_wrong_context_or_key() {
    let mut alice = member(21);
    let mut bob = member(22);
    alice.create_group().unwrap();
    bob.join(&alice.add(&bob.key_package().unwrap()).unwrap().welcome())
        .unwrap();
    let key = [7u8; 32];
    let sealed = alice.snapshot(&key, b"browser-fixture").unwrap();
    assert!(BrowserMember::restore(&sealed, &[8; 32], b"browser-fixture").is_err());
    assert!(BrowserMember::restore(&sealed, &key, b"another-context").is_err());
    assert!(BrowserMember::restore(&sealed, &[7; 31], b"browser-fixture").is_err());
    drop(alice);
    let mut restored = BrowserMember::restore(&sealed, &key, b"browser-fixture").unwrap();
    assert_eq!(
        bob.receive(&restored.send_bytes(&[255, 0]).unwrap())
            .unwrap()
            .bytes(),
        [255, 0]
    );
}

#[wasm_bindgen_test]
fn browser_frame_binding_accepts_fragments_and_rejects_routes() {
    let mut codec = BrowserFrameCodec::new(64.0).unwrap();
    let frame = codec.encode(&[0, 255]).unwrap();
    assert_eq!(codec.push(&frame[..3]).unwrap().length(), 0);
    let frames = codec.push(&frame[3..]).unwrap();
    assert_eq!(frames.length(), 1);
    assert_eq!(js_sys::Uint8Array::new(&frames.get(0)).to_vec(), [0, 255]);
    codec.finish().unwrap();
    assert!(codec.push(&[0]).is_err());
    for host in ["127.0.0.1", "example.com", "a.onion", "https://example.com"] {
        assert!(BrowserOnionEndpoint::new(host, 80.0).is_err());
    }
}

#[wasm_bindgen_test]
fn browser_rejects_tampering_without_losing_the_valid_message() {
    let mut alice = member(31);
    let mut bob = member(32);
    alice.create_group().unwrap();
    bob.join(&alice.add(&bob.key_package().unwrap()).unwrap().welcome())
        .unwrap();
    let wire = alice.send_bytes(&[0, 254, 253]).unwrap();
    let mut corrupted = wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(bob.receive(&corrupted).is_err());
    assert_eq!(bob.receive(&wire).unwrap().bytes(), [0, 254, 253]);
}
