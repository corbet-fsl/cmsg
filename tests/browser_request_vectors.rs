use cmsg::door::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

const VAULT_ORIGIN: &str = "https://vault.example";

fn config(community: &str) -> Configuration {
    Configuration::new(
        community.into(),
        BTreeMap::from([
            (
                Role::Member,
                BTreeSet::from(["https://member.example".into(), VAULT_ORIGIN.into()]),
            ),
            (
                Role::Admin,
                BTreeSet::from(["https://admin.example".into()]),
            ),
            (Role::Root, BTreeSet::from(["https://root.example".into()])),
        ]),
    )
    .unwrap()
}

fn actions() -> BTreeSet<String> {
    catalog().into_iter().map(|a| a.action).collect()
}

fn paired() -> (Door, ClientToken) {
    let mut door = Door::new(config("community-a"));
    let token = door
        .pair_client(VAULT_ORIGIN, Role::Member, actions(), 10, 100)
        .unwrap();
    (door, token)
}

fn value(output: Output) -> Value {
    serde_json::to_value(output).unwrap()
}

fn error(code: ErrorCode) -> Value {
    value(Output::Error { error: code })
}

/// Spell one name character as a JSON unicode escape on the wire. The escape
/// introducer is pushed numerically so the wire bytes carry exactly one
/// backslash before `u`, decoding to the identical field name.
fn escaped_name(head: &str, hex: &str, tail: &str) -> String {
    let mut name = String::from(head);
    name.push(0x5c as char);
    name.push('u');
    name.push_str(hex);
    name.push_str(tail);
    name
}

/// The unchanged grant still serves the real status action: the prior refusal
/// revoked and mutated nothing.
fn live_status(door: &mut Door, token: &ClientToken) -> Value {
    value(door.dispatch(
        VAULT_ORIGIN,
        token.expose_for_transport(),
        br#"{"action":"runtime.status","version":1,"body":{}}"#,
        11,
    ))
}

fn assert_grant_unchanged(door: &mut Door, token: &ClientToken) {
    let response = live_status(door, token);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["result"]["community"], "community-a");
    assert_eq!(response["result"]["preload"], "unavailable");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn escaped_name_alias_duplicates_are_refused_without_mutating_grant() {
    let action = escaped_name("act", "0069", "on");
    let version = escaped_name("vers", "0069", "on");
    let body = escaped_name("b", "006f", "dy");
    assert_eq!(
        action.as_bytes(),
        &[b'a', b'c', b't', 0x5c, b'u', b'0', b'0', b'6', b'9', b'o', b'n']
    );
    // Each envelope holds its field twice: once plain and once under the
    // escaped alias, which decodes to the identical name. The final vector
    // smuggles a client.revoke action through the same alias trick.
    let action_text = format!(
        r#"{{"action":"runtime.status","{action}":"runtime.status","version":1,"body":{{}}}}"#,
    );
    let version_text =
        format!(r#"{{"action":"runtime.status","version":1,"{version}":1,"body":{{}}}}"#,);
    let body_text =
        format!(r#"{{"action":"runtime.status","version":1,"body":{{}},"{body}":{{}}}}"#,);
    let revoke_text = format!(
        r#"{{"action":"runtime.status","{action}":"client.revoke","version":1,"body":{{}}}}"#,
    );
    let (mut door, token) = paired();
    for bytes in [
        action_text.into_bytes(),
        version_text.into_bytes(),
        body_text.into_bytes(),
        revoke_text.into_bytes(),
    ] {
        assert_eq!(
            value(door.dispatch(VAULT_ORIGIN, token.expose_for_transport(), &bytes, 11)),
            error(ErrorCode::InvalidRequest),
            "{}",
            String::from_utf8_lossy(&bytes),
        );
        assert_grant_unchanged(&mut door, &token);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_framing_vectors_keep_byte_bounds_before_decoding() {
    // A single escaped name decodes to the ordinary field, so valid JSON with
    // one escaped key still dispatches and reports the real readiness.
    let action = escaped_name("act", "0069", "on");
    let (mut door, token) = paired();
    let envelope_text = format!(r#"{{"{action}":"runtime.status","version":1,"body":{{}}}}"#);
    let envelope = envelope_text.into_bytes();
    let response = value(door.dispatch(VAULT_ORIGIN, token.expose_for_transport(), &envelope, 11));
    assert_eq!(response["status"], "ok");
    assert_eq!(response["result"]["preload"], "unavailable");

    for bytes in [
        vec![0xff],
        br#"{"action":"runtime.status","version":1,"body":{}} {}"#.to_vec(),
    ] {
        assert_eq!(
            value(door.dispatch(VAULT_ORIGIN, token.expose_for_transport(), &bytes, 11)),
            error(ErrorCode::InvalidRequest),
        );
        assert_grant_unchanged(&mut door, &token);
    }

    // Byte length, not character count, bounds the envelope: one two-byte
    // e-acute plus spaces sits at the character-count bound while the byte
    // length exceeds it, so the door reports Capacity before any decoding.
    let mut oversized = vec![0xc3, 0xa9];
    oversized.resize(MAX_BODY_BYTES + 1, b' ');
    assert_eq!(oversized.len(), MAX_BODY_BYTES + 1);
    let decoded = std::str::from_utf8(&oversized).expect("fixture stays valid UTF-8");
    assert_eq!(decoded.chars().count(), MAX_BODY_BYTES);
    assert_eq!(
        value(door.dispatch(VAULT_ORIGIN, token.expose_for_transport(), &oversized, 11)),
        error(ErrorCode::Capacity),
    );
    assert_grant_unchanged(&mut door, &token);
}
