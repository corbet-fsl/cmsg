//! Real dispatcher and original Board refusal paths. No admitted fixture owner.
use super::*;
use serde_json::json;

const ORIGIN: &str = "https://member.example.test";
fn configured() -> (Door, ClientToken) {
    let mut door = Door::new(
        super::super::Configuration::new(
            "example".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    door.configure_board(
        ORIGIN,
        Configuration {
            forum_origin: "https://forum.example.test".into(),
            maximum_response_bytes: MAX_RESULT_BYTES,
            timeout_millis: 1000,
            search_candidates: 32,
            search_publication_bytes: MAX_BODY_BYTES,
            tls_root_files: vec![],
            // The member's web origin, distinct from the door's (a native device's Board).
            member_origin: Some("https://example.test".into()),
            read_policy: ReadPolicy {
                admission_action: "fixture".into(),
            },
            #[cfg(feature = "ohttp")]
            ohttp: crate::door::ohttp::fixture_endpoint(),
        },
        SystemClock,
    )
    .unwrap();
    let actions = BTreeSet::from([
        "board.attend".into(),
        "board.search".into(),
        "board.watch".into(),
        "board.discovery".into(),
        "board.groups".into(),
        "board.group_act".into(),
        "board.group_propose".into(),
        "board.group_message".into(),
        "board.group_answer".into(),
        "board.group_welcome".into(),
        "board.profile_publish".into(),
    ]);
    let token = door
        .pair_client(ORIGIN, Role::Member, actions, 1, 100)
        .unwrap();
    (door, token)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn original_board_without_committed_owner_refuses_every_new_action() {
    let (mut door, token) = configured();
    for (action, body) in [
        ("board.attend", json!({})),
        ("board.search", json!({"cursor":null,"page_size":10})),
        ("board.watch", json!({"cursor":[1]})),
        ("board.discovery", json!({})),
        ("board.groups", json!({})),
        (
            "board.profile_publish",
            json!({"profile":{"community":"fixture","schema_version":1,"public":{},"private":{}},"rules":[]}),
        ),
        (
            "board.group_propose",
            json!({"intent":{"intent":"leave","group":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}),
        ),
        ("board.group_message", json!({"from":"m1","text":"{}"})),
        (
            "board.group_answer",
            json!({"operation":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"accept":true}),
        ),
        (
            "board.group_welcome",
            json!({"operation":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"delivered":[]}),
        ),
        (
            "board.group_act",
            json!({"intent":{"intent":"leave","group":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}}),
        ),
    ] {
        let request = serde_json::to_vec(&Invocation {
            action: action.into(),
            version: 1,
            body,
        })
        .unwrap();
        let result = door
            .dispatch(ORIGIN, token.expose_for_transport(), &request, 2)
            .await;
        assert!(matches!(
            result,
            Output::Error {
                error: ErrorCode::Unavailable
            }
        ));
        assert_eq!(
            door.boards.get(ORIGIN).unwrap().status().connection,
            clnk::State::Disconnected
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn public_board_actions_cannot_inject_owner_inputs_or_duplicate_paging_fields() {
    let (mut door, token) = configured();
    for request in [
        br#"{"action":"board.attend","version":1,"body":{"publication":[1]}}"#.as_slice(),
        br#"{"action":"board.attend","version":1,"body":{"signature":[1]}}"#.as_slice(),
        br#"{"action":"board.search","version":1,"body":{"cursor":null,"page_size":2,"page_size":3}}"#.as_slice(),
        br#"{"action":"board.search","version":1,"body":{"cursor":null,"page_size":2,"possession":{}}}"#.as_slice(),
        br#"{"action":"board.watch","version":1,"body":{"cursor":[1],"cursor":[2]}}"#.as_slice(),
        br#"{"action":"board.watch","version":1,"body":{"cursor":[1],"signature":[1]}}"#.as_slice(),
        br#"{"action":"board.watch","version":1,"body":{"cursor":[1],"possession":{}}}"#.as_slice(),
        br#"{"action":"board.watch","version":1,"body":{"cursor":[1],"maximum_wait":100}}"#.as_slice(),
        br#"{"action":"board.discovery","version":1,"body":{"admission_action":"accept"}}"#.as_slice(),
        br#"{"action":"board.groups","version":1,"body":{"policy":{}}}"#.as_slice(),
        br#"{"action":"board.group_act","version":1,"body":{"intent":{"intent":"leave","group":[1],"member":"m1"}}}"#.as_slice(),
        br#"{"action":"board.group_act","version":1,"body":{"intent":{"intent":"leave","group":[1]},"actor":"m1"}}"#.as_slice(),
        br#"{"action":"board.group_act","version":1,"body":{"intent":{"intent":"leave","group":[1]},"consents":[]}}"#.as_slice(),
        br#"{"action":"board.group_propose","version":1,"body":{"intent":{"intent":"leave","group":[1]},"consents":[]}}"#.as_slice(),
        br#"{"action":"board.group_message","version":1,"body":{"from":"m1","text":"{}","member":"m2"}}"#.as_slice(),
        br#"{"action":"board.group_answer","version":1,"body":{"operation":[1],"accept":true,"actor":"m1"}}"#.as_slice(),
    ] {
        let result = door.dispatch(ORIGIN, token.expose_for_transport(), request, 2).await;
        assert!(matches!(result, Output::Error { error: ErrorCode::InvalidRequest }));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn registry_uses_concrete_owner_operations_and_rejects_generic_dispatch() {
    for name in [
        "board.attend",
        "board.search",
        "board.watch",
        "board.discovery",
    ] {
        let descriptions: Vec<_> = catalog()
            .into_iter()
            .filter(|entry| entry.action == name)
            .collect();
        assert_eq!(descriptions.len(), 1);
        assert_eq!(descriptions[0].family, Family::Board);
    }
    for name in ["board.execute", "board.finish_search", "board.bind_owner"] {
        assert!(!catalog().iter().any(|entry| entry.action == name));
    }
    let description = catalog()
        .into_iter()
        .find(|entry| entry.action == "board.search")
        .unwrap();
    let properties = description.body["properties"].as_object().unwrap();
    assert_eq!(properties.len(), 2);
    assert!(properties.contains_key("cursor"));
    assert!(properties.contains_key("page_size"));
    let description = catalog()
        .into_iter()
        .find(|entry| entry.action == "board.watch")
        .unwrap();
    let properties = description.body["properties"].as_object().unwrap();
    assert_eq!(properties.len(), 1);
    assert!(properties.contains_key("cursor"));
    assert_eq!(description.body["additionalProperties"], false);
    assert_eq!(
        description.result,
        registry::schema::<cbrd::DiscoveryPage>()
    );
}

/// A connect refused before anything was sent clears the fence, so a member can attend
/// again once the Forum is up; a failure that may have reached the Forum keeps it and
/// asks for reconciliation.
#[test]
fn a_connect_refused_before_the_send_leaves_attendance_retryable_and_an_uncertain_one_does_not() {
    use super::handlers::connect_refused;
    use cbrd::clnk::ErrorCode as Wire;
    for definite in [
        Wire::AuthorityUnavailable,
        Wire::Origin,
        Wire::Host,
        Wire::Capacity,
        Wire::Rejected,
        Wire::UnsupportedVersion,
        Wire::InvalidRequest,
        Wire::MediaType,
    ] {
        let mut pending = true;
        let code = connect_refused(&mut pending, definite);
        assert!(!pending, "{definite:?}");
        assert_ne!(code, ErrorCode::Reconcile, "{definite:?}");
    }
    for uncertain in [
        Wire::Transport,
        Wire::Timeout,
        Wire::ResetRequired,
        Wire::TooLarge,
        Wire::Reconcile,
    ] {
        let mut pending = true;
        assert_eq!(
            connect_refused(&mut pending, uncertain),
            ErrorCode::Reconcile,
            "{uncertain:?}"
        );
        assert!(pending, "{uncertain:?}");
    }
    let mut pending = true;
    assert_eq!(
        connect_refused(&mut pending, Wire::AuthorityUnavailable),
        ErrorCode::Unavailable
    );
}

/// The attendance signature asks Keys for a short validity (one Enter), never for the
/// grant's long one, which would outlive the membership proof; a nearer grant wins.
#[test]
fn the_attendance_signature_is_short_lived_and_never_outlives_the_grant() {
    use super::handlers::attendance_signing_expiry;
    assert_eq!(attendance_signing_expiry(1_000, 1_000 + 86_400), 1_120);
    assert_eq!(attendance_signing_expiry(1_000, 1_050), 1_050);
    assert_eq!(attendance_signing_expiry(u64::MAX - 5, u64::MAX), u64::MAX);
}

/// A read that straddles a second boundary is retryable; a clock that went backwards is not.
#[test]
fn a_read_that_straddles_a_second_is_unavailable_and_a_backwards_clock_is_a_fault() {
    use super::handlers::read_moved;
    assert_eq!(read_moved(100, 101), ErrorCode::Unavailable);
    assert_eq!(read_moved(100, 160), ErrorCode::Unavailable);
    assert_eq!(read_moved(100, 99), ErrorCode::Clock);
}
