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
            read_policy: ReadPolicy {
                admission_action: "fixture".into(),
                maximum_snapshot_age: 60,
            },
        },
        SystemClock,
    )
    .unwrap();
    let actions = BTreeSet::from([
        "board.attend".into(),
        "board.search".into(),
        "board.discovery".into(),
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
        ("board.discovery", json!({})),
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
        br#"{"action":"board.discovery","version":1,"body":{"admission_action":"accept"}}"#.as_slice(),
    ] {
        let result = door.dispatch(ORIGIN, token.expose_for_transport(), request, 2).await;
        assert!(matches!(result, Output::Error { error: ErrorCode::InvalidRequest }));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn registry_uses_concrete_owner_operations_and_rejects_generic_dispatch() {
    for name in ["board.attend", "board.search", "board.discovery"] {
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
}
