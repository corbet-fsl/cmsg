//! Actual facade views and refusal boundaries. No test adapter grants member,
//! device, balance or network authority.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
use browser_coverage_runtime as _;
use cbrd::clnk;
use cmsg::door::*;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const MEMBER: &str = "https://alpha.example.test";
const ADMIN: &str = "https://admin.alpha.example.test";
fn door() -> Door {
    Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([
                (Role::Member, BTreeSet::from([MEMBER.into()])),
                (Role::Admin, BTreeSet::from([ADMIN.into()])),
            ]),
        )
        .unwrap(),
    )
}
fn pair(door: &mut Door) -> ClientToken {
    door.pair_client(
        MEMBER,
        Role::Member,
        catalog().into_iter().map(|a| a.action).collect(),
        10,
        100,
    )
    .unwrap()
}
async fn invoke(door: &mut Door, token: &ClientToken, action: &str, body: Value) -> Value {
    serde_json::to_value(
        surface::invoke(
            door,
            MEMBER,
            token.expose_for_transport(),
            action,
            1,
            body,
            11,
        )
        .await,
    )
    .unwrap()
}

struct RefusingTransport(Rc<Cell<usize>>);
impl clnk::Transport for RefusingTransport {
    async fn post(&self, _: &str, _: Vec<u8>) -> std::result::Result<Vec<u8>, clnk::ErrorCode> {
        self.0.set(self.0.get() + 1);
        Err(clnk::ErrorCode::AuthorityUnavailable)
    }
}
fn board(scope: &str, calls: Rc<Cell<usize>>) -> cbrd::Board<RefusingTransport> {
    cbrd::Board::new(scope.into(), clnk::Link::new(RefusingTransport(calls))).unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn actual_board_status_and_disconnect_preserve_scope_and_child_unavailability() {
    let calls = Rc::new(Cell::new(0));
    let mut door = door();
    let token = pair(&mut door);
    assert_eq!(
        door.bind_board(ADMIN, board("alpha", calls.clone())),
        Err(ErrorCode::Unauthorized)
    );
    assert_eq!(
        door.bind_board(MEMBER, board("foreign", calls.clone())),
        Err(ErrorCode::InvalidRequest)
    );
    let actual = board("alpha", calls.clone());
    let expected = serde_json::to_value(actual.status()).unwrap();
    door.bind_board(MEMBER, actual).unwrap();
    assert_eq!(
        door.bind_board(MEMBER, board("alpha", calls.clone())),
        Err(ErrorCode::InvalidRequest)
    );
    for action in ["board.status", "board.disconnect"] {
        let response = invoke(&mut door, &token, action, json!({})).await;
        assert_eq!(response["result"], expected);
        assert_eq!(response["events"], json!([]));
    }
    assert_eq!(
        calls.get(),
        0,
        "view/disconnect must not contact or authenticate a Forum"
    );
    assert_eq!(
        invoke(&mut door, &token, "runtime.status", json!({})).await["result"]["preload"],
        "unavailable"
    );
}

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
        Ok(11)
    }
}
struct RefusedAuthority;
impl ckmg::Authority for RefusedAuthority {
    async fn check(&mut self, _: ckmg::Authorization<'_>) -> std::result::Result<(), ckmg::Error> {
        Err(ckmg::Error::Unauthorized)
    }
}
struct UnavailableRecords;
impl cvlt::Records for UnavailableRecords {
    async fn lookup(&mut self, _: &ckmg::Locator) -> cvlt::RestoreLookup {
        cvlt::RestoreLookup::Unavailable
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn encrypted_storage_without_unlocked_current_keys_does_not_bind_vault_or_inbox() {
    let mut door = door();
    let token = pair(&mut door);
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[19; 32]).unwrap();
    let cipher = ckmg::passkey::store_cipher(&prf, "alpha").unwrap();
    let store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap();
    // This deliberately incomplete fixture must refuse. It never creates Keys,
    // fabricates a Wallet, or produces an accepted custody/read result.
    let vault = cvlt::Vault::new(
        store,
        "alpha",
        Clock,
        ckmg::SystemEntropy,
        RefusedAuthority,
        UnavailableRecords,
        (),
    )
    .unwrap();
    assert_eq!(
        door.bind_vault(MEMBER, vault).await,
        Err(ErrorCode::Unavailable)
    );
    for (action, body) in [
        ("inbox.history", json!({"conversation":([0; 32])})),
        (
            "inbox.snapshot",
            json!({"conversation":([0; 32]),"peer":"synthetic-peer"}),
        ),
        (
            "inbox.relation",
            json!({"conversation":([0; 32]),"peer":"synthetic-peer"}),
        ),
        (
            "inbox.delivery_status",
            json!({"conversation":([0; 32]),"message":([1; 32])}),
        ),
        ("vault.lock", json!({})),
        ("board.heartbeat", json!({})),
        ("board.depart", json!({})),
        ("mesh.status", json!({})),
        ("mesh.disconnect", json!({})),
    ] {
        assert_eq!(
            invoke(&mut door, &token, action, body).await,
            json!({"status":"error","error":"unavailable"})
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl native::Clock for Clock {
    fn now(&self) -> u64 {
        11
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn embedded_thread_retains_actual_non_send_board_through_http_and_shutdown() {
    let runtime = native::Embedded::start(
        || async {
            let mut door = door();
            // Link's transport deliberately owns Rc, so constructing the actual
            // Board here proves the facade never has to cross the HTTP thread.
            door.bind_board(MEMBER, board("alpha", Rc::new(Cell::new(0))))?;
            Ok(door)
        },
        native::Pairing {
            origin: MEMBER.into(),
            role: Role::Member,
            actions: BTreeSet::from(["board.status".into(), "board.disconnect".into()]),
            lifetime_seconds: 60,
        },
        std::sync::Arc::new(Clock),
    )
    .await
    .unwrap();
    let output = runtime
        .client()
        .invoke_bytes(br#"{"action":"board.status","version":1,"body":{}}"#)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(output).unwrap()["result"]["connection"],
        "Disconnected"
    );
    runtime.shutdown().await.unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn configured_native_owner_constructs_actual_https_clients_without_claiming_admission() {
    let configuration = native::DeviceConfiguration {
        community: "alpha".into(),
        origin: MEMBER.into(),
        role: Role::Member,
        primary: foyer::Scope::Community,
        trust: None,
        login: None,
        root_board: false,
        services: vec![browser::Service {
            scope: foyer::Scope::Community,
            base: "https://api.alpha.example.test".into(),
            host: "api.alpha.example.test".into(),
        }],
        forum: Some(board::Configuration {
            forum_origin: "https://forum.alpha.example.test".into(),
            maximum_response_bytes: 65_536,
            timeout_millis: 5_000,
            search_candidates: 8,
            search_publication_bytes: 65_536,
        }),
    };
    let runtime =
        native::Embedded::configured(configuration.clone(), 60, std::sync::Arc::new(Clock))
            .await
            .unwrap();
    let output = runtime
        .client()
        .invoke_bytes(br#"{"action":"board.status","version":1,"body":{}}"#)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(output).unwrap()["result"]["connection"],
        "Disconnected"
    );
    for action in [
        "board.heartbeat",
        "board.depart",
        "foyer.refresh",
        "login.start",
    ] {
        let input = serde_json::to_vec(&json!({"action":action,"version":1,"body":{}})).unwrap();
        let output = runtime.client().invoke_bytes(&input).await.unwrap();
        assert_eq!(
            serde_json::to_value(output).unwrap(),
            json!({"status":"error","error":"unavailable"})
        );
    }
    runtime.shutdown().await.unwrap();
    // These malformed public deployment anchors never manufacture a Charter.
    // Both wrappers retain the original owner configuration and validation.
    let trust = browser::TrustConfiguration {
        publishing: cfyr::trust::Configuration {
            origin: "https://api.alpha.example.test".into(),
            community: "alpha".into(),
            key_ring: vec![],
            minimum_revision: 1,
            ring_revision: 1,
        },
        following: cfyr::trust::Config {
            retry_entropy: 0,
            refresh_seconds: 30,
            poll_seconds: 30,
            request_seconds: 30,
            initial_backoff_seconds: 1,
            maximum_backoff_seconds: 60,
            maximum_staleness_seconds: 60,
        },
    };
    for (scope, origin, expected) in [
        (
            "other",
            "https://api.alpha.example.test",
            ErrorCode::Unauthorized,
        ),
        (
            "alpha",
            "https://api.other.example.test",
            ErrorCode::Unauthorized,
        ),
        (
            "alpha",
            "https://api.alpha.example.test",
            ErrorCode::InvalidRequest,
        ),
    ] {
        let mut invalid = configuration.clone();
        let mut trust = trust.clone();
        trust.publishing.community = scope.into();
        trust.publishing.origin = origin.into();
        invalid.trust = Some(trust);
        assert!(
            matches!(native::Embedded::configured(invalid, 60, std::sync::Arc::new(Clock)).await,
            Err(error) if error == expected)
        );
    }
    let mut invalid = configuration.clone();
    invalid.forum.as_mut().unwrap().search_candidates = 0;
    assert!(matches!(
        native::Embedded::configured(invalid, 60, std::sync::Arc::new(Clock)).await,
        Err(ErrorCode::InvalidRequest)
    ));
    let mut invalid = configuration;
    invalid.forum.as_mut().unwrap().forum_origin = "http://forum.alpha.example.test".into();
    assert!(matches!(
        native::Embedded::configured(invalid, 60, std::sync::Arc::new(Clock)).await,
        Err(ErrorCode::Unauthorized)
    ));
}
