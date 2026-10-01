use cmsg::door::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

const ORIGIN: &str = "https://member.example";

fn config(community: &str) -> Configuration {
    Configuration::new(
        community.into(),
        BTreeMap::from([
            (Role::Member, BTreeSet::from([ORIGIN.into()])),
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
        .pair_client(ORIGIN, Role::Member, actions(), 10, 100)
        .unwrap();
    (door, token)
}
fn value(output: Output) -> Value {
    serde_json::to_value(output).unwrap()
}
fn call(door: &mut Door, token: &ClientToken, action: &str, now: u64) -> Value {
    value(surface::invoke(
        door,
        ORIGIN,
        token.expose_for_transport(),
        action,
        1,
        json!({}),
        now,
    ))
}
fn error(code: ErrorCode) -> Value {
    value(Output::Error { error: code })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unavailable_owners_never_release_preload() {
    let (mut door, token) = paired();
    let response = call(&mut door, &token, "runtime.status", 11);
    assert_eq!(response["status"], "ok");
    assert_eq!(response["result"]["community"], "community-a");
    assert_eq!(response["result"]["preload"], "unavailable");
    assert_eq!(response["result"]["owners"].as_object().unwrap().len(), 5);
    for status in response["result"]["owners"].as_object().unwrap().values() {
        assert_eq!(status, "unavailable");
    }
    assert_eq!(
        call(&mut door, &token, "group.join", 12),
        error(ErrorCode::UnsupportedAction)
    );
    assert!(!serde_json::to_string(&response)
        .unwrap()
        .contains(token.expose_for_transport()));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn capabilities_are_bound_to_origin_scope_role_and_actions() {
    let (mut door, token) = paired();
    let input = br#"{"action":"runtime.status","version":1,"body":{}}"#;
    assert_eq!(
        value(door.dispatch(
            "https://attacker.example",
            token.expose_for_transport(),
            input,
            11
        )),
        error(ErrorCode::Unauthorized)
    );
    assert_eq!(
        value(door.dispatch(ORIGIN, "not a token", input, 11)),
        error(ErrorCode::Unauthorized)
    );
    let mut foreign = Door::new(config("community-b"));
    assert_eq!(
        value(foreign.dispatch(ORIGIN, token.expose_for_transport(), input, 11)),
        error(ErrorCode::Unauthorized)
    );
    assert!(door
        .pair_client(ORIGIN, Role::Admin, actions(), 11, 20)
        .is_err());
    let read = door
        .pair_client(
            ORIGIN,
            Role::Member,
            BTreeSet::from(["runtime.status".into()]),
            11,
            20,
        )
        .unwrap();
    assert_eq!(
        call(&mut door, &read, "client.revoke", 12),
        error(ErrorCode::Unauthorized)
    );
    assert_eq!(call(&mut door, &read, "runtime.status", 12)["status"], "ok");
    let admin = door
        .pair_client("https://admin.example", Role::Admin, actions(), 12, 30)
        .unwrap();
    assert_eq!(
        value(door.dispatch(ORIGIN, admin.expose_for_transport(), input, 12)),
        error(ErrorCode::Unauthorized)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn revocation_expiry_and_clock_regression_fail_closed() {
    let (mut door, token) = paired();
    assert_eq!(
        call(&mut door, &token, "runtime.status", 9),
        error(ErrorCode::Clock)
    );
    let response = call(&mut door, &token, "client.revoke", 11);
    assert_eq!(response["result"], json!({"revoked": true}));
    assert_eq!(response["events"], json!([{"event":"client_revoked"}]));
    assert_eq!(
        call(&mut door, &token, "runtime.status", 12),
        error(ErrorCode::Unauthorized)
    );
    let token = door
        .pair_client(ORIGIN, Role::Member, actions(), 12, 20)
        .unwrap();
    assert_eq!(
        call(&mut door, &token, "runtime.status", 20),
        error(ErrorCode::Unauthorized)
    );
    let token = door
        .pair_client(ORIGIN, Role::Member, actions(), 20, 30)
        .unwrap();
    door.revoke(&token);
    assert_eq!(
        call(&mut door, &token, "runtime.status", 21),
        error(ErrorCode::Unauthorized)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn reject_ambiguous_overlarge_or_foreign_requests() {
    let (mut door, token) = paired();
    for bytes in [
        b"not json".as_slice(),
        br#"{"action":"runtime.status","action":"client.revoke","version":1,"body":{}}"#,
        br#"{"action":"runtime.status","version":1,"body":{"unexpected":1}}"#,
        br#"{"action":"runtime.status","version":1,"body":{},"community":"other"}"#,
        br#"{"action":"runtime.status","version":1,"body":{},"role":"root"}"#,
    ] {
        assert_eq!(
            value(door.dispatch(ORIGIN, token.expose_for_transport(), bytes, 11)),
            error(ErrorCode::InvalidRequest)
        );
    }
    assert_eq!(
        value(surface::invoke(
            &mut door,
            ORIGIN,
            token.expose_for_transport(),
            "runtime.status",
            2,
            json!({}),
            11
        )),
        error(ErrorCode::UnsupportedVersion)
    );
    assert_eq!(
        value(door.dispatch(
            ORIGIN,
            token.expose_for_transport(),
            &vec![b' '; MAX_BODY_BYTES + 1],
            11
        )),
        error(ErrorCode::Capacity)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn client_pairing_is_bounded_and_not_a_public_action() {
    let mut door = Door::new(config("community-a"));
    for i in 0..MAX_CLIENTS {
        let token = door
            .pair_client(ORIGIN, Role::Member, actions(), 10, 100)
            .unwrap();
        assert_eq!(token.expose_for_transport().len(), 43, "{i}");
    }
    assert!(matches!(
        door.pair_client(ORIGIN, Role::Member, actions(), 10, 100),
        Err(ErrorCode::Capacity)
    ));
    assert!(door
        .pair_client(ORIGIN, Role::Member, actions(), 100, 200)
        .is_ok());
    assert!(door
        .pair_client(ORIGIN, Role::Member, actions(), 100, 100)
        .is_err());
    assert!(door
        .pair_client(
            ORIGIN,
            Role::Member,
            actions(),
            100,
            101 + MAX_GRANT_SECONDS
        )
        .is_err());
    assert!(door
        .pair_client(ORIGIN, Role::Member, BTreeSet::new(), 100, 110)
        .is_err());
    assert!(door
        .pair_client(
            ORIGIN,
            Role::Member,
            BTreeSet::from(["pair_client".into()]),
            100,
            110
        )
        .is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn configuration_refuses_cross_role_origins_and_non_origins() {
    for origin in [
        "null",
        "https://member.example/path",
        "https://member.example/",
        "http://member.example",
        "https://user@member.example",
        "file:///tmp",
    ] {
        assert!(Configuration::new(
            "a".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))])
        )
        .is_err());
    }
    assert!(Configuration::new(
        "a".into(),
        BTreeMap::from([
            (Role::Member, BTreeSet::from([ORIGIN.into()])),
            (Role::Root, BTreeSet::from([ORIGIN.into()])),
        ])
    )
    .is_err());
    assert!(Configuration::new("".into(), BTreeMap::new()).is_err());
    assert!(Configuration::new(
        "a".into(),
        BTreeMap::from([(Role::Member, BTreeSet::new())])
    )
    .is_err());
    assert!(Configuration::new(
        "a".into(),
        BTreeMap::from([(
            Role::Member,
            BTreeSet::from(["http://127.0.0.1:3000".into()])
        )])
    )
    .is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn projections_share_typed_action_bodies_and_refusal_semantics() {
    let (mut door, token) = paired();
    let description = call(&mut door, &token, "runtime.describe", 11);
    let bundle = surface::bundle();
    assert_eq!(description["result"], bundle["actions"]);
    for action in catalog() {
        let route = format!("/v{}/{}", action.version, action.action);
        let http = &bundle["openapi"]["paths"][route]["post"];
        let tool = bundle["mcp"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == action.action)
            .unwrap();
        assert_eq!(
            http["requestBody"]["content"]["application/json"]["schema"],
            action.body
        );
        assert_eq!(tool["inputSchema"], action.body);
        assert_eq!(action.body["additionalProperties"], false);
    }
    assert_eq!(bundle["cli"]["commands"], bundle["actions"]);
    for (failure, exit) in [
        (ErrorCode::InvalidRequest, 64),
        (ErrorCode::UnsupportedAction, 64),
        (ErrorCode::UnsupportedVersion, 64),
        (ErrorCode::Unauthorized, 77),
        (ErrorCode::Unavailable, 69),
        (ErrorCode::Capacity, 75),
        (ErrorCode::Clock, 75),
        (ErrorCode::Reconcile, 75),
    ] {
        assert_eq!(failure.exit_code(), exit);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn native_http_uses_identical_capability_checks_and_no_store_errors() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;
    struct Clock;
    impl native::Clock for Clock {
        fn now(&self) -> u64 {
            11
        }
    }
    let (mut door, token) = paired();
    let expected = call(&mut door, &token, "runtime.status", 11);
    let app = native::router(
        door,
        BTreeSet::from(["localhost:3000".into()]),
        Arc::new(Clock),
    )
    .unwrap();
    for (host, origin, credential, status) in [
        (
            "localhost:3000",
            ORIGIN,
            token.expose_for_transport(),
            StatusCode::OK,
        ),
        (
            "attacker.example",
            ORIGIN,
            token.expose_for_transport(),
            StatusCode::FORBIDDEN,
        ),
        (
            "localhost:3000",
            "https://attacker.example",
            token.expose_for_transport(),
            StatusCode::FORBIDDEN,
        ),
        ("localhost:3000", ORIGIN, "invalid", StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/runtime.status")
                    .header("Host", host)
                    .header("Origin", origin)
                    .header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {credential}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["Cache-Control"], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            if status == StatusCode::OK {
                expected.clone()
            } else {
                error(ErrorCode::Unauthorized)
            }
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn http_rejects_ambiguous_headers_and_bounds_every_route() {
    use axum::{
        body::Body,
        http::{HeaderName, HeaderValue, Request},
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;
    struct Clock;
    impl native::Clock for Clock {
        fn now(&self) -> u64 {
            11
        }
    }
    let (door, token) = paired();
    let app = native::router(
        door,
        BTreeSet::from(["localhost:3000".into()]),
        Arc::new(Clock),
    )
    .unwrap();
    let request = || {
        Request::post("/v1/runtime.status")
            .header("Host", "localhost:3000")
            .header("Origin", ORIGIN)
            .header(
                "Authorization",
                format!("Bearer {}", token.expose_for_transport()),
            )
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    };
    for name in ["host", "origin", "authorization", "content-type"] {
        for duplicate in [false, true] {
            let mut req = request();
            if duplicate {
                req.headers_mut().append(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_static("different"),
                );
            } else {
                req.headers_mut().remove(name);
            }
            let response = app.clone().oneshot(req).await.unwrap();
            assert_eq!(response.status(), 403);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }
    for (body, code) in [
        (vec![0xff], ErrorCode::InvalidRequest),
        (vec![b' '; MAX_BODY_BYTES + 1], ErrorCode::Capacity),
        (b"{\"bad\":1,\"bad\":2}".to_vec(), ErrorCode::InvalidRequest),
    ] {
        let mut req = request();
        *req.body_mut() = Body::from(body);
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            error(code)
        );
    }
    for (method, path) in [
        ("GET", "/v1/runtime.status"),
        ("OPTIONS", "/v1/runtime.status"),
        ("POST", "/unknown"),
        ("POST", "/v1/%FF"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response.status().is_success());
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
    }
    for host in ["", "bad/host", "bad@host"] {
        assert!(native::router(
            Door::new(config("a")),
            BTreeSet::from([host.into()]),
            Arc::new(Clock)
        )
        .is_err());
    }
    assert!(native::router(Door::new(config("a")), BTreeSet::new(), Arc::new(Clock)).is_err());
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn native_client_executes_real_loopback_door_and_preserves_raw_input() {
    use std::sync::Arc;
    struct Clock;
    impl native::Clock for Clock {
        fn now(&self) -> u64 {
            11
        }
    }
    let (mut door, token) = paired();
    let other_token = door
        .pair_client("https://admin.example", Role::Admin, actions(), 10, 100)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://{address}");
    let app = native::router(door, BTreeSet::from([address.to_string()]), Arc::new(Clock)).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = native::Client::new(&base, ORIGIN, token).unwrap();
    let status = client
        .invoke_bytes(br#"{"action":"runtime.status","version":1,"body":{}}"#)
        .await
        .unwrap();
    assert_eq!(value(status)["result"]["preload"], "unavailable");
    let description = client
        .invoke_bytes(br#"{"action":"runtime.describe","version":1,"body":{}}"#)
        .await
        .unwrap();
    assert_eq!(value(description)["result"], surface::bundle()["actions"]);
    assert_eq!(value(client.invoke_bytes(br#"{"action":"runtime.status","action":"client.revoke","version":1,"body":{}}"#).await.unwrap()),error(ErrorCode::InvalidRequest));
    assert_eq!(
        value(
            client
                .invoke_bytes(br#"{"action":"runtime.status","version":2,"body":{}}"#)
                .await
                .unwrap()
        ),
        error(ErrorCode::UnsupportedVersion)
    );
    assert!(matches!(
        client.invoke_bytes(&vec![0; MAX_BODY_BYTES + 1]).await,
        Err(ErrorCode::Capacity)
    ));
    let foreign = native::Client::new(&base, ORIGIN, other_token).unwrap();
    assert_eq!(
        value(
            foreign
                .invoke_bytes(br#"{"action":"runtime.status","version":1,"body":{}}"#)
                .await
                .unwrap()
        ),
        error(ErrorCode::Unauthorized)
    );
    assert_eq!(
        value(
            client
                .invoke_bytes(br#"{"action":"client.revoke","version":1,"body":{}}"#)
                .await
                .unwrap()
        )["result"]["revoked"],
        true
    );
    assert_eq!(
        value(
            client
                .invoke_bytes(br#"{"action":"runtime.status","version":1,"body":{}}"#)
                .await
                .unwrap()
        ),
        error(ErrorCode::Unauthorized)
    );
    server.abort();
    let _ = server.await;
    assert!(matches!(
        client.invoke_bytes(b"{}").await,
        Err(ErrorCode::Unavailable)
    ));
    for base in [
        "not a url",
        "http://example.test",
        "https://127.0.0.1",
        "http://localhost",
        "http://user@127.0.0.1",
        "http://u:p@127.0.0.1",
        "http://127.0.0.1/path",
        "http://127.0.0.1?query",
        "http://127.0.0.1#fragment",
    ] {
        let (_, token) = paired();
        assert!(matches!(
            native::Client::new(base, ORIGIN, token),
            Err(ErrorCode::InvalidRequest)
        ));
    }
    let (_, token) = paired();
    assert!(native::Client::new("http://[::1]:3000", ORIGIN, token).is_ok());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn imported_capability_is_only_an_encoding_until_the_door_authorizes_it() {
    let (mut door, token) = paired();
    let received = ClientToken::from_protected_transport(zeroize::Zeroizing::new(
        token.expose_for_transport().as_bytes().to_vec(),
    ))
    .unwrap();
    assert_eq!(
        call(&mut door, &received, "runtime.status", 11)["status"],
        "ok"
    );
    door.revoke(&token);
    assert_eq!(
        call(&mut door, &received, "runtime.status", 11),
        error(ErrorCode::Unauthorized)
    );
    for bytes in [vec![], vec![b'!'; 43], vec![b'A'; 44], vec![255; 43]] {
        assert!(matches!(
            ClientToken::from_protected_transport(zeroize::Zeroizing::new(bytes)),
            Err(ErrorCode::Unauthorized)
        ));
    }
    let unknown =
        ClientToken::from_protected_transport(zeroize::Zeroizing::new(vec![b'A'; 43])).unwrap();
    assert_eq!(
        call(&mut door, &unknown, "runtime.status", 11),
        error(ErrorCode::Unauthorized)
    );
}
