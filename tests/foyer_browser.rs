//! Executed from each real HTTPS portal; CORS and original owner sessions remain
//! active. No accepting browser transport, origin bypass or service mock exists.
#![cfg(target_arch = "wasm32")]
#[cfg(owned_browser_coverage)]
use browser_coverage_runtime as _;
use cmsg::door::{foyer, *};
use futures_util::{future, FutureExt};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

const MEMBER: &str = "https://alpha.example.test";
const VAULT: &str = "https://vault.alpha.example.test";
const WALLET: &str = "https://wallet.example.test";
const ADMIN: &str = "https://admin.alpha.example.test";
const ROOT: &str = "https://admin.root.example.test";

async fn fetch(path: &str) -> Value {
    gloo_net::http::Request::get(path)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
fn session(row: &Value) -> foyer::Foyer<foyer::Transport> {
    foyer::Foyer::new(
        foyer::Transport::new(
            row["base"].as_str().unwrap().into(),
            row["host"].as_str().unwrap().into(),
            row["session"].as_str().map(str::to_owned),
        )
        .unwrap(),
    )
}
fn configured() -> Door {
    Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([
                (
                    Role::Member,
                    BTreeSet::from([MEMBER.into(), VAULT.into(), WALLET.into()]),
                ),
                (Role::Admin, BTreeSet::from([ADMIN.into()])),
                (Role::Root, BTreeSet::from([ROOT.into()])),
            ]),
        )
        .unwrap(),
    )
}
fn pair(door: &mut Door, origin: &str, role: Role, now: u64) -> ClientToken {
    door.pair_client(
        origin,
        role,
        catalog().into_iter().map(|a| a.action).collect(),
        now,
        now + 60,
    )
    .unwrap()
}
async fn invoke(
    door: &mut Door,
    origin: &str,
    token: &ClientToken,
    name: &str,
    body: Value,
    now: u64,
) -> Value {
    serde_json::to_value(
        surface::invoke(
            door,
            origin,
            token.expose_for_transport(),
            name,
            1,
            body,
            now,
        )
        .await,
    )
    .unwrap()
}

#[wasm_bindgen_test]
async fn actual_portal_origin_dispatches_only_its_bound_real_session() {
    let fixture = fetch("/__fixture").await;
    let now = fixture["now"].as_u64().unwrap();
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let (role, scope, name, allowed, denied) = match origin.as_str() {
        MEMBER => (
            Role::Member,
            foyer::Scope::Community,
            "member",
            "foyer.lobby",
            "foyer.setting_set",
        ),
        VAULT => (
            Role::Member,
            foyer::Scope::Community,
            "vault",
            "foyer.lobby",
            "foyer.setting_set",
        ),
        WALLET => (
            Role::Member,
            foyer::Scope::Global,
            "global",
            "foyer.global_public",
            "foyer.lobby",
        ),
        ADMIN => (
            Role::Admin,
            foyer::Scope::Community,
            "admin",
            "foyer.setting_set",
            "foyer.platform_set",
        ),
        ROOT => (
            Role::Root,
            foyer::Scope::Community,
            "root",
            "foyer.platform_set",
            "foyer.handle_reserve",
        ),
        _ => panic!("browser must execute the configured HTTPS portal matrix"),
    };
    let mut door = configured();
    let mut sessions = foyer::Sessions::new(scope, session(&fixture[name]));
    if role == Role::Root {
        sessions = sessions
            .with_service(foyer::Scope::Global, session(&fixture["global_root"]))
            .unwrap();
    }
    door.bind_foyer(&origin, role, sessions).unwrap();
    let token = pair(&mut door, &origin, role, now);
    let set = json!({"key":"quota","value":7,"inherit":false,"effective_at":now});
    let body = match role {
        Role::Member => json!({}),
        Role::Admin => set.clone(),
        Role::Root => json!({"setting":set,"force":true}),
    };
    assert_eq!(
        invoke(&mut door, &origin, &token, allowed, body, now).await["status"],
        "ok"
    );
    if role == Role::Root {
        assert_eq!(
            invoke(
                &mut door,
                &origin,
                &token,
                "foyer.global_public",
                json!({}),
                now
            )
            .await["status"],
            "ok"
        );
    }
    assert_eq!(
        invoke(&mut door, &origin, &token, denied, json!({}), now).await,
        json!({"status":"error","error":"unauthorized"})
    );
    assert_eq!(
        invoke(
            &mut door,
            "https://foreign.example.test",
            &token,
            allowed,
            json!({}),
            now
        )
        .await,
        json!({"status":"error","error":"unauthorized"})
    );
    assert_eq!(
        invoke(
            &mut door,
            &origin,
            &token,
            "foyer.login_finish",
            json!({}),
            now
        )
        .await,
        json!({"status":"error","error":"unsupported_action"})
    );
    let duplicate = br#"{"action":"foyer.global_public","version":1,"body":{"a":{"b":0,"b":1}}}"#;
    assert!(matches!(
        door.dispatch(&origin, token.expose_for_transport(), duplicate, now)
            .await,
        Output::Error {
            error: ErrorCode::InvalidRequest
        }
    ));
    assert_eq!(
        invoke(&mut door, &origin, &token, "runtime.status", json!({}), now).await["result"]
            ["preload"],
        "unavailable"
    );
    assert_eq!(
        invoke(&mut door, &origin, &token, "foyer.logout", json!({}), now).await["status"],
        "ok"
    );
    // Public issuer material remains public; each protected portal operation
    // must reject the exact now-revoked session.
    let protected = match role {
        Role::Member if origin == WALLET => "foyer.passport_challenge",
        Role::Member => "foyer.lobby",
        Role::Admin => "foyer.setting_set",
        Role::Root => "foyer.platform_set",
    };
    let body = match role {
        Role::Member => json!({}),
        Role::Admin => json!({"key":"quota","value":8,"inherit":false,"effective_at":now}),
        Role::Root => {
            json!({"setting":{"key":"quota","value":8,"inherit":false,"effective_at":now},"force":true})
        }
    };
    assert_eq!(
        invoke(&mut door, &origin, &token, protected, body, now).await,
        json!({"status":"error","error":"unauthorized"})
    );
}

#[wasm_bindgen_test]
async fn actual_commits_survive_damaged_reply_bound_failure_and_borrow_cancellation() {
    // The runner executes this target at all five portals. Wallet alone owns
    // these independent actual global fixture sessions and same-origin faults.
    if web_sys::window().unwrap().location().origin().unwrap() != WALLET {
        return;
    }
    let fixture = fetch("/__fixture").await;
    let now = fixture["now"].as_u64().unwrap();
    for index in 0..3 {
        let mut door = configured();
        door.bind_foyer(
            WALLET,
            Role::Member,
            foyer::Sessions::new(foyer::Scope::Global, session(&fixture["faults"][index])),
        )
        .unwrap();
        let token = pair(&mut door, WALLET, Role::Member, now);
        if index < 2 {
            let action = if index == 0 {
                "foyer.logout"
            } else {
                "foyer.global_public"
            };
            assert_eq!(
                invoke(&mut door, WALLET, &token, action, json!({}), now).await,
                json!({"status":"error","error":"reconcile"})
            );
        } else {
            let pending =
                invoke(&mut door, WALLET, &token, "foyer.logout", json!({}), now).boxed_local();
            let observed = async {
                loop {
                    if fetch("/__stats").await[index].as_u64().unwrap() > 0 {
                        break;
                    }
                    gloo_timers::future::TimeoutFuture::new(10).await;
                }
            }
            .boxed_local();
            let observed = async {
                match future::select(
                    observed,
                    gloo_timers::future::TimeoutFuture::new(10_000).boxed_local(),
                )
                .await
                {
                    future::Either::Left(_) => {}
                    future::Either::Right(_) => panic!("real owner did not commit before deadline"),
                }
            }
            .boxed_local();
            match future::select(pending, observed).await {
                future::Either::Left(_) => panic!("actual owner reply must be held"),
                future::Either::Right(((), pending)) => drop(pending),
            }
        }
        assert_eq!(
            invoke(
                &mut door,
                WALLET,
                &token,
                "foyer.global_public",
                json!({}),
                now
            )
            .await,
            json!({"status":"error","error":"reconcile"})
        );
        assert_eq!(
            invoke(&mut door, WALLET, &token, "runtime.status", json!({}), now).await["status"],
            "ok"
        );
    }
    gloo_net::http::Request::post("/__release")
        .send()
        .await
        .unwrap();
    assert_eq!(fetch("/__stats").await, json!([1, 1, 1]));
}

async fn browser_output(promise: js_sys::Promise) -> Value {
    let value = wasm_bindgen_futures::JsFuture::from(promise).await.unwrap();
    serde_json::from_str(&value.as_string().unwrap()).unwrap()
}

#[wasm_bindgen_test]
async fn browser_owner_has_private_pairing_bounded_admission_and_drained_disposal() {
    let fixture = fetch("/__fixture").await;
    let origin = web_sys::window().unwrap().location().origin().unwrap();
    let (name, role, scope) = match origin.as_str() {
        MEMBER => ("member", Role::Member, foyer::Scope::Community),
        VAULT => ("vault", Role::Member, foyer::Scope::Community),
        WALLET => ("global", Role::Member, foyer::Scope::Global),
        ADMIN => ("admin", Role::Admin, foyer::Scope::Community),
        ROOT => ("root", Role::Root, foyer::Scope::Community),
        _ => panic!("the actual portal matrix is required"),
    };
    let configuration = browser::Configuration {
        community: "alpha".into(),
        origin: origin.clone(),
        role,
        primary: scope,
        trust: None,
        login: None,
        root_board: false,
        forum: (origin == MEMBER).then(|| board::Configuration {
            forum_origin: "https://forum.alpha.example.test".into(),
            maximum_response_bytes: 65_536,
            timeout_millis: 5_000,
            search_candidates: 8,
            search_publication_bytes: 65_536,
        }),
        services: vec![browser::Service {
            scope,
            base: fixture[name]["base"].as_str().unwrap().into(),
            host: fixture[name]["host"].as_str().unwrap().into(),
        }],
    };
    let mut foreign = configuration.clone();
    foreign.origin = "https://foreign.example.test".into();
    assert!(browser::BrowserRuntime::new(serde_json::to_string(&foreign).unwrap()).is_err());
    assert!(browser::BrowserRuntime::new("{}".into()).is_err());
    assert!(browser::BrowserRuntime::new(" ".repeat(MAX_BODY_BYTES + 1)).is_err());
    let mut duplicate = configuration.clone();
    duplicate.services.push(duplicate.services[0].clone());
    assert!(browser::BrowserRuntime::new(serde_json::to_string(&duplicate).unwrap()).is_err());
    let runtime =
        browser::BrowserRuntime::new(serde_json::to_string(&configuration).unwrap()).unwrap();
    if origin == MEMBER {
        let board = browser_output(
            runtime.invoke(r#"{"action":"board.status","version":1,"body":{}}"#.into()),
        )
        .await;
        assert_eq!(board["result"]["connection"], "Disconnected");
        let mutation = browser_output(
            runtime.invoke(r#"{"action":"board.heartbeat","version":1,"body":{}}"#.into()),
        )
        .await;
        assert_eq!(mutation, json!({"status":"error","error":"unavailable"}));
    }
    let status = r#"{"action":"runtime.status","version":1,"body":{}}"#;
    let pending: Vec<_> = (0..MAX_CLIENTS)
        .map(|_| runtime.invoke(status.into()))
        .collect();
    assert_eq!(
        browser_output(runtime.invoke(status.into())).await,
        json!({"status":"error","error":"capacity"})
    );
    for result in pending {
        let result = browser_output(result).await;
        assert_eq!(result["result"]["preload"], "unavailable");
    }
    assert_eq!(
        browser_output(runtime.invoke(" ".repeat(MAX_BODY_BYTES + 1))).await,
        json!({"status":"error","error":"capacity"})
    );
    assert_eq!(
        browser_output(
            runtime.invoke(r#"{"action":"runtime.status","version":1,"body":{},"body":{}}"#.into())
        )
        .await,
        json!({"status":"error","error":"invalid_request"})
    );
    // No JavaScript waiter remains, but the admitted real revocation still owns
    // completion before the following request is reauthenticated by the actor.
    drop(runtime.invoke(r#"{"action":"client.revoke","version":1,"body":{}}"#.into()));
    assert_eq!(
        browser_output(runtime.invoke(status.into())).await,
        json!({"status":"error","error":"unauthorized"})
    );
    wasm_bindgen_futures::JsFuture::from(runtime.dispose())
        .await
        .unwrap();
    wasm_bindgen_futures::JsFuture::from(runtime.dispose())
        .await
        .unwrap();
    assert_eq!(
        browser_output(runtime.invoke(status.into())).await,
        json!({"status":"error","error":"unavailable"})
    );

    let draining =
        browser::BrowserRuntime::new(serde_json::to_string(&configuration).unwrap()).unwrap();
    let admitted = draining.invoke(r#"{"action":"client.revoke","version":1,"body":{}}"#.into());
    wasm_bindgen_futures::JsFuture::from(draining.dispose())
        .await
        .unwrap();
    assert_eq!(
        browser_output(admitted).await,
        json!({"status":"ok","result":{"revoked":true},"events":[{"event":"client_revoked"}]})
    );
}
