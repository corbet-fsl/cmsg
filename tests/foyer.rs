//! Real cvld fixture runs in a separate process and dependency graph. There is
//! no accepting test transport or server feature in the cmsg production graph.
#![cfg(not(target_arch = "wasm32"))]
use cmsg::door::{foyer, native, *};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

const MEMBER: &str = "https://alpha.example.test";
const ADMIN: &str = "https://admin.alpha.example.test";
const ROOT: &str = "https://admin.root.example.test";
const WALLET: &str = "https://wallet.example.test";

fn fixture() -> Value {
    let path =
        std::env::var("CMSG_FOYER_FIXTURE").expect("Run this suite with .ci/with-foyer-fixture.py");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
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

fn grant(door: &mut Door, origin: &str, role: Role, now: u64) -> ClientToken {
    door.pair_client(
        origin,
        role,
        catalog().into_iter().map(|action| action.action).collect(),
        now,
        now + 60,
    )
    .unwrap()
}

async fn invoke(client: &native::Client, action: &str, body: Value) -> Value {
    let input = serde_json::to_vec(&Invocation {
        action: action.into(),
        version: 1,
        body,
    })
    .unwrap();
    serde_json::to_value(client.invoke_bytes(&input).await.unwrap()).unwrap()
}

#[tokio::test]
async fn local_http_routes_real_member_admin_root_and_rejects_foreign_authority() {
    let fixture = fixture();
    let now = fixture["now"].as_u64().unwrap();
    struct Clock(u64);
    impl native::Clock for Clock {
        fn now(&self) -> u64 {
            self.0
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (router, (member, admin, root, vault)) = native::router_with(
        move || async move {
            let configuration = Configuration::new(
                "alpha".into(),
                BTreeMap::from([
                    (Role::Member, BTreeSet::from([MEMBER.into(), WALLET.into()])),
                    (Role::Admin, BTreeSet::from([ADMIN.into()])),
                    (Role::Root, BTreeSet::from([ROOT.into()])),
                ]),
            )
            .unwrap();
            let mut door = Door::new(configuration);
            for (origin, role, scope, name) in [
                (MEMBER, Role::Member, foyer::Scope::Community, "member"),
                (ADMIN, Role::Admin, foyer::Scope::Community, "admin"),
                (WALLET, Role::Member, foyer::Scope::Global, "global"),
            ] {
                door.bind_foyer(
                    origin,
                    role,
                    foyer::Sessions::new(scope, session(&fixture[name])),
                )
                .unwrap();
            }
            door.bind_foyer(
                ROOT,
                Role::Root,
                foyer::Sessions::new(foyer::Scope::Community, session(&fixture["root"]))
                    .with_service(foyer::Scope::Global, session(&fixture["global_root"]))
                    .unwrap(),
            )
            .unwrap();
            assert!(door.live_membership(ADMIN).is_err());
            assert!(door.current_policy(ADMIN).is_err());
            assert!(door.live_membership(ROOT).is_err());
            assert!(door.live_membership(WALLET).is_err());
            assert!(door.current_policy(WALLET).is_err());
            assert!(door
                .live_membership("https://foreign.example.test")
                .is_err());
            assert!(door
                .current_policy(MEMBER)
                .unwrap()
                .with_current(now, |_| ())
                .is_err());
            // This fixture supplied an actual bearer at construction; it did
            // not run the original Foyer login/deadline adoption. The selected
            // community port exists but cannot invent its session deadline.
            assert!(door
                .live_membership(MEMBER)
                .unwrap()
                .observe(|| now)
                .await
                .is_err());
            assert!(door
                .bind_foyer(
                    MEMBER,
                    Role::Root,
                    foyer::Sessions::new(foyer::Scope::Community, session(&fixture["root"]))
                )
                .is_err());
            assert!(door
                .bind_foyer(
                    MEMBER,
                    Role::Member,
                    foyer::Sessions::new(foyer::Scope::Community, session(&fixture["member"]))
                )
                .is_err());
            assert!(
                foyer::Sessions::new(foyer::Scope::Global, session(&fixture["global"]))
                    .with_service(foyer::Scope::Global, session(&fixture["global"]))
                    .is_err()
            );
            let member = grant(&mut door, MEMBER, Role::Member, now);
            let admin = grant(&mut door, ADMIN, Role::Admin, now);
            let root = grant(&mut door, ROOT, Role::Root, now);
            let vault = grant(&mut door, WALLET, Role::Member, now);
            Ok((door, (member, admin, root, vault)))
        },
        BTreeSet::from([address.to_string()]),
        Arc::new(Clock(now)),
    )
    .await
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://{address}");
    let member = native::Client::new(&base, MEMBER, member).unwrap();
    let admin = native::Client::new(&base, ADMIN, admin).unwrap();
    let root = native::Client::new(&base, ROOT, root).unwrap();
    let vault = native::Client::new(&base, WALLET, vault).unwrap();
    assert_eq!(
        invoke(&member, "foyer.lobby", json!({})).await["status"],
        "ok"
    );
    assert_eq!(
        invoke(&vault, "foyer.global_public", json!({})).await["status"],
        "ok"
    );
    let set = json!({"key":"quota","value":5,"inherit":false,"effective_at":now});
    let changed = invoke(&admin, "foyer.setting_set", set.clone()).await;
    assert_eq!(changed["status"], "ok", "{changed}");
    assert!(changed["result"]["policy_epoch"].as_u64().unwrap() > 1);
    let forced = invoke(
        &root,
        "foyer.platform_set",
        json!({"setting":set,"force":true}),
    )
    .await;
    // The owner closes platform settings to a community garden's Root: only the
    // root board's own admin host may edit them (cvld `Access::Root` on garden hosts).
    assert_eq!(
        forced,
        json!({"status":"error","error":"unauthorized"}),
        "{forced}"
    );
    for (client, action, body) in [
        (&member, "foyer.setting_set", set),
        (&admin, "foyer.platform_set", json!({})),
        (&vault, "foyer.lobby", json!({})),
        (&root, "foyer.handle_reserve", json!({"handle":"fictional"})),
    ] {
        assert_eq!(
            invoke(client, action, body).await,
            json!({"status":"error","error":"unauthorized"})
        );
    }
    assert_eq!(
        invoke(&member, "foyer.login_finish", json!({})).await,
        json!({"status":"error","error":"unsupported_action"})
    );
    assert!(!catalog()
        .iter()
        .any(|action| action.action == "foyer.development_gate"));
    for raw in [
        br#"{"action":"foyer.setting_set","version":1,"body":{"key":"quota","key":"different","value":1,"inherit":false,"effective_at":1}}"#.as_slice(),
        br#"{"action":"foyer.setting_set","version":1,"body":{"key":"quota","value":{"a":1,"a":2},"inherit":false,"effective_at":1}}"#,
    ] {
        let output = serde_json::to_value(admin.invoke_bytes(raw).await.unwrap()).unwrap();
        assert_eq!(output, json!({"status":"error","error":"invalid_request"}));
    }
    // A successful result is released only after the real owner committed the
    // logout. The next operation uses that exact revoked service session.
    assert_eq!(
        invoke(&member, "foyer.logout", json!({})).await["status"],
        "ok"
    );
    assert_eq!(
        invoke(&member, "foyer.lobby", json!({})).await,
        json!({"status":"error","error":"unauthorized"})
    );
    assert_eq!(
        invoke(&member, "runtime.status", json!({})).await["result"]["preload"],
        "unavailable"
    );
    server.abort();
}

async fn direct(door: &mut Door, token: &ClientToken, action: &str, now: u64) -> Output {
    surface::invoke(
        door,
        MEMBER,
        token.expose_for_transport(),
        action,
        1,
        json!({}),
        now,
    )
    .await
}

async fn stats(base: &str) -> Vec<usize> {
    let bytes = reqwest::get(format!("{base}/__stats"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn real_owner_unknown_reply_oversize_and_cancellation_never_allow_blind_retry() {
    let fixture = fixture();
    let now = fixture["now"].as_u64().unwrap();
    let base = fixture["faults"][0]["base"].as_str().unwrap();
    for index in 0..3 {
        let config = Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([MEMBER.into()]))]),
        )
        .unwrap();
        let mut door = Door::new(config);
        door.bind_foyer(
            MEMBER,
            Role::Member,
            foyer::Sessions::new(foyer::Scope::Global, session(&fixture["faults"][index])),
        )
        .unwrap();
        let token = grant(&mut door, MEMBER, Role::Member, now);
        if index < 2 {
            let action = if index == 0 {
                "foyer.logout"
            } else {
                "foyer.global_public"
            };
            assert!(matches!(
                direct(&mut door, &token, action, now).await,
                Output::Error {
                    error: ErrorCode::Reconcile
                }
            ));
        } else {
            // Poll the real operation until the actual owner has committed. The
            // proxy withholds only its reply; dropping the borrow is ambiguous.
            let pending = direct(&mut door, &token, "foyer.logout", now);
            tokio::pin!(pending);
            tokio::select! {
                _ = &mut pending => panic!("reply was withheld"),
                observed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    while stats(base).await[index] == 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }) => { observed.unwrap(); }
            }
        }
        assert!(matches!(
            direct(&mut door, &token, "foyer.global_public", now).await,
            Output::Error {
                error: ErrorCode::Reconcile
            }
        ));
        assert!(matches!(
            direct(&mut door, &token, "runtime.status", now).await,
            Output::Ok { .. }
        ));
    }
    reqwest::Client::new()
        .post(format!("{base}/__release"))
        .send()
        .await
        .unwrap();
    assert_eq!(stats(base).await, vec![1, 1, 1]);
}

#[tokio::test]
async fn explicit_root_board_routes_admin_actions_but_other_root_surfaces_stay_denied() {
    let fixture = fixture();
    let now = fixture["now"].as_u64().unwrap();
    for (explicit, community, primary, row, expected) in [
        (true, "root", foyer::Scope::Community, "root_board", "ok"),
        (
            false,
            "root",
            foyer::Scope::Community,
            "root_board",
            "error",
        ),
        (false, "alpha", foyer::Scope::Community, "root", "error"),
        (false, "root", foyer::Scope::Global, "global_root", "error"),
    ] {
        let config = if explicit {
            Configuration::root_board(ROOT.into()).unwrap()
        } else {
            Configuration::new(
                community.into(),
                BTreeMap::from([(Role::Root, BTreeSet::from([ROOT.into()]))]),
            )
            .unwrap()
        };
        let mut door = Door::new(config);
        door.bind_foyer(
            ROOT,
            Role::Root,
            foyer::Sessions::new(primary, session(&fixture[row])),
        )
        .unwrap();
        let token = grant(&mut door, ROOT, Role::Root, now);
        let output = surface::invoke(
            &mut door,
            ROOT,
            token.expose_for_transport(),
            "foyer.setting_set",
            1,
            json!({"key":"quota", "value":5,
                "inherit":false, "effective_at":now + 86_400}),
            now,
        )
        .await;
        let output = serde_json::to_value(output).unwrap();
        assert_eq!(output["status"], expected, "{output}");
        if explicit {
            assert!(output["result"]["policy_epoch"].as_u64().unwrap() > 1);
            assert_eq!(
                serde_json::to_value(
                    surface::invoke(
                        &mut door,
                        ROOT,
                        token.expose_for_transport(),
                        "foyer.handle_reserve",
                        1,
                        json!({"handle":"fictional"}),
                        now
                    )
                    .await
                )
                .unwrap()["error"],
                "unauthorized"
            );
        } else {
            assert_eq!(output["error"], "unauthorized");
        }
    }
    let mut root = Door::new(Configuration::root_board(ROOT.into()).unwrap());
    assert!(matches!(
        root.bind_foyer(
            ROOT,
            Role::Root,
            foyer::Sessions::new(foyer::Scope::Global, session(&fixture["global_root"]))
        ),
        Err(ErrorCode::Unauthorized)
    ));
}
