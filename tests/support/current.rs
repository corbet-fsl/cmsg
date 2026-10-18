//! Original signed Charter over loopback HTTPS and the existing real Vault.
//! Its exact Create/Use fixture establishes storage custody, never production G3.
use super::*;
use crate::door::{current, registry, Invocation, Output};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[path = "../fixture/https.rs"]
mod https;

const ORIGIN: &str = "https://member.example.test";

#[derive(Clone)]
struct Time(Arc<AtomicU64>);
impl cbrd::clnk::Clock for Time {
    fn now(&self) -> std::result::Result<u64, cmmr::Error> {
        self.0
            .load(Ordering::SeqCst)
            .checked_mul(1000)
            .ok_or(cmmr::Error::Unavailable)
    }
}

fn issuer(now: u64) -> Signer {
    Signer::new("alpha", SecretKey::from_seed(&mut [11; 32]), now - 1, 3600).unwrap()
}

fn feed(now: u64, revision: u64, minimum: &str) -> Vec<u8> {
    let mut signer = issuer(now);
    let mut result = json!({
        "revision": revision,
        "policy_epoch": 2,
        "key_ring": signer.key_ring().to_cbor()
    });
    let sign = |signer: &mut Signer, kind, content: Value| {
        signer
            .sign(kind, &serde_json::to_vec(&content).unwrap(), now, now + 300)
            .unwrap()
    };
    result["manifest"] = json!(sign(
        &mut signer,
        Kind::SettingsSnapshot,
        json!({
            "purpose":"cplc.trust.v1", "community":"alpha",
            "revision":revision, "policy_epoch":2,
            "key_ring":issuer(now).key_ring().to_cbor(), "schema_version":1
        }),
    ));
    let schema = json!({"community":"alpha", "version":1, "public":[], "private":[]});
    for (name, kind, content) in [
        (
            "settings",
            Kind::SettingsSnapshot,
            json!({
                "forum.heartbeat_ms":3000,
                "forum.lease_ms":10000,
                "forum.minimum_client_version":minimum,
                "forum.room_passes_per_epoch":4
            }),
        ),
        ("schema", Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1", "current":1,
                "versions":[{"schema":schema, "changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!(["alpha"])),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            json!({"members":[], "devices":[]}),
        ),
    ] {
        result[name] = json!(sign(
            &mut signer,
            kind,
            json!({"community":"alpha", "revision":revision,
                "policy_epoch":2, "content":content}),
        ));
    }
    serde_json::to_vec(&result).unwrap()
}

struct PublicFeed {
    https: https::HttpsFixture,
    bytes: Arc<std::sync::RwLock<Vec<u8>>>,
}
impl PublicFeed {
    async fn new(bytes: Vec<u8>) -> Self {
        let bytes = Arc::new(std::sync::RwLock::new(bytes));
        let held = bytes.clone();
        let app = axum::Router::new().route(
            "/v1/trust_feed",
            axum::routing::post(move || {
                let held = held.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        held.read().unwrap().clone(),
                    )
                }
            }),
        );
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/current-tls");
        let https = https::HttpsFixture::start(
            app,
            (),
            &directory.join("certificate.pem"),
            &directory.join("key.pem"),
        )
        .await
        .unwrap();
        Self { https, bytes }
    }

    async fn foyer(&self, now: u64) -> foyer::Foyer<foyer::Transport> {
        let mut trust = cfyr::trust::Trust::native(
            cchr::Configuration {
                origin: self.https.base_url().into(),
                community: "alpha".into(),
                key_ring: issuer(now).key_ring().to_cbor(),
                minimum_revision: 1,
                ring_revision: 0,
            },
            cfyr::trust::Config {
                retry_entropy: 15,
                refresh_seconds: 30,
                poll_seconds: 1,
                request_seconds: 30,
                initial_backoff_seconds: 1,
                maximum_backoff_seconds: 10,
                maximum_staleness_seconds: 60,
            },
            &[include_bytes!("current-tls/ca.der").to_vec()],
        )
        .unwrap();
        trust.start(|| now).await.unwrap();
        foyer::Foyer::with_trust(
            foyer::fixture_transport("https://keyhole.example.test", "keyhole.example.test"),
            trust,
        )
    }

    async fn refresh(&self, foyer: &mut foyer::Foyer<foyer::Transport>, now: u64, bytes: Vec<u8>) {
        *self.bytes.write().unwrap() = bytes;
        let mut trust = foyer.trust().unwrap();
        trust.refresh(now).unwrap();
        assert!(trust.poll(|| now).await.unwrap());
    }
}

fn request(action: &str) -> Vec<u8> {
    let body = match action {
        "inbox.snapshot" | "inbox.relation" => json!({"conversation":vec![1;32], "peer":"peer"}),
        "inbox.history" | "inbox.thread" => json!({"conversation":vec![1;32]}),
        "inbox.delivery_status" => json!({"conversation":vec![1;32], "message":vec![2;32]}),
        _ => json!({}),
    };
    serde_json::to_vec(&Invocation {
        action: action.into(),
        version: 1,
        body,
    })
    .unwrap()
}

#[tokio::test]
async fn signed_minimum_version_guards_every_inbox_action_without_disabling_cleanup() {
    let now = cbrd::clnk::Clock::now(&crate::door::board::SystemClock).unwrap() / 1000;
    let server = PublicFeed::new(feed(now, 1, "999.0.0")).await;
    let foyer = server.foyer(now).await;
    let (owner, _, checks) = open_fixture().await;
    let mut door = Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    door.bind_foyer(
        ORIGIN,
        Role::Member,
        foyer::Sessions::new(foyer::Scope::Community, foyer),
    )
    .unwrap();
    door.vaults.insert(ORIGIN.into(), Box::new(owner));
    let token = door
        .pair_client(
            ORIGIN,
            Role::Member,
            registry::catalog()
                .into_iter()
                .map(|action| action.action)
                .collect(),
            now,
            now + 120,
        )
        .unwrap();
    for action in [
        "inbox.snapshot",
        "inbox.history",
        "inbox.relation",
        "inbox.delivery_status",
    ] {
        assert!(matches!(
            door.dispatch(
                ORIGIN,
                token.expose_for_transport(),
                &request(action),
                live_now()
            )
            .await,
            Output::Error {
                error: ErrorCode::UnsupportedVersion
            }
        ));
    }
    assert_eq!(checks.get(), 0);
    server
        .refresh(
            door.foyers
                .get_mut(ORIGIN)
                .unwrap()
                .sessions
                .clients
                .get_mut(&foyer::Scope::Community)
                .unwrap(),
            live_now(),
            feed(now, 2, env!("CARGO_PKG_VERSION")),
        )
        .await;
    for action in [
        "inbox.snapshot",
        "inbox.history",
        "inbox.relation",
        "inbox.delivery_status",
    ] {
        assert!(matches!(
            door.dispatch(
                ORIGIN,
                token.expose_for_transport(),
                &request(action),
                live_now()
            )
            .await,
            Output::Ok { .. }
        ));
    }
    assert_eq!(checks.get(), 4);
    server
        .refresh(
            door.foyers
                .get_mut(ORIGIN)
                .unwrap()
                .sessions
                .clients
                .get_mut(&foyer::Scope::Community)
                .unwrap(),
            live_now(),
            feed(now, 3, "999.0.0"),
        )
        .await;
    for action in ["runtime.status", "vault.lock", "client.revoke"] {
        assert!(matches!(
            door.dispatch(
                ORIGIN,
                token.expose_for_transport(),
                &request(action),
                live_now()
            )
            .await,
            Output::Ok { .. }
        ));
    }
    door.close_owned().await;
    server.https.shutdown().await.unwrap();
}

fn live_now() -> u64 {
    cbrd::clnk::Clock::now(&crate::door::board::SystemClock).unwrap() / 1000
}

#[tokio::test]
async fn current_original_charter_allows_real_committed_inbox_history() {
    let now = 2_000_000_000;
    let server = PublicFeed::new(feed(now, 1, env!("CARGO_PKG_VERSION"))).await;
    let foyer = server.foyer(now).await;
    let mut current = foyer.current_policy();
    let (mut owner, _, checks) = open_fixture().await;
    let clock = Time(Arc::new(AtomicU64::new(now)));
    let (history, completed) = current::read_with_clock(
        &mut owner,
        &mut current,
        current::Scope {
            community: "alpha",
            expires: now + 60,
            floor: now,
        },
        &clock,
        |vault| {
            vault.history(Conversation {
                conversation: [1; 32],
            })
        },
    )
    .await
    .unwrap();
    assert!(history.is_empty());
    assert_eq!(completed, now);
    assert_eq!(checks.get(), 1);
    Box::new(owner).lock().await;
    drop(foyer);
    server.https.shutdown().await.unwrap();
}

#[tokio::test]
async fn minimum_version_raised_while_real_keys_wait_withholds_completed_history() {
    let now = 2_000_000_000;
    let server = PublicFeed::new(feed(now, 1, env!("CARGO_PKG_VERSION"))).await;
    let mut foyer = server.foyer(now).await;
    let mut current = foyer.current_policy();
    let (mut owner, gate, checks) = open_fixture().await;
    let clock = Time(Arc::new(AtomicU64::new(now)));
    let held = gate.lock().await;
    let mut read = Box::pin(current::read_with_clock(
        &mut owner,
        &mut current,
        current::Scope {
            community: "alpha",
            expires: now + 60,
            floor: now,
        },
        &clock,
        |vault| {
            vault.history(Conversation {
                conversation: [1; 32],
            })
        },
    ));
    assert!(read.as_mut().now_or_never().is_none());
    assert_eq!(checks.get(), 1);
    server
        .refresh(&mut foyer, now, feed(now, 2, "999.0.0"))
        .await;
    drop(held);
    assert_eq!(read.await.err(), Some(ErrorCode::UnsupportedVersion));
    Box::new(owner).lock().await;
    drop(foyer);
    server.https.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_grant_regressed_clock_or_disposed_current_foyer_withhold_real_waited_reads() {
    for failure in [0, 1, 2] {
        let now = 2_000_000_000;
        let server = PublicFeed::new(feed(now, 1, env!("CARGO_PKG_VERSION"))).await;
        let foyer = server.foyer(now).await;
        let mut current = foyer.current_policy();
        let (mut owner, gate, checks) = open_fixture().await;
        let clock = Time(Arc::new(AtomicU64::new(now)));
        let held = gate.lock().await;
        let mut read = Box::pin(current::read_with_clock(
            &mut owner,
            &mut current,
            current::Scope {
                community: "alpha",
                expires: now + 60,
                floor: now,
            },
            &clock,
            |vault| {
                vault.history(Conversation {
                    conversation: [1; 32],
                })
            },
        ));
        assert!(read.as_mut().now_or_never().is_none());
        assert_eq!(checks.get(), 1);
        match failure {
            0 => clock.0.store(now + 60, Ordering::SeqCst),
            1 => clock.0.store(now - 1, Ordering::SeqCst),
            2 => (),
            _ => unreachable!(),
        }
        if failure == 2 {
            drop(foyer);
        }
        drop(held);
        let expected = [
            ErrorCode::Unauthorized,
            ErrorCode::Clock,
            ErrorCode::Unavailable,
        ][failure];
        assert_eq!(read.await.err(), Some(expected));
        Box::new(owner).lock().await;
        server.https.shutdown().await.unwrap();
    }
}
