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

fn feed(now: u64, revision: u64) -> Vec<u8> {
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
        ("settings", Kind::SettingsSnapshot, json!({})),
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

/// Inbox actions that stay callable below the signed minimum version because they are
/// cleanup (release or settle something already held), each with its one-line reason.
/// Empty: every Inbox action, including the background-worker calls, is guarded; a new
/// Inbox action fails the test until it is guarded or listed here with a reason.
const CLEANUP_EXEMPT_INBOX: [(&str, &str); 0] = [];

/// A minimal request body for a JSON schema: required fields only, the first variant.
fn sample(schema: &Value) -> Value {
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(value) = schema.get("enum").and_then(Value::as_array) {
        return value[0].clone();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(variants) = schema.get(key).and_then(Value::as_array) {
            let pick = variants
                .iter()
                .find(|variant| variant.get("type") != Some(&json!("null")))
                .unwrap_or(&variants[0]);
            return sample(pick);
        }
    }
    let kind = match schema.get("type") {
        Some(Value::Array(kinds)) => kinds
            .iter()
            .find(|kind| *kind != "null")
            .or(kinds.first())
            .and_then(Value::as_str),
        other => other.and_then(Value::as_str),
    };
    match kind {
        Some("object") => {
            let properties = schema.get("properties").and_then(Value::as_object);
            let required = schema.get("required").and_then(Value::as_array);
            let mut object = serde_json::Map::new();
            for name in required.into_iter().flatten().filter_map(Value::as_str) {
                let property = properties
                    .and_then(|all| all.get(name))
                    .unwrap_or(&Value::Null);
                object.insert(name.into(), sample(property));
            }
            Value::Object(object)
        }
        Some("array") => {
            let count = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let item = schema.get("items").map(sample).unwrap_or(Value::Null);
            Value::Array(vec![item; count as usize])
        }
        Some("string") => json!("a"),
        Some("integer" | "number") => schema.get("minimum").cloned().unwrap_or(json!(0)),
        Some("boolean") => json!(false),
        _ => Value::Null,
    }
}

/// Wave capabilities for the first phase only: the version guard refuses before any of
/// them is called, so each one is unreachable by construction.
struct NoPorts;
type Owned<'a, T> = crate::door::facades::OwnedFuture<'a, T>;
impl crate::door::inbox_waves::WavePorts for NoPorts {
    fn policy(&self, _: u64) -> crate::door::Result<crate::door::inbox_waves::Policy> {
        unreachable!("refused before the owner call")
    }
    fn terms<'a>(
        &'a self,
        _: &'a [u8; 32],
        _: &'a crate::door::inbox_waves::Hello,
        _: &'a str,
        _: u64,
        _: &'a dyn crate::door::inbox_waves::AccountSigner,
    ) -> Owned<'a, crate::door::inbox_waves::Terms> {
        unreachable!("refused before the owner call")
    }
    fn sign_contact<'a>(
        &'a self,
        _: crate::door::inbox_waves::ContactRequest<'a>,
        _: u64,
        _: &'a dyn crate::door::inbox_waves::AccountSigner,
    ) -> Owned<'a, Vec<u8>> {
        unreachable!("refused before the owner call")
    }
    fn verify_contact<'a>(
        &'a self,
        _: crate::door::inbox_waves::ContactRequest<'a>,
        _: &'a [u8],
        _: u64,
    ) -> Owned<'a, ()> {
        unreachable!("refused before the owner call")
    }
    fn verify_reservation<'a>(
        &'a self,
        _: &'a cwlt::wave::WaveStatement,
        _: &'a [u8],
        _: &'a cwlt::wave::WaveContext,
        _: u64,
    ) -> Owned<'a, cwlt::wave::VerifiedWaveReservation> {
        unreachable!("refused before the owner call")
    }
    fn verify_outcome<'a>(
        &'a self,
        _: &'a cwlt::wave::WaveOutcomeStatement,
        _: &'a [u8],
        _: &'a cwlt::wave::WaveContext,
        _: cwlt::wave::WaveOutcome,
        _: &'a [u8; 32],
        _: u64,
    ) -> Owned<'a, cwlt::wave::VerifiedWaveOutcome> {
        unreachable!("refused before the owner call")
    }
    fn own_record<'a>(&'a self, _: &'a ckmg::Binding) -> Owned<'a, ()> {
        unreachable!("refused before the owner call")
    }
    fn peer_lineage<'a>(&'a self, _: &'a ckmg::Binding) -> Owned<'a, ckmg::Lineage> {
        unreachable!("refused before the owner call")
    }
}

/// The runtime version is below the signed requirement at first, meets it after the first
/// refresh and is below it again after the second.
#[tokio::test]
async fn signed_minimum_version_guards_every_inbox_action_without_disabling_cleanup() {
    crate::door::with_client_version("0.0.1", minimum_version_guards_every_inbox_action()).await;
}

/// The one list of Inbox reads that carry the signed minimum-version guard. Both loops and
/// the expected number of lease checks derive from it; a new read is added here (the
/// catalog check below keeps every entry a real Inbox action).
const GUARDED_INBOX_READS: [&str; 5] = [
    "inbox.snapshot",
    "inbox.history",
    "inbox.thread",
    "inbox.relation",
    "inbox.delivery_status",
];

async fn minimum_version_guards_every_inbox_action() {
    // The set under test is the catalog's: every Family::Inbox action.
    let catalog = registry::catalog();
    let inbox: Vec<_> = catalog
        .iter()
        .filter(|entry| entry.family == registry::Family::Inbox)
        .collect();
    for action in GUARDED_INBOX_READS {
        assert!(
            inbox.iter().any(|entry| entry.action == action),
            "{action} is not an Inbox action of the catalog"
        );
    }
    for (action, reason) in CLEANUP_EXEMPT_INBOX {
        assert!(!reason.is_empty(), "{action} needs a reason");
        assert!(
            inbox.iter().any(|entry| entry.action == action),
            "{action} is not an Inbox action of the catalog"
        );
    }
    let now = cbrd::clnk::Clock::now(&crate::door::board::SystemClock).unwrap() / 1000;
    let server = PublicFeed::new(feed(now, 1)).await;
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
    door.bind_waves(ORIGIN, Box::new(NoPorts)).unwrap();
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
    // Every Inbox action of the catalog, not a hand-kept subset, is refused below the
    // signed minimum unless it is listed as cleanup.
    for entry in &inbox {
        if CLEANUP_EXEMPT_INBOX
            .iter()
            .any(|(name, _)| *name == entry.action)
        {
            continue;
        }
        let bytes = if GUARDED_INBOX_READS.contains(&entry.action.as_str()) {
            request(&entry.action)
        } else {
            serde_json::to_vec(&Invocation {
                action: entry.action.clone(),
                version: entry.version,
                body: sample(&entry.body),
            })
            .unwrap()
        };
        let reply = door
            .dispatch(ORIGIN, token.expose_for_transport(), &bytes, live_now())
            .await;
        assert!(
            matches!(
                reply,
                Output::Error {
                    error: ErrorCode::UnsupportedVersion
                }
            ),
            "{} is not guarded by the signed minimum version",
            entry.action
        );
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
            feed(now, 2),
        )
        .await;
    crate::door::set_client_version(env!("CARGO_PKG_VERSION"));
    for action in GUARDED_INBOX_READS {
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
    // One signed-requirement check per guarded action: the count follows the list.
    assert_eq!(checks.get(), GUARDED_INBOX_READS.len());
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
            feed(now, 3),
        )
        .await;
    crate::door::set_client_version("0.0.1");
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
    let server = PublicFeed::new(feed(now, 1)).await;
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
    crate::door::with_client_version(env!("CARGO_PKG_VERSION"), raised_while_keys_wait()).await;
}

async fn raised_while_keys_wait() {
    let now = 2_000_000_000;
    let server = PublicFeed::new(feed(now, 1)).await;
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
    server.refresh(&mut foyer, now, feed(now, 2)).await;
    crate::door::set_client_version("0.0.1");
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
        let server = PublicFeed::new(feed(now, 1)).await;
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

/// Journey row 6: the wave worker reads the Door's current Charter after its witness load.
/// The Door lock is fair, so another Door action can be served first while the worker waits,
/// and that action observes the same Trust a second later (every Inbox bracket and Board
/// read does). The worker's read must take its time once it holds the Door: a time taken
/// before the wait is behind the Charter's forward-only clock and is refused as a regression.
#[tokio::test]
async fn the_wave_trust_read_takes_its_time_once_the_door_is_held() {
    let now = 2_000_000_000;
    let server = PublicFeed::new(feed(now, 1)).await;
    let foyer = server.foyer(now).await;
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
    let door: crate::door::courier::SharedDoor = Rc::new(tokio::sync::Mutex::new(door));
    let time = Arc::new(AtomicU64::new(now));
    let clock = {
        let time = time.clone();
        move || time.load(Ordering::SeqCst)
    };
    // Another Door action holds the Door when the worker asks for it.
    let held = door.lock().await;
    let mut read = Box::pin(crate::door::inbox_waves::feed_trust::with_door_current(
        &door,
        ORIGIN,
        clock,
        |charter, at| Ok((charter.revision(), at)),
    ));
    assert!(read.as_mut().now_or_never().is_none(), "the Door is held");
    // That action observes the same Trust one second later, then releases the Door.
    time.store(now + 1, Ordering::SeqCst);
    held.current_policy(ORIGIN)
        .unwrap()
        .with_current(now + 1, |_| ())
        .unwrap();
    drop(held);
    assert_eq!(read.await, Ok(((1, now + 1), now + 1)));
    drop(door);
    server.https.shutdown().await.unwrap();
}

/// The refusals of the wave worker's trust read: a clock behind what the Charter already
/// observed, and an origin without a bound community, both answer unavailable/refused
/// (never a panic), so the worker's cadence retries.
#[tokio::test]
async fn the_wave_trust_read_refuses_a_clock_behind_the_charter_and_an_unbound_origin() {
    let now = 2_000_000_000;
    let server = PublicFeed::new(feed(now, 1)).await;
    let foyer = server.foyer(now).await;
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
    // The Charter has observed now + 5; a read at `now` regresses.
    door.current_policy(ORIGIN)
        .unwrap()
        .with_current(now + 5, |_| ())
        .unwrap();
    let door: crate::door::courier::SharedDoor = Rc::new(tokio::sync::Mutex::new(door));
    let behind = crate::door::inbox_waves::feed_trust::with_door_current(
        &door,
        ORIGIN,
        || now,
        |charter, at| Ok((charter.revision(), at)),
    )
    .await;
    assert_eq!(behind, Err(ErrorCode::Unavailable));
    let unbound = crate::door::inbox_waves::feed_trust::with_door_current(
        &door,
        "https://other.example.test",
        || now,
        |charter, at| Ok((charter.revision(), at)),
    )
    .await;
    assert_eq!(unbound, Err(ErrorCode::Unavailable));
    drop(door);
    server.https.shutdown().await.unwrap();
}

/// `inbox.wave_prewarm` on a real bound Door (signed Charter over loopback HTTPS, the real
/// Vault, the member origin): inside the current-policy bracket it wakes the origin's wave
/// worker once, starts the bound warm-up once, and sends nothing (the ports refuse any call).
struct CountingWarm(std::rc::Rc<std::cell::Cell<u32>>);
impl crate::door::inbox_waves::WavePrewarm for CountingWarm {
    fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
        self.0.set(self.0.get() + 1);
        Box::pin(async {})
    }
}
struct IdleWorker;
impl crate::door::wave_job::WaveWorker for IdleWorker {
    fn round(
        &self,
        _: crate::door::courier::SharedDoor,
        _: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize>>>> {
        unreachable!("the test never runs the worker; it only observes the wake")
    }
}

#[tokio::test]
async fn compose_wakes_the_wave_worker_once_warms_once_and_sends_nothing() {
    crate::door::with_client_version(env!("CARGO_PKG_VERSION"), async {
        let now = cbrd::clnk::Clock::now(&crate::door::board::SystemClock).unwrap() / 1000;
        let server = PublicFeed::new(feed(now, 1)).await;
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
        // Any wave port call (Terms, Hello, reserve, send) would panic: nothing may be sent.
        door.bind_waves(ORIGIN, Box::new(NoPorts)).unwrap();
        door.set_wave_worker(ORIGIN, std::rc::Rc::new(IdleWorker))
            .unwrap();
        let warmed = std::rc::Rc::new(std::cell::Cell::new(0));
        door.bind_wave_prewarm(ORIGIN, std::rc::Rc::new(CountingWarm(warmed.clone())))
            .unwrap();
        let wake = door.wave_wake(ORIGIN).expect("the worker has a wake");
        assert!(!wake.pending(), "no round is requested before the compose");
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
        let reply = door
            .dispatch(
                ORIGIN,
                token.expose_for_transport(),
                &request("inbox.wave_prewarm"),
                live_now(),
            )
            .await;
        assert!(matches!(reply, Output::Ok { .. }), "the compose is answered");
        assert!(wake.pending(), "the worker's next round is requested");
        assert_eq!(warmed.get(), 1, "the setup warm-up started exactly once");
        assert_eq!(checks.get(), 0, "the bracket reads nothing from the vault");
        door.close_owned().await;
        server.https.shutdown().await.unwrap();
    })
    .await;
}
