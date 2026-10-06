use super::*;
use futures_util::future::LocalBoxFuture;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Lifecycle-only start_composed tests: real Door/Pairing/Client, no readiness claims.
// Parent wires this as sibling native::composition_tests; only super::* is used.
const ORIGIN: &str = "https://member.example";
const STATUS: &[u8] = br#"{"action":"runtime.status","version":1,"body":{}}"#;
const REVOKE: &[u8] = br#"{"action":"client.revoke","version":1,"body":{}}"#;

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        11
    }
}

fn configuration() -> Configuration {
    Configuration::new(
        "a".into(),
        BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
    )
    .unwrap()
}

fn pairing(actions: BTreeSet<String>) -> Pairing {
    Pairing {
        origin: ORIGIN.into(),
        role: Role::Member,
        actions,
        lifetime_seconds: 60,
    }
}

fn status_only() -> Pairing {
    pairing(BTreeSet::from(["runtime.status".into()]))
}

// Bounded invoke helper: real Client bytes with a bounded owner round trip.
async fn invoke(client: &Client, request: &[u8]) -> Output {
    tokio::time::timeout(Duration::from_secs(5), client.invoke_bytes(request))
        .await
        .unwrap()
        .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    // Record the real action, then try to upgrade refusal to success.
    Preserve,
    // Pass through; optionally gate dispatch and drain on notifies.
    Gate,
    // Panic inside the admitted dispatch future.
    Panic,
}

// Test double: signals lifecycle via bounded channels/shared order only. It
// never fabricates custody and never claims readiness.
struct Probe {
    mode: Mode,
    seen: Option<tokio::sync::mpsc::Sender<String>>,
    entered: Option<tokio::sync::mpsc::Sender<()>>,
    allow: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    log: Arc<Mutex<Vec<&'static str>>>,
}

type Order = Arc<Mutex<Vec<&'static str>>>;
fn probe(mode: Mode) -> (Probe, Order) {
    let log = Arc::new(Mutex::new(Vec::new()));
    (
        Probe {
            mode,
            seen: None,
            entered: None,
            allow: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            log: log.clone(),
        },
        log,
    )
}

impl VaultComposer for Probe {
    fn after_dispatch<'a>(
        &'a mut self,
        _door: &'a mut Door,
        _origin: &'a str,
        _token: &'a ClientToken,
        action: &'a str,
        output: &'a mut Output,
        _now: u64,
    ) -> LocalBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            match self.mode {
                Mode::Preserve => {
                    if let Some(seen) = &self.seen {
                        let _ = seen.send(action.to_owned()).await;
                    }
                    // Deliberate violation: owner must restore the refusal.
                    *output = Output::Ok {
                        result: serde_json::json!({}),
                        events: Vec::new(),
                    };
                    Ok(())
                }
                Mode::Gate => {
                    if let Some(entered) = &self.entered {
                        let _ = entered.send(()).await;
                        self.allow.notified().await;
                    }
                    Ok(())
                }
                Mode::Panic => panic!("deliberate dispatch failure"),
            }
        })
    }
    fn close(&mut self) {
        self.log.lock().unwrap().push("close");
    }
    fn drain(&mut self) -> LocalBoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.log.lock().unwrap().push("drain");
            if self.mode == Mode::Gate {
                self.release.notified().await;
                self.log.lock().unwrap().push("drained");
            }
            Ok(())
        })
    }
}

type Initialization = LocalBoxFuture<'static, Result<(Door, Box<dyn VaultComposer>)>>;
fn composed(probe: Probe) -> impl FnOnce() -> Initialization + Send {
    move || {
        Box::pin(async move {
            Ok((
                Door::new(configuration()),
                Box::new(probe) as Box<dyn VaultComposer>,
            ))
        })
    }
}

#[tokio::test]
async fn refused_dispatch_keeps_original_error() {
    // Composer sees the real action but cannot turn refusal into success.
    let (mut probe, _log) = probe(Mode::Preserve);
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(4);
    probe.seen = Some(seen_tx);
    let embedded = Embedded::start_composed(composed(probe), status_only(), Arc::new(FixedClock))
        .await
        .unwrap();
    // `client.revoke` is registered but outside this pairing's grant.
    let output = invoke(embedded.client(), REVOKE).await;
    assert!(matches!(
        output,
        Output::Error {
            error: ErrorCode::Unauthorized
        }
    ));
    let seen = tokio::time::timeout(Duration::from_secs(2), seen_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen, "client.revoke");
    embedded.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_waits_for_drain_after_waiter_cancel() {
    // Close-before-drain; shutdown waits; a cancelled waiter cannot abort composition.
    let (mut probe, log) = probe(Mode::Gate);
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(1);
    probe.entered = Some(entered_tx);
    let (allow, release) = (probe.allow.clone(), probe.release.clone());
    let embedded = Embedded::start_composed(composed(probe), status_only(), Arc::new(FixedClock))
        .await
        .unwrap();
    let (client, runtime) = embedded.into_parts();
    let client = Arc::new(client);
    let call = tokio::spawn({
        let client = client.clone();
        async move { client.invoke_bytes(STATUS).await }
    });
    // Owner is inside admitted dispatch; cancel the HTTP waiter itself.
    tokio::time::timeout(Duration::from_secs(5), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    call.abort();
    allow.notify_one();
    let mut shutdown = Box::pin(runtime.shutdown());
    // Drain gate is still closed, so shutdown must stay pending.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
            .await
            .is_err()
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*log.lock().unwrap(), vec!["close", "drain", "drained"]);
}

#[tokio::test]
async fn invalid_pairing_drains_composer_before_return() {
    // Pairing failure drains synchronously before Err, never detached.
    let (test_probe, log) = probe(Mode::Gate);
    let release = test_probe.release.clone();
    let starting = Embedded::start_composed(
        composed(test_probe),
        pairing(BTreeSet::from(["not.a.registered.action".into()])),
        Arc::new(FixedClock),
    );
    tokio::pin!(starting);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut starting)
            .await
            .is_err()
    );
    release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(5), starting)
        .await
        .unwrap();
    assert!(matches!(result, Err(ErrorCode::Unauthorized)));
    assert_eq!(*log.lock().unwrap(), vec!["close", "drain", "drained"]);
}

#[tokio::test]
async fn dispatch_panic_fences_and_returns_reconcile() {
    // Caught dispatch panic fences later actions; shutdown returns Reconcile.
    let (test_probe, log) = probe(Mode::Panic);
    let runtime =
        Embedded::start_composed(composed(test_probe), status_only(), Arc::new(FixedClock))
            .await
            .unwrap();
    let output = invoke(runtime.client(), STATUS).await;
    assert!(matches!(
        output,
        Output::Error {
            error: ErrorCode::Reconcile
        }
    ));
    assert_eq!(*log.lock().unwrap(), vec!["close", "drain"]);
    // Later actions are fenced without touching the composer again.
    let output = invoke(runtime.client(), STATUS).await;
    assert!(matches!(
        output,
        Output::Error {
            error: ErrorCode::Unavailable
        }
    ));
    assert_eq!(*log.lock().unwrap(), vec!["close", "drain"]);
    assert_eq!(runtime.shutdown().await, Err(ErrorCode::Reconcile));
}
