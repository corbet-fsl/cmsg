#![cfg(not(target_arch = "wasm32"))]
//! Lifecycle checks only. These do not grant membership or claim Tor readiness.
use cmsg::door::{
    native::{Clock, Embedded, Pairing},
    Configuration, Door, ErrorCode, Output, Role,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

const ORIGIN: &str = "https://member.example";
struct Time;
impl Clock for Time {
    fn now(&self) -> u64 {
        10
    }
}
struct Retained {
    _local: Rc<()>,
    dropped: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Retained {
    fn drop(&mut self) {
        self.task.abort();
        self.dropped.store(true, Ordering::SeqCst);
    }
}
fn door() -> Door {
    Door::new(
        Configuration::new(
            "example".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    )
}
fn pairing() -> Pairing {
    Pairing {
        origin: ORIGIN.into(),
        role: Role::Member,
        actions: BTreeSet::from(["runtime.status".into()]),
        lifetime_seconds: 30,
    }
}

#[tokio::test]
async fn local_guard_outlives_actions_and_independent_work_progresses() {
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = dropped.clone();
    let (send, mut receive) = mpsc::channel::<oneshot::Sender<()>>(1);
    let runtime = Embedded::start_retained(
        move || async move {
            let local = Rc::new(());
            let held = local.clone();
            let task = tokio::task::spawn_local(async move {
                let _held = held;
                while let Some(reply) = receive.recv().await {
                    let _ = reply.send(());
                }
            });
            Ok((
                door(),
                Retained {
                    _local: local,
                    dropped: observed,
                    task,
                },
            ))
        },
        pairing(),
        Arc::new(Time),
    )
    .await
    .unwrap();
    for _ in 0..2 {
        let (reply, result) = oneshot::channel();
        send.send(reply).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), result)
            .await
            .unwrap()
            .unwrap();
        let output = runtime
            .client()
            .invoke_bytes(br#"{"action":"runtime.status","version":1,"body":{}}"#)
            .await
            .unwrap();
        assert!(
            matches!(output, Output::Ok { ref result, .. } if result["preload"] == "unavailable")
        );
        assert!(!dropped.load(Ordering::SeqCst));
    }
    runtime.shutdown().await.unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    assert!(send.send(oneshot::channel().0).await.is_err());
}

#[tokio::test]
async fn failed_local_pairing_drops_the_retained_owner() {
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = dropped.clone();
    let mut invalid = pairing();
    invalid.actions.insert("not.a.registered.action".into());
    let result = Embedded::start_retained(
        move || async move {
            let task = tokio::task::spawn_local(std::future::pending());
            Ok((
                door(),
                Retained {
                    _local: Rc::new(()),
                    dropped: observed,
                    task,
                },
            ))
        },
        invalid,
        Arc::new(Time),
    )
    .await;
    assert!(matches!(result, Err(ErrorCode::Unauthorized)));
    assert!(dropped.load(Ordering::SeqCst));
}

struct PanicClock(Arc<AtomicBool>);
impl Clock for PanicClock {
    fn now(&self) -> u64 {
        assert!(!self.0.load(Ordering::SeqCst), "deliberate owner failure");
        10
    }
}
#[tokio::test]
async fn owner_panic_drops_retained_work_before_shutdown() {
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = dropped.clone();
    let failed = Arc::new(AtomicBool::new(false));
    let runtime = Embedded::start_retained(
        move || async move {
            let task = tokio::task::spawn_local(std::future::pending());
            Ok((
                door(),
                Retained {
                    _local: Rc::new(()),
                    dropped: observed,
                    task,
                },
            ))
        },
        pairing(),
        Arc::new(PanicClock(failed.clone())),
    )
    .await
    .unwrap();
    failed.store(true, Ordering::SeqCst);
    let output = runtime
        .client()
        .invoke_bytes(br#"{"action":"runtime.status","version":1,"body":{}}"#)
        .await
        .unwrap();
    assert!(matches!(
        output,
        Output::Error {
            error: ErrorCode::Unavailable
        }
    ));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(runtime.shutdown().await, Err(ErrorCode::Reconcile));
}
