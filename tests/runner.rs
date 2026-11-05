//! The background jobs on this runtime (native owner thread and browser vault frame
//! alike), the runner gate of a Door and, in a real browser, the one wave runner per
//! device across tabs.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
use browser_coverage_runtime as _;
use cmsg::door::{
    courier::{
        decode_reachability, encode_reachability, Body, Couriers, Directory, Frame, SharedDoor,
    },
    runner::{RunnerGate, RunnerState, RunnerStatus},
    tasks, *,
};
use cmsh::{async_trait, Address, Backend, Capabilities, LatencyClass, Listener, Scheme};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    rc::Rc,
    sync::{Arc, Mutex},
    time::Duration,
};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ORIGIN: &str = "https://omega.example.test";
const PEER: &str = "peer-of-omega";

/// Native: the owner thread's `LocalSet`. Browser: the page's own executor.
async fn local<F: Future>(future: F) -> F::Output {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::LocalSet::new().run_until(future).await
    }
    #[cfg(target_arch = "wasm32")]
    {
        future.await
    }
}

fn door() -> Door {
    Door::new(
        Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
        )
        .unwrap(),
    )
}

fn address(byte: u8) -> Address {
    Address::new(Scheme::new("tor").unwrap(), vec![byte; 8]).unwrap()
}

/// A Mesh backend that keeps every application message it is asked to send.
#[derive(Clone, Default)]
struct Sent(Arc<Mutex<Vec<(Address, Vec<u8>)>>>);
struct Silent(Address);
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Listener for Silent {
    fn address(&self) -> &Address {
        &self.0
    }
    async fn next(&mut self) -> std::result::Result<cmsh::Event, cmsh::Error> {
        std::future::pending().await
    }
}
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Backend for Sent {
    fn scheme(&self) -> Scheme {
        Scheme::new("tor").unwrap()
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            anonymous: true,
            datagrams: false,
            offline_delivery: false,
            dht: false,
            latency: LatencyClass::Interactive,
        }
    }
    fn max_payload(&self) -> usize {
        16 * 1024
    }
    async fn listen(&self) -> std::result::Result<Box<dyn Listener>, cmsh::Error> {
        Ok(Box::new(Silent(address(1))))
    }
    async fn app_message(
        &self,
        to: &Address,
        payload: &[u8],
    ) -> std::result::Result<(), cmsh::Error> {
        self.0.lock().unwrap().push((to.clone(), payload.to_vec()));
        Ok(())
    }
    async fn app_call(&self, _: &Address, _: &[u8]) -> std::result::Result<Vec<u8>, cmsh::Error> {
        Ok(vec![])
    }
}
struct Here;
impl cmsh::Spawn for Here {
    fn spawn(&self, future: cmsh::BoxFuture<'static, ()>) {
        let _ = tasks::spawn(future);
    }
}

async fn bound(sent: &Sent) -> SharedDoor {
    let mut door = door();
    let mesh = cmsh::Mesh::builder(Arc::new(Here))
        .backend(Arc::new(sent.clone()))
        .build()
        .unwrap();
    door.bind_mesh(ORIGIN, mesh).await.unwrap();
    Rc::new(tokio::sync::Mutex::new(door))
}

/// First contact: the peer's published reachability (the forum entry in production).
struct Known;
impl Directory for Known {
    fn reachability(&self, peer: &str) -> Option<Vec<u8>> {
        (peer == PEER).then(|| encode_reachability(&[address(9)]))
    }
}

/// Wait (bounded) until `done` holds.
async fn until(done: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if done() {
            return true;
        }
        tasks::sleep(Duration::from_millis(50)).await;
    }
    done()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn the_courier_runs_on_this_runtime_and_delivers_what_waits_for_a_known_peer() {
    local(async {
        let sent = Sent::default();
        let door = bound(&sent).await;
        {
            let mut guard = door.lock().await;
            guard.bind_directory(ORIGIN, Box::new(Known)).unwrap();
            guard
                .courier_queue(
                    ORIGIN,
                    PEER,
                    Body::Chat {
                        conversation: [3; 32],
                        wire: vec![7, 7],
                    },
                )
                .unwrap();
        }
        let mut couriers = Couriers::default();
        couriers.sync(&door).await;
        assert_eq!(couriers.running(), vec![(ORIGIN.to_owned(), 0)]);
        assert!(
            until(|| !sent.0.lock().unwrap().is_empty()).await,
            "the courier sent the waiting frame"
        );
        let (to, bytes) = sent.0.lock().unwrap()[0].clone();
        assert_eq!(to, address(9));
        let frame: Frame = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            frame.body,
            Body::Chat {
                conversation: [3; 32],
                wire: vec![7, 7]
            }
        );
        // The frame carries this device's own listener address as the route back.
        assert_eq!(decode_reachability(&frame.reach), vec![address(1)]);
        // A second sync starts nothing twice; stop ends the courier and frees the Door.
        couriers.sync(&door).await;
        assert_eq!(couriers.running().len(), 1);
        couriers.stop(&door).await;
        assert!(couriers.running().is_empty());
        assert!(
            Rc::try_unwrap(door).is_ok(),
            "no job holds the Door any more"
        );
    })
    .await;
}

#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    all(feature = "browser-prover", target_arch = "wasm32")
))]
mod device {
    use super::*;
    use ckmg::wallet_engine::account::{Evidence, UpdateInput};
    use cmsg::door::inbox_lineage::{CharterView, HandleOpener, PeerUnavailable};
    use cmsg::door::inbox_waves::{
        device::{bind, WaveCapabilities},
        wallet::WaveProver,
    };
    use cmsg::door::record::RecordCurrent;

    #[derive(Clone)]
    struct NoPeers;
    impl HandleOpener for NoPeers {
        async fn read(
            &mut self,
            _: &ckmg::Binding,
            _: &[u8],
        ) -> std::result::Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
            Err(PeerUnavailable)
        }
    }
    struct NoCharter;
    impl CharterView for NoCharter {
        fn with_current<T>(
            &mut self,
            _: &str,
            _: u64,
            _: impl FnOnce(&cchr::VerifiedCharter) -> std::result::Result<T, cnbx::ContactError>,
        ) -> std::result::Result<T, cnbx::ContactError> {
            Err(cnbx::ContactError::Authority)
        }
    }
    /// A prover this test never reaches: no account is bound, so every round ends
    /// at the witness load, before any proof.
    struct Unreached;
    impl WaveProver for Unreached {
        async fn prove_update(&mut self, _: &UpdateInput) -> Result<Vec<u8>> {
            panic!("no round gets past the witness load");
        }
        async fn prove_evidence(&mut self, _: &Evidence) -> Result<Vec<u8>> {
            panic!("no round gets past the witness load");
        }
    }
    enum NoCheck {}
    impl cwlt::wave::ProofCheck for NoCheck {
        async fn check(
            &self,
            _: &[cwlt::wave::PublicField],
            _: &[u8],
        ) -> std::result::Result<(), czkp::Error> {
            match *self {}
        }
    }
    fn capabilities() -> WaveCapabilities<Unreached, NoCheck> {
        WaveCapabilities {
            provers: Rc::new(|| Ok(Unreached)),
            verifier: Box::new(|_, _, _| Err(ErrorCode::Unavailable)),
        }
    }

    /// The red test of the browser wave stack: on main the browser build has neither
    /// the device binder nor a courier, so a browser member's `inbox.wave_send` refuses
    /// at `inbox_waves.rs:94` (no ports) and nothing would carry the outbox.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    async fn a_bound_wave_device_runs_its_worker_beside_the_courier_until_the_mesh_ends() {
        local(async {
            let sent = Sent::default();
            let door = bound(&sent).await;
            {
                let mut guard = door.lock().await;
                bind(
                    &mut guard,
                    ORIGIN,
                    capabilities(),
                    RecordCurrent::default(),
                    NoPeers,
                    NoCharter,
                )
                .unwrap();
                assert_eq!(
                    bind(
                        &mut guard,
                        ORIGIN,
                        capabilities(),
                        RecordCurrent::default(),
                        NoPeers,
                        NoCharter,
                    ),
                    Err(ErrorCode::Unauthorized),
                    "a bound wave stack is never replaced"
                );
            }
            {
                // The member starts writing: the worker is woken, nothing is sent.
                let guard = door.lock().await;
                assert!(guard.wake_wave_worker(ORIGIN));
                assert!(!guard.wake_wave_worker("https://other.example.test"));
            }
            assert!(
                sent.0.lock().unwrap().is_empty(),
                "no Hello leaves at compose"
            );
            let mut couriers = Couriers::default();
            couriers.sync(&door).await;
            assert_eq!(
                couriers.running(),
                vec![(ORIGIN.to_owned(), 1)],
                "one courier and its wave worker"
            );
            couriers.stop(&door).await;
            assert!(
                Rc::try_unwrap(door).is_ok(),
                "the wave worker ended with the courier"
            );
        })
        .await;
    }
}

fn pair(door: &mut Door) -> ClientToken {
    door.pair_client(
        ORIGIN,
        Role::Member,
        catalog().into_iter().map(|a| a.action).collect(),
        10,
        100,
    )
    .unwrap()
}

async fn call(door: &mut Door, token: &ClientToken, action: &str) -> Output {
    let body = serde_json::json!({"action": action, "version": 1, "body": {}}).to_string();
    door.dispatch(ORIGIN, token.expose_for_transport(), body.as_bytes(), 11)
        .await
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn a_door_without_the_runner_answers_its_mesh_actions_runner_elsewhere() {
    let mut door = door();
    let token = pair(&mut door);
    let gate = RunnerGate::default();
    door.set_runner_gate(ORIGIN, gate.clone()).unwrap();
    assert_eq!(
        door.set_runner_gate(ORIGIN, RunnerGate::default()),
        Err(ErrorCode::Unauthorized),
        "the gate is set once"
    );
    let state = |output: Output| match output {
        Output::Ok { result, .. } => {
            serde_json::from_value::<RunnerStatus>(result)
                .unwrap()
                .state
        }
        Output::Error { error } => panic!("runner.status refused: {error:?}"),
    };
    assert_eq!(
        state(call(&mut door, &token, "runner.status").await),
        RunnerState::Here
    );
    gate.set(RunnerState::Elsewhere);
    assert_eq!(
        state(call(&mut door, &token, "runner.status").await),
        RunnerState::Elsewhere
    );
    for action in ["inbox.waves", "inbox.wave_outbox", "mesh.status"] {
        assert!(
            matches!(
                call(&mut door, &token, action).await,
                Output::Error {
                    error: ErrorCode::RunnerElsewhere
                }
            ),
            "{action} is a Mesh action"
        );
    }
    // Everything else is served as before; the takeover itself is the embedding's.
    assert!(matches!(
        call(&mut door, &token, "runtime.status").await,
        Output::Ok { .. }
    ));
    assert_eq!(
        state(call(&mut door, &token, "runner.take").await),
        RunnerState::Elsewhere
    );
    gate.set(RunnerState::Here);
    assert!(
        !matches!(
            call(&mut door, &token, "inbox.waves").await,
            Output::Error {
                error: ErrorCode::RunnerElsewhere
            }
        ),
        "with the runner here the Inbox answers for itself"
    );
}

// ---- the runner lock in a real browser ------------------------------------------

#[cfg(target_arch = "wasm32")]
fn tab(gate: &RunnerGate) -> (Door, ClientToken) {
    let mut door = Door::new(
        Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    door.set_runner_gate(ORIGIN, gate.clone()).unwrap();
    let token = door
        .pair_client(
            ORIGIN,
            Role::Member,
            catalog().into_iter().map(|a| a.action).collect(),
            10,
            100,
        )
        .unwrap();
    (door, token)
}

#[cfg(target_arch = "wasm32")]
async fn waves(door: &mut Door, token: &ClientToken) -> Output {
    let body = r#"{"action":"inbox.waves","version":1,"body":{}}"#;
    door.dispatch(ORIGIN, token.expose_for_transport(), body.as_bytes(), 11)
        .await
}

#[cfg(target_arch = "wasm32")]
fn elsewhere(output: &Output) -> bool {
    matches!(
        output,
        Output::Error {
            error: ErrorCode::RunnerElsewhere
        }
    )
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn the_second_tab_runs_nothing_until_it_takes_the_runner() {
    // A distinct origin per test keeps the lock name of this test to itself.
    let origin = "https://two-tabs.example.test";
    let (first, second) = (RunnerGate::default(), RunnerGate::default());
    use cmsg::door::browser::runner::{acquire, Ask};
    use std::cell::Cell;
    let held = acquire(origin, Ask::IfAvailable, first.clone())
        .await
        .unwrap()
        .expect("the first tab gets the runner");
    let lost = Rc::new(Cell::new(false));
    let flag = lost.clone();
    held.on_lost(move || flag.set(true));
    assert_eq!(first.state(), RunnerState::Here);

    assert!(
        acquire(origin, Ask::IfAvailable, second.clone())
            .await
            .unwrap()
            .is_none(),
        "the second tab gets no runner while the first holds it"
    );
    assert_eq!(second.state(), RunnerState::Elsewhere);
    let (mut tab, token) = tab(&second);
    assert!(
        elsewhere(&waves(&mut tab, &token).await),
        "typed, never a generic refusal"
    );

    // The takeover: the second tab steals, the first one's loss action runs.
    let taken = acquire(origin, Ask::Steal, second.clone())
        .await
        .unwrap()
        .expect("steal always grants");
    assert_eq!(second.state(), RunnerState::Here);
    for _ in 0..100 {
        if lost.get() {
            break;
        }
        gloo_timers::future::sleep(Duration::from_millis(20)).await;
    }
    assert!(lost.get(), "the old holder ends its jobs and Mesh");
    assert_eq!(first.state(), RunnerState::Elsewhere);
    assert!(!elsewhere(&waves(&mut tab, &token).await));

    // A clean release is no loss, and frees the runner for the next tab.
    drop(held);
    let lost_again = Rc::new(Cell::new(false));
    let flag = lost_again.clone();
    taken.on_lost(move || flag.set(true));
    drop(taken);
    let third = RunnerGate::default();
    assert!(acquire(origin, Ask::IfAvailable, third.clone())
        .await
        .unwrap()
        .is_some());
    assert!(!lost_again.get(), "releasing the lock is not losing it");
}
