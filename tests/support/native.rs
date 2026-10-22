use super::*;
use axum::body::{Body, Bytes};
use futures_util::{stream, FutureExt};
use http_body_util::BodyExt;

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
fn actions() -> BTreeSet<String> {
    BTreeSet::from(["runtime.status".into(), "client.revoke".into()])
}
async fn paired_with(
    clock: Arc<dyn Clock>,
) -> (HttpState, ClientToken, std::thread::JoinHandle<Result<()>>) {
    let (runtime, token, thread) = Owner::start(
        || async {
            let mut door = Door::new(configuration());
            let token = door.pair_client(ORIGIN, Role::Member, actions(), 10, 100)?;
            Ok((door, token))
        },
        clock,
    )
    .await
    .unwrap();
    (
        HttpState::new(runtime, BTreeSet::from(["localhost:3000".into()])),
        token,
        thread,
    )
}
async fn paired() -> (HttpState, ClientToken) {
    let (state, token, _thread) = paired_with(Arc::new(FixedClock)).await;
    (state, token)
}
fn request(token: &ClientToken, body: Body) -> Request {
    Request::post("/invoke")
        .header("host", "localhost:3000")
        .header("origin", ORIGIN)
        .header(
            "authorization",
            format!("Bearer {}", token.expose_for_transport()),
        )
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}
fn pending() -> Body {
    Body::from_stream(stream::pending::<std::result::Result<Bytes, std::io::Error>>())
}
async fn assert_error(response: Response, expected: ErrorCode) {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        matches!(serde_json::from_slice::<Output>(&bytes).unwrap(), Output::Error{error} if error == expected)
    );
}
#[tokio::test(start_paused = true)]
async fn bounds_waiting_bodies_and_releases_capacity_after_timeout_or_cancel() {
    let (state, token) = paired().await;
    let mut calls = Vec::new();
    for _ in 0..MAX_CLIENTS {
        let mut call = Box::pin(dispatch(state.clone(), None, request(&token, pending())));
        assert!(call.as_mut().now_or_never().is_none());
        calls.push(call);
    }
    assert_eq!(state.requests.available_permits(), 0);
    assert_error(
        dispatch(state.clone(), None, request(&token, pending())).await,
        ErrorCode::Capacity,
    )
    .await;
    drop(calls.pop());
    assert_eq!(state.requests.available_permits(), 1);
    assert_error(
        dispatch(state.clone(), None, request(&token, pending())).await,
        ErrorCode::Unavailable,
    )
    .await;
    drop(calls);
    assert_eq!(state.requests.available_permits(), MAX_CLIENTS);
    assert_eq!(
        dispatch(state.clone(), None, request(&token, Body::from(REVOKE)))
            .await
            .status(),
        StatusCode::OK
    );
    // A revoked capability is refused without polling this permanently pending body.
    assert_error(
        dispatch(state, None, request(&token, pending())).await,
        ErrorCode::Unauthorized,
    )
    .await;
}
#[tokio::test]
async fn rejects_invalid_header_bytes_and_preserves_reconciliation_status() {
    let (state, token) = paired().await;
    let mut req = request(&token, Body::empty());
    req.headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_bytes(&[255]).unwrap());
    assert_error(dispatch(state, None, req).await, ErrorCode::Unauthorized).await;
    assert_eq!(
        response(Output::Error {
            error: ErrorCode::Reconcile
        })
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
#[tokio::test]
async fn rechecks_authority_after_body_completion() {
    let (state, token) = paired().await;
    let revoked = Zeroizing::new(token.expose_for_transport().to_owned());
    let control = state.clone();
    let body = Body::from_stream(stream::once(async move {
        let permit = control.requests.acquire_owned().await.unwrap();
        assert!(matches!(
            control
                .runtime
                .invoke(ORIGIN.into(), revoked, REVOKE.to_vec(), permit)
                .await,
            Output::Ok { .. }
        ));
        Ok::<_, std::io::Error>(Bytes::from_static(STATUS))
    }));
    assert_error(
        dispatch(state, None, request(&token, body)).await,
        ErrorCode::Unauthorized,
    )
    .await;
}

struct GateClock {
    count: std::sync::atomic::AtomicUsize,
    at: usize,
    entered: tokio::sync::Notify,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
impl GateClock {
    fn new(at: usize) -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            at,
            entered: tokio::sync::Notify::new(),
            released: std::sync::Mutex::new(false),
            wake: std::sync::Condvar::new(),
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_one();
    }
}
impl Clock for GateClock {
    fn now(&self) -> u64 {
        if self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == self.at {
            self.entered.notify_one();
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.wake.wait(released).unwrap();
            }
        }
        11
    }
}
#[tokio::test]
async fn channel_waiters_are_bounded_and_cancellation_releases_capacity() {
    let clock = Arc::new(GateClock::new(0));
    let (state, token, _thread) = paired_with(clock.clone()).await;
    let mut calls = Vec::new();
    for _ in 0..MAX_CLIENTS {
        let mut call = Box::pin(dispatch(state.clone(), None, request(&token, pending())));
        assert!(call.as_mut().now_or_never().is_none());
        calls.push(call);
    }
    clock.entered.notified().await;
    assert_eq!(state.requests.available_permits(), 0);
    assert_error(
        dispatch(state.clone(), None, request(&token, pending())).await,
        ErrorCode::Capacity,
    )
    .await;
    drop(calls);
    assert_eq!(state.requests.available_permits(), MAX_CLIENTS);
    clock.release();
    assert_eq!(
        dispatch(state, None, request(&token, Body::from(STATUS)))
            .await
            .status(),
        StatusCode::OK
    );
}

struct PanicClock {
    at: usize,
    count: std::sync::atomic::AtomicUsize,
}
impl Clock for PanicClock {
    fn now(&self) -> u64 {
        assert_ne!(
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            self.at
        );
        11
    }
}
#[tokio::test]
async fn panics_fence_both_authentication_and_admitted_execution() {
    for (at, expected) in [(0, ErrorCode::Unavailable), (1, ErrorCode::Reconcile)] {
        let (state, token, thread) = paired_with(Arc::new(PanicClock {
            at,
            count: std::sync::atomic::AtomicUsize::new(0),
        }))
        .await;
        assert_error(
            dispatch(state.clone(), None, request(&token, Body::from(REVOKE))).await,
            expected,
        )
        .await;
        assert_error(
            dispatch(state, None, request(&token, Body::empty())).await,
            ErrorCode::Unavailable,
        )
        .await;
        assert_eq!(
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .unwrap()
                .unwrap(),
            Err(ErrorCode::Reconcile)
        );
    }
}
#[tokio::test]
async fn stopped_owner_is_refused_before_body_and_after_body_completion() {
    let (state, token) = paired().await;
    let control = state.runtime.clone();
    let body = Body::from_stream(stream::once(async move {
        control.0.send(Command::Stop).await.unwrap();
        control.0.closed().await;
        Ok::<_, std::io::Error>(Bytes::from_static(STATUS))
    }));
    assert_error(
        dispatch(state.clone(), None, request(&token, body)).await,
        ErrorCode::Unavailable,
    )
    .await;
    assert_error(
        dispatch(state, None, request(&token, pending())).await,
        ErrorCode::Unavailable,
    )
    .await;
}
#[tokio::test]
async fn drain_finishes_admitted_execution_after_http_waiter_cancellation() {
    let clock = Arc::new(GateClock::new(1));
    let (state, token, thread) = paired_with(clock.clone()).await;
    let mut call = Box::pin(dispatch(
        state.clone(),
        None,
        request(&token, Body::from(REVOKE)),
    ));
    tokio::select! {
        _ = clock.entered.notified() => {},
        _ = &mut call => panic!("owner must be held inside admitted execution"),
    }
    drop(call);
    assert_eq!(state.requests.available_permits(), MAX_CLIENTS - 1);
    // Queue the observation and Stop while the original admitted revoke is held.
    let (reply, receive) = oneshot::channel();
    state
        .runtime
        .0
        .send(Command::Authenticate {
            origin: ORIGIN.into(),
            token: Zeroizing::new(token.expose_for_transport().into()),
            reply,
        })
        .await
        .unwrap();
    state.runtime.0.send(Command::Stop).await.unwrap();
    clock.release();
    assert_eq!(receive.await.unwrap(), Err(ErrorCode::Unauthorized));
    tokio::task::spawn_blocking(move || thread.join())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(state.requests.available_permits(), MAX_CLIENTS);
}
#[tokio::test]
async fn embedded_owns_pairing_and_non_send_initialization_and_drains_shutdown() {
    let embedded = Embedded::start(
        || async {
            // Construct this thread-confined value inside the factory and keep it
            // over an await: the initializer future intentionally cannot be Send.
            let held = std::rc::Rc::new(configuration());
            tokio::task::yield_now().await;
            let configuration = std::rc::Rc::try_unwrap(held).ok().unwrap();
            Ok(Door::new(configuration))
        },
        Pairing {
            origin: ORIGIN.into(),
            role: Role::Member,
            actions: actions(),
            lifetime_seconds: 60,
        },
        Arc::new(FixedClock),
    )
    .await
    .unwrap();
    assert!(matches!(
        embedded.client().invoke_bytes(STATUS).await.unwrap(),
        Output::Ok { .. }
    ));
    let (client, runtime) = embedded.into_parts();
    // The same non-Clone client can be owned by a 'static consumer. Retaining
    // it cannot keep the HTTP listener or owner alive after explicit shutdown.
    let client = tokio::spawn(async move {
        assert!(matches!(
            client.invoke_bytes(STATUS).await.unwrap(),
            Output::Ok { .. }
        ));
        client
    })
    .await
    .unwrap();
    runtime.shutdown().await.unwrap();
    assert!(matches!(
        client.invoke_bytes(STATUS).await,
        Err(ErrorCode::Reconcile)
    ));
    for lifetime in [0, MAX_GRANT_SECONDS + 1] {
        assert!(Embedded::start(
            || async { Ok(Door::new(configuration())) },
            Pairing {
                origin: ORIGIN.into(),
                role: Role::Member,
                actions: actions(),
                lifetime_seconds: lifetime
            },
            Arc::new(FixedClock)
        )
        .await
        .is_err());
    }
    assert!(router(
        || async { Err(ErrorCode::Refused) },
        BTreeSet::from(["localhost".into()]),
        Arc::new(FixedClock)
    )
    .await
    .is_err());
    assert!(router(
        || async { panic!("initializer failed") },
        BTreeSet::from(["localhost".into()]),
        Arc::new(FixedClock)
    )
    .await
    .is_err());
}

/// Serve `state` on loopback with a short operation hop; the returned clients
/// share one capability, like a front end restarted with the same pairing.
async fn served(
    mut state: HttpState,
    token: &ClientToken,
) -> (Client, Client, tokio::task::JoinHandle<std::io::Result<()>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    state.hosts = BTreeSet::from([address.clone()]);
    state.hop_wait = Duration::from_millis(40);
    let server = tokio::spawn(async move { axum::serve(listener, routes(state)).await });
    let client = || {
        let token = ClientToken(Zeroizing::new(token.expose_for_transport().into()));
        Client::with_hop(
            &format!("http://{address}"),
            ORIGIN,
            token,
            Duration::from_millis(150),
        )
        .unwrap()
    };
    (client(), client(), server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_action_longer_than_the_hop_reports_its_real_outcome() {
    // The owner is held inside the admitted action (second clock reading) for
    // many client hops; the client neither gives up nor reports Reconcile.
    let clock = Arc::new(GateClock::new(1));
    let (state, token, _thread) = paired_with(clock.clone()).await;
    let operations = state.operations.clone();
    let (client, _, server) = served(state, &token).await;
    let release = clock.clone();
    tokio::spawn(async move {
        release.entered.notified().await;
        tokio::time::sleep(Duration::from_millis(700)).await;
        release.release();
    });
    assert!(matches!(
        client.invoke_bytes(STATUS).await.unwrap(),
        Output::Ok { .. }
    ));
    // Read outcomes are acknowledged by the next request and then forgotten;
    // a repeated identical request after that is a new action.
    assert_eq!(operations.table().kept.len(), 1);
    assert!(matches!(
        client.invoke_bytes(STATUS).await.unwrap(),
        Output::Ok { .. }
    ));
    assert_eq!(operations.table().started, 2);
    assert_eq!(operations.table().kept.len(), 1);
    assert!(operations.table().running.is_empty());
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_front_end_reattaches_to_the_running_action() {
    let clock = Arc::new(GateClock::new(1));
    let (state, token, _thread) = paired_with(clock.clone()).await;
    let operations = state.operations.clone();
    let (first, restarted, server) = served(state, &token).await;
    // The first front end starts the action and dies while it runs.
    let mut call = Box::pin(async move { first.invoke_bytes(STATUS).await });
    tokio::select! {
        _ = clock.entered.notified() => {},
        _ = &mut call => panic!("the owner must be held inside the action"),
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    drop(call);
    assert_eq!(operations.table().running.len(), 1);
    // The restarted front end repeats the request and attaches to the running
    // action instead of starting it again, then gets its real outcome.
    let release = clock.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        release.release();
    });
    assert!(matches!(
        restarted.invoke_bytes(STATUS).await.unwrap(),
        Output::Ok { .. }
    ));
    // An outcome nobody has acknowledged yet is kept for the next restart, too.
    let again = Client::with_hop(
        restarted.endpoint.origin().ascii_serialization().as_str(),
        ORIGIN,
        ClientToken(Zeroizing::new(token.expose_for_transport().into())),
        Duration::from_millis(150),
    )
    .unwrap();
    assert!(matches!(
        again.invoke_bytes(STATUS).await.unwrap(),
        Output::Ok { .. }
    ));
    assert_eq!(operations.table().started, 1);
    server.abort();
}

struct SetClock(std::sync::atomic::AtomicU64);
impl Clock for SetClock {
    fn now(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
fn operation_request(token: &ClientToken, body: &'static [u8]) -> Request {
    let mut req = request(token, Body::from(body));
    req.headers_mut()
        .insert(OPERATION, HeaderValue::from_static("1"));
    req
}

#[tokio::test]
async fn a_revoked_or_expired_capability_gets_no_kept_outcome() {
    // Revoked: the kept status outcome is refused and dropped.
    let (state, token) = paired().await;
    let kept = dispatch(state.clone(), None, operation_request(&token, STATUS)).await;
    assert_eq!(kept.status(), StatusCode::OK);
    assert_eq!(state.operations.table().kept.len(), 1);
    assert_eq!(
        dispatch(state.clone(), None, request(&token, Body::from(REVOKE)))
            .await
            .status(),
        StatusCode::OK
    );
    assert_error(
        dispatch(state.clone(), None, operation_request(&token, STATUS)).await,
        ErrorCode::Unauthorized,
    )
    .await;
    assert!(state.operations.table().kept.is_empty());
    // Expired: the same without any owner command after the outcome was kept.
    let clock = Arc::new(SetClock(std::sync::atomic::AtomicU64::new(11)));
    let (state, token, _thread) = paired_with(clock.clone()).await;
    let kept = dispatch(state.clone(), None, operation_request(&token, STATUS)).await;
    assert_eq!(kept.status(), StatusCode::OK);
    clock.0.store(100, std::sync::atomic::Ordering::SeqCst);
    assert_error(
        dispatch(state.clone(), None, operation_request(&token, STATUS)).await,
        ErrorCode::Unauthorized,
    )
    .await;
    assert!(state.operations.table().kept.is_empty());
}

#[tokio::test]
async fn operation_hops_refuse_malformed_protocol_headers() {
    let (state, token) = paired().await;
    for (name, value) in [("cmsg-operation", "2"), ("cmsg-acknowledge", "not-an-id")] {
        let mut req = request(&token, Body::from(STATUS));
        req.headers_mut()
            .insert(OPERATION, HeaderValue::from_static("1"));
        req.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
        assert_error(
            dispatch(state.clone(), None, req).await,
            ErrorCode::InvalidRequest,
        )
        .await;
    }
    let ids = vec![encode_operation(&[0; 32]); MAX_ACKNOWLEDGED + 1].join(",");
    let mut req = request(&token, Body::from(STATUS));
    req.headers_mut()
        .insert(OPERATION, HeaderValue::from_static("1"));
    req.headers_mut()
        .insert(ACKNOWLEDGE, HeaderValue::from_str(&ids).unwrap());
    assert_error(
        dispatch(state.clone(), None, req).await,
        ErrorCode::InvalidRequest,
    )
    .await;
    // A refused capability is answered but leaves nothing behind.
    let mut req = request(
        &ClientToken(Zeroizing::new("AAAA".into())),
        Body::from(STATUS),
    );
    req.headers_mut()
        .insert(OPERATION, HeaderValue::from_static("1"));
    assert_error(
        dispatch(state.clone(), None, req).await,
        ErrorCode::Unauthorized,
    )
    .await;
    assert!(state.operations.table().kept.is_empty());
}

#[tokio::test]
async fn a_cancelled_operation_unregisters_and_kept_outcomes_are_bounded() {
    let operations = Arc::new(Operations::default());
    let Attached::Started(finish, mut receiver) = operations.attach([1; 32], [0; 32]) else {
        panic!("a new id starts an operation");
    };
    assert!(matches!(
        operations.attach([1; 32], [0; 32]),
        Attached::Running(_)
    ));
    // Its task ended without an outcome: waiters see the end, nothing is kept.
    drop(finish);
    assert!(operations.table().running.is_empty());
    assert!(receiver
        .wait_for(|outcome| outcome.is_some())
        .await
        .is_err());
    for n in 0..=MAX_KEPT {
        let Attached::Started(finish, _) = operations.attach([n as u8 + 2; 32], [0; 32]) else {
            panic!("a new id starts an operation");
        };
        finish.complete(Output::Error {
            error: ErrorCode::Refused,
        });
    }
    let table = operations.table();
    assert_eq!(table.kept.len(), MAX_KEPT);
    assert!(!table.kept.contains_key(&[2; 32]));
}

#[tokio::test]
async fn client_acknowledgements_are_bounded_and_pending_needs_an_operation() {
    let (_, token) = paired().await;
    let client = Client::with_hop(
        "http://127.0.0.1:1",
        ORIGIN,
        token,
        Duration::from_millis(150),
    )
    .unwrap();
    client.restore_acknowledged((0..MAX_KEPT + 3).map(|n| n.to_string()).collect());
    assert_eq!(client.acknowledged.lock().unwrap().len(), MAX_KEPT);
    assert_eq!(client.take_acknowledged().len(), MAX_ACKNOWLEDGED);
    // A `pending` answer without an operation id is outside the protocol.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route(
            "/invoke",
            post(|| async {
                (
                    StatusCode::ACCEPTED,
                    Json(serde_json::json!({ "status": "pending" })),
                )
            }),
        )
        .layer(middleware::map_response(no_store));
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let (_, token) = paired().await;
    let client = Client::with_hop(
        &format!("http://{address}"),
        ORIGIN,
        token,
        Duration::from_millis(150),
    )
    .unwrap();
    assert!(matches!(
        client.invoke_bytes(STATUS).await,
        Err(ErrorCode::Reconcile)
    ));
    server.abort();
}
