use super::*;
use axum::body::{Body, Bytes};
use futures_util::{stream, FutureExt};
use http_body_util::BodyExt;

const ORIGIN: &str = "https://member.example";
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> u64 {
        11
    }
}
fn paired() -> (HttpState, ClientToken) {
    let config = Configuration::new(
        "a".into(),
        BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
    )
    .unwrap();
    let mut door = Door::new(config);
    let token = door
        .pair_client(
            ORIGIN,
            Role::Member,
            BTreeSet::from(["runtime.status".into()]),
            10,
            100,
        )
        .unwrap();
    (
        HttpState {
            door: Arc::new(Mutex::new(door)),
            hosts: BTreeSet::from(["localhost:3000".into()]),
            clock: Arc::new(FixedClock),
            requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        },
        token,
    )
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
    let (state, token) = paired();
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
    let response = dispatch(state.clone(), None, request(&token, pending())).await;
    assert_error(response, ErrorCode::Unavailable).await;
    drop(calls);
    assert_eq!(state.requests.available_permits(), MAX_CLIENTS);
    state.door.lock().unwrap().revoke(&token);
    // A revoked capability is refused before any pending body is polled.
    let before = tokio::time::Instant::now();
    assert_error(
        dispatch(state.clone(), None, request(&token, pending())).await,
        ErrorCode::Unauthorized,
    )
    .await;
    assert_eq!(before, tokio::time::Instant::now());
}
#[tokio::test]
async fn rejects_invalid_header_bytes_and_poisoned_embedding_state() {
    let (state, token) = paired();
    let mut req = request(&token, Body::empty());
    req.headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_bytes(&[255]).unwrap());
    assert_error(
        dispatch(state.clone(), None, req).await,
        ErrorCode::Unauthorized,
    )
    .await;
    let locked = state.door.clone();
    let _ = std::thread::spawn(move || {
        let _guard = locked.lock().unwrap();
        panic!("trusted embedding failure");
    })
    .join();
    assert_error(
        dispatch(state, None, request(&token, Body::empty())).await,
        ErrorCode::Unavailable,
    )
    .await;
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
    let (state, token) = paired();
    let revoked = ClientToken::from_protected_transport(Zeroizing::new(
        token.expose_for_transport().as_bytes().to_vec(),
    ))
    .unwrap();
    let control = state.door.clone();
    let body = Body::from_stream(stream::once(async move {
        control.lock().unwrap().revoke(&revoked);
        Ok::<_, std::io::Error>(Bytes::from_static(
            br#"{"action":"runtime.status","version":1,"body":{}}"#,
        ))
    }));
    assert_error(
        dispatch(state.clone(), None, request(&token, body)).await,
        ErrorCode::Unauthorized,
    )
    .await;
    let (state, token) = paired();
    let control = state.door.clone();
    let body = Body::from_stream(stream::once(async move {
        let _ = std::thread::spawn(move || {
            let _guard = control.lock().unwrap();
            panic!("trusted embedding failure");
        })
        .join();
        Ok::<_, std::io::Error>(Bytes::from_static(b"{}"))
    }));
    assert_error(
        dispatch(state, None, request(&token, body)).await,
        ErrorCode::Unavailable,
    )
    .await;
}
