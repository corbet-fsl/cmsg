//! Native HTTP projection. Host and Origin are checked independently, and every
//! response is no-store. The runtime chooses a loopback listener; no body logs.
use super::*;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use futures_util::FutureExt;
use std::{future::Future, panic::AssertUnwindSafe, sync::Arc};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

/// Injected trusted clock. Member-controlled request data never supplies time.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone)]
struct HttpState {
    runtime: Owner,
    hosts: BTreeSet<String>,
    requests: Arc<tokio::sync::Semaphore>,
}

/// Only bounded messages cross threads. Door and all its child facades stay on
/// their owning thread, including browser-compatible Rc custody adapters.
#[derive(Clone)]
struct Owner(mpsc::Sender<Command>);
enum Command {
    Authenticate {
        origin: String,
        token: Zeroizing<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    Invoke {
        origin: String,
        token: Zeroizing<String>,
        envelope: Vec<u8>,
        reply: oneshot::Sender<Output>,
        permit: OwnedSemaphorePermit,
    },
    Stop,
}

impl Owner {
    async fn start<F, Fut, T>(
        initialize: F,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, T, std::thread::JoinHandle<Result<()>>)>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(Door, T)>> + 'static,
        T: Send + 'static,
    {
        let (sender, mut receiver) = mpsc::channel(MAX_CLIENTS);
        let (ready, initialized) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("cmsg-owner".into())
            .spawn(move || {
                let initialized = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                }));
                let Ok(Ok(runtime)) = initialized else {
                    let _ = ready.send(Err(ErrorCode::Unavailable));
                    return Err(ErrorCode::Unavailable);
                };
                runtime.block_on(tokio::task::LocalSet::new().run_until(async move {
                    let initialized = AssertUnwindSafe(async { initialize().await })
                        .catch_unwind()
                        .await;
                    let (mut door, value) = match initialized {
                        Ok(Ok(value)) => value,
                        Ok(Err(error)) => {
                            let _ = ready.send(Err(error));
                            return Err(error);
                        }
                        Err(_) => {
                            let _ = ready.send(Err(ErrorCode::Unavailable));
                            return Err(ErrorCode::Unavailable);
                        }
                    };
                    if ready.send(Ok(value)).is_err() {
                        door.close_owned().await;
                        return Err(ErrorCode::Unavailable);
                    }
                    let mut failed = false;
                    while let Some(command) = receiver.recv().await {
                        match command {
                            Command::Stop => receiver.close(),
                            Command::Authenticate {
                                origin,
                                token,
                                reply,
                            } => {
                                let checked = if failed {
                                    Err(ErrorCode::Unavailable)
                                } else {
                                    match std::panic::catch_unwind(AssertUnwindSafe(|| {
                                        door.authenticate(&origin, &token, clock.now()).map(|_| ())
                                    })) {
                                        Ok(result) => result,
                                        Err(_) => {
                                            failed = true;
                                            Err(ErrorCode::Unavailable)
                                        }
                                    }
                                };
                                let _ = reply.send(checked);
                            }
                            Command::Invoke {
                                origin,
                                token,
                                envelope,
                                reply,
                                permit,
                            } => {
                                let _permit = permit;
                                let output = if failed {
                                    Output::Error {
                                        error: ErrorCode::Unavailable,
                                    }
                                } else {
                                    // Even a lost HTTP waiter cannot cancel this future.
                                    // A panic may follow a durable child effect: reconcile,
                                    // then refuse every later request on this runtime.
                                    match AssertUnwindSafe(async {
                                        door.dispatch(&origin, &token, &envelope, clock.now()).await
                                    })
                                    .catch_unwind()
                                    .await
                                    {
                                        Ok(output) => output,
                                        Err(_) => {
                                            failed = true;
                                            Output::Error {
                                                error: ErrorCode::Reconcile,
                                            }
                                        }
                                    }
                                };
                                let _ = reply.send(output);
                            }
                        }
                    }
                    if failed {
                        // Never call domain methods on a panic-fenced owner.
                        // Dropping its state cannot grant another request access.
                        return Err(ErrorCode::Reconcile);
                    }
                    door.close_owned().await;
                    Ok(())
                }))
            })
            .map_err(|_| ErrorCode::Unavailable)?;
        let value = initialized.await.map_err(|_| ErrorCode::Unavailable)??;
        Ok((Self(sender), value, thread))
    }

    async fn authenticate(&self, origin: &str, token: &str) -> Result<()> {
        let (reply, receive) = oneshot::channel();
        self.0
            .send(Command::Authenticate {
                origin: origin.into(),
                token: Zeroizing::new(token.into()),
                reply,
            })
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        receive.await.map_err(|_| ErrorCode::Unavailable)?
    }

    async fn invoke(
        &self,
        origin: String,
        token: Zeroizing<String>,
        envelope: Vec<u8>,
        permit: OwnedSemaphorePermit,
    ) -> Output {
        let (reply, receive) = oneshot::channel();
        if self
            .0
            .send(Command::Invoke {
                origin,
                token,
                envelope,
                reply,
                permit,
            })
            .await
            .is_err()
        {
            return Output::Error {
                error: ErrorCode::Unavailable,
            };
        }
        // A vanished owner after admission may have committed. Never suggest retry.
        receive.await.unwrap_or(Output::Error {
            error: ErrorCode::Reconcile,
        })
    }
}

fn validate_hosts(hosts: &BTreeSet<String>) -> Result<()> {
    if hosts.is_empty()
        || hosts.len() > 8
        || hosts.iter().any(|host| {
            host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('@')
        })
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// Construct all facades inside a dedicated current-thread runtime. The factory
/// may produce a non-Send future and Door; only the factory crosses threads.
/// Dropping every router closes admission and drains admitted owner work.
pub async fn router<F, Fut>(
    initialize: F,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
) -> Result<Router>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<Door>> + 'static,
{
    router_with(
        move || async { Ok((initialize().await?, ())) },
        hosts,
        clock,
    )
    .await
    .map(|(router, ())| router)
}

/// Trusted initialization with one protected in-process startup result. This is
/// useful for host pairing; it is never exposed through an HTTP/JSON action.
/// Construct non-Send facades inside initialize, not before moving the factory.
pub async fn router_with<F, Fut, T>(
    initialize: F,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
) -> Result<(Router, T)>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(Door, T)>> + 'static,
    T: Send + 'static,
{
    validate_hosts(&hosts)?;
    let (runtime, value, _thread) = Owner::start(initialize, clock).await?;
    Ok((
        routes(HttpState {
            runtime,
            hosts,
            requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        }),
        value,
    ))
}

fn routes(state: HttpState) -> Router {
    Router::new()
        .route("/invoke", post(invoke))
        .route("/v1/{action}", post(call))
        .with_state(state)
        .fallback(|| async {
            response(Output::Error {
                error: ErrorCode::UnsupportedAction,
            })
        })
        .method_not_allowed_fallback(|| async {
            response(Output::Error {
                error: ErrorCode::InvalidRequest,
            })
        })
        .layer(middleware::map_response(no_store))
}

/// Trusted native pairing configuration. This is not an API request and grants
/// only local access; configured Foyer sessions supply remote authority.
pub struct Pairing {
    pub origin: String,
    pub role: Role,
    pub actions: BTreeSet<String>,
    pub lifetime_seconds: u64,
}

/// Owns the listener, protected local client and facade thread. No capability is
/// exposed as JSON, environment data or a URL. Explicit shutdown drains admitted
/// owner work, including work whose HTTP request has already disappeared.
pub struct Embedded {
    client: Client,
    runtime: RuntimeHandle,
}

/// Owns the embedded listener and facade thread independently of its single
/// protected client. Explicit shutdown drains admitted owner work even after
/// the client or an HTTP waiter has disappeared. No endpoint or capability is
/// exposed by this handle.
#[must_use = "retain the runtime handle and await shutdown after its client finishes"]
pub struct RuntimeHandle {
    owner: Owner,
    stop: Option<oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    thread: std::thread::JoinHandle<Result<()>>,
}
/// Public deployment data. Native construction uses the same schema as the
/// browser; capabilities, authenticators and storage secrets are not fields.
pub use super::browser::Configuration as DeviceConfiguration;

impl Embedded {
    /// Construct configured actual Foyer/Board owners inside the dedicated
    /// thread. This partial startup keeps custody/login/Mesh unavailable until
    /// their real initializer is integrated; it never claims messaging readiness.
    pub async fn configured(
        configuration: DeviceConfiguration,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let pairing = Pairing {
            origin: configuration.origin.clone(),
            role: configuration.role,
            actions: catalog().into_iter().map(|action| action.action).collect(),
            lifetime_seconds,
        };
        Self::start(
            move || async move { configuration.construct() },
            pairing,
            clock,
        )
        .await
    }

    pub async fn start<F, Fut>(
        initialize: F,
        pairing: Pairing,
        clock: Arc<dyn Clock>,
    ) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Door>> + 'static,
    {
        validate_origin(&pairing.origin)?;
        if pairing.lifetime_seconds == 0 || pairing.lifetime_seconds > MAX_GRANT_SECONDS {
            return Err(ErrorCode::InvalidRequest);
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let address = listener.local_addr().map_err(|_| ErrorCode::Unavailable)?;
        let origin = pairing.origin.clone();
        let pairing_clock = clock.clone();
        let (owner, token, thread) = Owner::start(
            move || async move {
                let mut door = initialize().await?;
                let now = pairing_clock.now();
                let expires = now
                    .checked_add(pairing.lifetime_seconds)
                    .ok_or(ErrorCode::Clock)?;
                let token =
                    door.pair_client(&pairing.origin, pairing.role, pairing.actions, now, expires)?;
                Ok((door, token))
            },
            clock,
        )
        .await?;
        let client = Client::new(&format!("http://{address}"), &origin, token)?;
        let app = routes(HttpState {
            runtime: owner.clone(),
            hosts: BTreeSet::from([address.to_string()]),
            requests: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        });
        let (stop, receive) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receive.await;
                })
                .await
        });
        Ok(Self {
            client,
            runtime: RuntimeHandle {
                owner,
                stop: Some(stop),
                server,
                thread,
            },
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Move the one protected client into an owned CLI/MCP consumer while the
    /// caller retains responsibility for draining the runtime. Neither value
    /// clones or exports its local capability.
    pub fn into_parts(self) -> (Client, RuntimeHandle) {
        (self.client, self.runtime)
    }

    pub async fn shutdown(self) -> Result<()> {
        let (client, runtime) = self.into_parts();
        drop(client);
        runtime.shutdown().await
    }
}

impl RuntimeHandle {
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let server = self.server.await;
        // Stop closes the queue and drains it; HTTP graceful shutdown alone is
        // insufficient because cancelled waiters may already be gone.
        let _ = self.owner.0.send(Command::Stop).await;
        let joined = tokio::task::spawn_blocking(move || self.thread.join()).await;
        joined
            .map_err(|_| ErrorCode::Reconcile)?
            .map_err(|_| ErrorCode::Reconcile)??;
        if !matches!(server, Ok(Ok(()))) {
            return Err(ErrorCode::Unavailable);
        }
        Ok(())
    }
}

// Never let different HTTP consumers choose different values for an authority
// header. Exact configured origins and hosts do not accept comma lists either.
fn unique_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

async fn call(
    State(state): State<HttpState>,
    Path(action): Path<String>,
    request: Request,
) -> Response {
    dispatch(state, Some(action), request).await
}

async fn invoke(State(state): State<HttpState>, request: Request) -> Response {
    dispatch(state, None, request).await
}

async fn dispatch(state: HttpState, action: Option<String>, request: Request) -> Response {
    let headers = request.headers();
    let host = unique_header(headers, header::HOST);
    let origin = unique_header(headers, header::ORIGIN);
    let token =
        unique_header(headers, header::AUTHORIZATION).and_then(|h| h.strip_prefix("Bearer "));
    let (Some(host), Some(origin), Some(token)) = (host, origin, token) else {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    };
    if !state.hosts.contains(host)
        || unique_header(headers, header::CONTENT_TYPE) != Some("application/json")
    {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    }
    let origin = origin.to_owned();
    let token = Zeroizing::new(token.to_owned());
    let Ok(permit) = state.requests.clone().try_acquire_owned() else {
        return response(Output::Error {
            error: ErrorCode::Capacity,
        });
    };
    // Bound queued work before authentication; repeat authority after body and
    // channel waiting with fresh time inside the owner thread.
    let authorized = state.runtime.authenticate(&origin, &token).await;
    if let Err(error) = authorized {
        return response(Output::Error { error });
    }
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return response(Output::Error {
                error: ErrorCode::Capacity,
            })
        }
        Err(_) => {
            return response(Output::Error {
                error: ErrorCode::Unavailable,
            })
        }
    };
    // Preserve the exact body bytes for the typed Serde decoder, including its
    // duplicate-field rejection. No Value round trip before authorization.
    let envelope = if let Some(action) = action {
        let Ok(body) = std::str::from_utf8(&bytes) else {
            return response(Output::Error {
                error: ErrorCode::InvalidRequest,
            });
        };
        let name = serde_json::to_string(&action).expect("a string always encodes as JSON");
        format!("{{\"action\":{name},\"version\":1,\"body\":{body}}}").into_bytes()
    } else {
        bytes.to_vec()
    };
    let output = state.runtime.invoke(origin, token, envelope, permit).await;
    response(output)
}

fn response(output: Output) -> Response {
    let code = match output {
        Output::Ok { .. } => StatusCode::OK,
        Output::Error {
            error: ErrorCode::Unauthorized,
        } => StatusCode::FORBIDDEN,
        Output::Error {
            error: ErrorCode::Capacity,
        } => StatusCode::PAYLOAD_TOO_LARGE,
        Output::Error {
            error: ErrorCode::Unavailable | ErrorCode::Reconcile,
        } => StatusCode::SERVICE_UNAVAILABLE,
        Output::Error { .. } => StatusCode::BAD_REQUEST,
    };
    (code, Json(output)).into_response()
}

// Includes routing and extraction refusals as well as domain responses.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Native paired-client transport for CLI/MCP/TUI. No Clone/Debug or credential
/// accessor exists. Pairing is performed by the trusted host, never by this client.
pub struct Client {
    http: reqwest::Client,
    endpoint: url::Url,
    origin: String,
    capability: ClientToken,
}

impl Client {
    /// Consume an already paired local capability. Only literal loopback HTTP
    /// origins are allowed; neither DNS, redirects nor environment proxies can
    /// forward this capability to a different service. No cookie jar is used.
    pub fn new(base: &str, origin: &str, capability: ClientToken) -> Result<Self> {
        validate_origin(origin)?;
        let mut endpoint = url::Url::parse(base).map_err(|_| ErrorCode::InvalidRequest)?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if !loopback
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        endpoint.set_path("/invoke");
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| ErrorCode::Unavailable)?;
        Ok(Self {
            http,
            endpoint,
            origin: origin.into(),
            capability,
        })
    }

    /// Forward the original invocation bytes. There is no Value parse/reencode
    /// that could erase duplicate fields before the Door's typed decoder.
    /// Once send begins, any transport/response failure is Reconcile: the action
    /// may already have committed. Valid owner refusals stay unchanged in Output.
    /// No automatic retry or redirect can repeat a mutation.
    pub async fn invoke_bytes(&self, request: &[u8]) -> Result<Output> {
        if request.len() > MAX_BODY_BYTES {
            return Err(ErrorCode::Capacity);
        }
        let bearer = Zeroizing::new(format!("Bearer {}", self.capability.expose_for_transport()));
        // Capability encoding is fixed ASCII base64url from the owner constructor.
        let mut authorization =
            HeaderValue::from_str(&bearer).expect("paired capability is fixed ASCII base64url");
        authorization.set_sensitive(true);
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .header(header::ORIGIN, &self.origin)
            .header(header::AUTHORIZATION, authorization)
            .header(header::CONTENT_TYPE, "application/json")
            .body(request.to_vec())
            .send()
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        let status = response.status();
        if unique_header(response.headers(), header::CONTENT_TYPE) != Some("application/json")
            || unique_header(response.headers(), header::CACHE_CONTROL) != Some("no-store")
        {
            return Err(ErrorCode::Reconcile);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| ErrorCode::Reconcile)? {
            if chunk.len() > MAX_RESULT_BYTES - bytes.len() {
                return Err(ErrorCode::Reconcile);
            }
            bytes.extend_from_slice(&chunk);
        }
        let output: Output = serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Reconcile)?;
        if status.is_success() != matches!(output, Output::Ok { .. }) {
            return Err(ErrorCode::Reconcile);
        }
        Ok(output)
    }
}

#[cfg(test)]
#[path = "../../tests/support/native.rs"]
mod tests;
