//! Native HTTP projection. Host and Origin are checked independently, and every
//! response is no-store. The runtime chooses a loopback listener; no body logs.
use super::*;
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::sync::{Arc, Mutex};

/// Injected trusted clock. Member-controlled request data never supplies time.
pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

#[derive(Clone)]
struct HttpState {
    door: Arc<Mutex<Door>>,
    hosts: BTreeSet<String>,
    clock: Arc<dyn Clock>,
}

pub fn router(door: Door, hosts: BTreeSet<String>, clock: Arc<dyn Clock>) -> Result<Router> {
    if hosts.is_empty()
        || hosts.len() > 8
        || hosts.iter().any(|host| {
            host.is_empty() || host.len() > 253 || host.contains('/') || host.contains('@')
        })
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(Router::new()
        .route("/v1/{action}", post(call))
        .with_state(HttpState {
            door: Arc::new(Mutex::new(door)),
            hosts,
            clock,
        })
        .fallback(|| async {
            response(Output::Error {
                error: ErrorCode::UnsupportedAction,
            })
        }))
}

async fn call(
    State(state): State<HttpState>,
    Path(action): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok());
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    let (Some(host), Some(origin), Some(token)) = (host, origin, token) else {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    };
    if !state.hosts.contains(host)
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            != Some("application/json")
    {
        return response(Output::Error {
            error: ErrorCode::Unauthorized,
        });
    }
    let origin = origin.to_owned();
    let token = Zeroizing::new(token.to_owned());
    let bytes = match to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return response(Output::Error {
                error: ErrorCode::Capacity,
            })
        }
    };
    // Preserve the exact body bytes for the typed Serde decoder, including its
    // duplicate-field rejection. No Value round trip before authorization.
    let Ok(body) = std::str::from_utf8(&bytes) else {
        return response(Output::Error {
            error: ErrorCode::InvalidRequest,
        });
    };
    let Ok(name) = serde_json::to_string(&action) else {
        return response(Output::Error {
            error: ErrorCode::InvalidRequest,
        });
    };
    let envelope = format!("{{\"action\":{name},\"version\":1,\"body\":{body}}}");
    let output = match state.door.lock() {
        Ok(mut door) => door.dispatch(&origin, &token, envelope.as_bytes(), state.clock.now()),
        Err(_) => Output::Error {
            error: ErrorCode::Unavailable,
        },
    };
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
    let mut response = (code, Json(output)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
