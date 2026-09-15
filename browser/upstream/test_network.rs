//! Test-only configuration boundary for disposable local Tor networks.
//! This module is absent from the production service source stage.
use arti_client::config::TorClientConfigBuilder;
use serde_json::Value;
use std::net::SocketAddr;
use wasm_bindgen::prelude::*;

fn failure() -> JsValue { JsValue::from_str("tor-js:TestNetworkConfig") }

pub(crate) fn config(json: Option<&str>) -> Result<TorClientConfigBuilder, JsValue> {
    let json = json.filter(|s| !s.is_empty() && s.len() <= 65536).ok_or_else(failure)?;
    let value: Value = serde_json::from_str(json).map_err(|_| failure())?;
    let network = value.get("tor_network").ok_or_else(failure)?;
    let authorities = network.get("authorities").ok_or_else(failure)?;
    let identities = authorities.get("v3idents").and_then(Value::as_array).ok_or_else(failure)?;
    if !(4..=16).contains(&identities.len()) { return Err(failure()); }
    for key in ["uploads", "downloads", "votes"] {
        if !authorities.get(key).and_then(Value::as_array).is_some_and(Vec::is_empty) {
            return Err(failure());
        }
    }
    let fallbacks = network.get("fallback_caches").and_then(Value::as_array).ok_or_else(failure)?;
    if fallbacks.is_empty() || fallbacks.len() > 64 { return Err(failure()); }
    for fallback in fallbacks {
        let sockets = fallback.get("orports").and_then(Value::as_array).ok_or_else(failure)?;
        if sockets.is_empty() || sockets.len() > 4 { return Err(failure()); }
        for socket in sockets {
            let socket: SocketAddr = socket.as_str().ok_or_else(failure)?.parse().map_err(|_| failure())?;
            if !socket.ip().is_loopback() || socket.port() == 0 { return Err(failure()); }
        }
    }
    // Exercise the service's full vanguard path; the fixture must provide
    // enough distinct relays rather than disable this protection.
    if value.pointer("/vanguards/mode").and_then(Value::as_str) != Some("full") {
        return Err(failure());
    }
    if let Some(parameters) = value.get("override_net_params").and_then(Value::as_object) {
        for (key, minimum) in [("guard-hs-l2-number", 4), ("guard-hs-l3-number", 8)] {
            if parameters.get(key).is_some_and(|v| v.as_i64().is_none_or(|n| n < minimum)) {
                return Err(failure());
            }
        }
    }
    serde_json::from_value(value).map_err(|_| failure())
}
