//! Generated descriptions. No transport owns a separate action/schema table.
use super::*;
use serde_json::json;

/// Preserve the single wire envelope while specializing its success payload
/// with the action owner's exact result type.
pub fn output_schema(action: &ActionDescription) -> Value {
    let mut schema = registry::schema::<Output>();
    if let Some(variants) = schema.get_mut("oneOf").and_then(Value::as_array_mut) {
        for variant in variants {
            if let Some(result) = variant["properties"].get_mut("result") {
                *result = action.result.clone();
            }
        }
    }
    schema
}

pub fn openapi() -> Value {
    let mut paths = serde_json::Map::new();
    for action in catalog() {
        paths.insert(format!("/v{}/{}", action.version, action.action), json!({
            "post": {
                "operationId": action.action,
                "x-cmsg": {"family": action.family, "authority": action.authority, "effect": action.effect},
                "security": [{"localClient": []}],
                "requestBody": {"required": true, "content": {"application/json": {"schema": action.body}}},
                "responses": {"200": {"description": "Bounded local result", "content": {
                    "application/json": {"schema": output_schema(&action)}
                }}, "default": {"description": "Bounded refusal", "content": {
                    "application/json": {"schema": registry::schema::<Output>()}
                }}},
                "x-result-schema": action.result,
                "x-event-schema": action.event,
                "x-error-schema": action.error
            }
        }));
    }
    json!({"openapi": "3.1.0", "info": {"title": "Member local API", "version": "1"},
    "paths": paths, "components": {"securitySchemes": {"localClient": {
        "type": "http", "scheme": "bearer", "description": "Revocable paired local client capability"
    }}}})
}

pub fn mcp_tools() -> Value {
    json!({"tools": catalog().into_iter().map(|action| json!({
        "name": action.action,
        "description": format!("Version {} device-local action", action.version),
        "inputSchema": action.body,
        "outputSchema": output_schema(&action),
        "annotations": {"readOnlyHint": action.effect == Effect::Read},
        "_meta": {"cmsg": action}
    })).collect::<Vec<_>>()})
}

/// The CLI consumes this catalog instead of maintaining command/schema copies.
pub fn cli_commands() -> Value {
    json!({"version": 1, "commands": catalog()})
}

/// Build-time artifact, used by the maintained JSON Schema-to-TypeScript tool.
pub fn bundle() -> Value {
    json!({"version": 1, "actions": catalog(), "invocation": registry::schema::<Invocation>(),
        "output": registry::schema::<Output>(), "openapi": openapi(), "mcp": mcp_tools(),
        "cli": cli_commands()})
}

/// MCP and native/browser CLI use exactly the same invocation path. The host
/// authenticates the local transport and supplies its bound origin/capability.
pub fn invoke(
    door: &mut Door,
    origin: &str,
    token: &str,
    action: &str,
    version: u16,
    body: Value,
    now: u64,
) -> Output {
    match serde_json::to_vec(&Invocation {
        action: action.into(),
        version,
        body,
    }) {
        Ok(bytes) => door.dispatch(origin, token, &bytes, now),
        Err(_) => Output::Error {
            error: ErrorCode::InvalidRequest,
        },
    }
}
