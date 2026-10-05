//! Projection-result contract: every catalog action owns exactly one typed
//! HTTP route, MCP tool and CLI command sharing the generated output schema.

use cmsg::door::{catalog, surface, ActionDescription, Effect};
use serde_json::Value;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

fn action_value(action: &ActionDescription) -> Value {
    serde_json::to_value(action).unwrap()
}

fn output_variants(schema: &Value) -> (&Value, &Value) {
    let variants = schema["oneOf"].as_array().expect("output has oneOf");
    assert_eq!(variants.len(), 2, "output keeps success and refusal");
    let ok = variants
        .iter()
        .find(|v| v["properties"]["result"].is_object())
        .expect("success carries result");
    let refusal = variants
        .iter()
        .find(|v| v["properties"]["result"].is_null() && v["properties"]["error"].is_object())
        .expect("refusal carries error");
    (ok, refusal)
}

fn assert_local_client_security(node: &Value, label: &str) {
    let security = node["security"].as_array().expect("security is present");
    assert_eq!(security.len(), 1, "{label} names one requirement");
    assert!(
        security[0]["localClient"].is_array(),
        "{label} requires the local client"
    );
}

fn assert_requires(node: &Value, keys: &[&str], label: &str) {
    let required = node["required"].as_array().expect("required is present");
    for key in keys {
        assert!(
            required.iter().any(|entry| entry == *key),
            "{label} requires {key}"
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bundle_embeds_independently_generated_projections() {
    let bundle = surface::bundle();
    let live = catalog();
    assert!(!live.is_empty(), "catalog is nonempty");
    assert_eq!(bundle["version"], 1);
    assert_eq!(bundle["actions"], serde_json::to_value(&live).unwrap());
    assert_eq!(bundle["openapi"], surface::openapi());
    assert_eq!(bundle["mcp"], surface::mcp_tools());
    assert_eq!(bundle["cli"], surface::cli_commands());
    assert!(
        !bundle["types"].as_object().expect("owner types").is_empty(),
        "owner types are nonempty"
    );
    for key in ["invocation", "output"] {
        assert_eq!(bundle[key]["$schema"], DRAFT, "{key} pins draft 2020-12");
    }
    let invoke = &bundle["openapi"]["paths"]["/invoke"]["post"];
    assert_eq!(
        invoke["requestBody"]["content"]["application/json"]["schema"],
        bundle["invocation"]
    );
    assert_eq!(
        invoke["responses"]["default"]["content"]["application/json"]["schema"],
        bundle["output"]
    );
    assert_local_client_security(invoke, "invoke route");
    let scheme = &bundle["openapi"]["components"]["securitySchemes"]["localClient"];
    assert_eq!(scheme["type"], "http");
    assert_eq!(scheme["scheme"], "bearer");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn each_action_projects_one_typed_entry_with_shared_output() {
    let live = catalog();
    assert!(!live.is_empty(), "catalog is nonempty");
    let openapi = surface::openapi();
    let tools = surface::mcp_tools();
    let cli = surface::cli_commands();
    let generic_output = surface::bundle()["output"].clone();
    let (_, generic_refusal) = output_variants(&generic_output);
    for action in &live {
        let label = action.action.clone();
        let route = format!("/v{}/{}", action.version, action.action);
        let post = &openapi["paths"][route]["post"];
        assert!(post.is_object(), "{label} has an action route");
        assert_eq!(
            openapi["paths"]
                .as_object()
                .unwrap()
                .values()
                .filter(|path| path["post"]["operationId"] == action.action)
                .count(),
            1,
            "{label} has one route"
        );
        assert_eq!(post["operationId"], action.action);
        assert_eq!(
            post["x-cmsg"]["family"],
            serde_json::to_value(action.family).unwrap(),
            "{label} family"
        );
        assert_eq!(
            post["x-cmsg"]["authority"],
            serde_json::to_value(action.authority).unwrap(),
            "{label} authority"
        );
        assert_eq!(
            post["x-cmsg"]["effect"],
            serde_json::to_value(action.effect).unwrap(),
            "{label} effect"
        );
        assert_local_client_security(post, &label);
        assert_eq!(
            post["requestBody"]["content"]["application/json"]["schema"], action.body,
            "{label} route body"
        );
        assert_eq!(post["x-result-schema"], action.result, "{label} x-result");
        assert_eq!(post["x-event-schema"], action.event, "{label} x-event");
        assert_eq!(post["x-error-schema"], action.error, "{label} x-error");
        for schema in [&action.body, &action.result, &action.event, &action.error] {
            assert_eq!(schema["$schema"], DRAFT, "{label} pins draft 2020-12");
        }
        assert_eq!(
            action.error["type"], "string",
            "{label} error is a string enum"
        );
        assert!(
            !action.error["enum"]
                .as_array()
                .expect("error enum")
                .is_empty(),
            "{label} error lists variants"
        );
        let http_output = &post["responses"]["200"]["content"]["application/json"]["schema"];
        let generated = surface::output_schema(action);
        assert_eq!(http_output, &generated, "{label} HTTP 200 is generated");
        assert_eq!(
            post["responses"]["default"]["content"]["application/json"]["schema"], generic_output,
            "{label} refusal is generic"
        );
        let matches: Vec<&Value> = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| tool["name"] == action.action)
            .collect();
        assert_eq!(matches.len(), 1, "{label} has one MCP tool");
        let tool = matches[0];
        assert_eq!(tool["inputSchema"], action.body, "{label} tool input");
        assert_eq!(tool["outputSchema"], generated, "{label} tool output");
        assert_eq!(
            tool["_meta"]["cmsg"],
            action_value(action),
            "{label} tool metadata"
        );
        assert_eq!(
            tool["annotations"]["readOnlyHint"],
            action.effect == Effect::Read,
            "{label} tool effect hint"
        );
        assert!(
            tool["description"]
                .as_str()
                .expect("tool description")
                .contains(&action.version.to_string()),
            "{label} tool description carries its version"
        );
        let commands: Vec<&Value> = cli["commands"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|command| command["action"] == action.action)
            .collect();
        assert_eq!(commands.len(), 1, "{label} has one CLI command");
        assert_eq!(commands[0], &action_value(action), "{label} CLI entry");
        assert_eq!(
            generated["$schema"], DRAFT,
            "{label} output pins draft 2020-12"
        );
        let (ok, refusal) = output_variants(&generated);
        assert_requires(
            ok,
            &["status", "result", "events"],
            &format!("{label} success"),
        );
        assert_eq!(
            ok["properties"]["result"], action.result,
            "{label} success carries the owner result"
        );
        assert_eq!(
            ok["properties"]["events"]["type"], "array",
            "{label} success carries an event list"
        );
        assert!(
            ok["properties"]["events"]["items"].is_object(),
            "{label} event list carries event schemas"
        );
        assert_requires(refusal, &["status", "error"], &format!("{label} refusal"));
        assert_eq!(
            refusal["properties"]["error"]["type"], action.error["type"],
            "{label} refusal error type"
        );
        assert_eq!(
            refusal["properties"]["error"]["enum"], action.error["enum"],
            "{label} refusal error variants"
        );
        assert_eq!(
            refusal["properties"]["error"], generic_refusal["properties"]["error"],
            "{label} refusal matches the generic refusal"
        );
        for (name, variant) in [("success", ok), ("refusal", refusal)] {
            assert_eq!(
                variant["additionalProperties"], false,
                "{label} {name} envelope is closed"
            );
            assert!(
                variant["properties"]["status"].is_object(),
                "{label} {name} discriminates on status"
            );
        }
        assert_ne!(
            ok["properties"]["status"], refusal["properties"]["status"],
            "{label} variants select on status"
        );
    }
}

// Link maintained profiling support only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}
