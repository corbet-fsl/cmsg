use super::*;
use serde_json::json;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn forwarding_catalog_preserves_owner_metadata_and_withholds_session_secrets() {
    let catalog = super::catalog().collect::<Vec<_>>();
    assert!(
        !catalog.is_empty(),
        "the released owner must provide forwarding metadata"
    );
    assert!(action("foyer.login_finish").is_none());
    for description in catalog {
        let name = description.action.strip_prefix("foyer.").unwrap();
        let owner = cfyr::action(name).unwrap();
        let metadata = description.owner.unwrap();
        assert_eq!(metadata["role"], owner.schema()["x-role"]);
        assert_eq!(metadata["scope"], owner.schema()["x-scope"]);
        assert_eq!(metadata["effect"], owner.schema()["x-effect"]);
        let tool = surface::mcp_tools()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == description.action)
            .unwrap()
            .clone();
        assert_eq!(tool["annotations"]["readOnlyHint"], false);
        assert!(!serde_json::to_string(&description.result)
            .unwrap()
            .contains("\"token\""));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_visibility_authority_scope_effect_or_schema_is_not_forwarded() {
    let document = cfyr::contract();
    let path = cfyr::action("global_public").unwrap().path();
    let operation = document["paths"][path]["post"].clone();
    for (field, value) in [
        ("x-client-access", Value::Null),
        ("x-client-access", json!("trusted")),
        ("x-role", json!("superuser")),
        ("x-scope", json!("foreign")),
        ("x-effect", json!("unknown")),
        ("operationId", Value::Null),
        ("x-role", Value::Null),
        ("x-scope", Value::Null),
        ("x-effect", Value::Null),
        ("requestBody", Value::Null),
        ("responses", Value::Null),
    ] {
        let mut mutated = document.clone();
        mutated["paths"] = json!({path: {"post": operation.clone()}});
        mutated["paths"][path]["post"][field] = value;
        assert!(operations(&mutated).is_empty());
    }
    for reference in [
        json!(1),
        json!("https://foreign.example/schema"),
        json!("#/missing"),
        json!("#/components/schemas/loop"),
    ] {
        let mutated =
            json!({"components":{"schemas":{"loop":{"$ref":"#/components/schemas/loop"}}}});
        assert!(inline_schema(&json!({"$ref":reference}), &mutated, 0).is_none());
    }
    assert!(inline_schema(&json!({"$ref":"#/scalar"}), &json!({"scalar":false}), 0).is_none());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn owner_refusals_stay_bounded_and_distinguish_unknown_effects() {
    for (owner, local) in [
        (cfyr::Error::Invalid, ErrorCode::InvalidRequest),
        (cfyr::Error::Unauthorized, ErrorCode::Unauthorized),
        (cfyr::Error::Forbidden, ErrorCode::Unauthorized),
        (cfyr::Error::WrongHost, ErrorCode::Unauthorized),
        (cfyr::Error::Throttled, ErrorCode::Capacity),
        (cfyr::Error::Refused, ErrorCode::Refused),
        (cfyr::Error::Unavailable, ErrorCode::Unavailable),
        (cfyr::Error::Reconcile, ErrorCode::Reconcile),
    ] {
        assert_eq!(map_error(owner), local);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_json_rejects_duplicates_at_every_nesting_level() {
    let valid = r#"{"values":[null,true,false,-2,2,1.5,"escaped\nstring"],"empty":{}}"#;
    assert_eq!(
        super::super::json::unique_value(valid).unwrap(),
        serde_json::from_str::<Value>(valid).unwrap()
    );
    for invalid in [
        r#"{"a":1,"a":2}"#,
        r#"[{"a":null,"\u0061":false}]"#,
        r#"{"outer":{"a":1,"a":2}}"#,
        "{",
        "[",
        "1e999",
        "null trailing",
    ] {
        assert_eq!(
            super::super::json::unique_value(invalid),
            Err(ErrorCode::InvalidRequest)
        );
    }
}
