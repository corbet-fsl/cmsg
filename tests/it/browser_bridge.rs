//! Deployment and framing refusals shared by native schema and real browser CI.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
use browser_coverage_runtime as _;
use cmsg::door::{browser::*, ErrorCode};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn vault_frame_is_exactly_the_member_subdomain() {
    let configuration = VaultBridgeConfiguration {
        member_origin: "https://alpha.example.test".into(),
        vault_origin: "https://vault.alpha.example.test".into(),
        vault_url: "https://vault.alpha.example.test/runtime".into(),
        timeout_millis: 10_000,
        wallet_origin: None,
    };
    assert_eq!(configuration.validate(), Ok(()));
    for origin in [
        "https://vault.example.test",
        "https://vault.other.example.test",
        "https://vault.alpha.example.test:4443",
        "http://vault.alpha.example.test",
        "https://vault.alpha.example.test/path",
        "https://vault.alpha.example.test#fragment",
        "https://user@vault.alpha.example.test",
    ] {
        let mut invalid = configuration.clone();
        invalid.vault_origin = origin.into();
        assert!(invalid.validate().is_err());
    }
    let mut invalid = configuration;
    invalid.timeout_millis = 0;
    assert_eq!(invalid.validate(), Err(ErrorCode::InvalidRequest));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn channel_framing_preserves_original_bytes_and_refuses_ambiguous_fields() {
    let raw = r#"{"action":"runtime.status","version":1,"version":1,"body":{}}"#;
    let encoded = serde_json::to_string(&VaultBridgeRequest::Invoke {
        id: 1,
        request: raw.into(),
    })
    .unwrap();
    let decoded: VaultBridgeRequest = serde_json::from_str(&encoded).unwrap();
    assert!(matches!(decoded, VaultBridgeRequest::Invoke {id:1, request} if request == raw));
    for invalid in [
        r#"{"kind":"close","id":1,"id":2}"#,
        r#"{"kind":"close","id":1,"authority":true}"#,
        r#"{"kind":"invoke","id":-1,"request":"{}"}"#,
        r#"{"kind":"invoke","id":4294967296,"request":"{}"}"#,
        r#"{"kind":"invoke","id":1,"request":{}}"#,
    ] {
        assert!(serde_json::from_str::<VaultBridgeRequest>(invalid).is_err());
    }
}
