use super::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn duplicate_capability_cannot_replace_a_live_grant_and_outputs_are_bounded() {
    let origin = "https://member.example";
    let config = Configuration::new(
        "a".into(),
        BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))]),
    )
    .unwrap();
    let mut door = Door::new(config);
    let actions = BTreeSet::from(["runtime.status".into()]);
    let token = door
        .pair_client(origin, Role::Member, actions.clone(), 10, 20)
        .unwrap();
    let duplicate = ClientToken::from_protected_transport(Zeroizing::new(
        token.expose_for_transport().as_bytes().to_vec(),
    ))
    .unwrap();
    assert!(matches!(
        door.insert_client(duplicate, "https://foreign.example", actions, 200),
        Err(ErrorCode::Unavailable)
    ));
    assert!(matches!(
        door.dispatch(
            origin,
            token.expose_for_transport(),
            br#"{"action":"runtime.status","version":1,"body":{}}"#,
            11
        ),
        Output::Ok { .. }
    ));
    assert!(check_result_size(&Value::String("x".repeat(MAX_RESULT_BYTES - 2))).is_ok());
    assert_eq!(
        check_result_size(&Value::String("x".repeat(MAX_RESULT_BYTES - 1))),
        Err(ErrorCode::Capacity)
    );
}
