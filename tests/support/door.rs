use super::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn duplicate_capability_cannot_replace_a_live_grant_and_outputs_are_bounded() {
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
        )
        .await,
        Output::Ok { .. }
    ));
    assert!(check_result_size(&Value::String("x".repeat(MAX_RESULT_BYTES - 2))).is_ok());
    assert_eq!(
        check_result_size(&Value::String("x".repeat(MAX_RESULT_BYTES - 1))),
        Err(ErrorCode::Capacity)
    );
}

// Link maintained profiling support only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

/// A Door restricted to a device delegation (D1) admits exactly the status and member
/// purpose actions of `DELEGATE_ACTIONS` plus the explicit community checks; every other
/// action (wallet, account, stamps, genesis, community creation, voucher gates, waves,
/// profile publication, login) answers the typed state before any local work or request.
/// No owner is bound here: a forwarded call that got through would answer `Unavailable`.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn a_delegated_door_admits_member_purposes_and_refuses_the_rest_with_the_typed_state() {
    let origin = "https://member.example";
    let config = Configuration::new(
        "a".into(),
        BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))]),
    )
    .unwrap();
    let mut door = Door::new(config);
    assert!(!door.is_delegated());
    door.restrict_to_delegation();
    assert!(door.is_delegated());
    // Every listed delegate action is a real action (a rename cannot silently drop one).
    for name in registry::DELEGATE_ACTIONS {
        assert!(registry::action(name).is_some(), "{name}");
    }
    let catalog = catalog();
    let actions: BTreeSet<String> = catalog.iter().map(|d| d.action.clone()).collect();
    let token = door
        .pair_client(origin, Role::Member, actions.clone(), 10, 20)
        .unwrap();
    let mut refused = 0;
    let mut admitted = 0;
    // `client.revoke` is admitted and ends this client's own grant, so it goes last: every
    // later dispatch would otherwise answer `Unauthorized` (an invalid client, not the gate).
    let mut ordered: Vec<_> = catalog.iter().collect();
    ordered.sort_by_key(|description| description.action == "client.revoke");
    for description in ordered {
        let name = description.action.as_str();
        let body = format!(
            r#"{{"action":"{name}","version":{},"body":{{}}}}"#,
            description.version
        );
        let output = door
            .dispatch(origin, token.expose_for_transport(), body.as_bytes(), 11)
            .await;
        // Both constants are read through their owners: the local list directly, the
        // forwarded community checks through the operation's own `is_delegate_safe`
        // (explicit `DELEGATE_CHECKS` membership plus community scope, role and effect).
        let admits = registry::DELEGATE_ACTIONS.contains(&name)
            || foyer::action(name).is_some_and(|operation| operation.is_delegate_safe());
        if admits {
            admitted += 1;
            assert!(
                !matches!(
                    output,
                    Output::Error {
                        error: ErrorCode::NeedsPasskey
                    }
                ),
                "{name} must reach its handler, got {}",
                serde_json::to_string(&output).unwrap()
            );
        } else {
            refused += 1;
            assert!(
                matches!(
                    output,
                    Output::Error {
                        error: ErrorCode::NeedsPasskey
                    }
                ),
                "{name} must be refused with the typed state, got {}",
                serde_json::to_string(&output).unwrap()
            );
        }
    }
    assert!(admitted >= registry::DELEGATE_ACTIONS.len());
    // The accounts the manager named, explicitly (they exist in the catalog).
    for name in [
        "foyer.community_create",
        "foyer.voucher_link_create",
        "foyer.stamp_issue",
        "foyer.wallet_birth_genesis",
        "foyer.gate_withdraw",
        "inbox.waves",
        "inbox.wave_send",
        "board.profile_publish",
        "login.start",
        "community_join",
    ] {
        if actions.contains(name) {
            assert!(!registry::DELEGATE_ACTIONS.contains(&name), "{name}");
        }
    }
    assert!(refused > 10);
    // A plain full Door is not affected.
    assert!(!Door::new(
        Configuration::new(
            "a".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))])
        )
        .unwrap()
    )
    .is_delegated());
    assert_eq!(ErrorCode::NeedsPasskey.exit_code(), 77);
    assert_eq!(ErrorCode::DelegateRevoked.exit_code(), 77);
}
