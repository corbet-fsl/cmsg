use super::*;

fn request(address: &str, name: &str, gates: &[&str]) -> Create {
    Create {
        address: address.into(),
        display_name: name.into(),
        gates: gates.iter().map(|gate| (*gate).into()).collect(),
    }
}

#[test]
fn a_creation_needs_a_valid_address_a_name_and_the_legal_gate() {
    let (name, gates) = checked(&request(
        "gardenclub",
        " Garden Club ",
        &["legal", "voucher"],
    ))
    .unwrap();
    assert_eq!(name, "Garden Club");
    assert_eq!(gates, ["legal", "voucher"]);
    for bad in [
        request("short", "Club", &["legal"]),
        request("with-hyphen", "Club", &["legal"]),
        request("UPPERCASE1", "Club", &["legal"]),
        request("gardenclub", "   ", &["legal"]),
        request("gardenclub", &"x".repeat(65), &["legal"]),
        request("gardenclub", "Cl\nub", &["legal"]),
        request("gardenclub", "Club", &[]),
        request("gardenclub", "Club", &["voucher"]),
        request("gardenclub", "Club", &["legal", "legal"]),
        request("gardenclub", "Club", &["legal", "Bad Gate"]),
        request("gardenclub", "Club", &["legal", ""]),
    ] {
        assert_eq!(
            checked(&bad).err(),
            Some(ErrorCode::InvalidRequest),
            "{bad:?}"
        );
    }
    let many: Vec<String> = (0..17).map(|n| format!("gate{n}")).collect();
    let mut too_many = request("gardenclub", "Club", &["legal"]);
    too_many.gates.extend(many);
    assert_eq!(checked(&too_many).err(), Some(ErrorCode::InvalidRequest));
}

#[test]
fn the_claim_secret_travels_as_lowercase_hex() {
    let secret = [0u8, 1, 0xab, 0xff, 0x10];
    assert_eq!(to_hex(&secret), "0001abff10");
    assert_eq!(from_hex("0001abff10").unwrap(), secret);
    assert!(from_hex("0001abff1").is_none());
    assert!(from_hex("00AB").is_none());
    assert!(from_hex("zz").is_none());
    assert!(from_hex(&"00".repeat(65)).is_none());
}

#[test]
fn the_raw_creation_operations_are_not_republished_but_the_device_actions_are() {
    let catalog = super::super::catalog();
    for name in ["foyer.community_create", "foyer.community_creation_claim"] {
        let own: Vec<_> = catalog
            .iter()
            .filter(|entry| entry.action == name)
            .collect();
        assert_eq!(own.len(), 1, "{name}");
        assert!(
            own[0].owner.is_none(),
            "{name} is the device action, not a forward"
        );
    }
    let create = catalog
        .iter()
        .find(|entry| entry.action == "foyer.community_create")
        .unwrap();
    let properties = create.body["properties"].as_object().unwrap();
    for field in ["address", "display_name", "gates"] {
        assert!(properties.contains_key(field), "{field}");
    }
    assert!(!properties.contains_key("token"));
}

#[cfg(not(feature = "ohttp"))]
#[tokio::test]
async fn a_lent_global_session_serves_creation_and_nothing_else() {
    use super::super::foyer::{fixture_transport, owner_operation, Binding, Scope, Sessions};
    let transport = || fixture_transport("http://127.0.0.1:9", "community.test");
    let mut sessions = Sessions::new(Scope::Community, cfyr::Foyer::new(transport()));
    sessions
        .attach_creation(cfyr::Foyer::new(transport()), cfyr::Foyer::new(transport()))
        .unwrap();
    // The channels cannot be attached twice.
    assert!(sessions
        .attach_creation(cfyr::Foyer::new(transport()), cfyr::Foyer::new(transport()))
        .is_err());
    let mut binding = Binding {
        role: Role::Member,
        root_board: false,
        sessions,
        uncertain: false,
    };
    let issue = owner_operation("creation_token_issue").unwrap();
    let other = owner_operation("passport_challenge").unwrap();
    // No forwarded action reaches the lent global session.
    assert_eq!(
        binding.call(issue, serde_json::json!({})).await.err(),
        Some(ErrorCode::Unauthorized)
    );
    // And the creation path refuses every other global operation.
    assert_eq!(
        binding
            .call_global(other, serde_json::json!({}))
            .await
            .err(),
        Some(ErrorCode::Unauthorized)
    );
}
