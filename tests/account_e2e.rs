#![cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
#![allow(dead_code)] // shares the journey helpers of the other suites; only part of them is used
//! The account lifecycle against the REAL native accounting operator: enroll, open with the
//! real prover, a lost operator response (reopen re-sends the identical outbox), activate, and
//! every action repeated on the active account. The operator and its artifacts come from the
//! assembled G5 configuration (`CMSG_G5_ACCOUNT_CONFIG`); nothing here is a double.
use cmsg::door::{composer, composer::Services as _, Output, Role};
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Duration};

#[path = "support/initial_network.rs"]
mod initial_network;

#[path = "support/wallet.rs"]
mod wallet;
use wallet::*;

fn fixture() -> Value {
    let path = std::env::var("CMSG_FOYER_FIXTURE").expect("original owner fixture required");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(fixture["certified_wallet"]["clock"], "SystemClock");
    assert!(
        fixture["certified_wallet"]["accounting"]
            .as_str()
            .unwrap()
            .starts_with("configured"),
        "start the fixture with the assembled G5 account configuration"
    );
    fixture["certified_wallet"].clone()
}

/// The device configuration the composer takes, from the assembled fixture worlds.
fn device(
    f: &Value,
    config: &Value,
) -> (
    composer::DeviceSettings,
    composer::DeviceKeys<cpky::software::SoftwareAuthenticator>,
) {
    let root = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("account-e2e-ca.der");
    std::fs::write(&root, include_bytes!("support/current-tls/ca.der")).unwrap();
    let service = |world: &Value| composer::ServiceSettings {
        origin: world["base"].as_str().unwrap().into(),
        scope: world["scope"].as_str().unwrap().into(),
        passkey_origin: world["passkey_origin"].as_str().unwrap().into(),
        rp_id: world["rp_id"].as_str().unwrap().into(),
        trust_key_ring: world["trust_key_ring"].clone(),
        connect_host: "127.0.0.1".into(),
        tls_root_files: vec![root.clone()],
        fingerprint: None,
        pin: None,
    };
    let files = &config["extension_artifacts"];
    let path = |key: &str| std::path::PathBuf::from(files[key].as_str().unwrap());
    let settings = composer::DeviceSettings {
        global: service(&f["wallet"]),
        community: service(&f["community"]),
        community_name: "omega".into(),
        prover: composer::ProverArtifacts {
            worker_executable: std::env::var_os("CMSG_NATIVE_PROVER_WORKER")
                .expect("the owned native prover worker")
                .into(),
            circuit_file: path("circuit_file"),
            keys_file: path("keys_file"),
            srs_g1_file: path("srs_g1_file"),
            srs_g2_file: path("srs_g2_file"),
            wave: None,
            timeout_seconds: 300,
            threads: 2,
            memory_megabytes: 4096,
        },
        forum: None,
    };
    let keys = composer::DeviceKeys {
        global: passkeys(&f["wallet"]),
        community: passkeys(&f["community"]),
    };
    (settings, keys)
}

/// The fixture community's founding fingerprint (hex), from the genesis document its trust
/// feed publishes, verified here: the composer refuses community settings without it.
async fn community_fingerprint(world: &Value) -> String {
    let feed = foyer(world, false)
        .await
        .call("trust_feed", json!({}))
        .await
        .unwrap();
    let genesis: Vec<u8> = serde_json::from_value(feed["genesis"].clone()).unwrap();
    data_encoding::HEXLOWER.encode(&csgn::verify_genesis(&genesis).unwrap().fingerprint())
}

/// The fixture platform is a development build: its wallet gate is opened here, never
/// by the production composer.
struct Gated<'a>(composer::NativeServices<'a>);
impl composer::Services for Gated<'_> {
    async fn foyer(
        &mut self,
        service: composer::Service,
    ) -> Result<cfyr::Foyer<cmsg::door::foyer::Transport>, composer::ComposeError> {
        self.0.foyer(service).await
    }
    async fn public(
        &mut self,
        service: composer::Service,
    ) -> Result<cfyr::Foyer<cmsg::door::foyer::Transport>, composer::ComposeError> {
        self.0.public(service).await
    }
    async fn wallet_authorized(
        &mut self,
        api: &mut cfyr::Foyer<cmsg::door::foyer::Transport>,
    ) -> Result<(), composer::ComposeError> {
        api.call("development_gate", json!({}))
            .await
            .map(|_| ())
            .map_err(|e| composer::ComposeError::Step("development gate", format!("{e:?}")))
    }
}

async fn call(door: &mut cmsg::door::Door, origin: &str, token: &str, action: &str) -> Output {
    let request = json!({"action":action,"version":1,"body":{}}).to_string();
    door.dispatch(origin, token, request.as_bytes(), now())
        .await
}

fn result(output: Output) -> Value {
    match output {
        Output::Ok { result, .. } => result,
        Output::Error { error } => panic!("account action refused: {error:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_open_lose_the_response_reopen_activate_and_repeat_on_the_real_operator() {
    tokio::time::timeout(Duration::from_secs(1500), async {
        let f = fixture();
        let config: Value = serde_json::from_slice(
            &std::fs::read(std::env::var("CMSG_G5_ACCOUNT_CONFIG").unwrap()).unwrap(),
        )
        .unwrap();

        let (mut settings, mut keys) = device(&f, &config);
        settings.community.fingerprint = Some(community_fingerprint(&f["community"]).await);
        // The production composer: global registration, wallet enrollment, passport issue,
        // community enrollment at the accounting operator and `bind_native_account`.
        let mut door = composer::compose_native_device(
            &settings,
            &mut Gated(composer::NativeServices(&settings)),
            &mut keys,
            composer::DeviceStorage {
                global: cwst::backend::Memory::new(),
                community: cwst::backend::Memory::new(),
                progress: None,
            },
            initial_network::Nodes::new(),
        )
        .await
        .unwrap();
        let origin = settings.community.origin.clone();
        let origin = origin.as_str();
        let expires = now() + 1200;
        let actions = BTreeSet::from(
            [
                "account_enroll",
                "account_open",
                "account_reopen",
                "account_activate",
            ]
            .map(String::from),
        );
        let token = door
            .pair_client(origin, Role::Member, actions, now(), expires)
            .unwrap();
        let token = token.expose_for_transport().to_owned();

        // 5. Enroll; a frozen slot may delay the checkpoint, so wait for it (bounded) and repeat.
        let mut waited = 0;
        loop {
            let answer = result(call(&mut door, origin, &token, "account_enroll").await);
            if answer["checkpoint"] == "ready" {
                break;
            }
            let eligible = answer["eligible_at"]
                .as_u64()
                .expect("a pending checkpoint names its time");
            assert!(waited < 3, "the checkpoint never became ready");
            waited += 1;
            tokio::time::sleep(Duration::from_secs(eligible.saturating_sub(now()) + 2)).await;
        }
        // Repeating enroll is idempotent.
        assert_eq!(
            result(call(&mut door, origin, &token, "account_enroll").await)["checkpoint"],
            "ready"
        );

        // 6. Open: the real prover runs and the operator accepts, but the fixture loses the response
        // (and requires the retry to carry the identical outbox). The account stays uncertain.
        let lost = call(&mut door, origin, &token, "account_open").await;
        assert!(
            matches!(lost, Output::Error { .. }),
            "the lost operator response must read as uncertain"
        );
        // 7. Reopen re-sends the same bytes; the operator answers the same acceptance.
        let reopened = result(call(&mut door, origin, &token, "account_reopen").await);
        let accepted_at = reopened["accepted_at"].as_u64().unwrap();
        assert!(accepted_at > 0);
        // 8. Activate.
        let activation = result(call(&mut door, origin, &token, "account_activate").await);
        assert_eq!(activation["outbox_settled"], true);
        // 9. Every action repeated on the active account returns the existing state.
        for action in [
            "account_enroll",
            "account_open",
            "account_reopen",
            "account_activate",
        ] {
            let again = result(call(&mut door, origin, &token, action).await);
            match action {
                "account_enroll" => assert_eq!(again["checkpoint"], "ready"),
                "account_activate" => assert_eq!(again, activation),
                _ => assert_eq!(again["accepted_at"], accepted_at),
            }
        }
    })
    .await
    .expect("bounded real-operator account lifecycle");
}
