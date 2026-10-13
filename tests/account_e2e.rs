#![cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
#![allow(dead_code)] // shares the journey helpers of the other suites; only part of them is used
//! The account lifecycle against the REAL native accounting operator: enroll, open with the
//! real prover, a lost operator response (reopen re-sends the identical outbox), activate, and
//! every action repeated on the active account. The operator and its artifacts come from the
//! assembled G5 configuration (`CMSG_G5_ACCOUNT_CONFIG`); nothing here is a double.
use cmsg::door::{
    custody::{self, SystemClock},
    foyer::Scope,
    Output, Role,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};

#[path = "support/initial_network.rs"]
mod initial_network;

#[path = "support/wallet.rs"]
mod wallet;
use wallet::*;

#[path = "support/common_record.rs"]
mod common_record;

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

/// The real client prover over the same retained extension group the operator authenticates.
fn prover(config: &Value) -> ckmg::wallet_engine::native_prover::NativeProver {
    use ckmg::wallet_engine::native_prover::{NativeProver, NativeProverConfig};
    let files = &config["extension_artifacts"];
    let read = |key: &str, maximum: usize| {
        let bytes = std::fs::read(files[key].as_str().unwrap()).unwrap();
        assert!(bytes.len() <= maximum);
        bytes
    };
    let sha = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
    let circuit = read("circuit_file", 64 << 20);
    let keys = read("keys_file", 1 << 20);
    let g1 = read("srs_g1_file", 128 << 20);
    let g2 = read("srs_g2_file", 128);
    let executable = std::path::PathBuf::from(
        std::env::var_os("CMSG_NATIVE_PROVER_WORKER").expect("the owned native prover worker"),
    );
    assert!(executable.is_absolute());
    let executable_digest = sha(&std::fs::read(&executable).unwrap());
    NativeProver::new(NativeProverConfig {
        executable,
        executable_digest,
        scope: cblc::accounting::AccountProofScope {
            circuit_digest: sha(&circuit),
            verifying_key_digest: sha(&keys),
        },
        circuit,
        verification_key: keys,
        srs_g1_digest: sha(&g1),
        srs_g1: g1,
        num_points: 2_621_440,
        srs_g2_digest: sha(&g2),
        srs_g2: g2.try_into().unwrap(),
        timeout: Duration::from_secs(900),
        maximum_parallel: 1,
        threads: 2,
        memory_megabytes: 4096,
    })
    .unwrap()
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
        let wallet_world = &f["wallet"];
        let wallet_origin = wallet_world["passkey_origin"].as_str().unwrap();
        let mut entropy = ckmg::SystemEntropy;
        let mut clock = SystemClock;

        // 1. A certified wallet user with a durable initial lineage (as wallet_enrollment).
        let mut api = foyer(wallet_world, true).await;
        let mut reservation = api
            .begin_global_initial_registration(wallet_world["base"].as_str().unwrap(), now)
            .await
            .unwrap();
        let user = reservation.account().to_owned();
        let seed =
            ckmg::EnrollmentSeed::new(ckmg::Binding::new("wallet", &user).unwrap(), &mut entropy)
                .unwrap();
        let commitment = seed.commitment().unwrap();
        let pending = reservation
            .continue_initial(&api, commitment, now)
            .await
            .unwrap();
        let mut keys = passkeys(wallet_world);
        let registration = keys
            .register_member(pending.options().clone())
            .await
            .unwrap();
        let wallet_backend = cwst::backend::Memory::new();
        let candidate = custody::retain_global_initial_enrollment(
            &api,
            pending,
            registration,
            seed,
            wallet_backend.clone(),
            "original-wallet",
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        let device = candidate.device();
        candidate.resume_finish(&mut api, now).await.unwrap();
        login(&mut api, &mut keys).await;
        let body = wallet::proven(
            &mut api,
            &mut keys,
            json!({"kind":"device_authorize","key":device.value()}),
            json!({"key":device.value()}),
        )
        .await;
        api.call("wallet_device_authorize", body).await.unwrap();
        api.call("development_gate", json!({})).await.unwrap();
        let wallet_door = bound("wallet", wallet_origin, Role::Member, Scope::Global, api);
        // The recovery owners live as long as the account actor: lend them for 'static.
        let wallet_policy: &'static mut _ = Box::leak(Box::new(
            wallet_door.wallet_current_policy(wallet_origin).unwrap(),
        ));
        let lease = initial(&wallet_door, wallet_origin, &mut *wallet_policy).await;
        let creation = custody::activate_initial(candidate, lease, &mut clock, &mut entropy)
            .await
            .unwrap();
        let lease = initial(&wallet_door, wallet_origin, &mut *wallet_policy).await;
        let (creation, lease) = custody::prepare_initial_publication(
            creation,
            lease,
            &mut keys,
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        let creation = custody::retain_initial_publication(creation, lease, &mut clock)
            .await
            .unwrap();
        let network = initial_network::Nodes::new();
        let staged = creation
            .stage(cdht::NetworkBackend::new(
                network.clone(),
                initial_network::Verifier,
            ))
            .await
            .unwrap();
        let (creation, _) = staged.flush().await.unwrap();
        let read = creation
            .read_first_lineage(network.clone(), &mut clock)
            .await
            .unwrap();
        let lease = initial(&wallet_door, wallet_origin, &mut *wallet_policy).await;
        let creation = custody::acknowledge_initial_publication(
            read,
            lease,
            network.clone(),
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        let lease = initial(&wallet_door, wallet_origin, &mut *wallet_policy).await;
        drop(
            custody::complete_initial_recovery(
                creation,
                lease,
                network.clone(),
                &mut clock,
                &mut entropy,
            )
            .await
            .unwrap(),
        );

        // 2. Restore the global holder and obtain one real passport (one challenge only).
        let mut companion = foyer(wallet_world, true).await;
        let challenge = companion.begin_browser_login().await.unwrap();
        let authentication = keys.sign_in(challenge.options).await.unwrap();
        let (credential, outcome) = authentication.into_parts();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("original same-key PRF required");
        };
        let opening = cvlt::PreparedOpen::new(unlock, "wallet").unwrap();
        companion
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        let locator = opening.locator();
        let mut records = opening.tor_records(network.clone()).await.unwrap();
        let checkpoint = records.checkpoint(&locator).await.unwrap();
        drop(records);
        let recovered: &'static cvlt::RecoveryCandidate = Box::leak(Box::new(
            opening.prepare_initial_recovery(&checkpoint).unwrap(),
        ));
        let lease = initial(&wallet_door, wallet_origin, wallet_policy).await;
        let owners = custody::prepare_initial_recovery(recovered, lease, network.clone())
            .await
            .unwrap();
        let mut global = owners
            .open_global_passport(network.clone(), wallet_backend.clone())
            .await
            .unwrap();
        let issuance = companion
            .live_global_wallet(wallet_world["base"].as_str().unwrap().into())
            .observe_lease(now)
            .await
            .unwrap()
            .passport_challenge(now)
            .await
            .unwrap();
        cmsg::door::passport::issue_global_passport(
            issuance,
            &mut global,
            &mut cwlt::passport::rand::rngs::OsRng,
        )
        .await
        .unwrap();

        // 3. Present it to the community and enroll a member there (as common_record).
        let community_world = &f["community"];
        let community = cwlt::passport::CommunityId::new(b"omega").unwrap();
        let pseudonym = global
            .with_global_passport(|holder| holder.pseudonym(&community).to_bytes())
            .await
            .unwrap();
        let mut community_api = foyer(community_world, false).await;
        let request = community_api
            .call("presentation_challenge", json!({}))
            .await
            .unwrap();
        let signed: Vec<u8> = serde_json::from_value(request["request"].clone()).unwrap();
        let mut community_policy = community_api.current_policy();
        let expected = community_policy
            .with_current(now(), |current| {
                cwlt::passport::AuthenticatedCommunity::from_authenticated_origin(
                    community.clone(),
                    current.key_ring().clone(),
                )
            })
            .unwrap();
        let proof = global
            .with_global_passport(|holder| {
                holder
                    .present(
                        &mut cwlt::passport::rand::rngs::OsRng,
                        &expected,
                        &signed,
                        now(),
                    )
                    .unwrap()
                    .to_bytes()
            })
            .await
            .unwrap();
        let member = data_encoding::HEXLOWER.encode(&pseudonym);
        let common_record::Community {
            mut door,
            mut keys,
            backend,
            network,
            device,
        } = common_record::enrolled(
            community_world,
            community_api,
            json!({"challenge":request["challenge"], "proof":proof}),
            &member,
        )
        .await;
        let origin = community_world["base"].as_str().unwrap();

        // 4. Recover the community account with the accounting intents and start the actor.
        let mut companion = foyer(community_world, false).await;
        let challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("original PRF required")
        };
        companion
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        let opening = cvlt::PreparedOpen::new(unlock, "omega").unwrap();
        let mut records = opening.tor_records(network.clone()).await.unwrap();
        let checkpoint = records.checkpoint(&opening.locator()).await.unwrap();
        drop(records);
        let recovered: &'static cvlt::RecoveryCandidate = Box::leak(Box::new(
            opening.prepare_initial_recovery(&checkpoint).unwrap(),
        ));
        let policy: &'static mut _ = Box::leak(Box::new(door.current_policy(origin).unwrap()));
        let lease = common_record::initial(&door, origin, policy).await;
        let owners = custody::prepare_initial_recovery(recovered, lease, network.clone())
            .await
            .unwrap();
        // The production composer reserves the three single-use intents and binds the actor.
        cmsg::door::account::bind_native_account(
            &mut door,
            origin,
            owners,
            network.clone(),
            backend.clone(),
            global,
            *device.value(),
            prover(&config),
        )
        .await
        .unwrap();
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
