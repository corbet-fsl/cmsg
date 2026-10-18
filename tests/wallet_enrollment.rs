#![cfg(not(target_arch = "wasm32"))]
//! Current original Wallet owners, encrypted ACK custody and actual blind issuance.
//! The validating record transport is inert; this is no Tor or account-proof claim.
use cmsg::door::{
    custody::{self, SystemClock},
    foyer::Scope,
    Role,
};
use serde_json::{json, Value};
use std::time::Duration;

#[path = "support/initial_network.rs"]
mod initial_network;

#[path = "support/wallet.rs"]
mod wallet;
use wallet::*;

#[path = "support/foyer_fixture.rs"]
mod foyer_fixture;

#[path = "support/common_record.rs"]
mod common_record;

fn fixture() -> Value {
    let path = foyer_fixture::fixture_path();
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let actual = fixture["certified_wallet"].clone();
    assert_eq!(actual["clock"], "SystemClock");
    assert_eq!(actual["wallet"]["scope"], "wallet");
    actual
}
/// All tests share one owner fixture with bounded ceremony and registration
/// capacity; running them concurrently makes admission depend on timing.
static FIXTURE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread")]
async fn same_certified_wallet_restores_its_holder_issues_and_joins_a_community() {
    let _gate = FIXTURE_GATE.lock().await;
    tokio::time::timeout(Duration::from_secs(180), async {
        let f = fixture();
        let wallet_world = &f["wallet"];
        let origin = wallet_world["passkey_origin"].as_str().unwrap();
        let mut api = foyer(wallet_world, true).await;
        let mut reservation = api
            .begin_global_initial_registration(wallet_world["base"].as_str().unwrap(), now)
            .await
            .unwrap();
        let user = reservation.account().to_owned();
        let mut entropy = ckmg::SystemEntropy;
        let mut clock = SystemClock;
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
        let backend = cwst::backend::Memory::new();
        let candidate = custody::retain_global_initial_enrollment(
            &api,
            pending,
            registration,
            seed,
            backend.clone(),
            "original-wallet",
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        assert!(cwst::backend::Backend::read(&backend)
            .await
            .unwrap()
            .is_some());
        let device = candidate.device();
        // Before finish, only encrypted data exists. A genuine local PRF assertion
        // reopens the SAME opaque finish request, never an authenticated session.
        drop(candidate);
        let challenge = api.begin_browser_login().await.unwrap();
        let authentication = keys.sign_in(challenge.options).await.unwrap();
        let candidate =
            custody::reopen_initial_enrollment(authentication, "wallet", backend.clone())
                .await
                .unwrap();
        assert_eq!(candidate.device(), device);
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
        let door = bound("wallet", origin, Role::Member, Scope::Global, api);
        let mut policy = door.wallet_current_policy(origin).unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let original_key = lease.credential_id().unwrap().to_vec();
        assert_eq!(lease.observation().unwrap().member, user);
        assert_eq!(lease.seed().unwrap(), commitment);
        let creation = custody::activate_initial(candidate, lease, &mut clock, &mut entropy)
            .await
            .unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let (creation, lease) = custody::prepare_initial_publication(
            creation,
            lease,
            &mut keys,
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        let publication = creation.publication_commitment().unwrap();
        let creation = custody::retain_initial_publication(creation, lease, &mut clock)
            .await
            .unwrap();
        let network = initial_network::Nodes::new();
        let publication_owner = creation
            .stage(cdht::NetworkBackend::new(
                network.clone(),
                initial_network::Verifier,
            ))
            .await
            .unwrap();
        let (creation, report) = publication_owner.flush().await.unwrap();
        assert_eq!(report.written, 1);
        let read = creation
            .read_first_lineage(network.clone(), &mut clock)
            .await
            .unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let creation = custody::acknowledge_initial_publication(
            read,
            lease,
            network.clone(),
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Acknowledged);
        let lease = initial(&door, origin, &mut policy).await;
        assert_eq!(lease.publication().unwrap(), Some(publication));
        let retired = custody::complete_initial_recovery(
            creation,
            lease,
            network.clone(),
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        drop(retired);

        // An actual new PRF assertion and original network checkpoint authenticate
        // the cold ACK. The holder restores only after fresh certified normal Use.
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
        let recovered = opening.prepare_initial_recovery(&checkpoint).unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let owners = custody::prepare_initial_recovery(&recovered, lease, network.clone())
            .await
            .unwrap();
        let mut vault = owners
            .open_global_passport(network.clone(), backend.clone())
            .await
            .unwrap();
        let community = cwlt::passport::CommunityId::new(b"omega").unwrap();
        let original_pseudonym = vault
            .with_global_passport(|holder| {
                assert!(holder.attributes().is_none());
                holder.pseudonym(&community).to_bytes()
            })
            .await
            .unwrap();
        // The held Wallet session excludes another lease before mutex acquisition.
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            door.live_wallet_membership(origin)
                .unwrap()
                .observe_lease(now)
        )
        .await
        .unwrap()
        .is_err());
        let alternate_world = &f["wallet_alternate"];
        assert_ne!(wallet_world["base"], alternate_world["base"]);
        let mut alternate = foyer(alternate_world, true).await;
        login(&mut alternate, &mut keys).await;
        let mut wrong_origin = alternate
            .live_global_wallet(alternate_world["base"].as_str().unwrap().into())
            .observe_lease(now)
            .await
            .unwrap()
            .passport_challenge(now)
            .await
            .unwrap();
        wrong_origin
            .with_current(now, |account, key, _, _, _| {
                assert_eq!(account, user);
                assert_eq!(key, original_key);
            })
            .unwrap();
        let before = cwst::backend::Backend::read(&backend).await.unwrap();
        assert!(cmsg::door::passport::issue_global_passport(
            wrong_origin,
            &mut vault,
            &mut cwlt::passport::rand::rngs::OsRng
        )
        .await
        .is_err());
        assert_eq!(
            cwst::backend::Backend::read(&backend).await.unwrap(),
            before
        );
        drop(alternate);

        let mut late = companion
            .live_global_wallet(wallet_world["base"].as_str().unwrap().into())
            .observe_lease(now)
            .await
            .unwrap()
            .passport_challenge(now)
            .await
            .unwrap();
        let pending = vault
            .prepare_global_passport_issuance(&mut late, &mut cwlt::passport::rand::rngs::OsRng)
            .await
            .unwrap();
        // The original private opening is now durable. Closing only the issuer
        // Foyer must withhold sending/accepting its answer, without regenerating
        // the holder or automatically abandoning that pending operation.
        drop(companion);
        assert!(late.issue(pending.to_bytes(), now).await.is_err());
        assert!(late.with_current(now, |_, _, _, _, _| ()).is_err());
        drop(late);
        let mut cancel = [0; 32];
        getrandom::fill(&mut cancel).unwrap();
        vault
            .cancel_global_passport_issuance(cancel, &mut cwlt::passport::rand::rngs::OsRng)
            .await
            .unwrap();
        companion = foyer(wallet_world, true).await;
        login(&mut companion, &mut keys).await;

        let mut lost = companion
            .live_global_wallet(wallet_world["base"].as_str().unwrap().into())
            .observe_lease(now)
            .await
            .unwrap()
            .passport_challenge(now)
            .await
            .unwrap();
        let request = vault
            .prepare_global_passport_issuance(&mut lost, &mut cwlt::passport::rand::rngs::OsRng)
            .await
            .unwrap();
        // The actual issuer commits its answer, but the client loses that answer
        // before its original durable finish. No helper retries or cancels it.
        drop(lost.issue(request.to_bytes(), now).await.unwrap());
        drop(lost);
        drop(vault);
        let authentication_challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys
            .sign_in(authentication_challenge.options)
            .await
            .unwrap()
            .into_parts();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("original same-key PRF required");
        };
        companion
            .finish_browser_login(authentication_challenge.ceremony, credential)
            .await
            .unwrap();
        let opening = cvlt::PreparedOpen::new(unlock, "wallet").unwrap();
        let mut records = opening.tor_records(network.clone()).await.unwrap();
        let checkpoint = records.checkpoint(&opening.locator()).await.unwrap();
        drop(records);
        let reopened = opening.prepare_initial_recovery(&checkpoint).unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let owners = custody::prepare_initial_recovery(&reopened, lease, network.clone())
            .await
            .unwrap();
        let mut vault = owners
            .open_global_passport(network.clone(), backend.clone())
            .await
            .unwrap();
        assert_eq!(
            vault
                .with_global_passport(|holder| {
                    assert!(holder.attributes().is_none());
                    holder.pseudonym(&community).to_bytes()
                })
                .await
                .unwrap(),
            original_pseudonym
        );
        let mut cancel = [0; 32];
        getrandom::fill(&mut cancel).unwrap();
        vault
            .cancel_global_passport_issuance(cancel, &mut cwlt::passport::rand::rngs::OsRng)
            .await
            .unwrap();
        assert_eq!(
            vault
                .with_global_passport(|holder| holder.pseudonym(&community).to_bytes())
                .await
                .unwrap(),
            original_pseudonym
        );
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
            &mut vault,
            &mut cwlt::passport::rand::rngs::OsRng,
        )
        .await
        .unwrap();
        let actual_pseudonym = vault
            .with_global_passport(|holder| {
                assert!(holder.attributes().is_some());
                holder.pseudonym(&community).to_bytes()
            })
            .await
            .unwrap();
        assert_eq!(actual_pseudonym, original_pseudonym);
        drop(vault);
        let authentication_challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys
            .sign_in(authentication_challenge.options)
            .await
            .unwrap()
            .into_parts();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("original same-key PRF required");
        };
        companion
            .finish_browser_login(authentication_challenge.ceremony, credential)
            .await
            .unwrap();
        let opening = cvlt::PreparedOpen::new(unlock, "wallet").unwrap();
        let mut records = opening.tor_records(network.clone()).await.unwrap();
        let checkpoint = records.checkpoint(&opening.locator()).await.unwrap();
        drop(records);
        let finished = opening.prepare_initial_recovery(&checkpoint).unwrap();
        let lease = initial(&door, origin, &mut policy).await;
        let owners = custody::prepare_initial_recovery(&finished, lease, network.clone())
            .await
            .unwrap();
        let mut vault = owners.open_global_passport(network, backend).await.unwrap();
        assert_eq!(
            vault
                .with_global_passport(|holder| {
                    assert!(holder.attributes().is_some());
                    holder.pseudonym(&community).to_bytes()
                })
                .await
                .unwrap(),
            original_pseudonym
        );

        let mut community_api = foyer(&f["community"], false).await;
        let request = community_api
            .call("presentation_challenge", json!({}))
            .await
            .unwrap();
        let signed: Vec<u8> = serde_json::from_value(request["request"].clone()).unwrap();
        let mut community_policy = community_api.current_policy();
        let expected = community_policy
            .with_current(now(), |current| {
                assert_eq!(current.community(), "omega");
                cwlt::passport::AuthenticatedCommunity::from_authenticated_origin(
                    community.clone(),
                    current.key_ring().clone(),
                )
            })
            .unwrap();
        let proof = vault
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
        let member = data_encoding::HEXLOWER.encode(&original_pseudonym);
        assert_ne!(member, user);
        common_record::exercise(
            &f["community"],
            community_api,
            json!({"challenge":request["challenge"], "proof":proof}),
            &member,
        )
        .await;
        // Accounting is explicitly unconfigured: original membership enrollment
        // and a real holder proof do not imply a native initialized account.
        assert_eq!(
            f["accounting"],
            "unconfigured; no accepted account or proof claim"
        );
    })
    .await
    .expect("bounded original Wallet lifecycle");
}

#[tokio::test(flavor = "multi_thread")]
async fn wallet_factory_refuses_community_scope_or_operator_bindings() {
    let _gate = FIXTURE_GATE.lock().await;
    let f = fixture();
    let origin = f["wallet"]["passkey_origin"].as_str().unwrap();
    for (community, role, scope) in [
        ("omega", Role::Member, Scope::Global),
        ("wallet", Role::Member, Scope::Community),
        ("wallet", Role::Admin, Scope::Global),
    ] {
        let door = bound(
            community,
            origin,
            role,
            scope,
            foyer(&f["wallet"], true).await,
        );
        assert!(door.live_wallet_membership(origin).is_err());
        assert!(door.wallet_current_policy(origin).is_err());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn another_real_reserved_uuid_cannot_label_the_original_registration_tuple() {
    let _gate = FIXTURE_GATE.lock().await;
    let f = fixture();
    let world = &f["wallet"];
    let trusted = world["base"].as_str().unwrap();
    let mut original = foyer(world, true).await;
    let mut foreign = foyer(world, true).await;
    let mut first = original
        .begin_global_initial_registration(trusted, now)
        .await
        .unwrap();
    let second = foreign
        .begin_global_initial_registration(trusted, now)
        .await
        .unwrap();
    assert_ne!(first.account(), second.account());
    let mut entropy = ckmg::SystemEntropy;
    let seed = ckmg::EnrollmentSeed::new(
        ckmg::Binding::new("wallet", second.account()).unwrap(),
        &mut entropy,
    )
    .unwrap();
    let pending = first
        .continue_initial(&original, seed.commitment().unwrap(), now)
        .await
        .unwrap();
    let mut keys = passkeys(world);
    let registration = keys
        .register_member(pending.options().clone())
        .await
        .unwrap();
    let backend = cwst::backend::Memory::new();
    assert!(custody::retain_global_initial_enrollment(
        &original,
        pending,
        registration,
        seed,
        backend.clone(),
        "wrong-uuid",
        &mut SystemClock,
        &mut entropy
    )
    .await
    .is_err());
    assert!(cwst::backend::Backend::read(&backend)
        .await
        .unwrap()
        .is_none());
}
