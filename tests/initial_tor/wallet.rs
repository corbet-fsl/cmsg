//! Same original certified Wallet protocol over actual maintained private Tor.
use super::*;
#[path = "../support/wallet.rs"]
mod owned;
use owned::{bound, foyer, initial, now, passkeys};

async fn opening(
    api: &mut cfyr::Foyer<cfyr::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) -> cvlt::PreparedOpen {
    let challenge = api.begin_browser_login().await.unwrap();
    let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
    let cpky::VaultOutcome::Ready(unlock) = outcome else {
        panic!("original same-key PRF required")
    };
    cvlt::PreparedOpen::new(unlock, "wallet").unwrap()
}
fn config(
    tor: &Value,
    base: &Path,
    index: usize,
    bootstrap: Vec<cdht::rpc::UnverifiedPeerInfoBytes>,
    storage: bool,
) -> network::Configuration {
    let mut config = configuration(tor, base, index, bootstrap, storage);
    // A distinct private fixture namespace, with the unchanged original limits.
    config.scope = ctrn::Scope([72; 32]);
    config
}
async fn native(
    door: &Door,
    origin: &str,
    opening: &cvlt::PreparedOpen,
    user: &str,
    config: network::Configuration,
) -> Native {
    start_scope(door, origin, opening, "wallet", user, config).await
}

pub(super) async fn journey() {
    let tor: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("TOR_FIXTURE_JSON").unwrap()).unwrap())
            .unwrap();
    let mut fixture = Fixture::wallet().await;
    let world = &fixture.value["wallet"];
    let origin = world["passkey_origin"].as_str().unwrap();
    let base = fixture.directory.path().join("wallet-tor");
    std::fs::create_dir(&base).unwrap();
    let mut peers = Vec::new();
    let mut peer_owners = Vec::new();
    let mut starts = Vec::new();
    for index in 0..5 {
        let mut api = foyer(world, true).await;
        let pending = api.begin_member_registration(None).await.unwrap();
        let mut keys = passkeys(world);
        let (credential, unlock) = keys
            .register_member(pending.options().clone())
            .await
            .unwrap()
            .into_parts();
        drop(unlock);
        let registered = api
            .finish_member_registration(pending, credential)
            .await
            .unwrap();
        owned::login(&mut api, &mut keys).await;
        registered
            .continue_after_login(&api, now)
            .await
            .unwrap()
            .consume_checked(&api, now)
            .await
            .unwrap();
        let prepared = opening(&mut api, &mut keys).await;
        api.call(
            "wallet_device_authorize",
            json!({"key":prepared.device().unwrap().value()}),
        )
        .await
        .unwrap();
        let member = api
            .live_wallet_membership()
            .observe_lease(now)
            .await
            .unwrap()
            .observation()
            .member
            .clone();
        let door = bound("wallet", origin, Role::Member, Scope::Global, api);
        peer_owners.push((door, prepared, member, keys));
        starts.push(config(&tor, &base, index, vec![], true));
    }
    let mut starting = Vec::new();
    for ((door, prepared, member, _), config) in peer_owners.iter().zip(starts) {
        starting.push(native(door, origin, prepared, member, config));
    }
    for peer in futures_util::future::join_all(starting).await {
        peers.push(peer);
    }
    let advertisements: Vec<_> = peers
        .iter()
        .map(|peer| peer.advertisement().unwrap().clone())
        .collect();
    assert_eq!(advertisements.len(), 5);

    let mut api = foyer(world, true).await;
    let mut reservation = api
        .begin_global_initial_registration(world["base"].as_str().unwrap(), now)
        .await
        .unwrap();
    let user = reservation.account().to_owned();
    let mut clock = custody::SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let seed =
        ckmg::EnrollmentSeed::new(ckmg::Binding::new("wallet", &user).unwrap(), &mut entropy)
            .unwrap();
    let commitment = seed.commitment().unwrap();
    let pending = reservation
        .continue_initial(&api, commitment, now)
        .await
        .unwrap();
    let mut keys = passkeys(world);
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
        "private Tor Wallet",
        &mut clock,
        &mut entropy,
    )
    .await
    .unwrap();
    candidate.resume_finish(&mut api, now).await.unwrap();
    let prepared = opening(&mut api, &mut keys).await;
    api.call(
        "wallet_device_authorize",
        json!({"key":candidate.device().value()}),
    )
    .await
    .unwrap();
    api.call("development_gate", json!({})).await.unwrap();
    let door = bound("wallet", origin, Role::Member, Scope::Global, api);

    // Actual independent same-key transport session, never the retained lease's
    // own Foyer. All private-network signatures use its original live authority.
    let mut transport_api = foyer(world, true).await;
    let transport_opening = opening(&mut transport_api, &mut keys).await;
    assert_eq!(
        prepared.device().unwrap(),
        transport_opening.device().unwrap()
    );
    let transport_door = bound("wallet", origin, Role::Member, Scope::Global, transport_api);
    let target = native(
        &transport_door,
        origin,
        &transport_opening,
        &user,
        config(&tor, &base, 5, advertisements.clone(), false),
    )
    .await;
    let mut alias_policy = transport_door.wallet_current_policy(origin).unwrap();
    let alias = initial(&transport_door, origin, &mut alias_policy).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        assert!(target.initial_records(&alias).is_err());
    })
    .await
    .unwrap();
    drop(alias);
    let mut policy = door.wallet_current_policy(origin).unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let creation = activate_initial(candidate, lease, &mut clock, &mut entropy)
        .await
        .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let (creation, lease) =
        prepare_initial_publication(creation, lease, &mut keys, &mut clock, &mut entropy)
            .await
            .unwrap();
    let creation = retain_initial_publication(creation, lease, &mut clock)
        .await
        .unwrap();
    let record_network = target.records().unwrap().network();
    let publication = creation
        .stage(cdht::NetworkBackend::new(
            record_network.clone(),
            scenario::Verifier,
        ))
        .await
        .unwrap();
    let (creation, report) = publication.flush().await.unwrap();
    assert_eq!(report.written, 1);
    let read = creation
        .read_first_lineage(record_network.clone(), &mut clock)
        .await
        .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let selected = target.initial_records(&lease).unwrap();
    let creation = acknowledge_initial_publication(read, lease, selected, &mut clock, &mut entropy)
        .await
        .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let selected = target.initial_records(&lease).unwrap();
    let retired = complete_initial_recovery(creation, lease, selected, &mut clock, &mut entropy)
        .await
        .unwrap();
    drop(retired);

    let mut companion = foyer(world, true).await;
    let cold = opening(&mut companion, &mut keys).await;
    let mut records = cold.tor_records(record_network.clone()).await.unwrap();
    let checkpoint = records.checkpoint(&cold.locator()).await.unwrap();
    let closest = cdht::Network::closest(&record_network, &checkpoint.record_key())
        .await
        .unwrap();
    assert_eq!(closest.len(), 5, "actual Wallet consensus width");
    drop(records);
    let recovered = cold.prepare_initial_recovery(&checkpoint).unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let selected = target.initial_records(&lease).unwrap();
    let owners = custody::prepare_initial_recovery(&recovered, lease, selected.clone())
        .await
        .unwrap();
    let mut vault = owners
        .open_global_passport(selected, backend.clone())
        .await
        .unwrap();
    let community = cwlt::passport::CommunityId::new(b"omega").unwrap();
    let pseudonym = vault
        .with_global_passport(|holder| holder.pseudonym(&community).to_bytes())
        .await
        .unwrap();
    let issuance = companion
        .live_global_wallet(world["base"].as_str().unwrap().into())
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
    drop(vault);
    let cold = opening(&mut companion, &mut keys).await;
    let mut records = cold.tor_records(record_network.clone()).await.unwrap();
    let checkpoint = records.checkpoint(&cold.locator()).await.unwrap();
    drop(records);
    let finished = cold.prepare_initial_recovery(&checkpoint).unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let selected = target.initial_records(&lease).unwrap();
    let owners = custody::prepare_initial_recovery(&finished, lease, selected.clone())
        .await
        .unwrap();
    let mut vault = owners
        .open_global_passport(selected, backend)
        .await
        .unwrap();
    assert_eq!(
        vault
            .with_global_passport(|holder| {
                assert!(holder.attributes().is_some());
                holder.pseudonym(&community).to_bytes()
            })
            .await
            .unwrap(),
        pseudonym
    );
    vault.lock().await;
    drain("Wallet target", target).await;
    drop(transport_door);
    for peer in peers {
        drain("Wallet storage peer", peer).await;
    }
    drop(peer_owners);
    fixture.shutdown().await;
}
