#![cfg(all(not(target_arch = "wasm32"), feature = "native-tor"))]
//! Original custody over actual Arti onion services on CTRN's private network.
//! The owner fixture uses its original development passport gate. This does
//! not qualify production gate inputs, public Tor, hardware or wallet readiness.
use cmsg::door::{
    custody::{
        self, acknowledge_initial_publication, activate_initial, complete_initial_recovery,
        prepare_initial_publication, retain_initial_enrollment, retain_initial_publication,
    },
    foyer::{Scope, Sessions},
    scenario::{self, network},
    Configuration, Door, Role,
};
use cpky::{
    software::{SoftwareAuthenticator, TestConfiguration},
    Context,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    num::NonZeroUsize,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

fn now() -> u64 {
    ckmg::Clock::now(&mut custody::SystemClock).unwrap()
}
fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}

struct Fixture {
    child: Child,
    directory: tempfile::TempDir,
    value: Value,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // This is exclusively the subprocess created below, never a host owner.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Fixture {
    async fn start() -> Self {
        let binary = std::env::var("CMSG_ACCEPTANCE_FIXTURE")
            .expect("original current-time fixture binary required");
        let directory = tempfile::tempdir().unwrap();
        let chain = directory.path().join("chain.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(
            &chain,
            include_bytes!("support/current-tls/certificate.pem"),
        )
        .unwrap();
        std::fs::write(&key, include_bytes!("support/current-tls/key.pem")).unwrap();
        let output = directory.path().join("fixture.json");
        let child = Command::new(binary)
            .arg("--current-owner")
            .arg(directory.path())
            .arg(chain)
            .arg(key)
            .arg(&output)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut original = Self {
            child,
            directory,
            value: Value::Null,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while !output.exists() {
            assert!(
                original.child.try_wait().unwrap().is_none(),
                "original owner exited before readiness"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "original owner startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let value: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(value["clock"], "SystemClock");
        assert_eq!(value["holders"], 6);
        original.value = value;
        original
    }
    fn origin(&self) -> &str {
        self.value["https"]["base"].as_str().unwrap()
    }
    async fn proof(&self, index: usize) -> Value {
        let root =
            reqwest::Certificate::from_der(include_bytes!("support/current-tls/ca.der")).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = client
            .post(format!("{}/__fixture/presentation/{index}", self.origin()))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        response.json().await.unwrap()
    }
    async fn foyer(&self) -> cfyr::Foyer<cfyr::HttpClient> {
        let roots = [include_bytes!("support/current-tls/ca.der").to_vec()];
        let mut trust = cfyr::trust::Trust::native(
            cfyr::trust::Configuration {
                origin: self.origin().into(),
                community: "alpha".into(),
                key_ring: serde_json::from_value(self.value["trust_key_ring"].clone()).unwrap(),
                minimum_revision: 1,
                ring_revision: 0,
            },
            cfyr::trust::Config {
                retry_entropy: 15,
                refresh_seconds: 30,
                poll_seconds: 1,
                request_seconds: 30,
                initial_backoff_seconds: 1,
                maximum_backoff_seconds: 10,
                // The maintained follower budget covers bounded private Tor
                // startup. Signed policy and original 600s session deadlines
                // remain separate exclusive bounds and are never extended.
                maximum_staleness_seconds: 900,
            },
            &roots,
        )
        .unwrap();
        trust.start(now).await.unwrap();
        cfyr::Foyer::with_trust(
            cfyr::HttpClient::with_roots(self.origin().into(), "127.0.0.1".into(), None, &roots)
                .unwrap(),
            trust,
        )
    }
    async fn shutdown(&mut self) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "original fixture drain failed");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
}
fn passkeys() -> cpky::Client<SoftwareAuthenticator> {
    const ORIGIN: &str = "https://vault.alpha.example.test";
    cpky::Client::new(
        Context::new(ORIGIN, "alpha.example.test").unwrap(),
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    )
}
async fn login(
    api: &mut cfyr::Foyer<cfyr::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) -> cvlt::PreparedOpen {
    let challenge = api.begin_browser_login().await.unwrap();
    let (credential, vault) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
    let cpky::VaultOutcome::Ready(unlock) = vault else {
        panic!("original PRF required")
    };
    cvlt::PreparedOpen::new(unlock, "alpha").unwrap()
}
fn door(origin: &str, api: cfyr::Foyer<cfyr::HttpClient>) -> Door {
    let mut door = Door::new(
        Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([origin.into()]))]),
        )
        .unwrap(),
    );
    door.bind_foyer(origin, Role::Member, Sessions::new(Scope::Community, api))
        .unwrap();
    door
}

// Watch authority is unused by this fixed publication/read journey. Missing
// original watch custody refuses rather than creating an accepting signer.
struct NoWatch;
impl cmsh::tor_discovery::TorWatcher for NoWatch {
    fn public_key(&self, _: &cdht::RecordKey) -> Result<cdht::NodeId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    fn question<'a>(
        &'a self,
        _: &'a cdht::RecordKey,
        _: &'a cdht::rpc::Question,
        _: &'a cdht::NodeId,
    ) -> cmsh::BoxFuture<'a, Result<cdht::rpc::SignedOperation, cdht::Error>> {
        Box::pin(async { Err(cdht::Error::Unavailable) })
    }
}
type Native = network::Network<NoWatch>;
async fn drain(label: &str, owner: Native) {
    let begun = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(30), owner.shutdown())
        .await
        .unwrap()
        .unwrap();
    // Direct fixture output survives the test harness capture and is retained
    // by the original private-network driver's contract receipt. No IDs appear.
    writeln!(
        std::io::stdout(),
        "original Tor {label} drained in {} ms",
        begun.elapsed().as_millis()
    )
    .unwrap();
}
fn configuration(
    tor: &Value,
    base: &Path,
    index: usize,
    bootstrap: Vec<cdht::rpc::UnverifiedPeerInfoBytes>,
    storage: bool,
) -> network::Configuration {
    network::Configuration {
        tor: serde_json::from_value(tor.clone()).unwrap(),
        directories: ctrn::arti::Directories {
            state: base.join(format!("state-{index}")),
            cache: base.join(format!("cache-{index}")),
        },
        scope: ctrn::Scope([71; 32]),
        transport: ctrn::Limits {
            streams: 64,
            bootstrap_ms: 240_000,
            operation_ms: 60_000,
        },
        messages: ctrn::MessageLimits {
            max_payload: 65536,
            timeout_ms: 30_000,
        },
        discovery: cmsh::tor_discovery::TorDiscoveryLimits {
            peers: nz(32),
            lanes: nz(5),
            timeout_ms: 60_000,
        },
        records: cmsh::tor_records::TorRecordLimits {
            consensus_width: nz(5),
            watches: nz(32),
        },
        storage: storage.then_some((
            cdht::Capacity::NATIVE,
            cdht::watches::WatchLimits::native(30_000_000, nz(128)),
        )),
        bootstrap,
        maximum_bootstrap_bytes: nz(1024 * 1024),
        driver_tasks: nz(64),
        record_concurrency: nz(16),
        application_queue: nz(16),
        application_payload: nz(32768),
        startup_timeout: Duration::from_secs(300),
    }
}
async fn start(
    door: &Door,
    origin: &str,
    opening: &cvlt::PreparedOpen,
    member: &str,
    config: network::Configuration,
) -> Native {
    let window = cdht::rpc::envelope::TimeWindow {
        behind_us: 60_000_000,
        ahead_us: 5_000_000,
    };
    let (client, owner) = door
        .prepare_native_transport(
            origin,
            opening,
            ckmg::Binding::new("alpha", member).unwrap(),
            window,
        )
        .unwrap();
    Native::start(client, owner, config, NoWatch).await.unwrap()
}

async fn ordinary_open(
    native: &Native,
    door: &Door,
    origin: &str,
    opening: cvlt::PreparedOpen,
    member: &str,
    backend: cwst::backend::Memory,
) {
    let network = native.records().unwrap().network();
    let locator = opening.locator();
    let mut record = opening.tor_records(network.clone()).await.unwrap();
    let checkpoint = record.checkpoint(&locator).await.unwrap();
    let nodes = cdht::Network::closest(&network, &checkpoint.record_key())
        .await
        .unwrap();
    assert_eq!(
        nodes.len(),
        5,
        "actual authenticated storage consensus width"
    );
    drop(record);
    let completed = now();
    let candidate = door
        .current_policy(origin)
        .unwrap()
        .with_current(completed, |current| {
            opening.prepare_recovery(&checkpoint, current, member, completed)
        })
        .unwrap()
        .unwrap();
    let mut owners = native
        .take_member_authority()
        .unwrap()
        .prepare_recovery(&candidate, network.clone())
        .await
        .unwrap();
    // Load only the authenticated actual local common-root carrier, then force
    // the original network lookup under those signed sequence/byte floors.
    owners
        .recovery
        .load_existing_read_floors(&backend, &mut custody::SystemClock, &mut owners.authority)
        .await
        .unwrap();
    let records = owners
        .recovery
        .tor_passkey_records(network, &mut custody::SystemClock, &mut owners.authority)
        .await
        .unwrap();
    let actual = cvlt::Owners {
        clock: custody::SystemClock,
        entropy: ckmg::SystemEntropy,
        authority: owners.authority,
        records,
        wallet: (),
    };
    let mut vault = owners
        .recovery
        .open_existing(backend, actual)
        .await
        .unwrap();
    assert!(matches!(
        vault.restore_lookup(&locator).await,
        cvlt::RestoreLookup::Present(_)
    ));
    // This qualifies original normal root/Store custody only. The separate
    // accounting owner must restore Wallet custody before product readiness.
    vault.lock().await;
}

async fn journey() {
    let tor: Value = serde_json::from_slice(
        &std::fs::read(
            std::env::var("TOR_FIXTURE_JSON").expect("original private-network fixture required"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut fixture = Fixture::start().await;
    let base = fixture.directory.path().join("tor");
    std::fs::create_dir(&base).unwrap();
    let mut peers = Vec::new();
    let mut peer_doors = Vec::new();
    let mut starts = Vec::new();
    for index in 0..5 {
        let proof = fixture.proof(index).await;
        let mut api = fixture.foyer().await;
        let pending = api
            .begin_member_registration(Some(proof["passport"].clone()))
            .await
            .unwrap();
        let mut keys = passkeys();
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
        let opening = login(&mut api, &mut keys).await;
        drop(registered);
        api.call(
            "device_authorize",
            json!({"key":opening.device().unwrap().value()}),
        )
        .await
        .unwrap();
        let door = door(fixture.origin(), api);
        let config = configuration(&tor, &base, index, vec![], true);
        peer_doors.push((
            door,
            opening,
            proof["member"].as_str().unwrap().to_owned(),
            keys,
        ));
        starts.push(config);
    }
    let mut startup = Vec::new();
    for ((door, opening, member, _), config) in peer_doors.iter().zip(starts) {
        startup.push(start(door, fixture.origin(), opening, member, config));
    }
    for peer in futures_util::future::join_all(startup).await {
        peers.push(peer);
    }
    let advertisements: Vec<_> = peers
        .iter()
        .map(|peer| peer.advertisement().unwrap().clone())
        .collect();
    assert_eq!(peers.len(), 5);

    let proof = fixture.proof(5).await;
    let member = proof["member"].as_str().unwrap();
    let mut api = fixture.foyer().await;
    let mut keys = passkeys();
    let mut clock = custody::SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let seed =
        ckmg::EnrollmentSeed::new(ckmg::Binding::new("alpha", member).unwrap(), &mut entropy)
            .unwrap();
    let commitment = seed.commitment().unwrap();
    let pending = api
        .begin_initial_registration(proof["passport"].clone(), commitment, now)
        .await
        .unwrap();
    let registration = keys
        .register_member(pending.options().clone())
        .await
        .unwrap();
    let backend = cwst::backend::Memory::new();
    let candidate = retain_initial_enrollment(
        &api,
        pending,
        registration,
        seed,
        backend.clone(),
        "private Tor enrollment",
        &mut clock,
        &mut entropy,
    )
    .await
    .unwrap();
    candidate.resume_finish(&mut api, now).await.unwrap();
    let opening = login(&mut api, &mut keys).await;
    api.call(
        "device_authorize",
        json!({"key":candidate.device().value()}),
    )
    .await
    .unwrap();

    // Production Tor signatures use a separately, actually authenticated session
    // of this same original passkey. Its guard can never alias the initial lease.
    let mut transport_api = fixture.foyer().await;
    let transport_opening = login(&mut transport_api, &mut keys).await;
    assert_eq!(
        opening.device().unwrap(),
        transport_opening.device().unwrap()
    );
    let transport_door = door(fixture.origin(), transport_api);
    let native = start(
        &transport_door,
        fixture.origin(),
        &transport_opening,
        member,
        configuration(&tor, &base, 5, advertisements.clone(), false),
    )
    .await;
    let mut alias_policy = transport_door.current_policy(fixture.origin()).unwrap();
    let alias = transport_door
        .live_membership(fixture.origin())
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(&mut alias_policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        assert!(native.initial_records(&alias).is_err());
    })
    .await
    .unwrap();
    drop(alias);

    let mut policy = api.current_policy();
    let initial = api
        .live_membership()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap();
    let creation = activate_initial(candidate, initial, &mut clock, &mut entropy)
        .await
        .unwrap();
    let initial = api
        .live_membership()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap();
    let (creation, initial) =
        prepare_initial_publication(creation, initial, &mut keys, &mut clock, &mut entropy)
            .await
            .unwrap();
    let creation = retain_initial_publication(creation, initial, &mut clock)
        .await
        .unwrap();
    let network = native.records().unwrap().network();
    let publication = creation
        .stage(cdht::NetworkBackend::new(
            network.clone(),
            scenario::Verifier,
        ))
        .await
        .unwrap();
    let (creation, report) = publication.flush().await.unwrap();
    assert_eq!(report.written, 1);
    let read = creation
        .read_first_lineage(network.clone(), &mut clock)
        .await
        .unwrap();
    let initial = api
        .live_membership()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap();
    let network = native.initial_records(&initial).unwrap();
    let creation =
        acknowledge_initial_publication(read, initial, network.clone(), &mut clock, &mut entropy)
            .await
            .unwrap();
    assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Acknowledged);
    let initial = api
        .live_membership()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap();
    let network = native.initial_records(&initial).unwrap();
    let retired = tokio::time::timeout(
        Duration::from_secs(180),
        complete_initial_recovery(creation, initial, network.clone(), &mut clock, &mut entropy),
    )
    .await
    .unwrap()
    .unwrap();

    // Drop the first local preparation and sign in again with the actual key.
    // No ACK handle or creation intent participates in ordinary reopening.
    drop(opening);
    let fresh = login(&mut api, &mut keys).await;
    ordinary_open(
        &native,
        &transport_door,
        fixture.origin(),
        fresh,
        member,
        backend.clone(),
    )
    .await;
    drop(retired);
    drain("target", native).await;
    drop(transport_door);
    drop(policy);
    drop(api);
    // Actual new local Foyer/session/transport owners, same original device key
    // and persistent Tor directory, same committed Store. No initial handles.
    let mut restarted_api = fixture.foyer().await;
    let restarted_opening = login(&mut restarted_api, &mut keys).await;
    let reopened = login(&mut restarted_api, &mut keys).await;
    let restarted_door = door(fixture.origin(), restarted_api);
    let restarted = start(
        &restarted_door,
        fixture.origin(),
        &restarted_opening,
        member,
        configuration(&tor, &base, 5, advertisements, false),
    )
    .await;
    ordinary_open(
        &restarted,
        &restarted_door,
        fixture.origin(),
        reopened,
        member,
        backend,
    )
    .await;
    drain("restarted target", restarted).await;
    drop(restarted_door);
    for peer in peers {
        drain("storage peer", peer).await;
    }
    drop(peer_doors);
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_enrollment_retirement_and_reopen_over_private_tor() {
    // LocalSet owns actual non-Send Foyer/Keys custody; maintained Arti remains
    // independently driven by the multithread runtime's original transport.
    tokio::task::LocalSet::new()
        .run_until(async {
            tokio::time::timeout(Duration::from_secs(900), journey())
                .await
                .unwrap();
        })
        .await;
}
