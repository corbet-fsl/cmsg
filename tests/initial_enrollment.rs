#![cfg(not(target_arch = "wasm32"))]
//! Actual HTTPS enrollment, original Passkeys custody and real encrypted CAS.
use cmsg::door::custody::{
    acknowledge_initial_publication, activate_initial, complete_initial_recovery,
    prepare_initial_publication, reopen_initial_enrollment, reopen_initial_publication,
    retain_initial_enrollment, retain_initial_publication,
};
use cpky::{
    software::{SoftwareAuthenticator, TestConfiguration},
    Context,
};
use serde_json::{json, Value};

#[path = "support/initial_network.rs"]
mod initial_network;

struct Clock(u64);
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, ckmg::Error> {
        Ok(self.0)
    }
}
fn fixture() -> Value {
    let path = std::env::var("CMSG_FOYER_FIXTURE").expect("actual owner fixture required");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
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
async fn foyer(f: &Value) -> cfyr::Foyer<cfyr::HttpClient> {
    let roots = [include_bytes!("support/current-tls/ca.der").to_vec()];
    let origin = f["https"]["base"].as_str().unwrap().to_owned();
    let now = f["now"].as_u64().unwrap();
    let mut trust = cfyr::trust::Trust::native(
        cfyr::trust::Configuration {
            origin: origin.clone(),
            community: "alpha".into(),
            key_ring: serde_json::from_value(f["trust_key_ring"].clone()).unwrap(),
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
            maximum_staleness_seconds: 60,
        },
        &roots,
    )
    .unwrap();
    trust.start(|| now).await.unwrap();
    cfyr::Foyer::with_trust(
        cfyr::HttpClient::with_roots(origin, "127.0.0.1".into(), None, &roots).unwrap(),
        trust,
    )
}
async fn login(
    api: &mut cfyr::Foyer<cfyr::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) {
    let challenge = api.begin_browser_login().await.unwrap();
    let (credential, unlock) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    drop(unlock);
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn original_registration_tuple_activates_only_after_durable_candidate_and_fresh_owner() {
    for (scenario, before_finish) in [("durable", false), ("before-finish", true)] {
        let f = fixture();
        let now = f["now"].as_u64().unwrap();
        let input = &f["initial_enrollments"][scenario];
        let mut api = foyer(&f).await;
        let mut clock = Clock(now);
        let mut entropy = ckmg::SystemEntropy;
        let binding = ckmg::Binding::new("alpha", input["member"].as_str().unwrap()).unwrap();
        let seed = ckmg::EnrollmentSeed::new(binding, &mut entropy).unwrap();
        let commitment = seed.commitment().unwrap();
        let pending = api
            .begin_initial_registration(input["passport"].clone(), commitment, || now)
            .await
            .unwrap();
        let mut keys = passkeys();
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
            "original",
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        // The real first durable Store exists before any accepting finish call.
        assert!(cwst::backend::Backend::read(&backend)
            .await
            .unwrap()
            .is_some());
        let device = candidate.device();
        let candidate = if before_finish {
            drop(candidate);
            // A local original PRF assertion can reopen encrypted data while the
            // server still has only its pending registration, never login authority.
            let challenge = api.begin_browser_login().await.unwrap();
            let authentication = keys.sign_in(challenge.options).await.unwrap();
            reopen_initial_enrollment(authentication, "alpha", backend.clone())
                .await
                .unwrap()
        } else {
            candidate
        };
        assert_eq!(candidate.device(), device);
        candidate.resume_finish(&mut api, || now).await.unwrap();
        login(&mut api, &mut keys).await;
        api.call("device_authorize", json!({"key":device.value()}))
            .await
            .unwrap();
        let mut policy = api.current_policy();
        let initial = api
            .live_membership()
            .observe_lease(|| now)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || now)
            .await
            .unwrap()
            .initial_creation(|| now)
            .await
            .unwrap();
        assert_eq!(initial.seed().unwrap(), commitment);
        let creation = activate_initial(candidate, initial, &mut clock, &mut entropy)
            .await
            .unwrap();
        assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Pending);
        assert_eq!(
            creation
                .receipt()
                .attested_lineage()
                .unwrap()
                .0
                .binding
                .member(),
            input["member"].as_str().unwrap()
        );
        let initial = api
            .live_membership()
            .observe_lease(|| now)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || now)
            .await
            .unwrap()
            .initial_creation(|| now)
            .await
            .unwrap();
        let (creation, initial) =
            prepare_initial_publication(creation, initial, &mut keys, &mut clock, &mut entropy)
                .await
                .unwrap();
        assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Prepared);
        let publication = creation.publication_commitment().unwrap();
        assert_eq!(initial.publication().unwrap(), Some(publication));
        let exact_intent = creation.completion_binding().unwrap().0;
        // Loss after the actual server bind reopens the same durable operation.
        // A fresh owner observation confirms its exact immutable winner.
        let (creation, initial) = if before_finish {
            drop((creation, initial));
            let challenge = api.begin_browser_login().await.unwrap();
            let authentication = keys.sign_in(challenge.options).await.unwrap();
            let initial = api
                .live_membership()
                .observe_lease(|| now)
                .await
                .unwrap()
                .passkey_certificate(&mut policy, || now)
                .await
                .unwrap()
                .initial_creation(|| now)
                .await
                .unwrap();
            let (creation, initial) =
                reopen_initial_publication(authentication, initial, backend.clone(), &mut clock)
                    .await
                    .unwrap();
            assert_eq!(creation.publication_commitment().unwrap(), publication);
            assert_eq!(
                creation.completion_binding().unwrap().0.packed_evidence,
                exact_intent.packed_evidence
            );
            (creation, initial)
        } else {
            (creation, initial)
        };
        let creation = retain_initial_publication(creation, initial, &mut clock)
            .await
            .unwrap();
        assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Retained);
        assert!(creation.acknowledged_candidate().is_err());
        assert_eq!(creation.publication_commitment().unwrap(), publication);
        let network = initial_network::Nodes::new();
        let publication = creation
            .stage(cdht::NetworkBackend::new(
                network.clone(),
                initial_network::Verifier,
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
            .observe_lease(|| now)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || now)
            .await
            .unwrap()
            .initial_creation(|| now)
            .await
            .unwrap();
        let (read, initial) = if before_finish {
            let durable = cwst::backend::Backend::read(&backend).await.unwrap();
            // A retained first-read witness cannot replace the fresh network
            // read required by normal Keys Use. Failure consumes only the live
            // attempt; the exact staged operation remains durable for restart.
            assert!(acknowledge_initial_publication(
                read,
                initial,
                initial_network::Nodes::new(),
                &mut clock,
                &mut entropy,
            )
            .await
            .is_err());
            assert_eq!(
                cwst::backend::Backend::read(&backend).await.unwrap(),
                durable
            );
            let challenge = api.begin_browser_login().await.unwrap();
            let authentication = keys.sign_in(challenge.options).await.unwrap();
            let initial = api
                .live_membership()
                .observe_lease(|| now)
                .await
                .unwrap()
                .passkey_certificate(&mut policy, || now)
                .await
                .unwrap()
                .initial_creation(|| now)
                .await
                .unwrap();
            let (creation, initial) =
                reopen_initial_publication(authentication, initial, backend.clone(), &mut clock)
                    .await
                    .unwrap();
            assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Staged);
            let read = creation
                .read_first_lineage(network.clone(), &mut clock)
                .await
                .unwrap();
            (read, initial)
        } else {
            (read, initial)
        };
        let creation = acknowledge_initial_publication(
            read,
            initial,
            network.clone(),
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
        assert_eq!(creation.phase().unwrap(), cvlt::InitialPhase::Acknowledged);
        let candidate = creation.acknowledged_candidate().unwrap();
        assert_eq!(candidate.enrollment_commitment(), commitment);
        assert_eq!(
            candidate.publication_commitment(),
            creation.publication_commitment().unwrap()
        );
        drop(candidate);
        let initial = api
            .live_membership()
            .observe_lease(|| now)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || now)
            .await
            .unwrap()
            .initial_creation(|| now)
            .await
            .unwrap();
        let retired =
            complete_initial_recovery(creation, initial, network, &mut clock, &mut entropy)
                .await
                .unwrap();
        let mut initial = api
            .live_membership()
            .observe_lease(|| now)
            .await
            .unwrap()
            .passkey_certificate(&mut policy, || now)
            .await
            .unwrap()
            .initial_creation(|| now)
            .await
            .unwrap();
        let candidate = initial
            .with_current(
                || now,
                |current| retired.prepare_recovery(current, input["member"].as_str().unwrap(), now),
            )
            .unwrap()
            .unwrap();
        // Actual recovery publication, winner selection and retirement have run;
        // the ordinary nonpending candidate still grants no usable Vault itself.
        drop(candidate);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn another_keys_prf_cannot_be_labeled_with_the_accepted_original_credential() {
    let f = fixture();
    let now = f["now"].as_u64().unwrap();
    let input = &f["initial_enrollments"]["wrong-key"];
    let mut api = foyer(&f).await;
    let mut clock = Clock(now);
    let mut entropy = ckmg::SystemEntropy;
    let seed = ckmg::EnrollmentSeed::new(
        ckmg::Binding::new("alpha", input["member"].as_str().unwrap()).unwrap(),
        &mut entropy,
    )
    .unwrap();
    let pending = api
        .begin_initial_registration(
            input["passport"].clone(),
            seed.commitment().unwrap(),
            || now,
        )
        .await
        .unwrap();
    let mut a = passkeys();
    let mut b = passkeys();
    let (credential_a, unlock_a) = a
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    let (credential_b, unlock_b) = b
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    let id_a = credential_a.credential_id().unwrap();
    let id_b = credential_b.credential_id().unwrap();
    assert_ne!(id_a, id_b);
    drop((credential_a, unlock_b));
    let finish = pending
        .prepare_finish(&api, credential_b, || now)
        .await
        .unwrap();
    let bytes = finish.to_bytes().unwrap();
    let backend = cwst::backend::Memory::new();
    // Model the adversarial lower-owner composition explicitly. The production
    // CMSG constructor accepts a whole Registration and cannot express this split.
    let opening = cvlt::PreparedOpen::new(unlock_a, "alpha").unwrap();
    let device_a = opening.device().unwrap();
    let mislabeled = opening
        .retain_enrollment(
            backend.clone(),
            seed,
            ckmg::DeviceInfo::new("mislabeled", &id_b).unwrap(),
            &bytes,
            &mut clock,
            &mut entropy,
        )
        .await
        .unwrap();
    drop(mislabeled);
    api.resume_initial_registration(finish, || now)
        .await
        .unwrap();
    login(&mut api, &mut b).await;
    // Even genuine B's authorization of A's device cannot attest that B supplied
    // A's PRF. A certificate/authorized-device equality alone is insufficient.
    api.call("device_authorize", json!({"key":device_a.value()}))
        .await
        .unwrap();
    let mut policy = api.current_policy();
    let initial = api
        .live_membership()
        .observe_lease(|| now)
        .await
        .unwrap()
        .passkey_certificate(&mut policy, || now)
        .await
        .unwrap()
        .initial_creation(|| now)
        .await
        .unwrap();
    assert_eq!(initial.credential_id().unwrap(), id_b);
    assert!(initial
        .observation()
        .unwrap()
        .device_keys
        .contains(device_a.value()));
    drop(initial);
    let challenge = api.begin_browser_login().await.unwrap();
    let authentication = a.sign_in(challenge.options).await.unwrap();
    assert!(
        reopen_initial_enrollment(authentication, "alpha", backend.clone())
            .await
            .is_err()
    );
    let challenge = api.begin_browser_login().await.unwrap();
    let authentication = b.sign_in(challenge.options).await.unwrap();
    assert!(reopen_initial_enrollment(authentication, "alpha", backend)
        .await
        .is_err());
}
