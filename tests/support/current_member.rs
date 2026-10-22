//! Genuine source-owner cancellation at the original final Keys read.
//! This fresh holder fixture is not durable Wallet, Tor or account qualification.
use super::*;

#[path = "foyer_fixture.rs"]
mod foyer_fixture;
use std::{cell::Cell, rc::Rc, time::Duration};

#[path = "common_record.rs"]
#[allow(dead_code)] // Shared fixture also exposes the independent receiver journey.
mod common_record;
#[path = "initial_network.rs"]
mod initial_network;
#[path = "wallet.rs"]
#[allow(dead_code)] // The Wallet initial-lease helper belongs the other journey.
mod wallet;
use wallet::*;

struct PausedStore {
    original: cvlt::KeyStore<cwst::backend::Memory>,
    gate: Rc<futures_util::lock::Mutex<()>>,
    loads: Rc<Cell<usize>>,
}
impl ckmg::SecureStore for PausedStore {
    async fn load(&mut self, location: &ckmg::Locator) -> Result<Option<Vec<u8>>, Error> {
        self.loads.set(self.loads.get() + 1);
        let _held = self.gate.lock().await;
        // Only scheduling is changed. All bytes and outcomes come from the
        // actual scoped KeyStore/ReadHandle of the authenticated compound Store.
        ckmg::SecureStore::load(&mut self.original, location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<ckmg::Commit, Error> {
        ckmg::SecureStore::compare_exchange(&mut self.original, location, expected, replacement)
            .await
    }
}

async fn genuine_holder_presentation(
    fixture: &serde_json::Value,
) -> (cfyr::Foyer<Transport>, serde_json::Value, String) {
    use cwlt::passport::*;
    let wallet = &fixture["wallet"];
    let mut global = foyer(wallet, true).await;
    let pending = global.begin_member_registration(None).await.unwrap();
    let mut passkey = passkeys(wallet);
    let (credential, unlock) = passkey
        .register_member(pending.options().clone())
        .await
        .unwrap()
        .into_parts();
    drop(unlock);
    global
        .finish_member_registration(pending, credential)
        .await
        .unwrap();
    login(&mut global, &mut passkey).await;
    global
        .call("development_gate", serde_json::json!({}))
        .await
        .unwrap();
    let public = global
        .call("global_public", serde_json::json!({}))
        .await
        .unwrap();
    let issuer: Vec<u8> = serde_json::from_value(public["issuer"].clone()).unwrap();
    let issuer = IssuerPublicKey::from_bytes(&issuer).unwrap();
    let answer = global
        .call("passport_challenge", serde_json::json!({}))
        .await
        .unwrap();
    let challenge: Vec<u8> = serde_json::from_value(answer["bytes"].clone()).unwrap();
    let challenge = IssuanceChallenge::from_bytes(challenge.try_into().unwrap());
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).unwrap();
    let mut holder = Holder::from_seed(&mut seed);
    let request = holder.with_session(|mut session| {
        session
            .begin_issuance(&mut rand::rngs::OsRng, &issuer, &challenge)
            .unwrap()
    });
    let answer = global
        .call(
            "passport_issue",
            serde_json::json!({
                "challenge": challenge.to_bytes().to_vec(), "request": request.to_bytes()
            }),
        )
        .await
        .unwrap();
    let answer: Vec<u8> = serde_json::from_value(answer["bytes"].clone()).unwrap();
    holder.with_session(|mut session| {
        session
            .finish_issuance(&BlindPassport::from_bytes(&answer).unwrap())
            .unwrap()
    });
    let mut community = foyer(&fixture["community"], false).await;
    let request = community
        .call("presentation_challenge", serde_json::json!({}))
        .await
        .unwrap();
    let signed: Vec<u8> = serde_json::from_value(request["request"].clone()).unwrap();
    let id = CommunityId::new(b"omega").unwrap();
    let expected = community
        .current_policy()
        .with_current(now(), |current| {
            AuthenticatedCommunity::from_authenticated_origin(
                id.clone(),
                current.key_ring().clone(),
            )
        })
        .unwrap();
    let (proof, member) = holder.with_session(|session| {
        (
            session
                .present(&mut rand::rngs::OsRng, &expected, &signed, now())
                .unwrap()
                .to_bytes(),
            data_encoding::HEXLOWER.encode(&session.pseudonym(&id).to_bytes()),
        )
    });
    (
        community,
        serde_json::json!({"challenge":request["challenge"], "proof":proof}),
        member,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_final_store_read_discards_the_genuine_ordinary_member_lease() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(foyer_fixture::fixture_path()).unwrap(),
        )
        .unwrap();
        let fixture = &fixture["certified_wallet"];
        let world = &fixture["community"];
        // One origin for the Door key and the authenticated HTTPS lease: the server base.
        let origin = world["base"].as_str().unwrap();
        let (api, proof, member) = genuine_holder_presentation(fixture).await;
        let common_record::Community {
            door,
            mut keys,
            backend,
            network,
            device,
        } = common_record::enrolled(world, api, proof, &member).await;

        let mut companion = foyer(world, false).await;
        let challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
        companion
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("real same-key PRF required")
        };
        let opening = cvlt::PreparedOpen::new(unlock, "omega").unwrap();
        let mut records = opening.tor_records(network.clone()).await.unwrap();
        let checkpoint = records.checkpoint(&opening.locator()).await.unwrap();
        drop(records);
        // Exact targeted request-shape refusals use this actual authenticated
        // checkpoint's public lineage. Shape success alone grants no authority.
        let inspection = opening.inspect_record(&checkpoint).unwrap();
        let lineage = inspection.lineage();
        let mut request = Authorization {
            binding: &lineage.binding,
            root: Some(lineage.root),
            device,
            epoch: lineage.epoch,
            action: Action::Use,
            target: None,
            statement: None,
            signing: None,
            now: now(),
            evidence: &[],
        };
        assert!(shape(&request, Purpose::RecordRecipient).is_ok());
        assert!(shape(&request, Purpose::DeviceSigning).is_err());
        request.target = Some(device);
        assert!(shape(&request, Purpose::RecordRecipient).is_err());
        request.target = None;
        request.statement = Some(lineage.digest().unwrap());
        assert!(shape(&request, Purpose::RecordRecipient).is_err());
        request.statement = None;
        request.evidence = b"external evidence cannot replace the owned read";
        assert!(shape(&request, Purpose::RecordRecipient).is_err());
        request.evidence = &[];
        request.root = None;
        assert!(shape(&request, Purpose::RecordRecipient).is_err());
        request.root = Some(lineage.root);
        request.epoch = 0;
        assert!(shape(&request, Purpose::RecordRecipient).is_err());
        drop(inspection);
        let initial = opening.prepare_initial_recovery(&checkpoint).unwrap();
        let mut policy = door.current_policy(origin).unwrap();
        let lease = common_record::initial(&door, origin, &mut policy).await;
        let owners = super::super::prepare_initial_recovery(&initial, lease, network.clone())
            .await
            .unwrap();
        let vault = owners.open_root(network.clone(), backend).await.unwrap();
        let storage = vault.storage().clone();
        drop(vault); // releases the original initial-authority session lease

        // Two real assertions from the same original credential: one remains
        // opaque in normal recovery, the other enters the original Keys import.
        let challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
        companion
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("real PRF required")
        };
        let opening = cvlt::PreparedOpen::new(unlock, "omega").unwrap();
        let candidate = door
            .current_policy(origin)
            .unwrap()
            .with_current(now(), |current| {
                opening.prepare_recovery(&checkpoint, current, None, &member, now())
            })
            .unwrap()
            .unwrap();
        let challenge = companion.begin_browser_login().await.unwrap();
        let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
        companion
            .finish_browser_login(challenge.ceremony, credential)
            .await
            .unwrap();
        let cpky::VaultOutcome::Ready(unlock) = outcome else {
            panic!("real PRF required")
        };
        let prf = unlock
            .import(|bytes| ckmg::passkey::PrfOutput::from_bytes(bytes))
            .unwrap();
        let (transport, lifetime) = door
            .transport_authority(
                origin,
                Binding::new("omega", &member).unwrap(),
                device,
                SystemClock,
            )
            .unwrap();
        let mut owners = door
            .member_authority_builder(origin, &transport)
            .unwrap()
            .prepare_recovery(&candidate, network.clone())
            .await
            .unwrap();
        let (reached, notice) = tokio::sync::oneshot::channel();
        owners.authority.reached_current = Some(reached);
        let gate = Rc::new(futures_util::lock::Mutex::new(()));
        let loads = Rc::new(Cell::new(0));
        let store = PausedStore {
            original: cvlt::KeyStore::new(storage.clone(), "omega").unwrap(),
            gate: gate.clone(),
            loads: loads.clone(),
        };
        let mut original =
            ckmg::Keys::new(store, SystemClock, ckmg::SystemEntropy, owners.authority);
        original.unlock(&prf, "omega").await.unwrap();
        assert_eq!(loads.get(), 1);
        let called = Cell::new(false);
        let mut operation = Box::pin(original.with_record_recipient(|_| called.set(true)));
        assert!(matches!(
            futures_util::poll!(operation.as_mut()),
            std::task::Poll::Pending
        ));
        // The initial target refresh reached the actual ReadHandle before the
        // network/HTTPS await. The final load alone will wait on this mutex.
        assert_eq!(loads.get(), 2);
        let held = gate.lock().await;
        tokio::select! {
            reached = notice => reached.unwrap(),
            finished = operation.as_mut() => panic!("final original Store read must remain blocked: {:?}", finished.err()),
        }
        assert_eq!(
            loads.get(),
            3,
            "the genuine retained owner preceded final load"
        );
        drop(operation);
        assert!(!called.get());
        assert_eq!(original.state(), ckmg::State::Locked);
        assert!(lifetime.is_closed());
        drop(held);
        // Cancellation releases the actual Foyer guard; a new independently
        // performed membership read succeeds, rather than timing out or using
        // the cancelled capability's cached observation.
        let observed = tokio::time::timeout(
            Duration::from_secs(10),
            door.live_membership(origin).unwrap().observe_lease(now),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(observed.observation().member, member);
        assert!(observed.observation().device_keys.contains(device.value()));
        drop(observed);
        assert!(original
            .with_record_recipient(|_| called.set(true))
            .await
            .is_err());
        assert!(!called.get());
        drop(original);

        // A new ordinary owner, not revival of the cancelled one, completes the
        // same original callback and releases its real source lease on success.
        let (transport, lifetime) = door
            .transport_authority(
                origin,
                Binding::new("omega", &member).unwrap(),
                device,
                SystemClock,
            )
            .unwrap();
        let owners = door
            .member_authority_builder(origin, &transport)
            .unwrap()
            .prepare_recovery(&candidate, network.clone())
            .await
            .unwrap();
        let mut current = ckmg::Keys::new(
            cvlt::KeyStore::new(storage, "omega").unwrap(),
            SystemClock,
            ckmg::SystemEntropy,
            owners.authority,
        );
        current.unlock(&prf, "omega").await.unwrap();
        let public = current
            .with_record_recipient(|recipient| recipient.public_key())
            .await
            .unwrap();
        assert_ne!(public, [0; 32]);
        assert!(!lifetime.is_closed());
        let observed = tokio::time::timeout(
            Duration::from_secs(10),
            door.live_membership(origin).unwrap().observe_lease(now),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(observed.observation().member, member);
        drop(observed);
    })
    .await
    .expect("bounded genuine source-owner cancellation");
}
