//! Peer lineage port against the original Keys receipt, Keyhole passkey, signed Charter
//! and certified evidence (fixture copied from the cvlt lineage vectors).
//! Original cryptographic evidence only. A narrowly authorized test Create builds
//! the original Keys receipt; this is not live G3/adoption or complete custody.
#![cfg(not(target_arch = "wasm32"))]
#![allow(dead_code)]
use ckmg::{Action, Authority, Authorization, Binding, DeviceInfo, Error, PublicKey};
use ckyh::{CreationMonth, LibsqlStore, Passkeys, Url, Uuid};
use cmsg::door::inbox_lineage::{CharterView, PeerLineage, PeerRecords, PeerUnavailable};
use cnbx::{ContactError, DeviceAuthority};
use cpky::{
    software::{SoftwareAuthenticator, TestConfiguration},
    Client, Context,
};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{json, Value};
use std::{cell::Cell, rc::Rc};

const NOW: u64 = 1_800_000_000;
const SCOPE: &str = "alpha";
const MEMBER: &str = "fixture-pseudonym";
const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";

struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(NOW)
    }
}

// First refuse to capture only the original derived public device. Then allow
// exactly one fixture Create with that same device and complete request shape.
// No PRF derivation, attestation transcript or signature is reconstructed here.
struct FixtureCreate {
    device: Option<PublicKey>,
    captured: Rc<Cell<Option<PublicKey>>>,
    used: bool,
}
impl Authority for FixtureCreate {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.action != Action::Create
            || request.binding != &Binding::new(SCOPE, MEMBER).unwrap()
            || request.root.is_some()
            || request.epoch != 0
            || request.now != NOW
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
            || request.evidence != b"fixture-create"
            || self.used
        {
            return Err(Error::Unauthorized);
        }
        match self.device {
            None => {
                self.captured.set(Some(request.device));
                Err(Error::Unauthorized)
            }
            Some(expected) if expected == request.device => {
                self.used = true;
                Ok(())
            }
            Some(_) => Err(Error::Unauthorized),
        }
    }
}

// Deliberately seed the unpublished legacy PRF-wrapped fixture. Its pending
// receipt tests exercise retention, not common-root recovery. A production
// compound adapter MUST forward compare_exchange_wrapped; this test adapter
// intentionally models the older ordinary-CAS implementation.
#[derive(Clone)]
struct LegacyFixtureStore<B: cwst::backend::Backend>(cvlt::KeyStore<B>);
impl<B: cwst::backend::Backend> ckmg::SecureStore for LegacyFixtureStore<B> {
    async fn load(&mut self, location: &ckmg::Locator) -> Result<Option<Vec<u8>>, Error> {
        ckmg::SecureStore::load(&mut self.0, location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &ckmg::Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<ckmg::Commit, Error> {
        ckmg::SecureStore::compare_exchange(&mut self.0, location, expected, replacement).await
    }
}

async fn receipt<B: cwst::backend::Backend>(
    prf: &ckmg::passkey::PrfOutput,
    credential_id: &[u8],
    backend: B,
) -> ckmg::Receipt {
    let cipher = ckmg::passkey::store_cipher(prf, SCOPE).unwrap();
    let store = cwst::Store::create(backend, &cipher, SCOPE).await.unwrap();
    let shared = cvlt::shared_store(store);
    let mut key_store = cvlt::KeyStore::new(shared.clone(), SCOPE).unwrap();
    let captured = Rc::new(Cell::new(None));
    let mut probe = ckmg::Keys::new(
        LegacyFixtureStore(key_store.clone()),
        Clock,
        ckmg::SystemEntropy,
        FixtureCreate {
            device: None,
            captured: captured.clone(),
            used: false,
        },
    );
    assert!(matches!(
        probe
            .create_scope(
                prf,
                Binding::new(SCOPE, MEMBER).unwrap(),
                DeviceInfo::new("fixture", credential_id).unwrap(),
                b"fixture-create"
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(shared.lock().await.version().unwrap(), 0);
    drop(probe);
    let mut keys = ckmg::Keys::new(
        LegacyFixtureStore(key_store.clone()),
        Clock,
        ckmg::SystemEntropy,
        FixtureCreate {
            device: Some(captured.get().unwrap()),
            captured,
            used: false,
        },
    );
    let guard = key_store
        .stage(cvlt::Batch {
            expected: 0,
            operation: [61; 32],
            mutations: vec![],
            outputs: vec![],
        })
        .unwrap();
    let receipt = keys
        .create_scope(
            prf,
            Binding::new(SCOPE, MEMBER).unwrap(),
            DeviceInfo::new("fixture", credential_id).unwrap(),
            b"fixture-create",
        )
        .await
        .unwrap();
    drop(guard);
    assert_eq!(shared.lock().await.version().unwrap(), 1);
    assert_eq!(keys.pending_output().await.unwrap().unwrap(), receipt);
    assert_eq!(keys.lineage().await.unwrap_err(), Error::Unauthorized);
    receipt
}

struct Fixture {
    receipt: ckmg::Receipt,
    assertion: ckyh::lineage::Assertion,
    other_assertion: ckyh::lineage::Assertion,
    descriptor: ckyh::lineage::PublicCredential,
    certificate: Vec<u8>,
    revoked: Vec<Vec<u8>>,
    prf: ckmg::passkey::PrfOutput,
    backend: cwst::native::FileBackend,
    _directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    // Same original maintained authenticator/SQL Keyhole path as cpky tests/server.rs.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let url = Url::from_file_path(directory.path().join("community.db")).unwrap();
    let db = runtime
        .block_on(crlt::Db::open(crlt::Config::new(url.as_str(), "")))
        .unwrap();
    runtime
        .block_on(db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)]))
        .unwrap();
    let store = LibsqlStore::new(&db, SCOPE, runtime.handle().clone()).unwrap();
    let server = Passkeys::new(store, SCOPE, RP, &[Url::parse(ORIGIN).unwrap()]).unwrap();
    let member = Uuid::from_u128(17);
    let mut device = Client::new(
        Context::new(ORIGIN, RP).unwrap(),
        SoftwareAuthenticator::new(
            ORIGIN,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    );
    let (options, pending) = server.start_registration(member).unwrap();
    let (public, unlock) =
        futures_executor::block_on(device.register_member(serde_json::to_value(options).unwrap()))
            .unwrap()
            .into_parts();
    let response = serde_json::from_value(public.into_json()).unwrap();
    let stored = server
        .finish_registration(pending, &response, CreationMonth::new(2026, 10).unwrap())
        .unwrap();
    let descriptor = server
        .registered_public_credential(member, stored.credential_id())
        .unwrap();
    let registration = server
        .registration_certificate(member, stored.credential_id(), MEMBER)
        .unwrap();
    let certificate = runtime.block_on(async {
        let mut signer = csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            SCOPE,
            SecretKey::from_seed(&mut [71; 32]),
            NOW - 1,
            1000,
        )
        .await
        .unwrap();
        registration.sign(&mut signer, NOW).await.unwrap()
    });
    let prf = unlock
        .import(|bytes| ckmg::passkey::PrfOutput::from_bytes(bytes))
        .unwrap();
    let custody_directory = tempfile::tempdir().unwrap();
    let backend = cwst::native::FileBackend::new(custody_directory.path());
    let receipt = futures_executor::block_on(receipt(
        &prf,
        stored.credential_id().as_ref(),
        backend.clone(),
    ));
    let challenge = receipt.passkey_challenge().unwrap();
    let assertion = assertion(&mut device, &descriptor, challenge);
    ckyh::lineage::verify(&descriptor, &assertion, challenge).unwrap();
    // A second authentic signature over different options is valid for its own
    // challenge. It must never authorize this receipt; no signed bytes are edited.
    let mut other_challenge = challenge;
    other_challenge[0] ^= 1;
    let other_assertion = self::assertion(&mut device, &descriptor, other_challenge);
    ckyh::lineage::verify(&descriptor, &other_assertion, other_challenge).unwrap();
    server.revoke(member, stored.credential_id()).unwrap();
    let revoked = server
        .list(member)
        .unwrap()
        .into_iter()
        .filter(|row| row.is_revoked())
        .map(|row| row.credential_id().as_ref().to_vec())
        .collect();
    assert!(matches!(
        server.registered_public_credential(member, stored.credential_id()),
        Err(ckyh::Error::Revoked)
    ));
    Fixture {
        receipt,
        assertion,
        other_assertion,
        descriptor,
        certificate,
        revoked,
        prf,
        backend,
        _directory: custody_directory,
    }
}

fn assertion(
    device: &mut Client<SoftwareAuthenticator>,
    descriptor: &ckyh::lineage::PublicCredential,
    challenge: [u8; 32],
) -> ckyh::lineage::Assertion {
    let (public, _) = futures_executor::block_on(
        device.sign_in(serde_json::to_value(descriptor.request(challenge)).unwrap()),
    )
    .unwrap()
    .into_parts();
    let response: ckyh::PublicKeyCredential = serde_json::from_value(public.into_json()).unwrap();
    ckyh::lineage::Assertion {
        credential_id: response.raw_id.as_ref().to_vec(),
        client_data_json: response.response.client_data_json.as_ref().to_vec(),
        authenticator_data: response.response.authenticator_data.as_ref().to_vec(),
        signature: response.response.signature.as_ref().to_vec(),
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|h| h.as_ref().to_vec()),
    }
}

fn signer() -> Signer {
    Signer::new(SCOPE, SecretKey::from_seed(&mut [71; 32]), NOW - 1, 1000).unwrap()
}
fn sign(signer: &mut Signer, kind: Kind, payload: Value, until: u64) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(&payload).unwrap(), NOW, until)
        .unwrap()
}
fn charter(
    scope: &str,
    signer: &mut Signer,
    revoked: &[Vec<u8>],
    members: &[&str],
    passkeys: bool,
) -> cchr::Charter {
    // Original Charter vectors' signed five-document publication, no permissive
    // verifier or manually constructed VerifiedCharter/private-field witness.
    let schema = json!({"community":scope,"version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":scope,"revision":1,
        "policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),"schema_version":1});
    let mut feed = json!({"revision":1,"policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),
        "manifest":sign(signer,Kind::SettingsSnapshot,manifest,NOW+500)});
    let mut revocations = json!({"members":members,"devices":[]});
    if passkeys {
        revocations["passkeys"] = json!(revoked);
    }
    for (name, kind, content) in [
        (
            "settings",
            Kind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
        ),
        ("schema", Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!([scope])),
        ("revocations", Kind::RevocationListSnapshot, revocations),
    ] {
        feed[name] = json!(sign(
            signer,
            kind,
            json!({"community":scope,"revision":1,
            "policy_epoch":1,"content":content}),
            NOW + 500
        ));
    }
    let mut owner = cchr::Charter::new(cchr::Configuration {
        origin: ORIGIN.into(),
        community: scope.into(),
        key_ring: signer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    owner
        .install(&serde_json::to_vec(&feed).unwrap(), NOW)
        .unwrap();
    owner
}

struct Records(Option<Vec<Vec<u8>>>);
impl PeerRecords for Records {
    async fn read(&mut self, _: &Binding) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
        let items = self.0.as_ref().ok_or(PeerUnavailable)?;
        Ok(items
            .iter()
            .map(|bytes| cvlt::LineageEvidence::from_bytes(bytes).unwrap())
            .collect())
    }
}
struct View<'a>(&'a cchr::VerifiedCharter);
impl CharterView for View<'_> {
    fn with_current<T>(
        &mut self,
        community: &str,
        _: u64,
        inspect: impl FnOnce(&cchr::VerifiedCharter) -> Result<T, ContactError>,
    ) -> Result<T, ContactError> {
        if community != self.0.community() {
            return Err(ContactError::Authority);
        }
        inspect(self.0)
    }
}

fn evidence_bytes(fixture: &Fixture, current: &cchr::VerifiedCharter) -> Vec<u8> {
    cvlt::LineageEvidence::prepare(
        current,
        &fixture.receipt,
        &fixture.assertion,
        &fixture.certificate,
        MEMBER,
        NOW,
    )
    .unwrap()
    .evidence()
    .to_bytes()
    .unwrap()
}

#[test]
fn peer_lineage_selects_fresh_evidence_and_refuses_everything_else() {
    let fixture = fixture();
    let mut signer = signer();
    let mut owner = charter(SCOPE, &mut signer, &[], &[], true);
    let current = owner.current(NOW).unwrap();
    let bytes = evidence_bytes(&fixture, current);
    let binding = Binding::new(SCOPE, MEMBER).unwrap();
    let lineage = fixture.receipt.attested_lineage().unwrap().0.clone();
    let time = |values: Vec<u64>| {
        let mut values = values.into_iter();
        move || values.next()
    };
    let run = |records: Records, view: View<'_>, clock: Vec<u64>, binding: &Binding| {
        let mut port = PeerLineage::new(records, view, time(clock));
        futures_executor::block_on(port.current(binding))
    };

    // Valid, fresh, forced-read evidence yields exactly the attested lineage.
    // Duplicated evidence is a tie of the same lineage.
    for items in [vec![bytes.clone()], vec![bytes.clone(), bytes.clone()]] {
        assert_eq!(
            run(
                Records(Some(items)),
                View(current),
                vec![NOW, NOW],
                &binding
            ),
            Ok(lineage.clone())
        );
    }
    // Missing evidence, unreadable records, a missing or regressing clock and
    // validity that has run out are all Unavailable, never permissive.
    for (records, clock) in [
        (Records(Some(vec![])), vec![NOW, NOW]),
        (Records(None), vec![NOW, NOW]),
        (Records(Some(vec![bytes.clone()])), vec![]),
        (Records(Some(vec![bytes.clone()])), vec![NOW, NOW - 1]),
        (Records(Some(vec![bytes.clone()])), vec![NOW, NOW + 500]),
        (Records(Some(vec![bytes.clone()])), vec![NOW, NOW + 1000]),
    ] {
        assert_eq!(
            run(records, View(current), clock, &binding),
            Err(ContactError::Unavailable)
        );
    }
    // Present negative evidence is Authority: another member's binding, another
    // scope, a revoked passkey, and garbled certificate bytes.
    let other = Binding::new(SCOPE, "someone-else").unwrap();
    assert_eq!(
        run(
            Records(Some(vec![bytes.clone()])),
            View(current),
            vec![NOW, NOW],
            &other
        ),
        Err(ContactError::Authority)
    );
    let credential = fixture.assertion.credential_id.clone();
    let mut revoking = charter(SCOPE, &mut signer, &[credential], &[], true);
    let revoked = revoking.current(NOW).unwrap();
    assert_eq!(
        run(
            Records(Some(vec![bytes.clone()])),
            View(revoked),
            vec![NOW, NOW],
            &binding
        ),
        Err(ContactError::Authority)
    );
    let mut garbled: Value = serde_json::from_slice(&bytes).unwrap();
    garbled["certificate"] = json!([]);
    assert_eq!(
        run(
            Records(Some(vec![serde_json::to_vec(&garbled).unwrap()])),
            View(current),
            vec![NOW, NOW],
            &binding
        ),
        Err(ContactError::Authority)
    );
}
