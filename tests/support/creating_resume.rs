//! Interrupting a creation after every step and resuming it. The service is a small
//! in-process HTTP server that answers like the real one (a repeated blinded message
//! gets the same signature, a repeated creation the same community) and can lose any
//! answer after acting on the request. The device logic under test is the real one.
use super::super::accounting;
use super::super::facades::{BoundVault, OwnedFuture, VaultIdentity};
use super::*;
use blind_rsa_signatures::{DefaultRng, KeyPairSha384PSSRandomized as KeyPair};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

struct Service {
    pair: KeyPair,
    signatures: BTreeMap<Vec<u8>, Vec<u8>>,
    created: BTreeMap<Vec<u8>, Value>,
    issuances: usize,
    creations: usize,
    claims: usize,
    key_reads: usize,
    /// Operations whose next answer is lost after the service acted.
    lose: BTreeSet<&'static str>,
    /// Operations the service does not receive at all, once.
    drop: BTreeSet<&'static str>,
    /// The accounting terms the platform names; `None` is a platform without accounts.
    terms: Option<Value>,
    /// Activations `community_create` received.
    activations: Vec<Value>,
    /// Refuse the next activation as outdated (a day passed while proving).
    refuse_activation: bool,
}

type Shared = Arc<Mutex<Service>>;

fn answer(service: &Shared, name: &str, body: Value) -> Option<Value> {
    let mut service = service.lock().unwrap();
    let operation = [
        "creation_token_key",
        "creation_token_issue",
        "community_create",
        "community_creation_claim",
        "community_terms",
    ]
    .into_iter()
    .find(|known| *known == name)?;
    if service.drop.remove(operation) {
        return None;
    }
    let reply = match operation {
        "creation_token_key" => {
            service.key_reads += 1;
            json!({"public_key": service.pair.pk.to_der().unwrap()})
        }
        "creation_token_issue" => {
            let blinded: Vec<u8> = serde_json::from_value(body["blinded"].clone()).unwrap();
            if !service.signatures.contains_key(&blinded) {
                let signature = service.pair.sk.blind_sign(&blinded).unwrap().0;
                service.issuances += 1;
                service.signatures.insert(blinded.clone(), signature);
            }
            json!({"blind_signature": service.signatures[&blinded]})
        }
        "community_terms" => json!({"accounting": service.terms}),
        "community_create" => {
            if service.terms.is_some() && body.get("activation").is_none() {
                return Some(Value::Null);
            }
            if let Some(activation) = body.get("activation") {
                if std::mem::take(&mut service.refuse_activation) {
                    return Some(Value::Null);
                }
                service.activations.push(activation.clone());
            }
            let message: Vec<u8> =
                serde_json::from_value(body["token"]["message"].clone()).unwrap();
            if !service.created.contains_key(&message) {
                service.creations += 1;
                let address = body["address"].as_str().unwrap();
                let made = json!({
                    "id": format!("{:032x}", service.creations),
                    "fingerprint": "ab".repeat(32),
                    "community_host": format!("{address}.example.test"),
                    "vault_host": format!("vault.{address}.example.test"),
                    "claim": vec![7u8; 32],
                    "expires_at": 1_000_000u64,
                });
                service.created.insert(message.clone(), made);
            }
            service.created[&message].clone()
        }
        _ => {
            service.claims += 1;
            json!({"id": format!("{:032x}", 1), "expires_at": 1_000_000u64})
        }
    };
    if service.lose.remove(operation) {
        return None;
    }
    Some(reply)
}

async fn serve(service: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service.clone();
            tokio::spawn(async move {
                let handler = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let service = service.clone();
                    async move {
                        let name = request.uri().path().trim_start_matches("/v1/").to_owned();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        Ok::<_, std::convert::Infallible>(match answer(&service, &name, body) {
                            // The service's own refusal: HTTP 400 with its fixed error body.
                            Some(Value::Null) => Response::builder()
                                .status(400)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(r#"{"error":"invalid"}"#)))
                                .unwrap(),
                            Some(reply) => Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(reply.to_string())))
                                .unwrap(),
                            None => Response::builder()
                                .status(503)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        })
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            });
        }
    });
    base
}

/// A Vault that keeps only the custody record, in memory shared across restarts.
struct Custody(Arc<Mutex<Option<Vec<u8>>>>);

impl BoundVault for Custody {
    fn current_identity(&mut self) -> OwnedFuture<'_, VaultIdentity> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn snapshot(&mut self, _: facades::Relation) -> OwnedFuture<'_, cnbx::ConversationView> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn history(&mut self, _: facades::Conversation) -> OwnedFuture<'_, Vec<cnbx::Message>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn relation(&mut self, _: facades::Relation) -> OwnedFuture<'_, cnbx::Relation> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn delivery(&mut self, _: facades::Delivery) -> OwnedFuture<'_, Option<cnbx::DeliveryStatus>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn sign_board<'a>(
        &'a mut self,
        _: &'a cbrd::Prepared,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> OwnedFuture<'a, super::super::facades::SignedBoard> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn lock(self: Box<Self>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> {
        Box::pin(async {})
    }
    fn voucher_custody(&mut self) -> OwnedFuture<'_, Option<Zeroizing<Vec<u8>>>> {
        let held = self.0.lock().unwrap().clone();
        Box::pin(async move { Ok(held.map(Zeroizing::new)) })
    }
    fn replace_voucher_custody<'a>(
        &'a mut self,
        expected: Option<&'a [u8]>,
        custody: &'a [u8],
    ) -> OwnedFuture<'a, ()> {
        Box::pin(async move {
            let mut held = self.0.lock().unwrap();
            if held.as_deref() != expected {
                return Err(ErrorCode::Reconcile);
            }
            *held = Some(custody.to_vec());
            Ok(())
        })
    }
}

struct Device {
    door: Door,
    key: [u8; 32],
}

/// A freshly started device: new Door and Foyers, the same Vault custody.
fn start(base: &str, custody: &Arc<Mutex<Option<Vec<u8>>>>) -> Device {
    start_in(base, custody, foyer::Scope::Global)
}

fn start_in(base: &str, custody: &Arc<Mutex<Option<Vec<u8>>>>, scope: foyer::Scope) -> Device {
    let transport = || super::super::foyer::fixture_transport(base, "wallet.example.test");
    let mut door = Door::new(
        Configuration::new(
            "wallet".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([base.to_owned()]))]),
        )
        .unwrap(),
    );
    let sessions = foyer::Sessions::new(scope, cfyr::Foyer::new(transport()))
        .with_public(cfyr::Foyer::new(transport()));
    door.bind_foyer(base, Role::Member, sessions).unwrap();
    door.vaults
        .insert(base.to_owned(), Box::new(Custody(custody.clone())));
    let actions = BTreeSet::from(["foyer.community_create".to_owned()]);
    let token = door
        .pair_client(base, Role::Member, actions, 100, 1_000)
        .unwrap();
    let key = token_hash(token.expose_for_transport());
    Device { door, key }
}

fn service() -> Shared {
    Arc::new(Mutex::new(Service {
        pair: KeyPair::generate(&mut DefaultRng, 2048).unwrap(),
        signatures: BTreeMap::new(),
        created: BTreeMap::new(),
        issuances: 0,
        creations: 0,
        claims: 0,
        key_reads: 0,
        lose: BTreeSet::new(),
        drop: BTreeSet::new(),
        terms: None,
        activations: Vec::new(),
        refuse_activation: false,
    }))
}

fn chosen() -> Create {
    Create {
        address: "gardenclub".into(),
        display_name: "Garden Club".into(),
        gates: vec!["legal".into(), "voucher".into()],
    }
}

fn resume() -> Create {
    Create {
        address: String::new(),
        display_name: String::new(),
        gates: Vec::new(),
    }
}

async fn draft(device: &mut Device) -> Draft {
    community_creation(&mut device.door, &device.key, Empty {})
        .await
        .unwrap()
        .0
}

/// Interrupt the first call at `step` (the service loses or never gets the call), restart
/// the device and resume with no input at all.
async fn interrupted(step: &'static str, lose: bool) -> (Shared, Created) {
    let shared = service();
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    {
        let mut service = shared.lock().unwrap();
        if lose {
            service.lose.insert(step);
        } else {
            service.drop.insert(step);
        }
    }
    let mut first = start(&base, &custody);
    assert!(
        community_create(&mut first.door, &first.key, chosen())
            .await
            .is_err()
    );
    // The choices are in the Vault already: nothing has to be entered again.
    let kept = draft(&mut first).await;
    assert_eq!(
        (
            kept.address.as_str(),
            kept.display_name.as_str(),
            kept.gates.len()
        ),
        ("gardenclub", "Garden Club", 2)
    );
    drop(first);
    // Restart: a new Door over the same custody; the person types nothing.
    let mut second = start(&base, &custody);
    let before = draft(&mut second).await;
    assert_eq!(before.address, "gardenclub");
    let (created, _) = community_create(&mut second.door, &second.key, resume())
        .await
        .unwrap();
    assert_eq!(created.address, "gardenclub");
    assert_eq!(created.display_name, "Garden Club");
    (shared, created)
}

#[tokio::test]
async fn an_interruption_at_any_step_resumes_without_asking_or_repeating() {
    for (step, lose) in [
        ("creation_token_key", false),
        ("creation_token_issue", false),
        ("creation_token_issue", true),
        ("community_create", false),
        ("community_create", true),
    ] {
        let (shared, created) = interrupted(step, lose).await;
        let service = shared.lock().unwrap();
        assert_eq!(service.issuances, 1, "{step} {lose}");
        assert_eq!(service.creations, 1, "{step} {lose}");
        assert_eq!(created.claim, to_hex(&[7u8; 32]), "{step} {lose}");
    }
}

#[tokio::test]
async fn a_finished_creation_is_answered_from_the_vault_and_forgotten_on_request() {
    let shared = service();
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let mut device = start(&base, &custody);
    let (created, _) = community_create(&mut device.door, &device.key, chosen())
        .await
        .unwrap();
    let reads = shared.lock().unwrap().key_reads;
    drop(device);
    let mut device = start(&base, &custody);
    let again = draft(&mut device).await;
    assert_eq!(again.stage, "created");
    assert_eq!(again.creation.as_ref(), Some(&created));
    // Asking again reaches the service not at all.
    let (repeated, _) = community_create(&mut device.door, &device.key, resume())
        .await
        .unwrap();
    assert_eq!(repeated, created);
    assert_eq!(shared.lock().unwrap().key_reads, reads);
    // A different address while one exists is refused; finishing forgets it.
    let mut other = chosen();
    other.address = "otherclub1".into();
    assert_eq!(
        community_create(&mut device.door, &device.key, other.clone())
            .await
            .err(),
        Some(ErrorCode::Refused)
    );
    community_creation_finish(&mut device.door, &device.key, Empty {})
        .await
        .unwrap();
    assert_eq!(draft(&mut device).await.stage, "none");
    assert!(
        community_create(&mut device.door, &device.key, other)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_choices_can_change_until_the_service_made_the_community() {
    let shared = service();
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    shared.lock().unwrap().drop.insert("community_create");
    let mut device = start(&base, &custody);
    assert!(
        community_create(&mut device.door, &device.key, chosen())
            .await
            .is_err()
    );
    let mut changed = chosen();
    changed.address = "rosegarden".into();
    let (created, _) = community_create(&mut device.door, &device.key, changed)
        .await
        .unwrap();
    assert_eq!(created.address, "rosegarden");
    // One token served both attempts.
    assert_eq!(shared.lock().unwrap().issuances, 1);
}

#[tokio::test]
async fn a_claim_is_remembered_until_the_join_is_done() {
    let shared = service();
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let mut device = start_in(&base, &custody, foyer::Scope::Community);
    // The claim's answer is lost once; repeating it is harmless and stores the id.
    shared
        .lock()
        .unwrap()
        .lose
        .insert("community_creation_claim");
    let claim = Claim {
        claim: to_hex(&[7u8; 32]),
    };
    assert!(
        community_creation_claim(&mut device.door, &device.key, claim.clone())
            .await
            .is_err()
    );
    assert!(draft_claimed(&custody).is_none());
    // The device restarts and repeats.
    drop(device);
    let mut device = start_in(&base, &custody, foyer::Scope::Community);
    let (claimed, _) = community_creation_claim(&mut device.door, &device.key, claim)
        .await
        .unwrap();
    assert_eq!(draft_claimed(&custody), Some(claimed.id));
    settle(&mut device.door, &device.key).await.unwrap();
    assert!(draft_claimed(&custody).is_none());
}

fn draft_claimed(custody: &Arc<Mutex<Option<Vec<u8>>>>) -> Option<String> {
    let held = custody.lock().unwrap().clone()?;
    vouching::Book::decode(Some(&held)).unwrap().claimed.clone()
}

/// A prover that answers from a script, one poll at a time, and counts its starts.
struct Scripted {
    script: Mutex<Vec<accounting::ActivationPoll>>,
    polls: Mutex<usize>,
}

impl accounting::ActivationProver for Scripted {
    fn poll(&self, _address: &str, terms: &Value) -> accounting::ActivationPoll {
        assert_eq!(terms["observed_at"], 5);
        *self.polls.lock().unwrap() += 1;
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            accounting::ActivationPoll::Pending
        } else {
            script.remove(0)
        }
    }
}

fn activation() -> accounting::Activation {
    accounting::Activation {
        statement: json!({"community": vec![1u8; 32]}),
        proof: vec![4, 2],
    }
}

fn accounts() -> Value {
    json!({"observed_at": 5, "ledger_policy": {"account": {}}, "extension_policy": {}})
}

fn scripted(script: Vec<accounting::ActivationPoll>) -> Arc<Scripted> {
    Arc::new(Scripted {
        script: Mutex::new(script),
        polls: Mutex::new(0),
    })
}

#[tokio::test]
async fn the_accounting_proof_runs_in_the_background_and_nothing_is_asked_again() {
    let shared = service();
    shared.lock().unwrap().terms = Some(accounts());
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let prover = scripted(vec![
        accounting::ActivationPoll::Pending,
        accounting::ActivationPoll::Pending,
        accounting::ActivationPoll::Failed,
        accounting::ActivationPoll::Ready(activation()),
    ]);
    let mut device = start(&base, &custody);
    device.door.set_activation_prover(prover.clone());
    // Being prepared: the call does not wait, the choices and the token are kept.
    assert_eq!(
        community_create(&mut device.door, &device.key, chosen())
            .await
            .err(),
        Some(ErrorCode::Reconcile)
    );
    let draft = draft(&mut device).await;
    assert_eq!(draft.stage, "proving");
    assert_eq!(draft.address, "gardenclub");
    assert_eq!(shared.lock().unwrap().issuances, 1);
    // A restart in the middle loses nothing; the failed proof simply starts again.
    drop(device);
    let mut device = start(&base, &custody);
    device.door.set_activation_prover(prover.clone());
    assert_eq!(
        community_create(&mut device.door, &device.key, resume())
            .await
            .err(),
        Some(ErrorCode::Reconcile)
    );
    let (created, _) = community_create(&mut device.door, &device.key, resume())
        .await
        .unwrap();
    assert_eq!(created.address, "gardenclub");
    let service = shared.lock().unwrap();
    assert_eq!(service.creations, 1);
    assert_eq!(service.issuances, 1);
    assert_eq!(service.activations.len(), 1);
    assert_eq!(service.activations[0]["proof"], json!([4, 2]));
    drop(service);
    // The proof is not kept once the community exists.
    let held = custody.lock().unwrap().clone().unwrap();
    let book = vouching::Book::decode(Some(&held)).unwrap();
    assert!(book.creation.as_ref().unwrap().activation.is_none());
    assert_eq!(draft_stage(&mut device).await, "created");
}

async fn draft_stage(device: &mut Device) -> String {
    draft(device).await.stage
}

#[tokio::test]
async fn an_outdated_proof_is_replaced_silently() {
    let shared = service();
    {
        let mut service = shared.lock().unwrap();
        service.terms = Some(accounts());
        service.refuse_activation = true;
    }
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let prover = scripted(vec![
        accounting::ActivationPoll::Ready(activation()),
        accounting::ActivationPoll::Ready(activation()),
    ]);
    let mut device = start(&base, &custody);
    device.door.set_activation_prover(prover.clone());
    // The hub refuses the first proof: a day passed while it was made.
    assert_eq!(
        community_create(&mut device.door, &device.key, chosen())
            .await
            .err(),
        Some(ErrorCode::Reconcile)
    );
    let (created, _) = community_create(&mut device.door, &device.key, resume())
        .await
        .unwrap();
    assert_eq!(created.address, "gardenclub");
    assert_eq!(*prover.polls.lock().unwrap(), 2);
    assert_eq!(shared.lock().unwrap().issuances, 1);
}

#[tokio::test]
async fn a_platform_without_accounts_needs_no_proof_and_no_prover() {
    let shared = service();
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let mut device = start(&base, &custody);
    assert!(
        community_create(&mut device.door, &device.key, chosen())
            .await
            .is_ok()
    );
    assert!(shared.lock().unwrap().activations.is_empty());
}

#[tokio::test]
async fn a_device_that_cannot_prove_is_unavailable_not_stuck() {
    let shared = service();
    shared.lock().unwrap().terms = Some(accounts());
    let base = serve(shared.clone()).await;
    let custody = Arc::new(Mutex::new(None));
    let mut device = start(&base, &custody);
    assert_eq!(
        community_create(&mut device.door, &device.key, chosen())
            .await
            .err(),
        Some(ErrorCode::Unavailable)
    );
    assert_eq!(shared.lock().unwrap().creations, 0);
}
