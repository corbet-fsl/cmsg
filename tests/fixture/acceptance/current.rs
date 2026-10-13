//! Current-time original owners for the private Tor custody journey.
//! The original development gate supplies fixture passports only. It is not
//! production gate qualification. Both actual Doors use SystemClock throughout.
#[path = "../owner/mod.rs"]
mod owner;
#[path = "../wallet.rs"]
mod wallet;

use super::*;
use cvld::{api::*, cli::Client, service::Clock};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

const COMMUNITY_HOST: &str = "api.alpha.example.test";
const HOLDERS: usize = 6;

struct OriginalOwner {
    door: Door,
    base: String,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
impl Drop for OriginalOwner {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl OriginalOwner {
    async fn listen(door: Door, directory: tempfile::TempDir) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = cvld::api::router(door.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            door,
            base,
            task,
            _directory: directory,
        }
    }
    fn client(&self, host: &str, token: Option<&str>) -> Client {
        Client::new(self.base.clone(), host.into(), token.map(str::to_owned)).unwrap()
    }
}

// The exact original wallet_passport flow, using the actual current-time Door
// rather than the fixed-time Running fixture. No owner state is injected.
async fn passport(global: &OriginalOwner) -> cpsd::Passport {
    let public = global.client(owner::WALLET, None);
    let start: Ceremony = serde_json::from_value(
        public
            .call("register_begin", json!({"bootstrap":null,"passport":null}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::CreationChallengeResponse = serde_json::from_value(start.options).unwrap();
    let mut authenticator = SoftToken::new(true).unwrap().0;
    let mut options = challenge.public_key;
    // The original SoftToken fixture is non-resident. This modifies only its
    // local authenticator request; the server still verifies its real ceremony.
    options
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let credential = authenticator
        .perform_register(
            ckyh::Url::parse("https://wallet.example.test").unwrap(),
            options,
            300_000,
        )
        .unwrap();
    let id = credential.raw_id.as_ref().to_vec();
    let user: User = serde_json::from_value(
        public
            .call(
                "register_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let start: Ceremony = serde_json::from_value(
        public
            .call("login_begin", json!({"user":user.user,"credential":id}))
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge: ckyh::RequestChallengeResponse = serde_json::from_value(start.options).unwrap();
    let credential = authenticator
        .perform_auth(
            ckyh::Url::parse("https://wallet.example.test").unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let session: Session = serde_json::from_value(
        public
            .call(
                "login_finish",
                json!({"ceremony":start.ceremony,"credential":credential}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let client = global.client(owner::WALLET, Some(&session.token));
    client.call("development_gate", json!({})).await.unwrap();
    let global: GlobalPublic =
        serde_json::from_value(client.call("global_public", json!({})).await.unwrap()).unwrap();
    let issuer = cpsd::IssuerPublicKey::from_bytes(&global.issuer).unwrap();
    let mut rng = cpsd::rand::rngs::OsRng;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let challenge: Bytes =
        serde_json::from_value(client.call("passport_challenge", json!({})).await.unwrap())
            .unwrap();
    let challenge = cpsd::IssuanceChallenge::from_bytes(challenge.bytes.try_into().unwrap());
    let (request, pending) = cpsd::request_issue(&mut rng, &secret, &issuer, &challenge).unwrap();
    let response: Bytes = serde_json::from_value(
        client
            .call(
                "passport_issue",
                json!({"challenge":challenge.to_bytes().to_vec(),"request":request.to_bytes()}),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    pending
        .finish(&cpsd::BlindPassport::from_bytes(&response.bytes).unwrap())
        .unwrap()
}

async fn presentation(community: &OriginalOwner, passport: &cpsd::Passport) -> Value {
    let client = community.client(COMMUNITY_HOST, None);
    let challenge: PresentationChallenge = serde_json::from_value(
        client
            .call("presentation_challenge", json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let feed: TrustFeed =
        serde_json::from_value(client.call("trust_feed", json!({})).await.unwrap()).unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new("alpha").unwrap(),
        csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
    );
    let proof = passport
        .present(
            &mut cpsd::rand::rngs::OsRng,
            &expected,
            &challenge.request,
            SystemClock.now(),
        )
        .unwrap();
    json!({"member":passport.pseudonym(&cpsd::CommunityId::new("alpha").unwrap()).to_hex(),
        "passport":PresentationInput {challenge:challenge.challenge, proof:proof.to_bytes()}})
}

pub(super) async fn run() -> Result<()> {
    run_selected(false).await
}
pub(super) async fn run_wallet() -> Result<()> {
    run_selected(true).await
}

enum Fixture {
    Community(https::HttpsFixture),
    Wallet(wallet::Fixture),
}
impl Fixture {
    async fn shutdown(self) -> Result<()> {
        match self {
            Self::Community(fixture) => fixture.shutdown().await,
            Self::Wallet(fixture) => fixture.shutdown().await,
        }
        .map_err(|_| "HTTPS shutdown failed")
    }
}
async fn start_selected(
    wallet: bool,
    directory: &Path,
    chain: &Path,
    key: &Path,
) -> Result<(Fixture, Value)> {
    if wallet {
        let fixture = wallet::Fixture::start(chain, key)
            .await
            .map_err(|_| "Wallet startup failed")?;
        let data = fixture.data.clone();
        Ok((Fixture::Wallet(fixture), data))
    } else {
        let (fixture, feed) = start(directory, chain, key).await?;
        let data = json!({"https":{"base":fixture.base_url()},
            "trust_key_ring":feed.key_ring,"holders":HOLDERS,"clock":"SystemClock",
            "passport_gate":"original development fixture"});
        Ok((Fixture::Community(fixture), data))
    }
}
async fn run_selected(wallet: bool) -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(2).take(5).collect();
    if args.len() != 4 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("usage: --current-owner FIXTURE_DIR CHAIN KEY OUTPUT");
    }
    let directory = Path::new(&args[0]);
    if !directory.is_absolute() || !directory.is_dir() {
        return Err("invalid fixture directory");
    }
    let directory = directory
        .canonicalize()
        .map_err(|_| "invalid fixture directory")?;
    if !directory.is_dir() {
        return Err("invalid fixture directory");
    }
    let chain = input_file(&directory, Path::new(&args[1]))?;
    let key = input_file(&directory, Path::new(&args[2]))?;
    let output = local_destination(&directory, Path::new(&args[3]))?;
    match fs::symlink_metadata(&output) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("output must be absent"),
    }
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal setup failed")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal setup failed")?;
    let (fixture, data) = tokio::select! {
        result = tokio::time::timeout(STARTUP_LIMIT, start_selected(wallet, &directory, &chain, &key)) =>
            result.map_err(|_| "owner startup timed out")??,
        _ = interrupt.recv() => return Ok(()),
        _ = terminate.recv() => return Ok(()),
    };
    let result = async {
        let mut file = tempfile::NamedTempFile::new_in(&directory).map_err(|_| "output preparation failed")?;
        file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_| "output permissions failed")?;
        serde_json::to_writer(&mut file, &data).map_err(|_| "output write failed")?;
        file.write_all(b"\n").map_err(|_| "output write failed")?;
        file.as_file().sync_all().map_err(|_| "output sync failed")?;
        file.persist_noclobber(&output).map_err(|_| "output publication failed")?;
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {}, _ = tokio::time::sleep(LIFETIME) => {} }
        Ok(())
    }.await;
    let shutdown = fixture
        .shutdown()
        .await
        .map_err(|_| "HTTPS shutdown failed");
    result.and(shutdown)
}

async fn start(
    directory: &Path,
    chain: &Path,
    key: &Path,
) -> Result<(https::HttpsFixture, TrustFeed)> {
    let global_dir =
        tempfile::tempdir_in(&directory).map_err(|_| "global directory unavailable")?;
    let mut config = owner::global_config_at(global_dir.path(), 1000, SystemClock.now()).await;
    // The fixture never uses operator bootstrap; remove the original helper's
    // configured capability instead of carrying it into this member journey.
    config.root_bootstrap_file = None;
    let global = OriginalOwner::listen(
        Door::global(config, Arc::new(SystemClock))
            .await
            .map_err(|_| "global owner unavailable")?,
        global_dir,
    )
    .await;
    let public: GlobalPublic = serde_json::from_value(
        global
            .client(owner::WALLET, None)
            .call("global_public", json!({}))
            .await
            .map_err(|_| "global public unavailable")?,
    )
    .map_err(|_| "invalid global public")?;
    let mut passports = Vec::with_capacity(HOLDERS);
    for _ in 0..HOLDERS {
        passports.push(passport(&global).await);
    }
    let community_dir =
        tempfile::tempdir_in(&directory).map_err(|_| "community directory unavailable")?;
    let mut config = owner::community_config(community_dir.path(), "alpha", &public, 1000);
    config.root.bootstrap_file = None;
    config.admin.bootstrap_file = None;
    let community = Arc::new(
        OriginalOwner::listen(
            Door::community(config, Arc::new(SystemClock))
                .await
                .map_err(|_| "community owner unavailable")?,
            community_dir,
        )
        .await,
    );
    let feed: TrustFeed = serde_json::from_value(
        community
            .client(COMMUNITY_HOST, None)
            .call("trust_feed", json!({}))
            .await
            .map_err(|_| "trust unavailable")?,
    )
    .map_err(|_| "invalid trust")?;
    let passports = Arc::new(passports);
    let proofs_owner = community.clone();
    // Fixed test-owned holders only; no Host/URL/root/key input controls routing.
    let proofs = axum::Router::new().route(
        "/__fixture/presentation/{index}",
        axum::routing::post(
            move |axum::extract::Path(index): axum::extract::Path<usize>| {
                let owner = proofs_owner.clone();
                let passports = passports.clone();
                async move {
                    match passports.get(index) {
                        Some(passport) => Ok(axum::Json(presentation(&owner, passport).await)),
                        None => Err(axum::http::StatusCode::NOT_FOUND),
                    }
                }
            },
        ),
    );
    let router = cvld::api::router(community.door.clone())
        .merge(proofs)
        .layer(axum::middleware::from_fn(
            |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                // Fixed ephemeral ingress relation; WebAuthn retains the original
                // separate vault.alpha.example.test realm. No URL equivalence grants membership.
                request.headers_mut().insert(
                    axum::http::header::HOST,
                    axum::http::HeaderValue::from_static(COMMUNITY_HOST),
                );
                next.run(request).await
            },
        ));
    let fixture = https::HttpsFixture::start(router, (global, community), chain, key)
        .await
        .map_err(|_| "HTTPS startup failed")?;
    Ok((fixture, feed))
}
