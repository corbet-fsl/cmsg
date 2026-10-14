//! Production composer of a native device: from one configuration to a bound,
//! fully registered device.
//!
//! The steps, in order, each resumable from durable state:
//!
//! 1. global initial registration of the wallet (one Passkeys registration),
//!    retained in the encrypted vault before the server finish is sent,
//! 2. wallet enrollment: login, device authorization, activation, genesis
//!    publication, acknowledgment and recovery publication on the recovery network,
//! 3. global passport issue (never retried: an uncertain issue is refused),
//! 4. community enrollment at the accounting operator: passport presentation,
//!    the same lineage steps in the community scope,
//! 5. `bind_native_account`: the account actor with its three single-use intents.
//!
//! Resumption never creates a second registration: the vault checkpoint and a small
//! progress file (`composer.json`, written atomically after each step) decide
//! where a half-registered device continues. A vault that holds a candidate whose
//! progress marker was lost is treated as retained, never as fresh. No request
//! reaches this module: it is called by the embedding process (CLI, E2E device).
use super::identity;
use super::{
    custody::{self, SystemClock},
    foyer::{Scope, Sessions, Transport},
    Configuration, Door, Role,
};
use cfyr::{passkeys::Client, Foyer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    path::{Path, PathBuf},
    time::Duration,
};

/// Which of the two services a call talks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The wallet (global registration and passports).
    Global,
    /// The community (membership, accounting operator).
    Community,
}

/// One service endpoint and its trust anchors.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServiceSettings {
    /// Exact HTTPS base of the service; also the Door origin.
    pub origin: String,
    /// Trust scope the service signs for (`wallet` for the global service).
    pub scope: String,
    /// Origin and relying-party id of the Passkeys ceremonies. The embedder builds its
    /// authenticator with exactly these.
    pub passkey_origin: String,
    pub rp_id: String,
    /// Pinned key ring (the serialized `cnvy` key ring).
    pub trust_key_ring: Value,
    /// Founding-key fingerprint of the community (hex). When set, the trust is
    /// anchored to it instead of `trust_key_ring`: the feed must carry the
    /// genesis and an unbroken key chain, and registration options must carry
    /// a user id that opens with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Chain head this device verified before (from its pinned membership);
    /// a feed that rolls back below it or forks from it is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<identity::Head>,
    /// Host or address the HTTPS client dials (the origin's own host in production).
    pub connect_host: String,
    /// Extra DER certificate files trusted for this service.
    #[serde(default)]
    pub tls_root_files: Vec<PathBuf>,
}

/// The native prover's artifacts (the same retained extension group the operator authenticates).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverArtifacts {
    pub worker_executable: PathBuf,
    pub circuit_file: PathBuf,
    pub keys_file: PathBuf,
    pub srs_g1_file: PathBuf,
    pub srs_g2_file: PathBuf,
    /// Circuit and verification key of the wave update, when the platform distributes
    /// them. The native prover is single-circuit today; this slot only carries the
    /// files to the device so the wave prover can take them as a parameter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wave: Option<CircuitFiles>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_threads")]
    pub threads: usize,
    #[serde(default = "default_memory")]
    pub memory_megabytes: usize,
}
/// One extension circuit and its verification key (the SRS and worker are shared).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CircuitFiles {
    pub circuit_file: PathBuf,
    pub keys_file: PathBuf,
}
fn default_timeout() -> u64 {
    900
}
fn default_threads() -> usize {
    2
}
fn default_memory() -> usize {
    4096
}

/// Everything a device needs except live handles (network, authenticator).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceSettings {
    pub global: ServiceSettings,
    pub community: ServiceSettings,
    /// Community name: Door label, vault scope, passport community id and seed binding.
    pub community_name: String,
    pub prover: ProverArtifacts,
    /// Forum (Board) configuration of the community as the deployment serves it
    /// (`board::Configuration` JSON). It is copied into the device deployment on open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forum: Option<Value>,
}

impl DeviceSettings {
    /// Read a JSON settings file.
    pub fn load(path: &Path) -> Result<Self, ComposeError> {
        let bytes = std::fs::read(path).map_err(|e| ComposeError::Config(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| ComposeError::Config(e.to_string()))
    }

    fn validate(&self) -> Result<(), ComposeError> {
        if self.community_name.is_empty() || self.community_name == "wallet" {
            return Err(ComposeError::Config("community name".into()));
        }
        if self.global.scope != "wallet" || self.global.origin == self.community.origin {
            return Err(ComposeError::Config("service scopes".into()));
        }
        Ok(())
    }
}

/// The two Passkeys clients of one authenticator (global and community ceremony contexts).
pub struct DeviceKeys<A: cfyr::passkeys::Authenticator> {
    pub global: Client<A>,
    pub community: Client<A>,
}

/// Where the encrypted checkpoints live. Both backends are `Clone` handles to
/// one durable checkpoint each.
pub struct DeviceStorage<B> {
    pub global: B,
    pub community: B,
    /// Progress file; `None` keeps progress in memory (not resumable).
    pub progress: Option<PathBuf>,
}

impl DeviceStorage<cwst::native::FileBackend> {
    /// File vault under an existing private directory: `global/` and `community/`
    /// checkpoints and `composer.json` are created inside it.
    pub fn files(directory: &Path) -> Result<Self, ComposeError> {
        let global = directory.join("global");
        let community = directory.join("community");
        for path in [&global, &community] {
            std::fs::create_dir_all(path).map_err(|e| ComposeError::Config(e.to_string()))?;
        }
        Ok(Self {
            global: cwst::native::FileBackend::new(&global),
            community: cwst::native::FileBackend::new(&community),
            progress: Some(directory.join("composer.json")),
        })
    }
}

/// Opens a Foyer client for one service (fresh session each time).
#[allow(async_fn_in_trait)]
pub trait Services {
    async fn foyer(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError>;
    /// A client of the service that never carries a session or trust (the redemption of a
    /// creation token must not be linked to the member).
    async fn public(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError>;
    /// Called once with the logged-in wallet client right after its first device was
    /// authorized. The production composer does nothing here: the global uniqueness
    /// gate of a passport is the platform's decision. Only a test harness for a
    /// development build of the platform enables its development gate in this hook.
    async fn wallet_authorized(
        &mut self,
        _api: &mut Foyer<Transport>,
    ) -> Result<(), ComposeError> {
        Ok(())
    }
}

/// Why a composition stopped. Never contains secrets.
#[derive(Debug)]
pub enum ComposeError {
    Config(String),
    /// A step refused or failed; the device stays resumable unless the step says otherwise.
    Step(&'static str, String),
    /// The vault says a step happened that the progress file does not know, or the
    /// other way round. Needs an operator; nothing is retried automatically.
    Inconsistent(&'static str),
}
impl std::fmt::Display for ComposeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "device configuration: {e}"),
            Self::Step(step, e) => write!(f, "device composition at {step}: {e}"),
            Self::Inconsistent(step) => write!(f, "device composition inconsistent at {step}"),
        }
    }
}
impl std::error::Error for ComposeError {}

fn step<E: Debug>(name: &'static str) -> impl FnOnce(E) -> ComposeError {
    move |e| ComposeError::Step(name, format!("{e:?}"))
}

fn now() -> u64 {
    ckmg::Clock::now(&mut SystemClock).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    /// Nothing durable yet.
    #[default]
    Fresh,
    /// The registration tuple is in the vault; the server finish may not have happened.
    Retained,
    /// The server finish is done.
    Finished,
    /// The device is authorized on the server.
    Authorized,
    /// The vault holds the activated creation; the publication steps continue by its phase.
    Activated,
    /// Recovery published and retired.
    Done,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Progress {
    global: Stage,
    community: Stage,
}

struct ProgressFile {
    path: Option<PathBuf>,
    value: Progress,
}
impl ProgressFile {
    fn open(path: Option<PathBuf>) -> Result<Self, ComposeError> {
        let value = match &path {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => serde_json::from_slice(&bytes).map_err(step("progress"))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Progress::default(),
                Err(e) => return Err(step("progress")(e)),
            },
            None => Progress::default(),
        };
        Ok(Self { path, value })
    }
    fn stage(&self, wallet: bool) -> Stage {
        if wallet {
            self.value.global
        } else {
            self.value.community
        }
    }
    /// Durable before the next step starts: write, sync, rename.
    fn advance(&mut self, wallet: bool, stage: Stage) -> Result<(), ComposeError> {
        if wallet {
            self.value.global = stage;
        } else {
            self.value.community = stage;
        }
        let Some(path) = &self.path else {
            return Ok(());
        };
        let temporary = path.with_extension("tmp");
        let bytes = serde_json::to_vec(&self.value).map_err(step("progress"))?;
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        };
        write().map_err(step("progress"))
    }
}

/// The resume decision table: where a lineage continues, from its progress marker and
/// whether its vault checkpoint exists.
///
/// | marker            | vault empty | vault held           |
/// |-------------------|-------------|----------------------|
/// | Fresh             | Fresh       | Retained (lost marker)|
/// | Retained..Done    | refused     | the marker's stage   |
///
/// A marker that claims durable work over an empty vault is refused: creating again could
/// register a second identity.
fn resume_stage(marker: Stage, vault_held: bool) -> Result<Stage, ComposeError> {
    match (marker, vault_held) {
        (Stage::Fresh, false) => Ok(Stage::Fresh),
        (Stage::Fresh, true) => Ok(Stage::Retained),
        (_, false) => Err(ComposeError::Inconsistent("progress without a vault")),
        (marker, true) => Ok(marker),
    }
}

struct LineageVerifier;
impl cdht::Verifier for LineageVerifier {
    fn verify(&self, public: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
        ckmg::verify(
            &ckmg::PublicKey::new(ckmg::VLD0, *public),
            data,
            &ckmg::Signature::new(ckmg::VLD0, *signature),
        )
        .is_ok()
    }
}

fn bound(
    scope_name: &str,
    origin: &str,
    scope: Scope,
    api: Foyer<Transport>,
) -> Result<Door, ComposeError> {
    let mut door = Door::new(
        Configuration::new(
            scope_name.into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([origin.to_owned()]))]),
        )
        .map_err(step("door"))?,
    );
    door.bind_foyer(origin, Role::Member, Sessions::new(scope, api))
        .map_err(step("door"))?;
    Ok(door)
}

type Policy = cfyr::policy::CurrentPolicy<Transport>;
type Lease<'p> = cfyr::membership::InitialCreationLease<'p, Transport>;

async fn lease<'p>(
    door: &Door,
    origin: &str,
    wallet: bool,
    policy: &'p mut Policy,
) -> Result<Lease<'p>, ComposeError> {
    let mut membership = if wallet {
        door.live_wallet_membership(origin)
    } else {
        door.live_membership(origin)
    }
    .map_err(step("lease_open"))?;
    membership
        .observe_lease(now)
        .await
        .map_err(step("lease_observe"))?
        .passkey_certificate(policy, now)
        .await
        .map_err(step("lease_passkey"))?
        .initial_creation(now)
        .await
        .map_err(step("lease_creation"))
}

/// Fingerprint the community trust of this Foyer is anchored to, if it is.
fn anchored(api: &mut Foyer<Transport>) -> Option<identity::Fingerprint> {
    let trust = api.trust().ok()?;
    trust.fingerprint().copied().map(identity::Fingerprint)
}

/// Hold back an assertion whose user handle does not open with the anchored
/// community's fingerprint; it is dropped here and never sent.
fn guard(api: &mut Foyer<Transport>, credential: &Value) -> Result<(), ComposeError> {
    match anchored(api) {
        Some(fingerprint) => identity::guard_assertion(credential, &fingerprint)
            .map_err(|_| ComposeError::Inconsistent("a passkey of another community")),
        None => Ok(()),
    }
}

async fn login<A: cfyr::passkeys::Authenticator>(
    api: &mut Foyer<Transport>,
    keys: &mut Client<A>,
) -> Result<(), ComposeError> {
    let challenge = api.begin_browser_login().await.map_err(step("login"))?;
    let (credential, unlock) = keys
        .sign_in(challenge.options)
        .await
        .map_err(step("login"))?
        .into_parts();
    drop(unlock);
    guard(api, credential.as_json())?;
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .map(|_| ())
        .map_err(step("login"))
}

/// A fresh user-verifying assertion for exactly one action (`step_up`).
async fn authorize_device<A: cfyr::passkeys::Authenticator, S: Services>(
    services: &mut S,
    api: &mut Foyer<Transport>,
    keys: &mut Client<A>,
    wallet: bool,
    device: &ckmg::PublicKey,
) -> Result<(), ComposeError> {
    let begin = api
        .call(
            "step_up_begin",
            json!({"action": {"kind":"device_authorize","key":device.value()}}),
        )
        .await
        .map_err(step("device authorize"))?;
    let (credential, _) = keys
        .sign_in(begin["options"].clone())
        .await
        .map_err(step("device authorize"))?
        .into_parts();
    guard(api, credential.as_json())?;
    let body = json!({
        "key": device.value(),
        "step_up": {"ceremony": begin["ceremony"], "credential": credential.into_json()},
    });
    let action = if wallet {
        "wallet_device_authorize"
    } else {
        "device_authorize"
    };
    api.call(action, body)
        .await
        .map_err(step("device authorize"))?;
    if wallet {
        services.wallet_authorized(api).await?;
    }
    Ok(())
}

/// What a fresh registration needs beyond the vault.
enum Entry {
    Global {
        origin: String,
    },
    Community {
        passport: Value,
        member: String,
        community: String,
    },
}

/// One lineage driven to its recovered, retired state; the Door is logged in.
struct Driven {
    door: Door,
    policy: &'static mut Policy,
}

#[allow(clippy::too_many_arguments)]
async fn drive<A, B, N, S>(
    services: &mut S,
    mut api: Foyer<Transport>,
    wallet: bool,
    scope: &str,
    origin: &str,
    entry: Option<Entry>,
    keys: &mut Client<A>,
    backend: B,
    network: &N,
    progress: &mut ProgressFile,
) -> Result<Driven, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend + Clone,
    N: cdht::Network + Clone,
    S: Services,
{
    let mut clock = SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let vault_held = cwst::backend::Backend::read(&backend)
        .await
        .map_err(step("vault"))?
        .is_some();
    let mut stage = resume_stage(progress.stage(wallet), vault_held)?;

    // Registration (fresh) or reopening of the retained enrollment.
    let mut enrollment: Option<custody::InitialEnrollment<B>> = None;
    if stage == Stage::Fresh {
        let entry = entry.ok_or(ComposeError::Inconsistent("registration entry"))?;
        enrollment = Some(
            register(
                &mut api,
                entry,
                keys,
                backend.clone(),
                &mut clock,
                &mut entropy,
            )
            .await?,
        );
        progress.advance(wallet, Stage::Retained)?;
        stage = Stage::Retained;
    } else if stage < Stage::Activated {
        let challenge = api.begin_browser_login().await.map_err(step("reopen"))?;
        let authentication = keys
            .sign_in(challenge.options)
            .await
            .map_err(step("reopen"))?;
        match custody::reopen_initial_enrollment(authentication, scope, backend.clone()).await {
            Ok(opened) => enrollment = Some(opened),
            // Activation may have landed before its marker: the creation is then the owner.
            Err(_) if stage == Stage::Authorized => stage = Stage::Activated,
            Err(e) => return Err(step("reopen enrollment")(e)),
        }
    }
    if let (Some(retained), Stage::Retained) = (&enrollment, stage) {
        retained
            .resume_finish(&mut api, now)
            .await
            .map_err(step("finish"))?;
        progress.advance(wallet, Stage::Finished)?;
        stage = Stage::Finished;
    }
    if stage >= Stage::Finished {
        login(&mut api, keys).await?;
    }
    if let (Some(retained), Stage::Finished) = (&enrollment, stage) {
        authorize_device(services, &mut api, keys, wallet, &retained.device()).await?;
        progress.advance(wallet, Stage::Authorized)?;
        stage = Stage::Authorized;
    }

    // The sign-in that reopens an activated creation must be made before the Foyer moves
    // into the Door.
    let reopening = if stage == Stage::Activated {
        let challenge = api.begin_browser_login().await.map_err(step("reopen"))?;
        Some(
            keys.sign_in(challenge.options)
                .await
                .map_err(step("reopen"))?,
        )
    } else {
        None
    };

    let door = bound(
        scope,
        origin,
        if wallet {
            Scope::Global
        } else {
            Scope::Community
        },
        api,
    )?;
    let policy: &'static mut Policy = Box::leak(Box::new(
        if wallet {
            door.wallet_current_policy(origin)
        } else {
            door.current_policy(origin)
        }
        .map_err(step("policy"))?,
    ));
    if stage == Stage::Done {
        return Ok(Driven { door, policy });
    }

    let mut creation = if let Some(retained) = enrollment {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        let created = custody::activate_initial(retained, held, &mut clock, &mut entropy)
            .await
            .map_err(step("activate"))?;
        progress.advance(wallet, Stage::Activated)?;
        created
    } else if let Some(authentication) = reopening {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        custody::reopen_initial_publication(authentication, held, backend.clone(), &mut clock)
            .await
            .map_err(step("reopen publication"))?
            .0
    } else {
        return Err(ComposeError::Inconsistent("no owner for the lineage"));
    };

    let verifier = || cdht::NetworkBackend::new(network.clone(), LineageVerifier);
    let mut phase = creation.phase().map_err(step("phase"))?;
    if phase == cvlt::InitialPhase::Pending {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        let (prepared, held) =
            custody::prepare_initial_publication(creation, held, keys, &mut clock, &mut entropy)
                .await
                .map_err(step("prepare publication"))?;
        creation = custody::retain_initial_publication(prepared, held, &mut clock)
            .await
            .map_err(step("retain publication"))?;
        phase = cvlt::InitialPhase::Retained;
    } else if phase == cvlt::InitialPhase::Prepared {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        creation = custody::retain_initial_publication(creation, held, &mut clock)
            .await
            .map_err(step("retain publication"))?;
        phase = cvlt::InitialPhase::Retained;
    }
    let creation = match phase {
        cvlt::InitialPhase::Conflicted => {
            return Err(ComposeError::Inconsistent("conflicted creation"));
        }
        cvlt::InitialPhase::Retained | cvlt::InitialPhase::Staged => {
            let publication = if phase == cvlt::InitialPhase::Retained {
                creation.stage(verifier()).await.map_err(step("stage"))?
            } else {
                creation
                    .resume_publication(verifier())
                    .map_err(step("stage"))?
            };
            let (creation, _) = publication.flush().await.map_err(step("publish"))?;
            let read = creation
                .read_first_lineage(network.clone(), &mut clock)
                .await
                .map_err(step("read lineage"))?;
            let held = lease(&door, origin, wallet, &mut *policy).await?;
            custody::acknowledge_initial_publication(
                read,
                held,
                network.clone(),
                &mut clock,
                &mut entropy,
            )
            .await
            .map_err(step("acknowledge"))?
        }
        _ => creation,
    };
    let held = lease(&door, origin, wallet, &mut *policy).await?;
    drop(
        custody::complete_initial_recovery(
            creation,
            held,
            network.clone(),
            &mut clock,
            &mut entropy,
        )
        .await
        .map_err(step("recovery"))?,
    );
    progress.advance(wallet, Stage::Done)?;
    Ok(Driven { door, policy })
}

async fn register<A, B>(
    api: &mut Foyer<Transport>,
    entry: Entry,
    keys: &mut Client<A>,
    backend: B,
    clock: &mut SystemClock,
    entropy: &mut ckmg::SystemEntropy,
) -> Result<custody::InitialEnrollment<B>, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend,
{
    match entry {
        Entry::Global { origin } => {
            let mut reservation = api
                .begin_global_initial_registration(&origin, now)
                .await
                .map_err(step("register"))?;
            let user = reservation.account().to_owned();
            let seed = ckmg::EnrollmentSeed::new(
                ckmg::Binding::new("wallet", &user).map_err(step("register"))?,
                entropy,
            )
            .map_err(step("register"))?;
            let commitment = seed.commitment().map_err(step("register"))?;
            let pending = reservation
                .continue_initial(api, commitment, now)
                .await
                .map_err(step("register"))?;
            let registration = keys
                .register_member(pending.options().clone())
                .await
                .map_err(step("register"))?;
            custody::retain_global_initial_enrollment(
                api,
                pending,
                registration,
                seed,
                backend,
                "original-wallet",
                clock,
                entropy,
            )
            .await
            .map_err(step("retain"))
        }
        Entry::Community {
            passport,
            member,
            community,
        } => {
            let seed = ckmg::EnrollmentSeed::new(
                ckmg::Binding::new(&community, &member).map_err(step("register"))?,
                entropy,
            )
            .map_err(step("register"))?;
            let commitment = seed.commitment().map_err(step("register"))?;
            let pending = api
                .begin_initial_registration(passport, commitment, now)
                .await
                .map_err(step("register"))?;
            if let Some(fingerprint) = anchored(api) {
                identity::guard_creation(pending.options(), &fingerprint).map_err(|_| {
                    ComposeError::Inconsistent("registration user id of another community")
                })?;
            }
            let registration = keys
                .register_member(pending.options().clone())
                .await
                .map_err(step("register"))?;
            custody::retain_initial_enrollment(
                api,
                pending,
                registration,
                seed,
                backend,
                "same-holder-community",
                clock,
                entropy,
            )
            .await
            .map_err(step("retain"))
        }
    }
}

/// Sign in once, open the vault of `scope` and prepare its initial recovery candidate. The
/// returned device key is the PRF-derived coordinate of this vault.
async fn restore<A, N>(
    companion: &mut Foyer<Transport>,
    keys: &mut Client<A>,
    scope: &str,
    network: &N,
) -> Result<(ckmg::PublicKey, &'static cvlt::RecoveryCandidate), ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    N: cdht::Network + Clone,
{
    let challenge = companion
        .begin_browser_login()
        .await
        .map_err(step("restore"))?;
    let (credential, outcome) = keys
        .sign_in(challenge.options)
        .await
        .map_err(step("restore"))?
        .into_parts();
    let cfyr::passkeys::VaultOutcome::Ready(unlock) = outcome else {
        return Err(ComposeError::Inconsistent("the authenticator gave no PRF"));
    };
    let opening = cvlt::PreparedOpen::new(unlock, scope).map_err(step("restore"))?;
    guard(companion, credential.as_json())?;
    companion
        .finish_browser_login(challenge.ceremony, credential)
        .await
        .map_err(step("restore"))?;
    let device = opening.device().map_err(step("restore"))?;
    let locator = opening.locator();
    let mut records = opening
        .tor_records(network.clone())
        .await
        .map_err(step("restore"))?;
    let checkpoint = records
        .checkpoint(&locator)
        .await
        .map_err(step("restore"))?;
    drop(records);
    // The recovery owners live as long as the account actor: lend them for 'static.
    let recovered: &'static cvlt::RecoveryCandidate = Box::leak(Box::new(
        opening
            .prepare_initial_recovery(&checkpoint)
            .map_err(step("restore"))?,
    ));
    Ok((device, recovered))
}

impl ProverArtifacts {
    /// The real client prover over the retained extension group.
    pub fn prover(&self) -> Result<ckmg::wallet_engine::native_prover::NativeProver, ComposeError> {
        use ckmg::wallet_engine::native_prover::{NativeProver, NativeProverConfig};
        let read = |path: &Path, maximum: usize| -> Result<Vec<u8>, ComposeError> {
            let bytes = std::fs::read(path).map_err(step("prover artifacts"))?;
            if bytes.len() > maximum {
                return Err(ComposeError::Config("prover artifact too large".into()));
            }
            Ok(bytes)
        };
        let sha = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
        let circuit = read(&self.circuit_file, 64 << 20)?;
        let keys = read(&self.keys_file, 1 << 20)?;
        let g1 = read(&self.srs_g1_file, 128 << 20)?;
        let g2 = read(&self.srs_g2_file, 128)?;
        let executable = self.worker_executable.clone();
        if !executable.is_absolute() {
            return Err(ComposeError::Config(
                "the prover worker path must be absolute".into(),
            ));
        }
        let executable_digest = sha(&read(&executable, 512 << 20)?);
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
            srs_g2: g2
                .try_into()
                .map_err(|_| ComposeError::Config("srs g2 size".into()))?,
            timeout: Duration::from_secs(self.timeout_seconds),
            maximum_parallel: 1,
            threads: self.threads,
            memory_megabytes: self.memory_megabytes,
        })
        .map_err(step("prover"))
    }
}

/// HTTPS Foyer clients from the settings (direct HTTPS; the production default).
#[cfg(not(any(feature = "ohttp", target_arch = "wasm32")))]
pub struct NativeServices<'a>(pub &'a DeviceSettings);

#[cfg(not(any(feature = "ohttp", target_arch = "wasm32")))]
impl Services for NativeServices<'_> {
    async fn foyer(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        let settings = match service {
            Service::Global => &self.0.global,
            Service::Community => &self.0.community,
        };
        let mut roots = Vec::new();
        for file in &settings.tls_root_files {
            roots.push(std::fs::read(file).map_err(step("tls roots"))?);
        }
        let following = cfyr::trust::Config {
            retry_entropy: 27,
            refresh_seconds: 30,
            poll_seconds: 1,
            request_seconds: 30,
            initial_backoff_seconds: 1,
            maximum_backoff_seconds: 10,
            maximum_staleness_seconds: 900,
        };
        let mut trust = if let (Some(fingerprint), Service::Community) =
            (settings.fingerprint.as_deref(), service)
        {
            let fingerprint = identity::Fingerprint::from_hex(fingerprint)
                .ok_or_else(|| ComposeError::Config("fingerprint".into()))?;
            cfyr::trust::Trust::anchored_native(
                &cfyr::trust::Anchor {
                    origin: &settings.origin,
                    community: &settings.scope,
                    fingerprint: fingerprint.0,
                    minimum_revision: 1,
                    pin: settings.pin.map(Into::into),
                },
                following,
                &roots,
            )
        } else {
            let configuration = cfyr::trust::Configuration {
                origin: settings.origin.clone(),
                community: settings.scope.clone(),
                key_ring: serde_json::from_value(settings.trust_key_ring.clone())
                    .map_err(|e| ComposeError::Config(e.to_string()))?,
                minimum_revision: 1,
                ring_revision: 0,
            };
            if service == Service::Global {
                cfyr::trust::Trust::wallet_native(configuration, following, &roots)
            } else {
                cfyr::trust::Trust::native(configuration, following, &roots)
            }
        }
        .map_err(step("trust"))?;
        trust.start(now).await.map_err(step("trust"))?;
        let client = cfyr::HttpClient::with_roots(
            settings.origin.clone(),
            settings.connect_host.clone(),
            None,
            &roots,
        )
        .map_err(step("transport"))?;
        Ok(Foyer::with_trust(client, trust))
    }

    async fn public(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        let settings = match service {
            Service::Global => &self.0.global,
            Service::Community => &self.0.community,
        };
        let mut roots = Vec::new();
        for file in &settings.tls_root_files {
            roots.push(std::fs::read(file).map_err(step("tls roots"))?);
        }
        let client = cfyr::HttpClient::with_roots(
            settings.origin.clone(),
            settings.connect_host.clone(),
            None,
            &roots,
        )
        .map_err(step("transport"))?;
        Ok(Foyer::new(client))
    }
}

/// The registration markers and the deployment must belong to this device. A device that
/// never finished registration is refused: starting it must never register a second identity.
#[cfg(feature = "native-tor")]
fn check_open(
    settings: &DeviceSettings,
    deployment: &mut super::native::NativeDeployment,
    registered: bool,
) -> Result<(), ComposeError> {
    settings.validate()?;
    if !registered {
        return Err(ComposeError::Config(
            "the device is not registered: run compose_native_device first".into(),
        ));
    }
    let runtime = &deployment.runtime;
    if runtime.origin != settings.community.origin
        || runtime.community != settings.community_name
        || runtime.role != Role::Member
        || deployment.native_tor.is_none()
    {
        return Err(ComposeError::Config(
            "deployment does not match the device settings".into(),
        ));
    }
    // The forum travels with the device settings; a deployment that names another one
    // is refused rather than silently preferred.
    if let Some(forum) = &settings.forum {
        let forum: super::board::Configuration = serde_json::from_value(forum.clone())
            .map_err(|e| ComposeError::Config(format!("forum: {e}")))?;
        match &deployment.runtime.forum {
            None => deployment.runtime.forum = Some(forum),
            Some(held)
                if serde_json::to_value(held).ok() == serde_json::to_value(&forum).ok() => {}
            Some(_) => {
                return Err(ComposeError::Config(
                    "deployment forum differs from the device settings".into(),
                ))
            }
        }
    }
    Ok(())
}

#[cfg(feature = "native-tor")]
fn registered(progress: &Path) -> Result<bool, ComposeError> {
    let marker = ProgressFile::open(Some(progress.to_owned()))?;
    Ok(marker.stage(true) == Stage::Done && marker.stage(false) == Stage::Done)
}

/// Every start of an already registered native device. Registration happens once through
/// `compose_native_device`; afterwards each start calls this instead: it checks that both
/// registration markers are `Done`, that the deployment belongs to these settings, and then
/// starts the restoring composer (`scenario::restore::Composer`) through
/// `Embedded::start_composed`. Custody opens only after the login action: login, then the
/// login-recovery lease, then the Board, verified groups and the Mesh are bound.
///
/// This variant lends the Door nothing: use [`open_native_device_with`] for a device that
/// must create communities, join and prove.
#[cfg(feature = "native-tor")]
pub async fn open_native_device(
    settings: &DeviceSettings,
    progress: &Path,
    mut deployment: super::native::NativeDeployment,
    lifetime_seconds: u64,
    clock: std::sync::Arc<dyn super::native::Clock>,
) -> Result<super::native::Embedded, ComposeError> {
    check_open(settings, &mut deployment, registered(progress)?)?;
    super::native::Embedded::configured_restore(deployment, lifetime_seconds, clock)
        .await
        .map_err(step("open"))
}

/// Clients of the two HTTPS services that own their settings, so they can move into the
/// Door's thread.
#[cfg(all(feature = "native-tor", not(any(feature = "ohttp", target_arch = "wasm32"))))]
pub struct OwnedNativeServices(pub DeviceSettings);

#[cfg(all(feature = "native-tor", not(any(feature = "ohttp", target_arch = "wasm32"))))]
impl Services for OwnedNativeServices {
    async fn foyer(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        NativeServices(&self.0).foyer(service).await
    }
    async fn public(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        NativeServices(&self.0).public(service).await
    }
}

/// What the embedder lends a reopened device: the services, a source of the member's
/// authenticator per service (a fresh instance per ceremony; it must keep its credential
/// across process restarts), and an optional last step on the Door.
#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
pub struct OpenParts<S, F> {
    pub services: S,
    /// One authenticator per service; called for every ceremony.
    pub authenticators: F,
    /// Runs on the Door's thread after everything else is lent (for example
    /// `bind_waves`). It cannot replace what the composer lent.
    pub finish: Option<super::native::DeviceSetup>,
}

/// Open an already registered device and lend its Door everything a restart must restore
/// that custody does not: the embedded authenticator for the community login (so the login
/// action works without a human), the member's global session and the session-less global
/// channel (community creation), and the activation prover. Custody itself still opens at
/// the login action, exactly as in [`open_native_device`].
#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
pub async fn open_native_device_with<A, S, F>(
    settings: &DeviceSettings,
    progress: &Path,
    mut deployment: super::native::NativeDeployment,
    lifetime_seconds: u64,
    clock: std::sync::Arc<dyn super::native::Clock>,
    parts: OpenParts<S, F>,
) -> Result<super::native::Embedded, ComposeError>
where
    A: cfyr::passkeys::Authenticator + cpky::Authenticator + 'static,
    S: Services + Send + 'static,
    F: Fn(Service) -> A + Clone + Send + 'static,
{
    check_open(settings, &mut deployment, registered(progress)?)?;
    let settings = settings.clone();
    let OpenParts {
        mut services,
        authenticators,
        finish,
    } = parts;
    let setup: super::native::DeviceSetup = Box::new(move |door: &mut Door| {
        Box::pin(async move {
            let global_origin = settings.global.origin.as_str();
            let community_origin = settings.community.origin.as_str();
            let log = |e: ComposeError| {
                eprintln!("device setup: {e}");
                super::ErrorCode::Unavailable
            };
            // The member's global session: the wallet login, once per start.
            let context = cpky::Context::new(
                &settings.global.passkey_origin,
                &settings.global.rp_id,
            )
            .map_err(|_| super::ErrorCode::InvalidRequest)?;
            let mut keys = Client::new(context, authenticators(Service::Global));
            let mut api = services.foyer(Service::Global).await.map_err(log)?;
            login(&mut api, &mut keys).await.map_err(log)?;
            let mut wallet_door =
                bound("wallet", global_origin, Scope::Global, api).map_err(log)?;
            let session = wallet_door.take_global(global_origin)?;
            let public = services.public(Service::Global).await.map_err(log)?;
            door.lend_global(community_origin, session, public)?;
            door.set_activation_prover(std::sync::Arc::new(
                super::accounting::NativeActivationProver::new(settings.prover.clone()),
            ));
            // The community login (vault unlock) runs on the embedded authenticator.
            let login_configuration = super::login::Configuration {
                page: format!("{}/login", settings.community.passkey_origin),
                origin: settings.community.passkey_origin.clone(),
                relying_party: settings.community.rp_id.clone(),
            };
            login_configuration
                .context()
                .map_err(|_| super::ErrorCode::InvalidRequest)?;
            door.login_configuration
                .insert(community_origin.to_owned(), login_configuration);
            let make = authenticators.clone();
            door.bind_authenticator(community_origin, Role::Member, move || {
                make(Service::Community)
            })?;
            if let Some(finish) = finish {
                finish(door).await?;
            }
            Ok(())
        })
    });
    super::native::Embedded::configured_restore_with(deployment, lifetime_seconds, clock, setup)
        .await
        .map_err(step("open"))
}

/// From a device configuration to a bound, fully registered device: global registration,
/// wallet enrollment, passport issue, community enrollment at the accounting operator and
/// `bind_native_account`. Idempotent and resumable: a half-registered device continues where
/// the vault and the progress file stand and never registers twice. The returned Door has the
/// account actor bound at `settings.community.origin`.
///
/// A passport issue whose outcome is uncertain is refused (`ComposeError::Step`) and never
/// retried: that needs explicit recovery, as `issue_global_passport` documents.
pub async fn compose_native_device<A, B, N, S>(
    settings: &DeviceSettings,
    services: &mut S,
    keys: &mut DeviceKeys<A>,
    storage: DeviceStorage<B>,
    network: N,
) -> Result<Door, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend + Clone + 'static,
    N: cdht::Network + Clone + 'static,
    S: Services,
{
    settings.validate()?;
    let prover = settings.prover.prover()?;
    let mut progress = ProgressFile::open(storage.progress.clone())?;
    let global_origin = settings.global.origin.as_str();
    let community_origin = settings.community.origin.as_str();

    // 1-2. The wallet lineage.
    let api = services.foyer(Service::Global).await?;
    let Driven {
        door: mut wallet_door,
        policy,
    } = drive(
        services,
        api,
        true,
        "wallet",
        global_origin,
        Some(Entry::Global {
            origin: global_origin.to_owned(),
        }),
        &mut keys.global,
        storage.global.clone(),
        &network,
        &mut progress,
    )
    .await?;

    // 3. Restore the global holder and make sure it holds one real passport.
    let mut companion = services.foyer(Service::Global).await?;
    let (_, recovered) = restore(&mut companion, &mut keys.global, "wallet", &network).await?;
    let held = lease(&wallet_door, global_origin, true, policy).await?;
    let owners = custody::prepare_initial_recovery(recovered, held, network.clone())
        .await
        .map_err(step("global recovery"))?;
    let mut global = owners
        .open_global_passport(network.clone(), storage.global.clone())
        .await
        .map_err(step("global passport"))?;
    // A readable session is not a passport: ask the holder itself.
    let holds = matches!(
        global
            .with_global_passport(|holder| holder.attributes().is_some())
            .await,
        Ok(true)
    );
    if !holds {
        let issuance = companion
            .live_global_wallet(global_origin.into())
            .observe_lease(now)
            .await
            .map_err(step("passport"))?
            .passport_challenge(now)
            .await
            .map_err(step("passport"))?;
        super::passport::issue_global_passport(
            issuance,
            &mut global,
            &mut cwlt::passport::rand::rngs::OsRng,
        )
        .await
        .map_err(step("passport issue"))?;
    }

    // 4. Present it to the community and enroll the member there.
    let mut community_api = services.foyer(Service::Community).await?;
    let community_held = cwst::backend::Backend::read(&storage.community)
        .await
        .map_err(step("vault"))?
        .is_some();
    let fresh = resume_stage(progress.stage(false), community_held)? == Stage::Fresh;
    let entry = if fresh {
        let community = cwlt::passport::CommunityId::new(settings.community_name.as_bytes())
            .map_err(step("passport"))?;
        let pseudonym = global
            .with_global_passport(|holder| holder.pseudonym(&community).to_bytes())
            .await
            .map_err(step("passport"))?;
        let request = community_api
            .call("presentation_challenge", json!({}))
            .await
            .map_err(step("presentation"))?;
        let signed: Vec<u8> =
            serde_json::from_value(request["request"].clone()).map_err(step("presentation"))?;
        let mut community_policy = community_api.current_policy();
        let expected = community_policy
            .with_current(now(), |current| {
                cwlt::passport::AuthenticatedCommunity::from_authenticated_origin(
                    community.clone(),
                    current.key_ring().clone(),
                )
            })
            .map_err(step("presentation"))?;
        let proof = global
            .with_global_passport(|holder| {
                holder
                    .present(
                        &mut cwlt::passport::rand::rngs::OsRng,
                        &expected,
                        &signed,
                        now(),
                    )
                    .map(|proof| proof.to_bytes())
            })
            .await
            .map_err(step("presentation"))?
            .map_err(step("presentation"))?;
        Some(Entry::Community {
            passport: json!({"challenge": request["challenge"], "proof": proof}),
            member: data_encoding::HEXLOWER.encode(&pseudonym),
            community: settings.community_name.clone(),
        })
    } else {
        None
    };
    let Driven { mut door, policy } = drive(
        services,
        community_api,
        false,
        &settings.community_name,
        community_origin,
        entry,
        &mut keys.community,
        storage.community.clone(),
        &network,
        &mut progress,
    )
    .await?;

    // 5. Recover the community account with the accounting intents and bind the actor.
    let mut companion = services.foyer(Service::Community).await?;
    let (device, recovered) = restore(
        &mut companion,
        &mut keys.community,
        &settings.community_name,
        &network,
    )
    .await?;
    // The companion session outlives this call: the account actor admits through it while
    // the recovery lease keeps the Door's own session for the Vault.
    let companion: &'static Foyer<Transport> = Box::leak(Box::new(companion));
    let actor_membership = companion.live_membership();
    let actor_policy = companion.current_policy();
    let held = lease(&door, community_origin, false, policy).await?;
    let owners = custody::prepare_initial_recovery(recovered, held, network.clone())
        .await
        .map_err(step("community recovery"))?;
    super::account::bind_native_account(
        &mut door,
        community_origin,
        owners,
        actor_membership,
        actor_policy,
        network,
        storage.community,
        global,
        *device.value(),
        prover,
    )
    .await
    .map_err(step("bind account"))?;
    // Community creation needs the member's global session and a session-less
    // channel to the global service; both are lent to this Door for that use only.
    let global_session = wallet_door
        .take_global(global_origin)
        .map_err(step("global session"))?;
    let public = services.public(Service::Global).await?;
    door.lend_global(community_origin, global_session, public)
        .map_err(step("global session"))?;
    // A community this device creates needs a genesis proof of its accounting; it is
    // made in the background with the same retained prover artifacts.
    door.set_activation_prover(std::sync::Arc::new(
        super::accounting::NativeActivationProver::new(settings.prover.clone()),
    ));
    // The member signs in again (vault unlock) through the same Passkeys context the
    // community credential was registered in.
    let login = super::login::Configuration {
        page: format!("{}/login", settings.community.passkey_origin),
        origin: settings.community.passkey_origin.clone(),
        relying_party: settings.community.rp_id.clone(),
    };
    login.context().map_err(step("login configuration"))?;
    door.login_configuration
        .insert(community_origin.to_owned(), login);
    Ok(door)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Stage; 6] = [
        Stage::Fresh,
        Stage::Retained,
        Stage::Finished,
        Stage::Authorized,
        Stage::Activated,
        Stage::Done,
    ];

    #[test]
    fn resume_table_covers_every_marker_and_vault_state() {
        assert_eq!(resume_stage(Stage::Fresh, false).unwrap(), Stage::Fresh);
        assert_eq!(resume_stage(Stage::Fresh, true).unwrap(), Stage::Retained);
        for marker in &ALL[1..] {
            assert!(matches!(
                resume_stage(*marker, false),
                Err(ComposeError::Inconsistent(_))
            ));
            assert_eq!(resume_stage(*marker, true).unwrap(), *marker);
        }
    }

    #[test]
    fn stages_are_ordered_by_progress() {
        assert!(ALL.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn progress_survives_a_restart_and_only_moves_by_explicit_advance() {
        let directory =
            std::env::temp_dir().join(format!("composer-progress-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("composer.json");
        let mut file = ProgressFile::open(Some(path.clone())).unwrap();
        assert_eq!(file.stage(true), Stage::Fresh);
        assert_eq!(file.stage(false), Stage::Fresh);
        file.advance(true, Stage::Done).unwrap();
        file.advance(false, Stage::Authorized).unwrap();
        let reopened = ProgressFile::open(Some(path.clone())).unwrap();
        assert_eq!(reopened.stage(true), Stage::Done);
        assert_eq!(reopened.stage(false), Stage::Authorized);
        std::fs::write(&path, b"not json").unwrap();
        assert!(ProgressFile::open(Some(path)).is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(feature = "native-tor")]
    mod open {
        use super::*;
        use futures_util::FutureExt;
        use std::sync::Arc;

        struct Fixed;
        impl crate::door::native::Clock for Fixed {
            fn now(&self) -> u64 {
                1
            }
        }

        fn settings() -> DeviceSettings {
            let service = |scope: &str, origin: &str| {
                serde_json::json!({"origin":origin,"scope":scope,"passkey_origin":origin,
                    "rp_id":"example.test","trust_key_ring":null,"connect_host":"example.test"})
            };
            serde_json::from_value(serde_json::json!({
                "global": service("wallet", "https://wallet.example.test"),
                "community": service("omega", "https://omega.example.test"),
                "community_name": "omega",
                "prover": {"worker_executable":"/w","circuit_file":"/c","keys_file":"/k",
                    "srs_g1_file":"/1","srs_g2_file":"/2","timeout_seconds":1,"threads":1,
                    "memory_megabytes":1}
            }))
            .unwrap()
        }

        fn deployment(origin: &str) -> crate::door::native::NativeDeployment {
            serde_json::from_value(serde_json::json!({"runtime":{
                "community":"omega","origin":origin,"role":"member",
                "primary":"community","services":[]}}))
            .unwrap()
        }

        fn marks(name: &str, global: Stage, community: Stage) -> PathBuf {
            let directory =
                std::env::temp_dir().join(format!("composer-open-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&directory).unwrap();
            let path = directory.join("composer.json");
            let mut file = ProgressFile::open(Some(path.clone())).unwrap();
            file.advance(true, global).unwrap();
            file.advance(false, community).unwrap();
            path
        }

        fn open(path: &Path, origin: &str) -> Option<ComposeError> {
            open_native_device(&settings(), path, deployment(origin), 60, Arc::new(Fixed))
                .now_or_never()
                .expect("a refusal never waits")
                .err()
        }

        #[test]
        fn an_unregistered_device_is_refused_before_anything_starts() {
            let origin = "https://omega.example.test";
            let missing = std::env::temp_dir().join("composer-open-missing/none.json");
            for (name, global, community) in [
                ("global", Stage::Authorized, Stage::Done),
                ("community", Stage::Done, Stage::Fresh),
            ] {
                let path = marks(name, global, community);
                assert!(matches!(open(&path, origin), Some(ComposeError::Config(_))));
                let _ = std::fs::remove_dir_all(path.parent().unwrap());
            }
            assert!(matches!(
                open(&missing, origin),
                Some(ComposeError::Config(_))
            ));
        }

        #[test]
        fn a_deployment_for_another_origin_or_without_tor_is_refused() {
            let path = marks("done", Stage::Done, Stage::Done);
            // Registered, but the deployment names another origin ...
            assert!(matches!(
                open(&path, "https://other.example.test"),
                Some(ComposeError::Config(_))
            ));
            // ... or carries no native Tor section: nothing may start.
            assert!(matches!(
                open(&path, "https://omega.example.test"),
                Some(ComposeError::Config(_))
            ));
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
    }

    #[test]
    fn settings_refuse_the_wallet_scope_for_a_community() {
        let service = |scope: &str, origin: &str| ServiceSettings {
            origin: origin.into(),
            scope: scope.into(),
            passkey_origin: origin.into(),
            rp_id: "example.test".into(),
            trust_key_ring: Value::Null,
            fingerprint: None,
            pin: None,
            connect_host: "127.0.0.1".into(),
            tls_root_files: vec![],
        };
        let mut settings = DeviceSettings {
            global: service("wallet", "https://wallet.example.test"),
            community: service("omega", "https://omega.example.test"),
            community_name: "omega".into(),
            prover: ProverArtifacts {
                worker_executable: "/x".into(),
                circuit_file: "/x".into(),
                keys_file: "/x".into(),
                srs_g1_file: "/x".into(),
                srs_g2_file: "/x".into(),
                wave: None,
                timeout_seconds: 1,
                threads: 1,
                memory_megabytes: 1,
            },
            forum: None,
        };
        assert!(settings.validate().is_ok());
        settings.community_name = "wallet".into();
        assert!(settings.validate().is_err());
        settings.community_name = "omega".into();
        settings.community.origin = settings.global.origin.clone();
        assert!(settings.validate().is_err());
    }
}
