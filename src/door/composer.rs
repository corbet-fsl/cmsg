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
//! 4. community join by device key (one confirmation per device): the community vault
//!    derives from the wallet unlock, the device key joins with the passport and ONE wallet
//!    stamp covering the join and the lineage genesis, opens its sessions by signature, and
//!    the first lineage is published with that stamp as genesis evidence. No community
//!    passkey is created,
//! 5. `bind_native_account`: the account actor with its three single-use intents.
//!
//! Resumption never creates a second registration: the vault checkpoint and a small
//! progress file (`composer.json`, written atomically after each step) decide
//! where a half-registered device continues. A vault that holds a candidate whose
//! progress marker was lost is treated as retained, never as fresh. No request
//! reaches this module: it is called by the embedding process (CLI, E2E device).
use super::composer_core::*;
pub use super::composer_core::{
    BackendProgress, ComposeError, DeviceKeys, ProgressStore, Service, Services,
};
use super::identity;
use super::{
    foyer::{Scope, Transport},
    Door, Role,
};
use cfyr::{passkeys::Client, Foyer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

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
    /// Circuit and verification key of the record epoch (the member's per-epoch
    /// record proof for Forum entry), when the platform distributes them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<CircuitFiles>,
    /// Circuit and verification key of the settled-wave outcome, when the platform
    /// distributes them (the group's files again: the program selects the member).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<CircuitFiles>,
    /// The owned `czkp-bb-worker` that checks a counterpart's `wave` and `outcome`
    /// proofs (not the prover worker above). Absent: this device cannot verify waves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_executable: Option<PathBuf>,
    /// The group's manifest. It authenticates the circuit, keys and SRS files above
    /// and is itself pinned by the community's published wave policy
    /// (`WavePolicy.manifest_sha256`); a mismatch refuses every counterpart proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_file: Option<PathBuf>,
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
    /// Catalogue key of the record period in the community's signed Rulebook
    /// (trusted deployment configuration). With `prover.record` it starts the
    /// background record job; without them the device keeps no epoch record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_period_key: Option<String>,
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
        // A device-key member's vault and stamp scope derive from the community's verified
        // founding fingerprint: settings without it would fail only later, at the join.
        match self.community.fingerprint.as_deref() {
            Some(hex) if identity::Fingerprint::from_hex(hex).is_some() => {}
            Some(_) => return Err(ComposeError::Config("community fingerprint".into())),
            None => {
                return Err(ComposeError::Config(
                    "the community settings must carry its founding fingerprint".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Where the encrypted checkpoints live. Both backends are `Clone` handles to
/// one durable checkpoint each.
#[derive(Clone)]
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

impl ProverArtifacts {
    /// The real client prover over the retained extension group.
    pub fn prover(&self) -> Result<ckmg::wallet_engine::native_prover::NativeProver, ComposeError> {
        // This is the account update prover; wave, outcome and record provers come from
        // the same group.
        self.circuit_prover(
            ckmg::wallet_engine::native_prover::Program::Update,
            &self.circuit_file,
            &self.keys_file,
        )
    }

    /// The record-epoch prover, when the record circuit was distributed.
    pub fn record_prover(
        &self,
    ) -> Result<Option<ckmg::wallet_engine::native_prover::NativeProver>, ComposeError> {
        self.record
            .as_ref()
            .map(|files| {
                self.circuit_prover(
                    ckmg::wallet_engine::native_prover::Program::RecordEpoch,
                    &files.circuit_file,
                    &files.keys_file,
                )
            })
            .transpose()
    }

    /// The provers of the wave worker (account update, `wave`, `outcome`), when both
    /// wave circuits were distributed; `None` leaves the device without a wave worker.
    pub fn wave_provers(
        &self,
    ) -> Result<Option<super::inbox_waves::native::NativeWaveProver>, ComposeError> {
        use ckmg::wallet_engine::native_prover::Program;
        let (Some(wave), Some(outcome)) = (&self.wave, &self.outcome) else {
            return Ok(None);
        };
        super::inbox_waves::native::NativeWaveProver::new(
            self.prover()?,
            self.circuit_prover(Program::Wave, &wave.circuit_file, &wave.keys_file)?,
            self.circuit_prover(Program::Outcome, &outcome.circuit_file, &outcome.keys_file)?,
        )
        .map(Some)
        .map_err(step("wave provers"))
    }

    fn circuit_prover(
        &self,
        program: ckmg::wallet_engine::native_prover::Program,
        circuit_file: &Path,
        keys_file: &Path,
    ) -> Result<ckmg::wallet_engine::native_prover::NativeProver, ComposeError> {
        use ckmg::wallet_engine::native_prover::{NativeProver, NativeProverConfig};
        let read = |path: &Path, maximum: usize| -> Result<Vec<u8>, ComposeError> {
            let bytes = std::fs::read(path).map_err(step("prover artifacts"))?;
            if bytes.len() > maximum {
                return Err(ComposeError::Config("prover artifact too large".into()));
            }
            Ok(bytes)
        };
        let sha = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
        let circuit = read(circuit_file, 64 << 20)?;
        let keys = read(keys_file, 1 << 20)?;
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
            program,
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
            srs_g2: g2.try_into().map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ComposeError::Config srs g2 size into",
                    ComposeError::Config("srs g2 size".into()),
                    &__cause,
                )
            })?,
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
            Some(held) if serde_json::to_value(held).ok() == serde_json::to_value(&forum).ok() => {}
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
#[cfg(all(
    feature = "native-tor",
    not(any(feature = "ohttp", target_arch = "wasm32"))
))]
pub struct OwnedNativeServices(pub DeviceSettings);

#[cfg(all(
    feature = "native-tor",
    not(any(feature = "ohttp", target_arch = "wasm32"))
))]
impl Services for OwnedNativeServices {
    async fn foyer(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        NativeServices(&self.0).foyer(service).await
    }
    async fn public(&mut self, service: Service) -> Result<Foyer<Transport>, ComposeError> {
        NativeServices(&self.0).public(service).await
    }
}

/// What the embedder lends a reopened device: the services, a source of the member's wallet
/// authenticator (a fresh instance per ceremony; it must keep its credential across process
/// restarts), and an optional last step on the Door.
#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
pub struct OpenParts<S, F, B, R> {
    pub services: S,
    /// The wallet authenticator; called for every ceremony.
    pub authenticator: F,
    /// The registration's checkpoints (the same `DeviceStorage` it composed into).
    pub storage: DeviceStorage<B>,
    /// The registration's records network, made on the Door's thread.
    pub records: R,
    /// Runs on the Door's thread after everything else is lent (for example
    /// `bind_waves`). It cannot replace what the composer lent.
    pub finish: Option<super::native::DeviceSetup>,
}

/// Open an already registered device and bind its Door before the app starts (see
/// [`restore_device_login`], C8 A): the member's global session and the session-less global
/// channel (community creation), the activation prover, the community Vault and the account
/// actor, and the retained device-key login for the start's transport, so the login action
/// completes without any ceremony. Only the global authenticator is used: a device-key member
/// has no community passkey.
#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
pub async fn open_native_device_with<A, S, F, B, R, N>(
    settings: &DeviceSettings,
    mut deployment: super::native::NativeDeployment,
    lifetime_seconds: u64,
    clock: std::sync::Arc<dyn super::native::Clock>,
    parts: OpenParts<S, F, B, R>,
) -> Result<super::native::Embedded, ComposeError>
where
    A: cfyr::passkeys::Authenticator + cpky::Authenticator + 'static,
    S: Services + Send + 'static,
    F: Fn() -> A + Send + 'static,
    B: cwst::backend::Backend + Clone + Send + 'static,
    R: FnOnce() -> N + Send + 'static,
    N: cdht::Network + Clone + 'static,
{
    let progress = parts.storage.progress.clone().ok_or(ComposeError::Config(
        "a registered device keeps its progress file".into(),
    ))?;
    check_open(settings, &mut deployment, registered(&progress)?)?;
    let settings = settings.clone();
    let OpenParts {
        services,
        authenticator,
        storage,
        records,
        finish,
    } = parts;
    // The Door is built here, from the same services as a registration: its community Foyer has
    // the founding-fingerprint-anchored, started trust that `restore_device_login` reads (a Foyer
    // built from the deployment's key-ring trust configuration cannot be anchored). The builder
    // is repeatable from these sources: the start's Door is its first build, a device restart
    // (session renewal) builds a fresh one through the same unchanged path.
    let build: super::native::DoorBuilder = Box::new(move || {
        let sources = std::rc::Rc::new(DoorSources {
            settings,
            services: tokio::sync::Mutex::new(services),
            authenticator,
            storage,
            network: records(),
            finish,
        });
        std::rc::Rc::new(move || {
            let sources = sources.clone();
            Box::pin(async move { sources.build().await })
        })
    });
    super::native::Embedded::configured_restore_built(deployment, lifetime_seconds, clock, build)
        .await
        .map_err(step("open"))
}

/// What a registered device's Door is built from, on the Door's thread (see
/// [`open_native_device_with`]); every build uses the same sources.
#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
struct DoorSources<S, F, B, N> {
    settings: DeviceSettings,
    services: tokio::sync::Mutex<S>,
    authenticator: F,
    storage: DeviceStorage<B>,
    network: N,
    finish: Option<super::native::DeviceSetup>,
}

#[cfg(all(
    feature = "native-tor",
    feature = "native-prover",
    feature = "embedded-authenticator",
    not(target_arch = "wasm32")
))]
impl<A, S, F, B, N> DoorSources<S, F, B, N>
where
    A: cfyr::passkeys::Authenticator + cpky::Authenticator + 'static,
    S: Services,
    F: Fn() -> A,
    B: cwst::backend::Backend + Clone + 'static,
    N: cdht::Network + Clone + 'static,
{
    async fn build(&self) -> super::Result<Door> {
        let settings = &self.settings;
        let mut services = self.services.lock().await;
        let origin = settings.community.origin.clone();
        let community = services.foyer(Service::Community).await.map_err(|e| {
            eprintln!("device setup: {e}");
            super::ErrorCode::Unavailable
        })?;
        let mut door = Door::new(super::Configuration::new(
            settings.community_name.clone(),
            std::collections::BTreeMap::from([(
                Role::Member,
                std::collections::BTreeSet::from([origin.clone()]),
            )]),
        )?);
        door.bind_foyer(
            &origin,
            Role::Member,
            super::foyer::Sessions::new(Scope::Community, community),
        )?;
        let context = cpky::Context::new(&settings.global.passkey_origin, &settings.global.rp_id)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "super::ErrorCode::InvalidRequest",
                    super::ErrorCode::InvalidRequest,
                    &__cause,
                )
            })?;
        let mut keys = DeviceKeys::new(
            Client::new(context, (self.authenticator)()),
            &settings.global.passkey_origin,
        );
        restore_device_login(
            &mut door,
            settings,
            &mut *services,
            &mut keys,
            self.storage.clone(),
            self.network.clone(),
        )
        .await
        .map_err(|e| {
            eprintln!("device setup: {e}");
            super::ErrorCode::Unavailable
        })?;
        if let Some(finish) = &self.finish {
            finish(&mut door).await?;
        }
        Ok(door)
    }
}

/// The Door's verified community identity must be the founding fingerprint the device settings
/// carry; any other community (or settings without a valid fingerprint) is refused.
fn ensure_founding_identity(
    configured: Option<&str>,
    verified: [u8; 32],
) -> Result<(), ComposeError> {
    let configured = configured.and_then(identity::Fingerprint::from_hex);
    if configured.map(|configured| configured.0) != Some(verified) {
        return Err(ComposeError::Config(
            "the community's verified identity differs from the device settings".into(),
        ));
    }
    Ok(())
}

type GlobalSessions = std::collections::BTreeMap<(String, String), Foyer<Transport>>;

thread_local! {
    /// The member's global session S1 per device identity (global origin, member id), kept on
    /// the Door's thread. The first start keeps S1 for the device's life, as before; a restart
    /// of the same device (a session renewal) REPLACES it, so the replaced S1 is dropped (its
    /// family closes and is never used again) and a device retains at most one S1 however often
    /// it renews. The map itself is never dropped, so the last S1 lives as long as the process.
    static GLOBAL_SESSIONS: std::cell::RefCell<std::mem::ManuallyDrop<GlobalSessions>> =
        const { std::cell::RefCell::new(std::mem::ManuallyDrop::new(GlobalSessions::new())) };
}

/// Retain `session` as the device's S1; the device's previous S1, if any, is dropped here.
fn retain_global_session(origin: &str, member: &str, session: Foyer<Transport>) {
    let replaced = GLOBAL_SESSIONS.with(|sessions| {
        sessions
            .borrow_mut()
            .insert((origin.to_owned(), member.to_owned()), session)
    });
    drop(replaced);
}

/// How many global sessions this thread retains (one per started device identity). For the
/// tests that count retained sessions across renewals.
#[doc(hidden)]
pub fn retained_global_sessions() -> usize {
    GLOBAL_SESSIONS.with(|sessions| sessions.borrow().len())
}

/// Every start of a registered device-key member, on its freshly constructed Door (C8 A): ONE
/// wallet sign-in with PRF (the start's only confirmation) gives the member's global session
/// S1 and the device unlock; the wallet's stamp trust is read over S1 and S1 is forked into
/// S2 (`session_fork`, same family, no ceremony). S1 holds the global passport's recovery
/// lease; S2 is lent to the Door for community creation. The community opening derives from
/// the unlock with the community identity the Door's verified policy reports (it must equal
/// the configured founding fingerprint), and the composer's community step 5
/// (`bind_community`, shared with a registration) binds the Vault and the account actor to
/// this Door before the app starts. The Door retains the device login only for the start's
/// transport: the next `login.start` opens the Door's community session by the device key
/// without a ceremony, and the start restore takes the eager binding
/// (`Door::take_eager_binding`) instead of recovering the Vault again. Interrupted anywhere,
/// the next start simply repeats this.
#[allow(clippy::too_many_arguments)]
pub async fn restore_device_login<A, S, B, N>(
    door: &mut Door,
    settings: &DeviceSettings,
    services: &mut S,
    wallet: &mut DeviceKeys<A>,
    storage: DeviceStorage<B>,
    network: N,
) -> Result<(), ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    S: Services,
    B: cwst::backend::Backend + Clone + 'static,
    N: cdht::Network + Clone + 'static,
{
    settings.validate()?;
    let prover = settings.prover.prover()?;
    let global_origin = settings.global.origin.as_str();
    let community_origin = settings.community.origin.as_str();
    let user = ProgressFile::open(storage.progress.clone())?
        .value
        .community_user
        .ok_or(ComposeError::Inconsistent(
            "a device-key member without its member id",
        ))?;
    // The wallet: S1 by the one sign-in, its stamp trust, the sibling S2, the passport.
    // The start's budget is its one login (REGISTERED_CONFIRMATIONS); nothing further prompts.
    wallet.limit(REGISTERED_CONFIRMATIONS);
    let mut api = services.foyer(Service::Global).await?;
    let unlock = super::unlock_once::DeviceUnlock::from_unlock(
        sign_in_unlock(&mut api, wallet.confirm("login")?).await?,
    );
    let stamps = stamp_trust(&api, global_origin).await?;
    let sibling = wallet_sibling(services, &mut api).await?;
    let mut wallet_door = bound("wallet", global_origin, Scope::Global, api)?;
    // The lease owns the policy: it lives as long as the global passport and drops with it.
    let policy: Policy = wallet_door
        .wallet_current_policy(global_origin)
        .map_err(step("policy"))?;
    let (_, recovered) =
        recover(unlock.wallet_opening().map_err(step("restore"))?, &network).await?;
    let held = lease(&wallet_door, global_origin, true, policy).await?;
    let global = super::custody::prepare_initial_recovery(recovered, held, network.clone())
        .await
        .map_err(step("global recovery"))?
        .open_global_passport(network.clone(), storage.global.clone())
        .await
        .map_err(step("global passport"))?;
    // The recovery lease holds S1 for the device's life: one slot per device identity, so a
    // renewal replaces (and closes) the previous S1 instead of keeping it forever.
    retain_global_session(
        global_origin,
        &user,
        wallet_door
            .take_global(global_origin)
            .map_err(step("global session"))?,
    );
    let public = services.public(Service::Global).await?;
    door.lend_global(community_origin, sibling, public)
        .map_err(step("global session"))?;
    door.set_activation_prover(std::sync::Arc::new(
        super::accounting::NativeActivationProver::new(settings.prover.clone()),
    ));
    // G2 for the wave ports: marked by the record job, read by the ports.
    let record_current = super::record::RecordCurrent::default();
    if let (Some(key), Some(prover)) = (
        settings.record_period_key.clone(),
        settings.prover.record_prover()?,
    ) {
        door.set_record_job(
            community_origin,
            super::record::RecordJob {
                configuration: super::record::RecordConfiguration::new(key)
                    .map_err(step("record configuration"))?,
                prover,
                current: record_current.clone(),
            },
        );
    }
    // The restoring composer binds the wave ports and worker from this, once it holds
    // the member's network: nothing is installed unless the wave and outcome circuits
    // were distributed.
    door.set_wave_device(
        community_origin,
        super::inbox_waves::native::WaveDevice {
            artifacts: settings.prover.clone(),
            record: record_current.clone(),
        },
    );

    // The community: its verified identity, then step 5 and the account actor.
    let fingerprint = door
        .current_policy(community_origin)
        .map_err(step("community identity"))?
        .with_current(now(), |current| current.fingerprint().copied())
        .map_err(step("community identity"))?
        .ok_or_else(|| {
            ComposeError::Config(
                "the community trust must be anchored to its founding fingerprint".into(),
            )
        })?;
    ensure_founding_identity(settings.community.fingerprint.as_deref(), fingerprint)?;
    let opening = unlock
        .community_opening(&fingerprint, &settings.community_name)
        .map_err(step("community opening"))?;
    let device = opening.device().map_err(step("restore"))?;
    let mut companion = services.foyer(Service::Community).await?;
    super::device_join::open_session(
        &mut companion,
        &settings.community_name,
        &user,
        &device,
        &mut session_signer(&opening),
    )
    .await
    .map_err(step("device session"))?;
    let CommunityBound {
        owner,
        member,
        account,
        actor_membership,
        actor_policy,
        device,
    } = bind_community(
        services,
        door,
        Names {
            global_origin,
            community_origin,
            community_name: &settings.community_name,
        },
        &unlock,
        &fingerprint,
        &user,
        companion,
        &stamps,
        network.clone(),
        storage.community,
    )
    .await?;
    drop(unlock);
    super::account_open::bind_member_account_with(
        door,
        community_origin,
        &owner,
        account,
        actor_membership,
        actor_policy,
        global,
        *device.value(),
        std::sync::Arc::new(prover),
    )
    .await
    .map_err(step("bind account"))?;
    door.retain_eager_binding(
        community_origin,
        owner,
        super::custody::MemberBinder::new(member, network),
    )
    .map_err(step("eager binding"))?;
    door.retain_device_login(community_origin, user, opening, stamps)
        .map_err(step("device login"))?;
    // `login.poll` reports Idle for a configured origin before the first start.
    let login = super::login::Configuration {
        page: format!("{}/login", settings.community.passkey_origin),
        origin: settings.community.passkey_origin.clone(),
        relying_party: settings.community.rp_id.clone(),
    };
    login.context().map_err(step("login configuration"))?;
    door.login_configuration
        .insert(community_origin.to_owned(), login);
    Ok(())
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
    compose(settings, services, keys, storage, network, false).await
}

/// Restore on a NEW device (row 11): only the synced wallet passkey and the community's
/// settings (address and founding fingerprint) are here; the local vault and progress are
/// empty. ONE wallet sign-in gives `W`; the wallet vault and passport restore from the wallet's
/// own records; the community opening derives from `W` and the fingerprint, so the device key is
/// the member's; the creation's seed commitment comes from that community's own checkpoint; and
/// the community re-confirms the device-key join it already applied (no stamp, nothing changes)
/// to answer the member id. Then the community vault and account recover exactly as in
/// `compose_native_device`. Resumable: the progress file marks the device as restored, and
/// every later start is the unchanged `open_native_device_with`. A device that already holds a
/// registration is refused (it never restores over its own vault).
pub async fn restore_native_device<A, B, N, S>(
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
    compose(settings, services, keys, storage, network, true).await
}

async fn compose<A, B, N, S>(
    settings: &DeviceSettings,
    services: &mut S,
    keys: &mut DeviceKeys<A>,
    storage: DeviceStorage<B>,
    network: N,
    restore: bool,
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
    if restore && !progress.value.restored {
        let held = |backend: &B| {
            let backend = backend.clone();
            async move {
                cwst::backend::Backend::read(&backend)
                    .await
                    .map(|read| read.is_some())
                    .map_err(step("vault"))
            }
        };
        if held(&storage.global).await?
            || held(&storage.community).await?
            || progress.stage(true) != Stage::Fresh
            || progress.stage(false) != Stage::Fresh
        {
            return Err(ComposeError::Config(
                "restore is for a new device: this one already holds a registration".into(),
            ));
        }
        // The wallet lineage exists in its records: sign in, never register again.
        progress.value.restored = true;
        progress.advance(true, Stage::Done).await?;
    }
    let global_origin = settings.global.origin.as_str();
    let community_origin = settings.community.origin.as_str();

    // 1-7. Wallet, passport, community join by device key, first publication and the
    //      community vault (the portable core, shared with the browser).
    let Composed {
        mut door,
        mut wallet_door,
        global_companion,
        owner,
        account,
        actor_membership,
        actor_policy,
        global,
        device,
    } = compose_device(
        Names {
            global_origin,
            community_origin,
            community_name: &settings.community_name,
        },
        services,
        keys,
        storage.global,
        storage.community,
        &mut progress,
        Networks::shared(network),
    )
    .await?;
    // 8. The account actor with its three single-use intents (needs the native prover).
    super::account_open::bind_member_account_with(
        &mut door,
        community_origin,
        &owner,
        account,
        actor_membership,
        actor_policy,
        global,
        *device.value(),
        std::sync::Arc::new(prover),
    )
    .await
    .map_err(step("bind account"))?;
    // Community creation needs the member's global session and a session-less
    // channel to the global service; both are lent to this Door for that use only.
    // The wallet Door's own session is locked by the global passport's recovery
    // lease for the device's life (it must outlive this call), so creation gets the
    // wallet companion, its sibling of the same family (no further ceremony). The same
    // per-device slot as a registered start: a restart of this composition replaces (and
    // closes) the previous S1 instead of keeping it forever.
    let user = progress
        .value
        .community_user
        .clone()
        .ok_or(ComposeError::Inconsistent(
            "a device-key member without its member id",
        ))?;
    retain_global_session(
        global_origin,
        &user,
        wallet_door
            .take_global(global_origin)
            .map_err(step("global session"))?,
    );
    let public = services.public(Service::Global).await?;
    door.lend_global(community_origin, global_companion, public)
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
    use futures_util::FutureExt as _;

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
        file.advance(true, Stage::Done)
            .now_or_never()
            .unwrap()
            .unwrap();
        file.advance(false, Stage::Authorized)
            .now_or_never()
            .unwrap()
            .unwrap();
        let reopened = ProgressFile::open(Some(path.clone())).unwrap();
        assert_eq!(reopened.stage(true), Stage::Done);
        assert_eq!(reopened.stage(false), Stage::Authorized);
        std::fs::write(&path, b"not json").unwrap();
        assert!(ProgressFile::open(Some(path)).is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    /// The file and the backend progress stores (the browser's IndexedDB is a backend) give
    /// the same resume decision for every marker pair and vault state.
    #[test]
    fn file_and_backend_progress_resume_identically_for_every_stage() {
        use futures_executor::block_on;
        let directory =
            std::env::temp_dir().join(format!("composer-stores-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let resume = |stage: Stage, held: bool| resume_stage(stage, held).ok();
        for global in ALL {
            for community in ALL {
                let path = directory.join(format!("{global:?}-{community:?}.json"));
                let backend = cwst::backend::Memory::new();
                let mut file = ProgressFile::open(Some(path.clone())).unwrap();
                let mut stored =
                    block_on(ProgressFile::load(BackendProgress::new(backend.clone()))).unwrap();
                block_on(file.advance(true, global)).unwrap();
                block_on(file.advance(false, community)).unwrap();
                block_on(stored.advance(true, global)).unwrap();
                block_on(stored.advance(false, community)).unwrap();
                let file = ProgressFile::open(Some(path)).unwrap();
                let stored = block_on(ProgressFile::load(BackendProgress::new(backend))).unwrap();
                for wallet in [true, false] {
                    assert_eq!(file.stage(wallet), stored.stage(wallet));
                    for held in [false, true] {
                        assert_eq!(
                            resume(file.stage(wallet), held),
                            resume(stored.stage(wallet), held)
                        );
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    /// A backend marker is replaced only from the value this store read: a second writer of
    /// the same vault is refused instead of overwritten.
    #[test]
    fn a_second_backend_progress_writer_is_refused() {
        use futures_executor::block_on;
        let backend = cwst::backend::Memory::new();
        let mut first =
            block_on(ProgressFile::load(BackendProgress::new(backend.clone()))).unwrap();
        let mut second =
            block_on(ProgressFile::load(BackendProgress::new(backend.clone()))).unwrap();
        block_on(first.advance(true, Stage::Retained)).unwrap();
        assert!(block_on(second.advance(true, Stage::Finished)).is_err());
        block_on(first.advance(true, Stage::Finished)).unwrap();
        let reopened = block_on(ProgressFile::load(BackendProgress::new(backend))).unwrap();
        assert_eq!(reopened.stage(true), Stage::Finished);
    }

    /// One-ceremony registration (C1-C8): a registration, fresh or resumed at any marker, and
    /// every start of a registered device run exactly ONE wallet confirmation through
    /// `DeviceKeys::confirm`; every former further prompt (login after finish, device
    /// authorization, lineage evidence, wallet session, join stamp, a second reopen) is refused
    /// before the authenticator runs. An authenticator without PRF at create answers its
    /// follow-up assertion inside the same confirmation (J1: a second platform prompt).
    #[test]
    fn every_registration_marker_and_registered_start_counts_one_wallet_confirmation() {
        use cfyr::passkeys::software::{SoftwareAuthenticator, TestConfiguration};
        use futures_executor::block_on;
        use serde_json::json;
        const ORIGIN: &str = "https://wallet.example.test";
        const RP: &str = "wallet.example.test";
        const REFUSED: [&str; 7] = [
            "register",
            "login",
            "device authorize",
            "lineage evidence",
            "wallet session",
            "join stamp",
            "reopen",
        ];
        let b64 = |bytes: &[u8]| data_encoding::BASE64URL_NOPAD.encode(bytes);
        let keys = |evaluate_at_create: bool| {
            let platform = SoftwareAuthenticator::new(
                ORIGIN,
                TestConfiguration {
                    user_verified: true,
                    prf: true,
                    evaluate_at_create,
                },
            )
            .unwrap();
            DeviceKeys::new(
                Client::new(cfyr::passkeys::Context::new(ORIGIN, RP).unwrap(), platform),
                ORIGIN,
            )
        };
        let refuses_every_further_prompt = |keys: &mut DeviceKeys<SoftwareAuthenticator>,
                                            used: u32| {
            for purpose in REFUSED {
                assert!(
                    matches!(keys.confirm(purpose), Err(ComposeError::Step(p, _)) if p == purpose)
                );
            }
            assert_eq!(keys.ceremonies(), used);
        };
        block_on(async {
            // A fresh registration: the create ceremony, with or without PRF at create.
            for evaluate_at_create in [true, false] {
                let mut keys = keys(evaluate_at_create);
                let progress =
                    ProgressFile::load(BackendProgress::new(cwst::backend::Memory::new()))
                        .await
                        .unwrap();
                assert_eq!(confirmation_budget(&progress), REGISTRATION_CONFIRMATIONS);
                assert_eq!(REGISTRATION_CONFIRMATIONS, 1);
                keys.limit(confirmation_budget(&progress));
                let (_, _unlock) = keys
                    .confirm("register")
                    .unwrap()
                    .register_member(json!({"publicKey": {
                        "rp":{"id":RP,"name":"Wallet"},
                        "user":{"id":b64(&[17;16]),"name":"member","displayName":"Member"},
                        "challenge":b64(&[41;32]),
                        "pubKeyCredParams":[{"type":"public-key","alg":-7}],
                        "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,
                            "userVerification":"required","authenticatorAttachment":"platform"},
                        "timeout":42000,"excludeCredentials":[],"attestation":"none",
                        "extensions":{"credProps":true},"hints":["client-device"]
                    }}))
                    .await
                    .unwrap()
                    .into_parts();
                assert_eq!(keys.ceremonies(), 1);
                refuses_every_further_prompt(&mut keys, 1);
            }

            // A restart at every registration marker: ONE merged assertion (C7).
            for (global, community) in [
                (Stage::Retained, Stage::Fresh),
                (Stage::Finished, Stage::Fresh),
                (Stage::Authorized, Stage::Fresh),
                (Stage::Activated, Stage::Fresh),
                (Stage::Done, Stage::Fresh),
                (Stage::Done, Stage::Retained),
                (Stage::Done, Stage::Activated),
            ] {
                let mut progress =
                    ProgressFile::load(BackendProgress::new(cwst::backend::Memory::new()))
                        .await
                        .unwrap();
                for stage in &ALL[1..] {
                    if *stage <= global {
                        progress.advance(true, *stage).await.unwrap();
                    }
                    if *stage <= community {
                        progress.advance(false, *stage).await.unwrap();
                    }
                }
                assert_eq!(confirmation_budget(&progress), REGISTRATION_CONFIRMATIONS);
                let mut keys = keys(true);
                keys.limit(confirmation_budget(&progress));
                keys.confirm("reopen").unwrap();
                refuses_every_further_prompt(&mut keys, 1);
            }

            // A registered start: one login, its PRF is the unlock; nothing further.
            let mut progress =
                ProgressFile::load(BackendProgress::new(cwst::backend::Memory::new()))
                    .await
                    .unwrap();
            for stage in &ALL[1..] {
                progress.advance(true, *stage).await.unwrap();
                progress.advance(false, *stage).await.unwrap();
            }
            assert_eq!(confirmation_budget(&progress), REGISTERED_CONFIRMATIONS);
            assert_eq!(REGISTERED_CONFIRMATIONS, 1);
            let mut keys = keys(true);
            keys.limit(confirmation_budget(&progress));
            keys.confirm("login").unwrap();
            refuses_every_further_prompt(&mut keys, 1);
        });
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
            let mut community = service("omega", "https://omega.example.test");
            community["fingerprint"] = serde_json::json!(
                "abababababababababababababababababababababababababababababababab"
            );
            serde_json::from_value(serde_json::json!({
                "global": service("wallet", "https://wallet.example.test"),
                "community": community,
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
            file.advance(true, global).now_or_never().unwrap().unwrap();
            file.advance(false, community)
                .now_or_never()
                .unwrap()
                .unwrap();
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
                record: None,
                outcome: None,
                verifier_executable: None,
                manifest_file: None,
                timeout_seconds: 1,
                threads: 1,
                memory_megabytes: 1,
            },
            forum: None,
            record_period_key: None,
        };
        // Without its founding fingerprint (or with a malformed one) the community is refused.
        assert!(settings.validate().is_err());
        settings.community.fingerprint = Some("ab".into());
        assert!(settings.validate().is_err());
        settings.community.fingerprint =
            Some("abababababababababababababababababababababababababababababababab".into());
        assert!(settings.validate().is_ok());
        settings.community_name = "wallet".into();
        assert!(settings.validate().is_err());
        settings.community_name = "omega".into();
        settings.community.origin = settings.global.origin.clone();
        assert!(settings.validate().is_err());
    }

    #[test]
    fn open_path_refuses_a_community_with_another_founding_fingerprint() {
        let hex = "ab".repeat(32);
        assert!(ensure_founding_identity(Some(&hex), [0xab; 32]).is_ok());
        assert!(ensure_founding_identity(Some(&hex), [0xcd; 32]).is_err());
        assert!(ensure_founding_identity(Some("ab"), [0xab; 32]).is_err());
        assert!(ensure_founding_identity(None, [0xab; 32]).is_err());
    }
}
