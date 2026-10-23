//! The portable core of a device composition (native and browser): steps 1-7 of
//! `composer::compose_native_device` and the Door's community vault. The native composer adds
//! the account actor (it needs the native prover); the browser stops after the vault is bound.
//!
//! Nothing here reads a file of its own or a native prover: the services, the authenticator,
//! the vault backends, the progress store and the records network are lent by the embedder.
use super::identity;
use super::{
    custody::{self, SystemClock},
    foyer::{Scope, Sessions, Transport},
    Configuration, Door, Role,
};
use cfyr::{passkeys::Client, Foyer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
};

/// Which of the two services a call talks to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The wallet (global registration and passports).
    Global,
    /// The community (membership, accounting operator).
    Community,
}

/// The member's wallet Passkeys client: its one confirmation per start unlocks every vault.
/// A device-key member has no community passkey. A composition starts every wallet ceremony
/// through [`DeviceKeys::confirm`], which counts it and refuses, before any prompt, one that
/// would exceed the start's budget ([`confirmation_budget`]). Embedders run no ceremony of
/// their own on `global` while a composition holds it.
pub struct DeviceKeys<A: cfyr::passkeys::Authenticator> {
    pub global: Client<A>,
    /// The wallet passkey origin as the device signs it in its birth signatures (the ASCII
    /// serialization of `global`'s configured origin: scheme, host, port; no path).
    signed_origin: String,
    used: u32,
    budget: u32,
}

/// Wallet confirmations of a start of a registered device (both lineages `Done`): ONE wallet
/// sign-in; its PRF unlocks the wallet vault and derives every community vault, its session
/// holds the wallet passport, and the community sessions open by the device key.
pub const REGISTERED_CONFIRMATIONS: u32 = 1;

/// The most wallet ceremonies a registration (fresh or resumed at any marker) starts: ONE.
/// A fresh registration is the create ceremony alone: `register_finish` returns the birth
/// session (C1), the wallet device binds by the device key's own signature (C3), the wallet
/// lineage's genesis evidence is the wallet-signed birth statement (C4), the passport and the
/// join stamp are issued under the birth grant (Q5, C5), and the companion is a fork of the
/// birth session (C6). A restart at any marker is ONE assertion that both reopens the retained
/// enrollment and logs the session in (C7). An authenticator that gives no PRF at create
/// answers one follow-up assertion inside the same confirmation (cpky `register_member`; J1:
/// two platform prompts, one confirmation of this budget).
pub const REGISTRATION_CONFIRMATIONS: u32 = 1;

impl<A: cfyr::passkeys::Authenticator> DeviceKeys<A> {
    /// `passkey_origin` is the origin `global`'s passkey context was built with.
    pub fn new(global: Client<A>, passkey_origin: &str) -> Self {
        let signed_origin = url::Url::parse(passkey_origin)
            .map(|url| url.origin().ascii_serialization())
            .unwrap_or_else(|_| passkey_origin.to_owned());
        Self {
            global,
            signed_origin,
            used: 0,
            budget: u32::MAX,
        }
    }

    /// Wallet ceremonies started through this client so far.
    pub fn ceremonies(&self) -> u32 {
        self.used
    }

    /// Allow at most `more` further ceremonies.
    pub fn limit(&mut self, more: u32) {
        self.budget = self.used.saturating_add(more);
    }

    /// Count one wallet ceremony for `purpose` and lend the client for it; over the budget
    /// nothing is prompted and the composition stops.
    pub(crate) fn confirm(&mut self, purpose: &'static str) -> Result<&mut Client<A>, ComposeError> {
        if self.used >= self.budget {
            return Err(ComposeError::Step(
                purpose,
                "a further wallet confirmation exceeds this start's budget".into(),
            ));
        }
        self.used += 1;
        Ok(&mut self.global)
    }
}

/// The wallet-confirmation budget of a composition from its progress marker.
pub(crate) fn confirmation_budget<P: ProgressStore>(progress: &ProgressFile<P>) -> u32 {
    if progress.stage(true) == Stage::Done && progress.stage(false) == Stage::Done {
        REGISTERED_CONFIRMATIONS
    } else {
        REGISTRATION_CONFIRMATIONS
    }
}

/// Opens a Foyer client for one service (fresh session each time).
#[allow(async_fn_in_trait)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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

pub(crate) fn step<E: Debug>(name: &'static str) -> impl FnOnce(E) -> ComposeError {
    move |e| ComposeError::Step(name, format!("{e:?}"))
}

pub(crate) fn now() -> u64 {
    ckmg::Clock::now(&mut SystemClock).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
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
pub(crate) struct Progress {
    pub(crate) global: Stage,
    pub(crate) community: Stage,
    /// The member id `device_join` returned for this device key: a restarted device-key
    /// member opens its sessions under it (the server assigns it; nothing local derives it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) community_user: Option<String>,
    /// A restored device (`restore_native_device`): its lineages live in their records, not
    /// (yet) in the local vault, so a marker over an empty local vault is not refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) restored: bool,
}

/// Where the progress marker lives. It is written after every step, before the next one
/// starts, and read once when a composition (re)starts.
#[allow(async_fn_in_trait)]
pub trait ProgressStore {
    /// The stored marker, `None` when nothing was ever stored.
    async fn load(&mut self) -> Result<Option<Vec<u8>>, ComposeError>;
    /// Durably replace the marker before returning.
    async fn store(&mut self, bytes: &[u8]) -> Result<(), ComposeError>;
}

/// The progress file (write, sync, rename); `None` keeps progress in memory only (not
/// resumable).
impl ProgressStore for Option<std::path::PathBuf> {
    async fn load(&mut self) -> Result<Option<Vec<u8>>, ComposeError> {
        match self {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(step("progress")(e)),
            },
            None => Ok(None),
        }
    }
    async fn store(&mut self, bytes: &[u8]) -> Result<(), ComposeError> {
        let Some(path) = self else {
            return Ok(());
        };
        let temporary = path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &*path)
        };
        write().map_err(step("progress"))
    }
}

/// The progress marker in a vault backend of its own (the browser keeps it in IndexedDB next
/// to the vaults). Every store is a compare-and-exchange against the marker this store last
/// read or wrote, so a second writer is refused instead of overwritten.
pub struct BackendProgress<B> {
    backend: B,
    held: Option<Vec<u8>>,
}
impl<B: cwst::backend::Backend> BackendProgress<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            held: None,
        }
    }
}
impl<B: cwst::backend::Backend> ProgressStore for BackendProgress<B> {
    async fn load(&mut self) -> Result<Option<Vec<u8>>, ComposeError> {
        let held = self.backend.read().await.map_err(step("progress"))?;
        self.held.clone_from(&held);
        Ok(held)
    }
    async fn store(&mut self, bytes: &[u8]) -> Result<(), ComposeError> {
        self.backend
            .compare_exchange(self.held.as_deref(), bytes)
            .await
            .map_err(step("progress"))?;
        self.held = Some(bytes.to_vec());
        Ok(())
    }
}

pub(crate) struct ProgressFile<P = Option<std::path::PathBuf>> {
    store: P,
    pub(crate) value: Progress,
}
impl ProgressFile<Option<std::path::PathBuf>> {
    /// The progress file (or memory), read synchronously: the file store never waits.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn open(path: Option<std::path::PathBuf>) -> Result<Self, ComposeError> {
        use futures_util::FutureExt;
        Self::load(path)
            .now_or_never()
            .unwrap_or(Err(ComposeError::Inconsistent("progress")))
    }
}
impl<P: ProgressStore> ProgressFile<P> {
    pub(crate) async fn load(mut store: P) -> Result<Self, ComposeError> {
        let value = match store.load().await? {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(step("progress"))?,
            None => Progress::default(),
        };
        Ok(Self { store, value })
    }
    pub(crate) fn stage(&self, wallet: bool) -> Stage {
        if wallet {
            self.value.global
        } else {
            self.value.community
        }
    }
    /// Durable before the next step starts.
    pub(crate) async fn advance(&mut self, wallet: bool, stage: Stage) -> Result<(), ComposeError> {
        if wallet {
            self.value.global = stage;
        } else {
            self.value.community = stage;
        }
        let bytes = serde_json::to_vec(&self.value).map_err(step("progress"))?;
        self.store.store(&bytes).await?;
        super::interrupt::point(&format!(
            "{}-{}",
            if wallet { "global" } else { "community" },
            serde_json::to_value(stage)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        ));
        Ok(())
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
pub(crate) fn resume_stage(marker: Stage, vault_held: bool) -> Result<Stage, ComposeError> {
    match (marker, vault_held) {
        (Stage::Fresh, false) => Ok(Stage::Fresh),
        (Stage::Fresh, true) => Ok(Stage::Retained),
        (_, false) => Err(ComposeError::Inconsistent("progress without a vault")),
        (marker, true) => Ok(marker),
    }
}

pub(crate) struct LineageVerifier;
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

pub(crate) fn bound(
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

pub(crate) type Policy = cfyr::policy::CurrentPolicy<Transport>;
pub(crate) type Lease<'p> = cfyr::membership::InitialCreationLease<'p, Transport>;

pub(crate) async fn lease<'p>(
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
pub(crate) fn anchored(api: &mut Foyer<Transport>) -> Option<identity::Fingerprint> {
    let trust = api.trust().ok()?;
    trust.fingerprint().copied().map(identity::Fingerprint)
}

/// Hold back an assertion whose user handle does not open with the anchored
/// community's fingerprint; it is dropped here and never sent.
pub(crate) fn guard(api: &mut Foyer<Transport>, credential: &Value) -> Result<(), ComposeError> {
    match anchored(api) {
        Some(fingerprint) => identity::guard_assertion(credential, &fingerprint)
            .map_err(|_| ComposeError::Inconsistent("a passkey of another community")),
        None => Ok(()),
    }
}

/// One wallet login; returns its vault outcome (the PRF unlock of this ceremony), so the same
/// confirmation that opens the session also unlocks the vaults.
pub(crate) async fn login<A: cfyr::passkeys::Authenticator>(
    api: &mut Foyer<Transport>,
    keys: &mut Client<A>,
) -> Result<cfyr::passkeys::VaultOutcome, ComposeError> {
    let challenge = api.begin_browser_login().await.map_err(step("login"))?;
    let (credential, unlock) = keys
        .sign_in(challenge.options)
        .await
        .map_err(step("login"))?
        .into_parts();
    guard(api, credential.as_json())?;
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .map_err(step("login"))?;
    Ok(unlock)
}

/// The wallet companion: a sibling of the live wallet session `api` in the same family (cvld
/// `session_fork`, no ceremony). The passport's recovery lease holds the wallet Door's session
/// for the device's life, so the passport issue, the join stamp and the creation channel lent
/// to the community Door use this one. Both end together (logout, revocation, deadline).
pub(crate) async fn wallet_sibling<S: Services>(
    services: &mut S,
    api: &mut Foyer<Transport>,
) -> Result<Foyer<Transport>, ComposeError> {
    let mut sibling = services.foyer(Service::Global).await?;
    api.fork_into(&mut sibling)
        .await
        .map_err(step("wallet session"))?;
    Ok(sibling)
}

/// C3: bind the account's first wallet device `device` (K) by K's own signature over
/// (WalletBirthDevice, origin, account, credential, seed commitment, K), under the birth grant
/// of `api`'s session (the registration's birth session or the restart's login). The server
/// rebuilds the payload from its own records; `signed_origin` is the wallet passkey origin.
pub(crate) async fn birth_device(
    api: &mut Foyer<Transport>,
    origin: &str,
    signed_origin: &str,
    seed: [u8; 32],
    device: ckmg::PublicKey,
    unlock: &super::unlock_once::DeviceUnlock,
) -> Result<(), ComposeError> {
    let mut wallet = api
        .live_global_wallet(origin.into())
        .observe_lease(now)
        .await
        .map_err(step("device authorize"))?;
    let payload = ckmg::wallet_birth_device_payload(
        signed_origin,
        wallet.user().map_err(step("device authorize"))?,
        wallet.credential_id().map_err(step("device authorize"))?,
        &seed,
        device.value(),
    )
    .map_err(step("device authorize"))?;
    let signature = unlock
        .wallet_opening()
        .map_err(step("device authorize"))?
        .sign_device(ckmg::DevicePurpose::WalletBirthDevice, &payload)
        .map_err(step("device authorize"))?;
    wallet
        .authorize_birth_device(*device.value(), signature, now)
        .await
        .map_err(step("device authorize"))
}

/// What a fresh registration needs beyond the vault.
pub(crate) enum Entry {
    Global {
        origin: String,
    },
}

/// One lineage driven to its recovered, retired state; the Door is logged in.
pub(crate) struct Driven {
    door: Door,
    policy: &'static mut Policy,
    /// The PRF unlock of this start's one confirmation (the registration's create, the
    /// restart's assertion or the registered login): the composition's unlock for every vault
    /// and the signer of the birth signatures.
    unlock: Option<super::unlock_once::DeviceUnlock>,
    /// The wallet's stamp trust, read over this session before any lease holds it (a
    /// registered wallet only; a registration reads it over the companion).
    stamps: Option<cvlt::StampTrust>,
    /// The wallet companion (`wallet_sibling`), forked before the Door takes this session;
    /// `None` for a community lineage.
    companion: Option<Foyer<Transport>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive<A, B, N, S, P>(
    services: &mut S,
    mut api: Foyer<Transport>,
    wallet: bool,
    scope: &str,
    origin: &str,
    entry: Option<Entry>,
    keys: &mut DeviceKeys<A>,
    backend: B,
    network: &N,
    progress: &mut ProgressFile<P>,
) -> Result<Driven, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend + Clone,
    N: cdht::Network + Clone,
    S: Services,
    P: ProgressStore,
{
    let mut clock = SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let vault_held = cwst::backend::Backend::read(&backend)
        .await
        .map_err(step("vault"))?
        .is_some();
    let mut stage = resume_stage(progress.stage(wallet), vault_held || progress.value.restored)?;

    // Registration (fresh) or reopening of the retained enrollment. Every path below has ONE
    // wallet confirmation: the create, the restart's assertion, or the registered login.
    let mut enrollment: Option<custody::InitialEnrollment<B>> = None;
    let mut unlock: Option<super::unlock_once::DeviceUnlock> = None;
    // The restart's credential id, for reopening an activated creation.
    let mut credential: Option<Vec<u8>> = None;
    if stage == Stage::Fresh {
        let entry = entry.ok_or(ComposeError::Inconsistent("registration entry"))?;
        let (retained, opened) = register(
            &mut api,
            entry,
            keys.confirm("register")?,
            backend.clone(),
            &mut clock,
            &mut entropy,
        )
        .await?;
        enrollment = Some(retained);
        unlock = Some(opened);
        progress.advance(wallet, Stage::Retained).await?;
        stage = Stage::Retained;
    } else if stage < Stage::Done {
        // C7: one assertion reopens the retained enrollment (its PRF) and, from Finished on,
        // logs the session in (a wallet login: the birth grant's user verification).
        let challenge = api.begin_browser_login().await.map_err(step("reopen"))?;
        let (public, vault) = keys
            .confirm("reopen")?
            .sign_in(challenge.options)
            .await
            .map_err(step("reopen"))?
            .into_parts();
        let id = public.credential_id().map_err(step("reopen"))?;
        let cfyr::passkeys::VaultOutcome::Ready(secret) = vault else {
            return Err(ComposeError::Inconsistent("the authenticator gave no PRF"));
        };
        let opened = super::unlock_once::DeviceUnlock::from_unlock(secret);
        if stage >= Stage::Finished {
            guard(&mut api, public.as_json())?;
            api.finish_browser_login(challenge.ceremony, public)
                .await
                .map_err(step("login"))?;
        }
        if stage < Stage::Activated {
            let opening = opened.wallet_opening().map_err(step("reopen"))?;
            match custody::reopen_initial_enrollment_opened(&id, opening, scope, backend.clone())
                .await
            {
                Ok(reopened) => enrollment = Some(reopened),
                // Activation may have landed before its marker: the creation is then the owner.
                Err(_) if stage == Stage::Authorized => stage = Stage::Activated,
                Err(e) => return Err(step("reopen enrollment")(e)),
            }
        }
        credential = Some(id);
        unlock = Some(opened);
    }
    if let (Some(retained), Stage::Retained) = (&enrollment, stage) {
        // C1: the finish answers with the birth session; the Foyer adopts it (no login).
        retained
            .resume_finish(&mut api, now)
            .await
            .map_err(step("finish"))?;
        progress.advance(wallet, Stage::Finished).await?;
        stage = Stage::Finished;
    }
    if stage == Stage::Done {
        if let cfyr::passkeys::VaultOutcome::Ready(secret) =
            login(&mut api, keys.confirm("login")?).await?
        {
            unlock = Some(super::unlock_once::DeviceUnlock::from_unlock(secret));
        }
    }
    if let (Some(retained), Stage::Finished) = (&enrollment, stage) {
        // C3: the account's first wallet device binds by that device key's own signature
        // under the birth grant; no step-up.
        let opened = unlock
            .as_ref()
            .ok_or(ComposeError::Inconsistent("the authenticator gave no PRF"))?;
        birth_device(
            &mut api,
            origin,
            &keys.signed_origin,
            retained.seed().map_err(step("device authorize"))?,
            retained.device(),
            opened,
        )
        .await?;
        if wallet {
            services.wallet_authorized(&mut api).await?;
        }
        progress.advance(wallet, Stage::Authorized).await?;
        stage = Stage::Authorized;
    }

    let stamps = if wallet && stage == Stage::Done {
        Some(stamp_trust(&api, origin).await?)
    } else {
        None
    };
    // The companion is forked while this session is still free: once bound, the passport's
    // recovery lease holds it.
    let companion = if wallet {
        Some(wallet_sibling(services, &mut api).await?)
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
        return Ok(Driven {
            door,
            policy,
            unlock,
            stamps,
            companion,
        });
    }

    let mut creation = if let Some(retained) = enrollment {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        let created = custody::activate_initial(retained, held, &mut clock, &mut entropy)
            .await
            .map_err(step("activate"))?;
        progress.advance(wallet, Stage::Activated).await?;
        created
    } else if let (Some(id), Some(opened)) = (&credential, &unlock) {
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        custody::reopen_initial_publication_opened(
            id,
            custody::Opening::Opened(opened.wallet_opening().map_err(step("reopen"))?),
            held,
            backend.clone(),
            &mut clock,
        )
        .await
        .map_err(step("reopen publication"))?
        .0
    } else {
        return Err(ComposeError::Inconsistent("no owner for the lineage"));
    };

    let verifier = || cdht::NetworkBackend::new(network.clone(), LineageVerifier);
    let mut phase = creation.phase().map_err(step("phase"))?;
    if phase == cvlt::InitialPhase::Pending {
        // C4: the wallet's birth statement is the genesis evidence; no passkey prompt.
        let held = lease(&door, origin, wallet, &mut *policy).await?;
        let birth = companion
            .as_ref()
            .ok_or(ComposeError::Inconsistent("a wallet lineage without its companion"))?
            .live_global_wallet(origin.into())
            .observe_lease(now)
            .await
            .map_err(step("prepare publication"))?;
        let prepared =
            custody::prepare_birth_publication(creation, held, birth, &mut clock, &mut entropy)
                .await
                .map_err(step("prepare publication"))?;
        let held = lease(&door, origin, wallet, &mut *policy).await?;
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
    progress.advance(wallet, Stage::Done).await?;
    Ok(Driven {
        door,
        policy,
        unlock,
        stamps,
        companion,
    })
}

pub(crate) async fn register<A, B>(
    api: &mut Foyer<Transport>,
    entry: Entry,
    keys: &mut Client<A>,
    backend: B,
    clock: &mut SystemClock,
    entropy: &mut ckmg::SystemEntropy,
) -> Result<(custody::InitialEnrollment<B>, super::unlock_once::DeviceUnlock), ComposeError>
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
            let (credential, secret) = keys
                .register_member(pending.options().clone())
                .await
                .map_err(step("register"))?
                .into_parts();
            // The create ceremony's PRF is this start's unlock: it opens the wallet vault, derives
            // every community vault and signs the birth signatures. Never asked for again.
            let unlock = super::unlock_once::DeviceUnlock::from_unlock(secret);
            let retained = custody::retain_global_initial_enrollment_opened(
                api,
                pending,
                credential,
                unlock.wallet_opening().map_err(step("retain"))?,
                seed,
                backend,
                "original-wallet",
                clock,
                entropy,
            )
            .await
            .map_err(step("retain"))?;
            Ok((retained, unlock))
        }
    }
}

/// The community lineage of a device-key member, driven to Done.
pub(crate) struct DeviceDriven {
    door: Door,
    policy: &'static mut Policy,
    /// A second community session of the same device key, independent of the Door's own
    /// (which the recovery lease holds for the Vault): the account actor admits through it.
    companion: Foyer<Transport>,
    /// The wallet's stamp trust, read over the member's wallet session.
    stamps: cvlt::StampTrust,
    /// The member id this device key belongs to (from the join, or kept since it).
    user: String,
}

/// The device lease of a device-key member's initial creation (no passkey certificate).
pub(crate) async fn device_lease<'p>(
    door: &Door,
    origin: &str,
    policy: &'p mut Policy,
) -> Result<Lease<'p>, ComposeError> {
    door.live_membership(origin)
        .map_err(step("lease_open"))?
        .observe_lease(now)
        .await
        .map_err(step("lease_observe"))?
        .device_initial_creation(policy, now)
        .await
        .map_err(step("lease_creation"))
}

/// The wallet's stamp trust from its signed global status, over the member's wallet session.
pub(crate) async fn stamp_trust(
    wallet_api: &Foyer<Transport>,
    wallet_origin: &str,
) -> Result<cvlt::StampTrust, ComposeError> {
    wallet_api
        .live_global_wallet(wallet_origin.into())
        .observe_lease(now)
        .await
        .map_err(step("stamp trust"))?
        .stamp_trust(now)
        .await
        .map_err(step("stamp trust"))
}

/// One confirmation per device (DESIGN-one-confirmation-2026-10-14): the member's community
/// lineage without any community passkey. Its vault opens from the wallet unlock
/// (`opening`); the device key joins with the global passport and ONE wallet stamp covering
/// the join and the lineage genesis (`device_join`), opens its sessions by signature, and the
/// first lineage is published with that stamp as its genesis evidence.
///
/// Resumable at every step without a second confirmation (`open` derives the community
/// opening from the wallet unlock as often as needed). Before activation the retained
/// enrollment signs and the retained stamp covers; once the join is applied its member id is
/// kept and the join is never sent again. During the first publication (Activated, or Finished
/// whose activation landed before its marker) the opening signs the sessions and rebuilds the
/// genesis salt, the activated creation reopens from the vault and continues by its phase.
/// After recovery (Done) both sessions open again by the device key.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drive_device<A, B, N, S, P, WB, WC, WE, WA, WR>(
    services: &mut S,
    mut api: Foyer<Transport>,
    name: &str,
    origin: &str,
    member: Option<String>,
    open: &dyn Fn() -> Result<cvlt::PreparedOpen, ComposeError>,
    wallet_api: &Foyer<Transport>,
    stamps: &cvlt::StampTrust,
    wallet_origin: &str,
    wallet: &mut super::passport::GlobalPassport<WB, WC, WE, WA, WR>,
    wallet_keys: &mut DeviceKeys<A>,
    birth: bool,
    backend: B,
    network: &N,
    progress: &mut ProgressFile<P>,
) -> Result<DeviceDriven, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend + Clone,
    N: cdht::Network + Clone,
    S: Services,
    P: ProgressStore,
    WB: cwst::backend::Backend,
    WC: ckmg::Clock,
    WE: ckmg::Entropy,
    WA: ckmg::Authority,
    WR: cvlt::Records,
{
    let mut clock = SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let vault_held = cwst::backend::Backend::read(&backend)
        .await
        .map_err(step("vault"))?
        .is_some();
    let mut stage = resume_stage(progress.stage(false), vault_held || progress.value.restored)?;
    if stage == Stage::Done {
        return reopen_device(services, api, name, origin, open()?, stamps.clone(), progress).await;
    }

    // Before activation the retained enrollment owns the device key; a vault that no longer
    // reopens as an enrollment after the join means activation landed before its marker.
    let mut enrollment = None;
    if stage == Stage::Fresh {
        let member = member.ok_or(ComposeError::Inconsistent("registration entry"))?;
        let seed = ckmg::EnrollmentSeed::new(
            ckmg::Binding::new(name, &member).map_err(step("enroll"))?,
            &mut entropy,
        )
        .map_err(step("enroll"))?;
        enrollment = Some(
            custody::retain_device_enrollment(
                open()?,
                seed,
                backend.clone(),
                "device-key-community",
                &mut clock,
                &mut entropy,
            )
            .await
            .map_err(step("retain"))?,
        );
        progress.advance(false, Stage::Retained).await?;
        stage = Stage::Retained;
    } else if stage < Stage::Activated {
        match custody::reopen_device_enrollment(open()?, backend.clone()).await {
            Ok(opened) => enrollment = Some(opened),
            Err(_) if stage >= Stage::Finished => stage = Stage::Activated,
            Err(e) => return Err(step("reopen enrollment")(e)),
        }
    }
    let mut companion = services.foyer(Service::Community).await?;

    let (door, policy, mut creation, gsalt, user) = if let Some(enrollment) = enrollment {
        let device = enrollment.device();
        let mut sign = enrollment.device_signer();
        let gsalt = super::device_join::derived_salt(
            name,
            &device,
            super::device_join::GENESIS_SALT_LABEL,
            &mut sign,
        )
        .await
        .map_err(step("genesis salt"))?;
        let user = match (stage, progress.value.community_user.clone()) {
            // The join is applied and its member id kept: never joined (or confirmed) again.
            (Stage::Finished | Stage::Authorized, Some(user)) => user,
            _ => {
                let genesis = enrollment
                    .lineage_genesis_action(gsalt)
                    .map_err(step("genesis action"))?;
                let seed = enrollment.seed().map_err(step("join"))?;
                // The join's wallet confirmation: none under a registration's birth grant (C5),
                // else a wallet passkey assertion for the stamp.
                let assertion = |options: Value| async move {
                    if birth {
                        return Ok(None);
                    }
                    let (credential, _) = wallet_keys
                        .confirm("join stamp")
                        .map_err(|_| super::ErrorCode::Refused)?
                        .sign_in(options)
                        .await
                        .map_err(|_| super::ErrorCode::Refused)?
                        .into_parts();
                    Ok(Some(credential.as_json().clone()))
                };
                let user = super::device_join::join(
                    &mut api,
                    name,
                    wallet_api,
                    wallet_origin,
                    wallet,
                    &device,
                    seed,
                    &[genesis],
                    stage != Stage::Fresh,
                    &mut sign,
                    assertion,
                )
                .await
                .map_err(step("device join"))?;
                progress.value.community_user = Some(user.clone());
                progress.advance(false, Stage::Finished).await?;
                user
            }
        };
        // Both sessions open by the device key's signature before activation.
        for foyer in [&mut api, &mut companion] {
            super::device_join::open_session(foyer, name, &user, &device, &mut sign)
                .await
                .map_err(step("device session"))?;
        }
        drop(sign);
        let door = bound(name, origin, Scope::Community, api)?;
        let policy: &'static mut Policy = Box::leak(Box::new(
            door.current_policy(origin).map_err(step("policy"))?,
        ));
        let held = device_lease(&door, origin, &mut *policy).await?;
        let creation = custody::activate_initial(enrollment, held, &mut clock, &mut entropy)
            .await
            .map_err(step("activate"))?;
        progress.advance(false, Stage::Activated).await?;
        (door, policy, creation, gsalt, user)
    } else {
        // Restarted during the first publication: the community opening (from the wallet
        // unlock) signs the sessions and rebuilds the genesis salt bit-exact; the member id is
        // the one the join kept. No wallet prompt.
        let user = progress
            .value
            .community_user
            .clone()
            .ok_or(ComposeError::Inconsistent(
                "a device-key member without its member id",
            ))?;
        let opening = open()?;
        let device = opening.device().map_err(step("reopen"))?;
        let mut sign = |purpose: ckmg::DevicePurpose, payload: Vec<u8>| {
            std::future::ready(
                opening
                    .sign_device(purpose, &payload)
                    .map(|signature| signature.to_vec())
                    .map_err(|_| super::ErrorCode::Unauthorized),
            )
        };
        let gsalt = super::device_join::derived_salt(
            name,
            &device,
            super::device_join::GENESIS_SALT_LABEL,
            &mut sign,
        )
        .await
        .map_err(step("genesis salt"))?;
        for foyer in [&mut api, &mut companion] {
            super::device_join::open_session(foyer, name, &user, &device, &mut sign)
                .await
                .map_err(step("device session"))?;
        }
        let door = bound(name, origin, Scope::Community, api)?;
        let policy: &'static mut Policy = Box::leak(Box::new(
            door.current_policy(origin).map_err(step("policy"))?,
        ));
        let held = device_lease(&door, origin, &mut *policy).await?;
        let (creation, _) =
            custody::reopen_device_initial_publication(open()?, held, backend.clone(), &mut clock)
                .await
                .map_err(step("reopen publication"))?;
        (door, policy, creation, gsalt, user)
    };

    // The first publication continues by the creation's durable phase (as `drive`).
    let stamps = stamps.clone();
    let mut phase = creation.phase().map_err(step("phase"))?;
    if phase == cvlt::InitialPhase::Pending {
        let held = device_lease(&door, origin, &mut *policy).await?;
        let (prepared, held) = custody::prepare_device_initial_publication(
            creation,
            held,
            wallet,
            &stamps,
            gsalt,
            &mut clock,
            &mut entropy,
        )
        .await
        .map_err(step("prepare publication"))?;
        creation = custody::retain_device_initial_publication(prepared, held, &stamps, &mut clock)
            .await
            .map_err(step("retain publication"))?;
        phase = cvlt::InitialPhase::Retained;
        super::interrupt::point("publication-retained");
    } else if phase == cvlt::InitialPhase::Prepared {
        let held = device_lease(&door, origin, &mut *policy).await?;
        creation = custody::retain_device_initial_publication(creation, held, &stamps, &mut clock)
            .await
            .map_err(step("retain publication"))?;
        phase = cvlt::InitialPhase::Retained;
        super::interrupt::point("publication-retained");
    }
    let creation = match phase {
        cvlt::InitialPhase::Conflicted => {
            return Err(ComposeError::Inconsistent("conflicted creation"));
        }
        cvlt::InitialPhase::Retained | cvlt::InitialPhase::Staged => {
            let verifier = cdht::NetworkBackend::new(network.clone(), LineageVerifier);
            let publication = if phase == cvlt::InitialPhase::Retained {
                creation.stage(verifier).await.map_err(step("stage"))?
            } else {
                creation
                    .resume_publication(verifier)
                    .map_err(step("stage"))?
            };
            let (creation, _) = publication.flush().await.map_err(step("publish"))?;
            super::interrupt::point("publication-flushed");
            let read = creation
                .read_first_lineage(network.clone(), &mut clock)
                .await
                .map_err(step("read lineage"))?;
            let held = device_lease(&door, origin, &mut *policy).await?;
            let acknowledged = custody::acknowledge_device_initial_publication(
                read,
                held,
                network.clone(),
                &stamps,
                &mut clock,
                &mut entropy,
            )
            .await
            .map_err(step("acknowledge"))?;
            super::interrupt::point("publication-acknowledged");
            acknowledged
        }
        _ => creation,
    };
    let held = device_lease(&door, origin, &mut *policy).await?;
    drop(
        custody::complete_device_initial_recovery(
            creation,
            held,
            network.clone(),
            &stamps,
            &mut clock,
            &mut entropy,
        )
        .await
        .map_err(step("recovery"))?,
    );
    progress.advance(false, Stage::Done).await?;
    Ok(DeviceDriven {
        door,
        policy,
        companion,
        stamps,
        user,
    })
}

/// A device-key member restarted after recovery: both community sessions open again by the
/// device key's session signature from the community opening (its Keys open later, under a
/// lease that needs this session); the member id is the one its join returned.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn reopen_device<S: Services, P: ProgressStore>(
    services: &mut S,
    mut api: Foyer<Transport>,
    name: &str,
    origin: &str,
    opening: cvlt::PreparedOpen,
    stamps: cvlt::StampTrust,
    progress: &ProgressFile<P>,
) -> Result<DeviceDriven, ComposeError> {
    let user = progress
        .value
        .community_user
        .clone()
        .ok_or(ComposeError::Inconsistent(
            "a device-key member without its member id",
        ))?;
    let device = opening.device().map_err(step("restore"))?;
    let mut sign = session_signer(&opening);
    let mut companion = services.foyer(Service::Community).await?;
    for foyer in [&mut api, &mut companion] {
        super::device_join::open_session(foyer, name, &user, &device, &mut sign)
            .await
            .map_err(step("device session"))?;
    }
    drop(sign);
    drop(opening);
    let door = bound(name, origin, Scope::Community, api)?;
    let policy: &'static mut Policy = Box::leak(Box::new(
        door.current_policy(origin).map_err(step("policy"))?,
    ));
    Ok(DeviceDriven {
        door,
        policy,
        companion,
        stamps,
        user,
    })
}

/// The device key's session signer from a community opening, once its enrollment is
/// activated (before that the enrollment signs): the session purpose only.
pub(crate) fn session_signer(
    opening: &cvlt::PreparedOpen,
) -> impl FnMut(ckmg::DevicePurpose, Vec<u8>) -> std::future::Ready<super::Result<Vec<u8>>> + '_ {
    move |purpose, payload| {
        std::future::ready(match purpose {
            ckmg::DevicePurpose::DeviceSession => opening
                .sign_device_session(&payload)
                .map(|signature| signature.to_vec())
                .map_err(|_| super::ErrorCode::Unauthorized),
            _ => Err(super::ErrorCode::Unauthorized),
        })
    }
}

/// Sign in once on `companion` with the PRF extension and return the unlock secret of this
/// ceremony; the login finishes on `companion` (the native open path's one confirmation).
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) async fn sign_in_unlock<A>(
    companion: &mut Foyer<Transport>,
    keys: &mut Client<A>,
) -> Result<cfyr::passkeys::UnlockSecret, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
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
    guard(companion, credential.as_json())?;
    companion
        .finish_browser_login(challenge.ceremony, credential)
        .await
        .map_err(step("restore"))?;
    Ok(unlock)
}

/// Read the vault checkpoint of `opening` from the records and prepare its initial recovery
/// candidate. The returned device key is the opening's coordinate of this vault.
pub(crate) async fn recover<N>(
    opening: cvlt::PreparedOpen,
    network: &N,
) -> Result<(ckmg::PublicKey, &'static cvlt::RecoveryCandidate), ComposeError>
where
    N: cdht::Network + Clone,
{
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

/// The wallet passport of a composed device (restored from the wallet's initial recovery).
pub(crate) type WalletPassport<B, N> = super::passport::GlobalPassport<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    custody::InitialRecoveryAuthority<'static, 'static, SystemClock, N>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
>;

/// The community vault owner the Door holds once a composition is bound.
pub(crate) type MemberOwner<B, N> = super::facades::VaultBoardOwner<
    B,
    SystemClock,
    ckmg::SystemEntropy,
    custody::InitialRecoveryAuthority<'static, 'static, SystemClock, N>,
    cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
    cvlt::WalletCustody,
>;

/// A composed device with its community vault bound to the Door (steps 1-7). The native
/// composer binds the account actor from these parts; the browser keeps the Door.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
/// The records networks a registration publishes to and recovers from, one per scope: the
/// wallet lineage and global passport use `wallet`, the community lineage and vault
/// `community`. A browser registration lends one isolated circuit per scope
/// (`registration::network`), so the two lineages never share a circuit; a native embedder
/// lends one network to both (`Networks::shared`).
pub struct Networks<N> {
    pub wallet: N,
    pub community: N,
}

impl<N: Clone> Networks<N> {
    pub fn shared(network: N) -> Self {
        Self {
            wallet: network.clone(),
            community: network,
        }
    }
}

pub(crate) struct Composed<B: cwst::backend::Backend + 'static, N: cdht::Network + 'static> {
    pub(crate) door: Door,
    /// The wallet Door: the global passport's recovery lease holds its session.
    pub(crate) wallet_door: Door,
    /// The wallet companion, a sibling of the wallet Door's session (passport issue, join
    /// stamp, the creation channel lent to the community Door).
    pub(crate) global_companion: Foyer<Transport>,
    pub(crate) owner: MemberOwner<B, N>,
    pub(crate) account: custody::AccountWiring,
    /// The account actor's admission (a second session of the same device key).
    pub(crate) actor_membership: cfyr::membership::LiveMembership<Transport>,
    pub(crate) actor_policy: Policy,
    pub(crate) global: WalletPassport<B, N>,
    pub(crate) device: ckmg::PublicKey,
}

/// The community account a composition bound to its Door (step 5).
pub(crate) struct CommunityBound<B: cwst::backend::Backend + 'static, N: cdht::Network + 'static> {
    pub(crate) owner: MemberOwner<B, N>,
    pub(crate) account: custody::AccountWiring,
    /// The account actor's admission (a second session of the same device key).
    pub(crate) actor_membership: cfyr::membership::LiveMembership<Transport>,
    pub(crate) actor_policy: Policy,
    pub(crate) device: ckmg::PublicKey,
}

/// Step 5 of every device composition, shared by a registration (`compose_device`) and every
/// start of a registered device (`restore_device_login`, C8 A): recover the community vault
/// from the wallet unlock, hold its initial-creation lease on a third session of the device
/// key, open the member vault with the accounting intents and bind it to `door`. `companion`
/// is the community session (by the device key) the account actor admits through. No
/// ceremony: every session opens by the device key's session signature.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_community<S, B, N>(
    services: &mut S,
    door: &mut Door,
    names: Names<'_>,
    unlock: &super::unlock_once::DeviceUnlock,
    fingerprint: &[u8; 32],
    user: &str,
    companion: Foyer<Transport>,
    stamps: &cvlt::StampTrust,
    community_network: N,
    community_storage: B,
) -> Result<CommunityBound<B, N>, ComposeError>
where
    S: Services,
    B: cwst::backend::Backend + Clone + 'static,
    N: cdht::Network + Clone + 'static,
{
    let Names {
        community_origin,
        community_name,
        ..
    } = names;
    // The vault opens from the wallet unlock; its stamp genesis is reauthorized at every check.
    let (device, recovered) = recover(
        unlock
            .community_opening(fingerprint, community_name)
            .map_err(step("community opening"))?,
        &community_network,
    )
    .await?;
    // The recovery lease holds its session for the device's life: it gets a third session of
    // the same device key, so the Door's own session stays free for owner actions (creation
    // claim, vouching), as the wallet Door lends its companion for creation.
    let mut vault_session = services.foyer(Service::Community).await?;
    {
        let opening = unlock
            .community_opening(fingerprint, community_name)
            .map_err(step("community opening"))?;
        super::device_join::open_session(
            &mut vault_session,
            community_name,
            user,
            &device,
            &mut session_signer(&opening),
        )
        .await
        .map_err(step("device session"))?;
    }
    // The companion session outlives this call: the account actor admits through it.
    let companion: &'static Foyer<Transport> = Box::leak(Box::new(companion));
    let actor_membership = companion.live_membership();
    let actor_policy = companion.current_policy();
    let vault_session: &'static Foyer<Transport> = Box::leak(Box::new(vault_session));
    let vault_policy: &'static mut Policy = Box::leak(Box::new(vault_session.current_policy()));
    let held = vault_session
        .live_membership()
        .observe_lease(now)
        .await
        .map_err(step("lease_observe"))?
        .device_initial_creation(vault_policy, now)
        .await
        .map_err(step("lease_creation"))?;
    let owners =
        custody::prepare_device_initial_recovery(recovered, held, community_network.clone(), stamps)
            .await
            .map_err(step("community recovery"))?;
    // One owner per Store: the Door holds the community Vault (voucher custody,
    // community creation, ...) and the account actor works through its port.
    let custody::ComposedMemberVault {
        vault,
        intent,
        account,
        lifetime,
    } = owners
        .open_member_vault(community_network, community_storage)
        .await
        .map_err(step("community vault"))?;
    let owner = door
        .bind_vault_with_board_owner(community_origin, vault, intent, lifetime)
        .await
        .map_err(step("bind vault"))?;
    Ok(CommunityBound {
        owner,
        account,
        actor_membership,
        actor_policy,
        device,
    })
}

/// The names a composition needs: the two service origins and the community name.
#[derive(Clone, Copy)]
pub(crate) struct Names<'a> {
    pub(crate) global_origin: &'a str,
    pub(crate) community_origin: &'a str,
    pub(crate) community_name: &'a str,
}

/// Steps 1-7 of a device composition and the Door's community vault: wallet registration and
/// enrollment, global passport, community join by device key, first lineage publication and
/// the community's initial recovery. Idempotent and resumable through `progress` and the two
/// vault checkpoints; never registers twice. A passport issue whose outcome is uncertain is
/// refused and never retried (`issue_global_passport`).
pub(crate) async fn compose_device<A, B, N, S, P>(
    names: Names<'_>,
    services: &mut S,
    keys: &mut DeviceKeys<A>,
    global_storage: B,
    community_storage: B,
    progress: &mut ProgressFile<P>,
    networks: Networks<N>,
) -> Result<Composed<B, N>, ComposeError>
where
    A: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend + Clone + 'static,
    N: cdht::Network + Clone + 'static,
    S: Services,
    P: ProgressStore,
{
    let Names {
        global_origin,
        community_origin,
        community_name,
    } = names;
    // Each scope has its own records network (the browser lends one isolated circuit per
    // scope; native lends one network to both).
    let Networks {
        wallet: network,
        community: community_network,
    } = networks;

    // A registered device's start has ONE wallet confirmation; a registration at most
    // REGISTRATION_CONFIRMATIONS. Nothing over the budget is ever prompted.
    keys.limit(confirmation_budget(progress));
    // A registration (any marker short of a registered start) issues its passport and join
    // stamp under the birth grant of its one confirmation (Q5, C5), without an assertion.
    let birth = confirmation_budget(progress) == REGISTRATION_CONFIRMATIONS;

    // 1-2. The wallet lineage.
    let api = services.foyer(Service::Global).await?;
    let Driven {
        door: wallet_door,
        policy,
        unlock,
        stamps,
        companion,
    } = drive(
        services,
        api,
        true,
        "wallet",
        global_origin,
        Some(Entry::Global {
            origin: global_origin.to_owned(),
        }),
        keys,
        global_storage.clone(),
        &network,
        progress,
    )
    .await?;

    // 3. Restore the global holder and make sure it holds one real passport.
    // The wallet login's PRF unlock opens the wallet vault and derives every community vault
    // (unlock once): no community passkey and no second unlock ceremony exist.
    let unlock = unlock.ok_or(ComposeError::Inconsistent("the authenticator gave no PRF"))?;
    let (_, recovered) = recover(
        unlock.wallet_opening().map_err(step("restore"))?,
        &network,
    )
    .await?;
    let held = lease(&wallet_door, global_origin, true, policy).await?;
    let owners = custody::prepare_initial_recovery(recovered, held, network.clone())
        .await
        .map_err(step("global recovery"))?;
    let mut global = owners
        .open_global_passport(network.clone(), global_storage.clone())
        .await
        .map_err(step("global passport"))?;
    // A readable session is not a passport: ask the holder itself.
    let holds = matches!(
        global
            .with_global_passport(|holder| holder.attributes().is_some())
            .await,
        Ok(true)
    );
    // The wallet companion, forked from the login before the lease held it: the passport issue,
    // the join stamp and a stamp trust not yet read use it, without a ceremony of their own.
    let mut global_companion =
        companion.ok_or(ComposeError::Inconsistent("a wallet lineage without its companion"))?;
    let stamps = match stamps {
        Some(stamps) => stamps,
        None => stamp_trust(&global_companion, global_origin).await?,
    };
    if !holds {
        let issuance = global_companion
            .live_global_wallet(global_origin.into())
            .observe_lease(now)
            .await
            .map_err(step("passport"))?
            .passport_challenge(now)
            .await
            .map_err(step("passport"))?;
        let signer = if birth {
            Some(unlock.wallet_opening().map_err(step("passport issue"))?)
        } else {
            None
        };
        super::passport::issue_global_passport_with(
            issuance,
            &mut global,
            signer.as_ref(),
            &mut cwlt::passport::rand::rngs::OsRng,
        )
        .await
        .map_err(step("passport issue"))?;
    }

    // 4. Join the community by device key: the passport, ONE wallet stamp for the join and
    //    the lineage genesis, sessions by the device key's signature. No community passkey.
    let mut community_api = services.foyer(Service::Community).await?;
    let community_held = cwst::backend::Backend::read(&community_storage)
        .await
        .map_err(step("vault"))?
        .is_some();
    let fresh = resume_stage(progress.stage(false), community_held || progress.value.restored)?
        == Stage::Fresh;
    // The community's identity (its founding fingerprint, as the verified Charter reports
    // it) derives its vault from the wallet unlock; never its reusable address.
    let fingerprint = community_api
        .current_policy()
        .with_current(now(), |current| current.fingerprint().copied())
        .map_err(step("community identity"))?
        .ok_or_else(|| {
            ComposeError::Config(
                "the community trust must be anchored to its founding fingerprint".into(),
            )
        })?;
    let open = || {
        unlock
            .community_opening(&fingerprint, community_name)
            .map_err(step("community opening"))
    };
    // The wallet membership index (a record only the wallet secret locates) lists this
    // community BEFORE its first join, so a restore on a new device can find it. A restored
    // device reads it instead: the community must be listed with the same founding identity.
    if progress.value.restored && progress.value.community_user.is_none() {
        let listed = unlock
            .indexed_memberships(network.clone())
            .await
            .map_err(step("membership index"))?
            .ok_or(ComposeError::Step(
                "membership index",
                "the wallet's membership record is unavailable".into(),
            ))?;
        let entry = cvlt::MembershipEntry::new(community_name, fingerprint)
            .map_err(step("membership index"))?;
        if !listed.contains(&entry) {
            return Err(ComposeError::Config(
                "the wallet's membership index does not list this community".into(),
            ));
        }
    } else if fresh && !progress.value.restored {
        match unlock
            .index_membership(network.clone(), community_name, &fingerprint)
            .await
            .map_err(step("membership index"))?
        {
            cvlt::Outcome::Confirmed => {}
            cvlt::Outcome::Queued => {
                return Err(ComposeError::Step(
                    "membership index",
                    "not replicated yet; resume to continue".into(),
                ));
            }
        }
    }
    // A restored device learns its member id from the community: the join it applied for this
    // passport, device key and the creation's seed commitment (from the community's own
    // checkpoint) is re-confirmed without a stamp. Then the member reopens like any other.
    if progress.value.restored && progress.value.community_user.is_none() {
        // The PRF-authenticated original initial ACK: its seed commitment, and the only
        // signer of the stamp-less join re-confirmation (the opening never signs a join).
        let candidate = {
            let opening = open()?;
            let locator = opening.locator();
            let mut records = opening
                .tor_records(community_network.clone())
                .await
                .map_err(step("restore"))?;
            let checkpoint = records
                .checkpoint(&locator)
                .await
                .map_err(step("restore"))?;
            drop(records);
            opening
                .prepare_initial_recovery(&checkpoint)
                .map_err(step("restore"))?
        };
        let seed = candidate.initial_seed().map_err(step("restore"))?;
        let opening = open()?;
        let device = opening.device().map_err(step("restore"))?;
        let mut sign = |purpose: ckmg::DevicePurpose, payload: Vec<u8>| {
            let signature = match purpose {
                ckmg::DevicePurpose::DeviceJoin => candidate.sign_device_join(&payload),
                _ => opening.sign_device(purpose, &payload),
            };
            std::future::ready(
                signature
                    .map(|signature| signature.to_vec())
                    .map_err(|_| super::ErrorCode::Unauthorized),
            )
        };
        let user = super::device_join::reconfirm(
            &mut community_api,
            community_name,
            &mut global,
            &device,
            seed,
            &mut sign,
        )
        .await
        .map_err(step("restore member"))?;
        progress.value.community_user = Some(user);
        progress.advance(false, Stage::Done).await?;
    }
    let member = if fresh {
        let community = cwlt::passport::CommunityId::new(community_name.as_bytes())
            .map_err(step("passport"))?;
        let pseudonym = global
            .with_global_passport(|holder| holder.pseudonym(&community).to_bytes())
            .await
            .map_err(step("passport"))?;
        Some(data_encoding::HEXLOWER.encode(&pseudonym))
    } else {
        None
    };
    let DeviceDriven {
        door,
        policy: _,
        companion,
        stamps,
        user,
    } = drive_device(
        services,
        community_api,
        community_name,
        community_origin,
        member,
        &open,
        &global_companion,
        &stamps,
        global_origin,
        &mut global,
        keys,
        birth,
        community_storage.clone(),
        &community_network,
        progress,
    )
    .await?;
    let mut door = door;

    // 5. Recover the community account with the accounting intents (shared with the open
    //    path's restore_device_login, C8 A).
    let CommunityBound {
        owner,
        account,
        actor_membership,
        actor_policy,
        device,
    } = bind_community(
        services,
        &mut door,
        names,
        &unlock,
        &fingerprint,
        &user,
        companion,
        &stamps,
        community_network,
        community_storage,
    )
    .await?;
    drop(unlock);
    Ok(Composed {
        door,
        wallet_door,
        global_companion,
        owner,
        account,
        actor_membership,
        actor_policy,
        global,
        device,
    })
}
