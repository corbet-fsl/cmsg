//! Device-local member API. Every projection invokes this same bounded dispatcher.
//!
//! Client grants are local capabilities, never remote member/admin/root authority.
//! Pairing belongs to the trusted embedding runtime; it is not an API action.
//! Unavailable domain owners cannot be replaced by caller-provided success values.
pub mod account;
#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    all(feature = "browser-prover", target_arch = "wasm32")
))]
pub mod account_open;
pub mod accounting;
mod actor;
pub mod board;
pub mod browser;
pub(crate) mod cause;
mod communities;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod composer;
pub(crate) mod composer_core;
mod composition;
pub mod courier;
mod creating;
mod current;
#[cfg(feature = "client-version-fixture")]
pub use current::{set_client_version, with_client_version};
pub mod device_join;
pub mod device_pair;
mod device_session;
pub mod stamp;
pub use composition::VaultComposer;
pub mod custody;
pub mod facades;
pub mod foyer;
pub mod identity;
mod inbox;
pub mod inbox_conversation;
pub mod inbox_lineage;
pub mod inbox_waves;
pub(crate) mod interrupt;
mod json;
pub mod login;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
#[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
pub mod network_browser;
#[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
pub mod network_native;
#[cfg(feature = "ohttp")]
pub mod ohttp;
pub mod pairing;
mod pairing_flow;
#[cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]
pub mod pairing_guest;
pub mod pairing_host;
#[cfg(not(target_arch = "wasm32"))]
pub mod pairing_onion;
pub mod pairing_publish;
pub mod pairing_roles;
pub mod passport;
pub mod portal;
pub mod record;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod record_job;
mod registry;
pub(crate) mod rooms;
mod transient;
mod voucher_thread;
mod vouching;
#[cfg(not(target_arch = "wasm32"))]
pub mod wave_job;
pub use rooms::RoomLink;
#[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
pub mod scenario;
pub mod surface;
pub mod unlock_once;

use data_encoding::BASE64URL_NOPAD;
pub use registry::{catalog, ActionDescription, Authority, Effect, Family};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;
pub const MAX_CLIENTS: usize = 64;
pub const MAX_GRANT_SECONDS: u64 = 86_400;

/// Errors contain no identifiers, dependency internals, keys or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Unavailable,
    UnsupportedAction,
    UnsupportedVersion,
    Capacity,
    Clock,
    Reconcile,
    Refused,
    /// The server holds this member in the lobby: the gates now in force are
    /// not passed. Clients show the lobby.
    HeldInLobby,
    /// The genesis request's proof window elapsed before the operator could
    /// accept it, again after the one bounded re-preparation. Nothing was
    /// accepted; a later join starts a fresh request.
    ProofWindowElapsed,
    /// The operator accepted a genesis request that this device had discarded
    /// on the operator's own signed proof that it could no longer commit. The
    /// discard guard failed; the account is not usable from this device.
    DiscardedRequestAccepted,
    /// The original global session this operation ran under passed its exclusive
    /// deadline (or a fresh one could not be opened). Its authority is never
    /// extended or re-bound: the device needs a fresh global session (a passkey
    /// assertion), and the operation starts again under it. Clients prompt for it.
    SessionExpired,
    /// This Door was opened from a device delegation (community sessions and member
    /// purposes only, D1): the action needs the member's wallet passkey. Refused at the
    /// client before any request is made; the caller asks the member for the passkey.
    NeedsPasskey,
    /// The server no longer accepts this delegate's key (its registry row was revoked or
    /// the member left). The delegation is dead: drop it and ask for the passkey.
    DelegateRevoked,
}

impl ErrorCode {
    /// Stable process projection: 64 invalid request/version/action, 77 denied,
    /// 69 unavailable, 75 transient capacity/clock/reconciliation refusal.
    /// A failed action never receives the success exit code zero.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidRequest | Self::UnsupportedAction | Self::UnsupportedVersion => 64,
            Self::Unauthorized
            | Self::Refused
            | Self::HeldInLobby
            | Self::NeedsPasskey
            | Self::DelegateRevoked => 77,
            Self::Unavailable | Self::DiscardedRequestAccepted => 69,
            Self::Capacity
            | Self::Clock
            | Self::Reconcile
            | Self::ProofWindowElapsed
            | Self::SessionExpired => 75,
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorCode>;

/// The embedder's port to a FRESH global session (custody decision 2026-10-27).
/// `renew` opens a new global session through the normal passkey path (silent in
/// the toy) and binds a new account actor for `origin`, rebuilt from that session
/// and the server state. The old session is never extended and its in-flight
/// intents are never re-bound: the Door drops the old actor before calling this.
pub trait SessionRenewal {
    fn renew<'a>(
        &'a mut self,
        door: &'a mut Door,
        origin: &'a str,
    ) -> futures_util::future::LocalBoxFuture<'a, Result<()>>;
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Admin,
    Root,
}

/// One community runtime. Client input can never override its scope or origins.
pub struct Configuration {
    community: String,
    origins: BTreeMap<Role, BTreeSet<String>>,
    root_board: bool,
}

impl Configuration {
    /// Exact HTTPS origins, or explicit loopback HTTP origins for a native client.
    /// Admin and root must use origins separate from the member and each other.
    pub fn new(community: String, origins: BTreeMap<Role, BTreeSet<String>>) -> Result<Self> {
        if community.is_empty() || community.len() > 253 || origins.is_empty() {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut distinct = BTreeSet::new();
        for values in origins.values() {
            if values.is_empty() || values.len() > 8 {
                return Err(ErrorCode::InvalidRequest);
            }
            for value in values {
                validate_origin(value)?;
                if !distinct.insert(value) {
                    return Err(ErrorCode::InvalidRequest);
                }
            }
        }
        Ok(Self {
            community,
            origins,
            root_board: false,
        })
    }

    /// Explicit trusted root-board portal. This selects only a local command
    /// surface; the original service must still authorize its real session.
    pub fn root_board(origin: String) -> Result<Self> {
        let mut configuration = Self::new(
            "root".into(),
            BTreeMap::from([(Role::Root, BTreeSet::from([origin]))]),
        )?;
        configuration.root_board = true;
        Ok(configuration)
    }
}

fn validate_origin(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let local = parsed
        .host_str()
        .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "[::1]");
    if value.len() > 2048
        || parsed.origin().ascii_serialization() != value
        || !(parsed.scheme() == "https" || (parsed.scheme() == "http" && local))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// An opaque local API secret. No Debug, Serialize or Clone implementation.
pub struct ClientToken(Zeroizing<String>);

impl ClientToken {
    /// Receive an existing capability over a private inherited pipe/socket from
    /// the trusted pairing host. Import is encoding validation, not pairing or
    /// authorization: unknown tokens are still rejected by the Door. Never use
    /// command-line arguments, environment variables, logs or raw token files.
    pub fn from_protected_transport(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        if bytes.len() != 43 {
            return Err(ErrorCode::Unauthorized);
        }
        let _decoded = Zeroizing::new(BASE64URL_NOPAD.decode(&bytes).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?);
        // Strict 43-byte base64url is exactly 32 decoded bytes and guarantees
        // ASCII, so UTF-8 is infallible.
        let text = std::str::from_utf8(&bytes).expect("base64url is ASCII");
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    /// Hand to the paired client's protected transport; never log or persist raw.
    pub fn expose_for_transport(&self) -> &str {
        &self.0
    }
}

struct Grant {
    origin: String,
    actions: BTreeSet<String>,
    expires: u64,
}

/// The version/body envelope is identical across HTTP, MCP, CLI and Wasm.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub action: String,
    pub version: u16,
    pub body: Value,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Output {
    Ok { result: Value, events: Vec<Event> },
    Error { error: ErrorCode },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    ClientRevoked,
    VaultLocked,
    MeshDisconnected,
    BoardDisconnected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Unavailable,
    /// The network connection is established: Tor bootstrap and onion
    /// publication are done.
    Ready,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStatus {
    pub community: String,
    pub preload: Readiness,
    pub owners: BTreeMap<Family, Readiness>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub revoked: bool,
}

/// Local authorization and projection runtime. Domain facades are intentionally
/// unavailable until their real authority, checkpoint and generated ports bind.
pub struct Door {
    config: Configuration,
    grants: BTreeMap<[u8; 32], Grant>,
    clock_floor: u64,
    preload: Readiness,
    foyers: BTreeMap<String, foyer::Binding>,
    boards: BTreeMap<String, Box<dyn facades::BoundBoard>>,
    meshes: BTreeMap<String, facades::BoundMesh>,
    vaults: BTreeMap<String, Box<dyn facades::BoundVault>>,
    accounts: BTreeMap<String, account::AccountActor>,
    /// Lent by the trusted embedder: opens a FRESH global session and binds a new
    /// account actor rebuilt from it (see `registry::with_fresh_session`).
    session_renewal: Option<Box<dyn SessionRenewal>>,
    /// Lent by the trusted embedder: proves a new community's accounting genesis
    /// on this device (see `creating`). Absent in a frontend that cannot prove.
    activation_prover: Option<std::sync::Arc<dyn accounting::ActivationProver>>,
    wave_ports: BTreeMap<String, Box<dyn inbox_waves::WavePorts>>,
    /// The background record job per community origin (trusted embedding only).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    record_jobs: BTreeMap<String, account::Shared<record::RecordJob>>,
    /// The background wave proof worker per community origin (trusted embedding only).
    #[cfg(not(target_arch = "wasm32"))]
    wave_workers: BTreeMap<String, std::rc::Rc<dyn wave_job::WaveWorker>>,
    /// What the restoring composer binds into ports and a worker per community origin
    /// (trusted embedding only).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    wave_devices: BTreeMap<String, inbox_waves::native::WaveDevice>,
    login_configuration: BTreeMap<String, login::Configuration>,
    logins: BTreeMap<[u8; 32], login::session::State>,
    /// Device-key members' retained logins of this start, per origin (no community passkey).
    #[cfg(not(target_arch = "wasm32"))]
    device_logins: BTreeMap<String, login::session::DeviceLogin>,
    /// Community custody bound at app start (C8 A), taken once by the start restore.
    eager_bindings: BTreeMap<String, facades::EagerBinding>,
    /// Opened from a device delegation (D1): only community-session work is admitted.
    delegated: bool,
    #[cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]
    embedded_authenticators: BTreeMap<String, login::native::Embedded>,
    #[cfg(target_arch = "wasm32")]
    browser_gesture: Option<login::browser::Gesture>,
}

impl Door {
    pub fn new(config: Configuration) -> Self {
        Self {
            config,
            grants: BTreeMap::new(),
            clock_floor: 0,
            preload: Readiness::Unavailable,
            foyers: BTreeMap::new(),
            boards: BTreeMap::new(),
            meshes: BTreeMap::new(),
            vaults: BTreeMap::new(),
            accounts: BTreeMap::new(),
            session_renewal: None,
            activation_prover: None,
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            record_jobs: BTreeMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            wave_workers: BTreeMap::new(),
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            wave_devices: BTreeMap::new(),
            wave_ports: BTreeMap::new(),
            login_configuration: BTreeMap::new(),
            logins: BTreeMap::new(),
            #[cfg(not(target_arch = "wasm32"))]
            device_logins: BTreeMap::new(),
            eager_bindings: BTreeMap::new(),
            delegated: false,
            #[cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]
            embedded_authenticators: BTreeMap::new(),
            #[cfg(target_arch = "wasm32")]
            browser_gesture: None,
        }
    }

    /// Trusted embedding: mark this Door as opened from a `ckmg::DeviceDelegation`. It
    /// admits community-session work only (D1); there is no way back to a full Door.
    pub fn restrict_to_delegation(&mut self) {
        self.delegated = true;
    }

    /// Whether this Door is restricted to a delegation's authority.
    pub fn is_delegated(&self) -> bool {
        self.delegated
    }

    /// Trusted embedding control: run the background record job for `origin`
    /// while its courier runs (the record-period key and the record prover).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub fn set_record_job(&mut self, origin: &str, job: record::RecordJob) {
        self.record_jobs
            .insert(origin.to_owned(), account::Shared::new(job));
    }

    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub(crate) fn record_job(&self, origin: &str) -> Option<account::Shared<record::RecordJob>> {
        self.record_jobs.get(origin).cloned()
    }

    /// Trusted embedding control: run the background wave proof worker for `origin`
    /// while its courier runs. Set once per origin; the worker cannot be replaced.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_wave_worker(
        &mut self,
        origin: &str,
        worker: std::rc::Rc<dyn wave_job::WaveWorker>,
    ) -> Result<()> {
        if self.wave_workers.contains_key(origin) {
            return Err(ErrorCode::Unauthorized);
        }
        self.wave_workers.insert(origin.to_owned(), worker);
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn wave_worker(
        &self,
        origin: &str,
    ) -> Option<std::rc::Rc<dyn wave_job::WaveWorker>> {
        self.wave_workers.get(origin).cloned()
    }

    /// Whether the embedding already installed the wave ports or the wave worker of
    /// `origin` (both are set once and never replaced).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub(crate) fn waves_installed(&self, origin: &str) -> bool {
        self.wave_ports.contains_key(origin) || self.wave_workers.contains_key(origin)
    }

    /// Trusted embedding control: the wave stack of `origin` (the retained extension group
    /// and the record-currency mark) for the restoring composer to bind.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub fn set_wave_device(&mut self, origin: &str, device: inbox_waves::native::WaveDevice) {
        self.wave_devices.insert(origin.to_owned(), device);
    }

    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    pub(crate) fn wave_device(&self, origin: &str) -> Option<inbox_waves::native::WaveDevice> {
        self.wave_devices.get(origin).cloned()
    }

    /// Trusted embedding control: lend the prover for new communities' accounting.
    pub fn set_activation_prover(
        &mut self,
        prover: std::sync::Arc<dyn accounting::ActivationProver>,
    ) {
        self.activation_prover = Some(prover);
    }

    /// Trusted embedding control: the runtime reports the network connection
    /// established (Tor bootstrap and onion publication done). Absent from every
    /// callable projection; it is never cleared by a local client.
    pub fn set_preload_ready(&mut self) {
        self.preload = Readiness::Ready;
    }

    /// Trusted embedding control for a real network bind: only a completed bind
    /// (Tor bootstrap and onion publication done) releases preload; a failed or
    /// cancelled one leaves it untouched. The bind result is returned unchanged.
    pub fn network_bound(&mut self, bound: Result<()>) -> Result<()> {
        if bound.is_ok() {
            self.set_preload_ready();
        }
        bound
    }

    /// Install actual Foyer sessions for an already configured local portal.
    /// This trusted embedding control is absent from every callable projection.
    /// The scope/session set cannot be supplied or changed by a local client.
    pub fn bind_foyer(
        &mut self,
        origin: &str,
        role: Role,
        sessions: foyer::Sessions,
    ) -> Result<()> {
        if !self
            .config
            .origins
            .get(&role)
            .is_some_and(|set| set.contains(origin))
            || self.foyers.contains_key(origin)
            || (self.config.root_board
                && (role != Role::Root || sessions.primary != foyer::Scope::Community))
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.foyers.insert(
            origin.into(),
            foyer::Binding {
                role,
                root_board: self.config.root_board,
                sessions,
                uncertain: false,
            },
        );
        Ok(())
    }

    /// Install the account actor of an already configured member origin. This
    /// trusted embedding control is absent from every callable projection; the
    /// actor ends at `expires`, on Vault lock or when the Door is dropped.
    pub fn bind_account(&mut self, origin: &str, actor: account::AccountActor) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|set| set.contains(origin))
            || self.accounts.contains_key(origin)
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.accounts.insert(origin.into(), actor);
        Ok(())
    }

    /// Lend the session renewal of this device (trusted embedding only).
    pub fn set_session_renewal(&mut self, renewal: Box<dyn SessionRenewal>) {
        self.session_renewal = Some(renewal);
    }

    fn observe(&mut self, now: u64) -> Result<()> {
        if now < self.clock_floor {
            return Err(ErrorCode::Clock);
        }
        self.clock_floor = now;
        for key in self
            .grants
            .iter()
            .filter_map(|(key, grant)| (now >= grant.expires).then_some(*key))
            .collect::<Vec<_>>()
        {
            login::session::retire(self, &key);
        }
        self.grants.retain(|_, grant| now < grant.expires);
        Ok(())
    }

    /// Trusted embedding control only, after actual local client pairing. This
    /// function is deliberately absent from every generated callable projection.
    /// It grants local actions only; it cannot mint any remote service authority.
    pub fn pair_client(
        &mut self,
        origin: &str,
        role: Role,
        actions: BTreeSet<String>,
        now: u64,
        expires: u64,
    ) -> Result<ClientToken> {
        self.observe(now)?;
        if !self
            .config
            .origins
            .get(&role)
            .is_some_and(|set| set.contains(origin))
            || actions.is_empty()
            || actions.len() > catalog().len()
            || actions.iter().any(|name| !registry::known(name))
            || expires <= now
            || expires - now > MAX_GRANT_SECONDS
        {
            return Err(ErrorCode::Unauthorized);
        }
        if self.grants.len() >= MAX_CLIENTS {
            return Err(ErrorCode::Capacity);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })?;
        let token = ClientToken(Zeroizing::new(BASE64URL_NOPAD.encode(bytes.as_ref())));
        self.insert_client(token, origin, actions, expires)
    }

    // Separate the actual insertion boundary so duplicate entropy cannot replace
    // a live client grant. Pairing always obtains fresh OS/browser entropy first.
    fn insert_client(
        &mut self,
        token: ClientToken,
        origin: &str,
        actions: BTreeSet<String>,
        expires: u64,
    ) -> Result<ClientToken> {
        let key = token_hash(token.expose_for_transport());
        if self.grants.contains_key(&key) {
            return Err(ErrorCode::Unavailable);
        }
        self.grants.insert(
            key,
            Grant {
                origin: origin.into(),
                actions,
                expires,
            },
        );
        Ok(token)
    }

    /// Trusted embedding revocation (including termination of a paired client).
    pub fn revoke(&mut self, token: &ClientToken) {
        login::session::retire(self, &token_hash(token.expose_for_transport()));
        self.grants
            .remove(&token_hash(token.expose_for_transport()));
    }

    pub async fn dispatch(&mut self, origin: &str, token: &str, bytes: &[u8], now: u64) -> Output {
        // One action is one operation: authority reads are reused inside it only.
        let operation = custody::operation_scope::DISPATCH.begin();
        let result = self.invoke(origin, token, bytes, now).await;
        drop(operation);
        match result {
            Ok((result, events)) => Output::Ok { result, events },
            Err(error) => Output::Error { error },
        }
    }

    fn authenticate(&mut self, origin: &str, token: &str, now: u64) -> Result<[u8; 32]> {
        self.observe(now)?;
        if token.len() != 43 || origin.len() > 2048 {
            return Err(ErrorCode::Unauthorized);
        }
        let key = token_hash(token);
        let grant = self.grants.get(&key).ok_or(ErrorCode::Unauthorized)?;
        if grant.origin != origin {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(key)
    }

    async fn invoke(
        &mut self,
        origin: &str,
        token: &str,
        bytes: &[u8],
        now: u64,
    ) -> Result<(Value, Vec<Event>)> {
        let key = self.authenticate(origin, token, now)?;
        let grant = self
            .grants
            .get(&key)
            .expect("authentication established this unchanged grant");
        if bytes.len() > MAX_BODY_BYTES {
            return Err(ErrorCode::Capacity);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireInvocation {
            action: String,
            version: u16,
            body: Box<serde_json::value::RawValue>,
        }
        let request: WireInvocation = serde_json::from_slice(bytes).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let local = registry::action(&request.action);
        let remote = foyer::action(&request.action);
        let version = local
            .map(|action| action.version)
            .or_else(|| remote.map(|action| action.description.version))
            .ok_or(ErrorCode::UnsupportedAction)?;
        // A delegated Door (D1): after the protocol version, this is the FIRST decision,
        // before any grant, size-dependent or handler work. Every action outside the
        // explicit lists answers the typed state, so a delegated CLI can tell "needs the
        // passkey" from "not authorized". Nothing is sent to any server for it.
        if self.delegated && request.version == version && !delegate_admits(local, remote) {
            return Err(ErrorCode::NeedsPasskey);
        }
        if !grant.actions.contains(&request.action) {
            return Err(ErrorCode::Unauthorized);
        }
        if request.version != version {
            return Err(ErrorCode::UnsupportedVersion);
        }
        // All projections converge here after the same scope/origin/capability check.
        if let Some(action) = local {
            let result = (action.handler)(self, &key, request.body.get()).await?;
            check_result_size(&result.0)?;
            Ok(result)
        } else {
            let action = remote.expect("a registered operation was resolved");
            let body = json::unique_value(request.body.get())?;
            let foyer = self.foyers.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
            let result = foyer.call(action, body).await?;
            Ok((result, vec![]))
        }
    }

    /// What is actually bound. The Inbox facade is served from the bound Vault.
    fn readiness(&self, owner: Family) -> Readiness {
        let bound = match owner {
            Family::Vault | Family::Inbox => !self.vaults.is_empty(),
            Family::Mesh => !self.meshes.is_empty(),
            Family::Foyer => !self.foyers.is_empty(),
            Family::Board => !self.boards.is_empty(),
            _ => false,
        };
        if bound {
            Readiness::Ready
        } else {
            Readiness::Unavailable
        }
    }

    fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            community: self.config.community.clone(),
            preload: self.preload.clone(),
            owners: [
                Family::Vault,
                Family::Mesh,
                Family::Foyer,
                Family::Board,
                Family::Inbox,
            ]
            .into_iter()
            .map(|owner| (owner, self.readiness(owner)))
            .collect(),
        }
    }
}

/// What a Door opened from a `DeviceDelegation` may do (D1): the local status and
/// member-purpose actions of `DELEGATE_ACTIONS` and the community-scope read-only checks. Everything else
/// (wallet, account signing, stamps, genesis, voucher gates, new communities, waves
/// needing account proofs) is refused. Deny by default.
fn delegate_admits(local: Option<&registry::Action>, remote: Option<&foyer::Operation>) -> bool {
    match (local, remote) {
        (Some(action), _) => action.is_delegate_safe(),
        (None, Some(operation)) => operation.is_delegate_safe(),
        (None, None) => false,
    }
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn check_result_size(result: &Value) -> Result<()> {
    // Value already contains JSON types; serialization cannot reject its data.
    if serde_json::to_vec(result)
        .expect("Value is JSON-compatible")
        .len()
        > MAX_RESULT_BYTES
    {
        return Err(ErrorCode::Capacity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/support/door.rs"]
mod tests;
