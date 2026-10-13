//! Device-local member API. Every projection invokes this same bounded dispatcher.
//!
//! Client grants are local capabilities, never remote member/admin/root authority.
//! Pairing belongs to the trusted embedding runtime; it is not an API action.
//! Unavailable domain owners cannot be replaced by caller-provided success values.
pub mod account;
pub mod accounting;
mod actor;
pub mod board;
pub mod browser;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod composer;
mod composition;
mod creating;
mod current;
pub use composition::VaultComposer;
pub mod custody;
pub mod facades;
pub mod foyer;
pub mod identity;
mod inbox;
pub mod inbox_conversation;
pub mod inbox_lineage;
pub mod inbox_waves;
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
pub mod pairing_roles;
mod pairing_flow;
pub mod pairing_publish;
pub mod passport;
pub mod record;
mod registry;
pub(crate) mod rooms;
mod vouching;
pub use rooms::RoomLink;
#[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
pub mod scenario;
pub mod surface;

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
}

impl ErrorCode {
    /// Stable process projection: 64 invalid request/version/action, 77 denied,
    /// 69 unavailable, 75 transient capacity/clock/reconciliation refusal.
    /// A failed action never receives the success exit code zero.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidRequest | Self::UnsupportedAction | Self::UnsupportedVersion => 64,
            Self::Unauthorized | Self::Refused => 77,
            Self::Unavailable => 69,
            Self::Capacity | Self::Clock | Self::Reconcile => 75,
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorCode>;

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
    let parsed = url::Url::parse(value).map_err(|_| ErrorCode::InvalidRequest)?;
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
        let _decoded = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(&bytes)
                .map_err(|_| ErrorCode::Unauthorized)?,
        );
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
    /// Lent by the trusted embedder: proves a new community's accounting genesis
    /// on this device (see `creating`). Absent in a frontend that cannot prove.
    activation_prover: Option<std::sync::Arc<dyn accounting::ActivationProver>>,
    /// Vouchers the member may still spend, as last reported by the accounting
    /// owner. `None` until one is known; links are then limited only by the
    /// community's own (alpha) allowance.
    voucher_allowance: Option<u32>,
    wave_ports: BTreeMap<String, Box<dyn inbox_waves::WavePorts>>,
    login_configuration: BTreeMap<String, login::Configuration>,
    logins: BTreeMap<[u8; 32], login::session::State>,
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
            activation_prover: None,
            voucher_allowance: None,
            wave_ports: BTreeMap::new(),
            login_configuration: BTreeMap::new(),
            logins: BTreeMap::new(),
            #[cfg(all(feature = "embedded-authenticator", not(target_arch = "wasm32")))]
            embedded_authenticators: BTreeMap::new(),
            #[cfg(target_arch = "wasm32")]
            browser_gesture: None,
        }
    }

    /// Trusted embedding control: lend the prover for new communities' accounting.
    pub fn set_activation_prover(
        &mut self,
        prover: std::sync::Arc<dyn accounting::ActivationProver>,
    ) {
        self.activation_prover = Some(prover);
    }

    /// Trusted embedding control: the accounting owner reports how many vouchers
    /// the member may still spend. At zero every open link is stopped and no new
    /// one is issued; a link may not offer more uses than remain. Absent from
    /// every callable projection.
    pub fn set_voucher_allowance(&mut self, remaining: Option<u32>) {
        self.voucher_allowance = remaining;
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
        getrandom::fill(bytes.as_mut()).map_err(|_| ErrorCode::Unavailable)?;
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
        let result = self.invoke(origin, token, bytes, now).await;
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
        let request: WireInvocation =
            serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
        let local = registry::action(&request.action);
        let remote = foyer::action(&request.action);
        let version = local
            .map(|action| action.version)
            .or_else(|| remote.map(|action| action.description.version))
            .ok_or(ErrorCode::UnsupportedAction)?;
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
            .map(|owner| (owner, Readiness::Unavailable))
            .collect(),
        }
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
