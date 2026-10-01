//! Device-local member API. Every projection invokes this same bounded dispatcher.
//!
//! Client grants are local capabilities, never remote member/admin/root authority.
//! Pairing belongs to the trusted embedding runtime; it is not an API action.
//! Unavailable domain owners cannot be replaced by caller-provided success values.
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
mod registry;
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
}

impl ErrorCode {
    /// Stable process projection: 64 invalid request/version/action, 77 denied,
    /// 69 unavailable, 75 transient capacity/clock/reconciliation refusal.
    /// A failed action never receives the success exit code zero.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidRequest | Self::UnsupportedAction | Self::UnsupportedVersion => 64,
            Self::Unauthorized => 77,
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
        Ok(Self { community, origins })
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
    role: Role,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Unavailable,
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
}

impl Door {
    pub fn new(config: Configuration) -> Self {
        Self {
            config,
            grants: BTreeMap::new(),
            clock_floor: 0,
        }
    }

    fn observe(&mut self, now: u64) -> Result<()> {
        if now < self.clock_floor {
            return Err(ErrorCode::Clock);
        }
        self.clock_floor = now;
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
            || actions.len() > registry::ACTIONS.len()
            || actions.iter().any(|name| registry::action(name).is_none())
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
        let key = token_hash(token.expose_for_transport());
        if self.grants.contains_key(&key) {
            return Err(ErrorCode::Unavailable);
        }
        self.grants.insert(
            key,
            Grant {
                origin: origin.into(),
                role,
                actions,
                expires,
            },
        );
        Ok(token)
    }

    /// Trusted embedding revocation (including termination of a paired client).
    pub fn revoke(&mut self, token: &ClientToken) {
        self.grants
            .remove(&token_hash(token.expose_for_transport()));
    }

    pub fn dispatch(&mut self, origin: &str, token: &str, bytes: &[u8], now: u64) -> Output {
        let result = self.invoke(origin, token, bytes, now);
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

    fn invoke(
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
        let action = registry::action(&request.action).ok_or(ErrorCode::UnsupportedAction)?;
        if !grant.actions.contains(&request.action) || !action.authority.permits(grant.role) {
            return Err(ErrorCode::Unauthorized);
        }
        if request.version != action.version {
            return Err(ErrorCode::UnsupportedVersion);
        }
        // All projections converge here after the same scope/origin/capability check.
        let result = (action.handler)(self, &key, request.body.get())?;
        if serde_json::to_vec(&result.0)
            .map_err(|_| ErrorCode::Unavailable)?
            .len()
            > MAX_RESULT_BYTES
        {
            return Err(ErrorCode::Capacity);
        }
        Ok(result)
    }

    fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            community: self.config.community.clone(),
            preload: Readiness::Unavailable,
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
