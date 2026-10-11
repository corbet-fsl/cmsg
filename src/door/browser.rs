//! Trusted page configuration and the origin-bound browser owner runtime.
//! Service addresses are deployment inputs, never action-body overrides.
use super::*;
pub mod deployment;

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub scope: foyer::Scope,
    pub base: String,
    pub host: String,
}

/// Compose original public deployment values without copying their fields.
/// Constructors still belong to Charter and Envoy; request JSON cannot install it.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustConfiguration {
    pub publishing: cfyr::trust::Configuration,
    pub following: cfyr::trust::Config,
}

/// Public deployment data only. No credential, PRF or session is accepted here.
/// The constructor requires `origin` to equal the actual browser page origin.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub community: String,
    pub origin: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_board: bool,
    pub primary: foyer::Scope,
    pub services: Vec<Service>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forum: Option<board::Configuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<login::Configuration>,
}

/// Public top-level UI configuration. The isolated vault frame owns custody.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VaultBridgeConfiguration {
    pub member_origin: String,
    pub vault_origin: String,
    pub vault_url: String,
    pub timeout_millis: u32,
}
impl VaultBridgeConfiguration {
    /// Check only deployment shape, never membership or a remote grant.
    pub fn validate(&self) -> Result<()> {
        if self.timeout_millis == 0 {
            return Err(ErrorCode::InvalidRequest);
        }
        vault_pair(&self.member_origin, &self.vault_origin)?;
        let page = url::Url::parse(&self.vault_url).map_err(|_| ErrorCode::InvalidRequest)?;
        if page.origin().ascii_serialization() != self.vault_origin
            || !page.username().is_empty()
            || page.password().is_some()
            || page.query().is_some()
            || page.fragment().is_some()
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }
}

/// Pinned Vault-page deployment data. The member page cannot supply this through
/// the bridge; the isolated page constructs its own actual owner configuration.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VaultHostConfiguration {
    pub member_origin: String,
    pub runtime: Configuration,
    /// Public Tor deployment budgets. Absence selects a bare partial host;
    /// presence installs restoration, never custody or a readiness assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_tor: Option<deployment::Configuration>,
}

pub(crate) const BRIDGE_READY: &str = "cmsg.ui.ready.v1";
pub(crate) const BRIDGE_CONNECT: &str = "cmsg.ui.connect.v1";
pub(crate) const BRIDGE_MAX_REQUEST: usize = MAX_BODY_BYTES * 6 + 256;
pub(crate) const BRIDGE_MAX_REPLY: usize = MAX_RESULT_BYTES * 6 + 4096;
pub(crate) const BRIDGE_ACK_MILLIS: u32 = 30_000;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultBridgeRequest {
    Invoke { id: u32, request: String },
    Close { id: u32 },
    Ack { id: u32, challenge: String },
}
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultBridgeReply {
    Ready,
    Output {
        id: u32,
        output: Output,
        challenge: String,
    },
    Closed {
        id: Option<u32>,
        error: Option<ErrorCode>,
    },
}
pub(crate) fn bridge_contract() -> Value {
    serde_json::json!({"ready":BRIDGE_READY,"connect":BRIDGE_CONNECT,
        "maximum_body_bytes":MAX_BODY_BYTES,"maximum_request_bytes":BRIDGE_MAX_REQUEST,
        "maximum_reply_bytes":BRIDGE_MAX_REPLY,"maximum_pending":MAX_CLIENTS,
        "maximum_unacknowledged_bytes":BRIDGE_MAX_REPLY,"acknowledgement_millis":BRIDGE_ACK_MILLIS})
}

fn vault_pair(member: &str, vault: &str) -> Result<()> {
    validate_origin(member)?;
    validate_origin(vault)?;
    let member = url::Url::parse(member).map_err(|_| ErrorCode::InvalidRequest)?;
    let vault = url::Url::parse(vault).map_err(|_| ErrorCode::InvalidRequest)?;
    if member.scheme() != "https"
        || vault.scheme() != "https"
        || member.port_or_known_default() != vault.port_or_known_default()
        || vault.host_str()
            != member
                .host_str()
                .map(|host| format!("vault.{host}"))
                .as_deref()
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod runtime;
#[cfg(target_arch = "wasm32")]
pub use runtime::BrowserRuntime;
#[cfg(target_arch = "wasm32")]
mod bridge;
#[cfg(target_arch = "wasm32")]
pub use bridge::VaultHost;
#[cfg(all(target_arch = "wasm32", feature = "browser-tor"))]
pub mod identity;
#[cfg(all(target_arch = "wasm32", feature = "browser-tor"))]
pub mod mesh;
#[cfg(all(target_arch = "wasm32", feature = "browser-tor"))]
pub mod records;
#[cfg(all(target_arch = "wasm32", feature = "browser-tor"))]
pub mod restore;

impl Configuration {
    /// Restoring hosts retain their original Board until the same Vault can
    /// supply its committed-read/signing owner. Validate before starting custody.
    #[cfg(any(feature = "native-tor", feature = "browser-tor", test))]
    pub(crate) fn construct_restoring(mut self) -> Result<(Door, Option<board::PendingBoard>)> {
        if self.role != Role::Member {
            return Err(ErrorCode::Unauthorized);
        }
        let board = self
            .forum
            .take()
            .map(|forum| forum.prepare(&self.community, &self.origin))
            .transpose()?;
        Ok((self.construct()?, board))
    }

    /// Build only actual configured service clients. A native owner thread or
    /// the verified browser origin retains them; this does not create custody.
    pub fn construct(self) -> Result<Door> {
        self.construct_inner(&[])
    }

    /// Trusted native deployment roots for the original HTTPS service and public
    /// policy follower. No JSON or Wasm constructor can select certificate trust.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn construct_with_roots(self, roots: &[Vec<u8>]) -> Result<Door> {
        self.construct_inner(roots)
    }

    fn construct_inner(mut self, roots: &[Vec<u8>]) -> Result<Door> {
        #[cfg(target_arch = "wasm32")]
        if !roots.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        let community = self.community.clone();
        let wallet = community == "wallet";
        if wallet
            && (self.role != Role::Member
                || self.root_board
                || self.primary != foyer::Scope::Global)
        {
            return Err(ErrorCode::Unauthorized);
        }
        let trust_scope = if wallet {
            foyer::Scope::Global
        } else {
            foyer::Scope::Community
        };
        let configuration = if self.root_board {
            if self.community != "root"
                || self.role != Role::Root
                || self.primary != foyer::Scope::Community
            {
                return Err(ErrorCode::InvalidRequest);
            }
            super::Configuration::root_board(self.origin.clone())?
        } else {
            super::Configuration::new(
                self.community,
                BTreeMap::from([(self.role, BTreeSet::from([self.origin.clone()]))]),
            )?
        };
        let mut door = Door::new(configuration);
        if !(1..=2).contains(&self.services.len()) {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut sessions = None;
        let mut other = None;
        for service in self.services {
            let feed_origin = url::Url::parse(&service.base)
                .map_err(|_| ErrorCode::InvalidRequest)?
                .origin()
                .ascii_serialization();
            #[cfg(not(target_arch = "wasm32"))]
            let transport = foyer::Transport::with_roots(service.base, service.host, None, roots)
                .map_err(|_| ErrorCode::InvalidRequest)?;
            #[cfg(target_arch = "wasm32")]
            let transport = foyer::Transport::new(service.base, service.host, None)
                .map_err(|_| ErrorCode::InvalidRequest)?;
            let trust = if service.scope == trust_scope {
                self.trust.take()
            } else {
                None
            };
            let client = if let Some(mut trust) = trust {
                if trust.publishing.community != community || trust.publishing.origin != feed_origin
                {
                    return Err(ErrorCode::Unauthorized);
                }
                // Retry jitter is fresh runtime entropy, never a persistent
                // deployment timestamp or a value selected by an action body.
                let mut entropy = [0; 8];
                getrandom::fill(&mut entropy).map_err(|_| ErrorCode::Unavailable)?;
                trust.following.retry_entropy = u64::from_le_bytes(entropy);
                #[cfg(not(target_arch = "wasm32"))]
                let trust = if wallet {
                    cfyr::trust::Trust::wallet_native(trust.publishing, trust.following, roots)
                } else {
                    cfyr::trust::Trust::native(trust.publishing, trust.following, roots)
                };
                #[cfg(target_arch = "wasm32")]
                let trust = if wallet {
                    cfyr::trust::Trust::wallet_browser(trust.publishing, trust.following)
                } else {
                    cfyr::trust::Trust::browser(trust.publishing, trust.following)
                };
                foyer::Foyer::with_trust(transport, trust.map_err(|_| ErrorCode::InvalidRequest)?)
            } else {
                foyer::Foyer::new(transport)
            };
            if service.scope == self.primary {
                if sessions
                    .replace(foyer::Sessions::new(service.scope, client))
                    .is_some()
                {
                    return Err(ErrorCode::InvalidRequest);
                }
            } else if other.replace((service.scope, client)).is_some() {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        if self.trust.is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut sessions = sessions.ok_or(ErrorCode::InvalidRequest)?;
        if let Some((scope, client)) = other {
            sessions = sessions.with_service(scope, client)?;
        }
        door.bind_foyer(&self.origin, self.role, sessions)?;
        if let Some(login) = self.login {
            login.context()?;
            door.login_configuration.insert(self.origin.clone(), login);
        }
        if let Some(forum) = self.forum {
            door.configure_board(&self.origin, forum, board::SystemClock)?;
        }
        Ok(door)
    }
}
