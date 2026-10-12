//! Thin forwarding of the original Foyer contract with runtime-owned sessions.
//! No request chooses its transport, portal role or community.
use super::*;
pub use cfyr::Foyer;
use std::sync::LazyLock;

#[cfg(feature = "ohttp")]
pub type Transport = cfyr::OhttpClient<super::ohttp::Wire>;
#[cfg(all(not(feature = "ohttp"), target_arch = "wasm32"))]
pub use cfyr::BrowserClient as Transport;
#[cfg(all(not(feature = "ohttp"), not(target_arch = "wasm32")))]
pub use cfyr::HttpClient as Transport;

/// A service scope selected by the trusted embedding, never by request JSON.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Global,
    Community,
}

/// Distinct configured owner sessions for one local portal origin. Public
/// bootstrap is a transport with no session; remote authority is never minted.
pub struct Sessions {
    pub(super) primary: Scope,
    pub(super) clients: BTreeMap<Scope, cfyr::Foyer<Transport>>,
}

impl Sessions {
    /// Select the service used by owner actions whose scope is Both.
    pub fn new(primary: Scope, client: Foyer<Transport>) -> Self {
        Self {
            primary,
            clients: BTreeMap::from([(primary, client)]),
        }
    }

    /// Attach the other service without reusing or exposing the first session.
    pub fn with_service(mut self, scope: Scope, client: Foyer<Transport>) -> Result<Self> {
        if self.clients.contains_key(&scope) {
            return Err(ErrorCode::InvalidRequest);
        }
        self.clients.insert(scope, client);
        Ok(self)
    }
}

pub(super) struct Binding {
    pub role: Role,
    pub root_board: bool,
    pub sessions: Sessions,
    pub uncertain: bool,
}

pub(super) struct Operation {
    pub description: ActionDescription,
    name: String,
    access: Access,
    scope: ServiceScope,
}

enum Access {
    Any,
    Member,
    Admin,
    Root,
}
enum ServiceScope {
    Primary,
    Exact(Scope),
}

/// Raw owner operations that cmsg's account lifecycle performs itself through the
/// held lease: no frontend builds or signs the delegation or acquires the
/// checkpoint, so they are not republished (`account_enroll` is cmsg's own action).
/// The step-up, passkey and device operations need a user-verified assertion from
/// the local Keyhole ceremony, so cmsg's own member actions will perform them.
const OWNED_BY_ACCOUNT_LIFECYCLE: [&str; 8] = [
    // The development gate exists only so test fixtures can open a development
    // window; no production door may ever forward it.
    "development_gate",
    "account",
    "account_enroll",
    "account_checkpoint",
    "step_up_begin",
    "passkey_add",
    "passkey_revoke",
    "device_authorize",
];

static OPERATIONS: LazyLock<Vec<Operation>> = LazyLock::new(|| operations(cfyr::contract()));

fn operations(document: &Value) -> Vec<Operation> {
    document["paths"]
        .as_object()
        .expect("the owner contract has paths")
        .values()
        .filter_map(|item| {
            let operation = &item["post"];
            // Positive owner metadata is required. In particular a raw login
            // Session must stay inside the Foyer bootstrap implementation.
            if operation["x-client-access"] != "forward" {
                return None;
            }
            let name = operation["operationId"].as_str()?;
            if OWNED_BY_ACCOUNT_LIFECYCLE.contains(&name) {
                return None;
            }
            let access = operation["x-role"].as_str()?;
            let scope = operation["x-scope"].as_str()?;
            let access_kind = match access {
                "public" | "authenticated" => Access::Any,
                "member" => Access::Member,
                "admin" => Access::Admin,
                "root" => Access::Root,
                _ => return None,
            };
            let service_scope = match scope {
                "both" => ServiceScope::Primary,
                "global" => ServiceScope::Exact(Scope::Global),
                "community" => ServiceScope::Exact(Scope::Community),
                _ => return None,
            };
            let effect = match operation["x-effect"].as_str()? {
                "check" => Effect::FoyerCheck,
                "record" => Effect::FoyerRecord,
                _ => return None,
            };
            let body = inline_schema(
                operation.pointer("/requestBody/content/application~1json/schema")?,
                document,
                0,
            )?;
            let result = inline_schema(
                operation.pointer("/responses/200/content/application~1json/schema")?,
                document,
                0,
            )?;
            Some(Operation {
                name: name.into(),
                access: access_kind,
                scope: service_scope,
                description: ActionDescription {
                    action: format!("foyer.{name}"),
                    version: 1,
                    family: Family::Foyer,
                    authority: Authority::Foyer,
                    effect,
                    body,
                    result,
                    event: registry::schema::<Event>(),
                    error: registry::schema::<ErrorCode>(),
                    owner: Some(serde_json::json!({
                        "action": name,
                        "role": access,
                        "scope": scope,
                        "effect": operation["x-effect"],
                    })),
                },
            })
        })
        .collect()
}

// Owner component references would otherwise refer to the enclosing cmsg
// document after projection. Inline only local, acyclic references; unsupported
// owner schema shapes fail closed instead of producing an inaccurate API.
fn inline_schema(value: &Value, document: &Value, depth: usize) -> Option<Value> {
    if depth > 64 {
        return None;
    }
    match value {
        Value::Object(object) => {
            let mut result = serde_json::Map::new();
            if let Some(reference) = object.get("$ref") {
                let pointer = reference.as_str()?.strip_prefix('#')?;
                let target = inline_schema(document.pointer(pointer)?, document, depth + 1)?;
                result.extend(target.as_object()?.clone());
            }
            for (key, child) in object {
                if key != "$ref" {
                    result.insert(key.clone(), inline_schema(child, document, depth + 1)?);
                }
            }
            Some(Value::Object(result))
        }
        Value::Array(values) => values
            .iter()
            .map(|child| inline_schema(child, document, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        _ => Some(value.clone()),
    }
}

pub(super) fn catalog() -> impl Iterator<Item = ActionDescription> {
    OPERATIONS.iter().map(|op| op.description.clone())
}

pub(super) fn action(name: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|op| op.description.action == name)
}

impl Binding {
    pub async fn call(&mut self, operation: &Operation, body: Value) -> Result<Value> {
        if self.uncertain {
            return Err(ErrorCode::Reconcile);
        }
        // This checks the local portal surface, not the membership's remote
        // role. An admin/root member uses an ordinary member portal/session for
        // member actions; cvld independently checks the real membership rights.
        let scope = match operation.scope {
            ServiceScope::Primary => self.sessions.primary,
            ServiceScope::Exact(scope) => scope,
        };
        let allowed = match operation.access {
            Access::Any => true,
            Access::Member => self.role == Role::Member,
            Access::Admin => {
                self.role == Role::Admin
                    || (self.role == Role::Root && self.root_board && scope == Scope::Community)
            }
            Access::Root => self.role == Role::Root,
        };
        if !allowed {
            return Err(ErrorCode::Unauthorized);
        }
        let client = self
            .sessions
            .clients
            .get_mut(&scope)
            .ok_or(ErrorCode::Unauthorized)?;
        // A borrowed browser invocation may be dropped or panic after send.
        // Latch uncertainty until an actual owner result arrives; no public
        // clear/retry can pretend that cancellation rolled a mutation back.
        self.uncertain = true;
        let result = client.call(&operation.name, body).await.map_err(map_error);
        if !matches!(result, Err(ErrorCode::Reconcile)) {
            self.uncertain = false;
        }
        let result = result?;
        // The child may already have committed even if its result cannot cross
        // the bounded local door. Never represent this as a pre-send refusal.
        if check_result_size(&result).is_err() {
            self.uncertain = true;
            return Err(ErrorCode::Reconcile);
        }
        Ok(result)
    }
}

impl Door {
    fn wallet_foyer(&self, origin: &str) -> Result<&Foyer<Transport>> {
        self.member_origin(origin)?;
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if self.config.community != "wallet"
            || binding.role != Role::Member
            || binding.uncertain
            || binding.sessions.primary != Scope::Global
        {
            return Err(ErrorCode::Unauthorized);
        }
        binding
            .sessions
            .clients
            .get(&Scope::Global)
            .ok_or(ErrorCode::Unavailable)
    }

    /// Lend only the explicitly configured literal Wallet's genuine global
    /// Foyer observation port. UUID/current-key/device reads remain original
    /// owner calls; this is not certified lineage or creation permission.
    pub fn live_wallet_membership(
        &self,
        origin: &str,
    ) -> Result<cfyr::membership::LiveMembership<Transport>> {
        Ok(self.wallet_foyer(origin)?.live_wallet_membership())
    }

    /// Reborrow only the original Wallet Charter beside that same global Foyer.
    /// A global passport feed or caller-supplied policy cannot construct it.
    pub fn wallet_current_policy(
        &self,
        origin: &str,
    ) -> Result<cfyr::policy::CurrentPolicy<Transport>> {
        Ok(self.wallet_foyer(origin)?.current_policy())
    }

    pub(super) fn custody_scope(&self) -> Scope {
        if self.config.community == "wallet" {
            Scope::Global
        } else {
            Scope::Community
        }
    }
    pub(super) fn custody_membership(
        &self,
        origin: &str,
    ) -> Result<cfyr::membership::LiveMembership<Transport>> {
        match self.custody_scope() {
            Scope::Global => self.live_wallet_membership(origin),
            Scope::Community => self.live_membership(origin),
        }
    }
    pub(super) fn custody_current_policy(
        &self,
        origin: &str,
    ) -> Result<cfyr::policy::CurrentPolicy<Transport>> {
        match self.custody_scope() {
            Scope::Global => self.wallet_current_policy(origin),
            Scope::Community => self.current_policy(origin),
        }
    }

    /// Lend only the configured community Foyer's weak live-membership read
    /// port to the trusted custody composer. This is not a public action or a
    /// session, G3, signing or runtime-readiness grant.
    pub fn live_membership(
        &self,
        origin: &str,
    ) -> Result<cfyr::membership::LiveMembership<Transport>> {
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if binding.role != Role::Member || binding.uncertain {
            return Err(ErrorCode::Unauthorized);
        }
        binding
            .sessions
            .clients
            .get(&Scope::Community)
            .map(Foyer::live_membership)
            .ok_or(ErrorCode::Unavailable)
    }

    /// Lend a weak scoped read of the same community's sole current Charter.
    /// The trusted composer reborrows after waits; no policy snapshot or grant
    /// crosses the generated action interface.
    pub fn current_policy(&self, origin: &str) -> Result<cfyr::policy::CurrentPolicy<Transport>> {
        let binding = self.foyers.get(origin).ok_or(ErrorCode::Unavailable)?;
        if binding.role != Role::Member || binding.uncertain {
            return Err(ErrorCode::Unauthorized);
        }
        binding
            .sessions
            .clients
            .get(&Scope::Community)
            .map(Foyer::current_policy)
            .ok_or(ErrorCode::Unavailable)
    }
}

/// Borrow only the original retained community Foyer. Public request data never
/// chooses another service or supplies a policy snapshot.
impl Binding {
    fn community(&mut self) -> Result<&mut Foyer<Transport>> {
        self.sessions
            .clients
            .get_mut(&Scope::Community)
            .ok_or(ErrorCode::Unavailable)
    }
    pub(super) fn current<R>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&cfyr::trust::VerifiedCharter) -> Result<R>,
    ) -> Result<R> {
        self.community()?
            .current(now, |current| {
                if current.community() != community {
                    return Err(ErrorCode::Unauthorized);
                }
                inspect(current)
            })
            .map_err(trust_error)?
    }
}

fn trust_error(error: cfyr::trust::Error) -> ErrorCode {
    use cfyr::trust::Error;
    match error {
        Error::Configuration => ErrorCode::InvalidRequest,
        Error::ClockRegression => ErrorCode::Clock,
        Error::Busy | Error::Exhausted => ErrorCode::Capacity,
        Error::Trust(_) | Error::Response | Error::BehindAnnouncement | Error::Obsolete => {
            ErrorCode::Refused
        }
        Error::Stopped | Error::Timeout | Error::Network | Error::Unavailable => {
            ErrorCode::Unavailable
        }
    }
}

/// Maintenance of the one original Foyer-retained public feed. The original
/// Envoy bounds the fetch and retries; this action executes only one request.
pub(super) async fn refresh(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Empty, Vec<Event>)> {
    let origin = door
        .grants
        .get(key)
        .ok_or(ErrorCode::Unauthorized)?
        .origin
        .clone();
    let community = door.config.community.clone();
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let mut trust = binding.community()?.trust().map_err(trust_error)?;
    let failed_clock = std::cell::Cell::new(false);
    let clock = || {
        match cbrd::clnk::Clock::now(&board::SystemClock) {
            Ok(milliseconds) => milliseconds / 1000,
            Err(_) => {
                // An unusable clock must not grant freshness. The original
                // bounded-time owner refuses this value; never reuse old time.
                failed_clock.set(true);
                u64::MAX
            }
        }
    };
    let result = if trust.state() == cfyr::trust::State::Stopped {
        trust.start(clock).await
    } else {
        match trust.refresh(clock()) {
            Ok(()) => trust.poll(clock).await.map(|_| ()),
            Err(error) => Err(error),
        }
    };
    if failed_clock.get() {
        return Err(ErrorCode::Clock);
    }
    result.map_err(trust_error)?;
    drop(trust);
    let now = cbrd::clnk::Clock::now(&board::SystemClock).map_err(|_| ErrorCode::Clock)? / 1000;
    binding.current(&community, now, |_| Ok(()))?;
    door.observe(now)?;
    Ok((Empty {}, vec![]))
}

pub(super) fn map_error(error: cfyr::Error) -> ErrorCode {
    match error {
        cfyr::Error::Invalid => ErrorCode::InvalidRequest,
        cfyr::Error::Unauthorized | cfyr::Error::Forbidden | cfyr::Error::WrongHost => {
            ErrorCode::Unauthorized
        }
        cfyr::Error::Throttled => ErrorCode::Capacity,
        cfyr::Error::Refused => ErrorCode::Refused,
        cfyr::Error::Unavailable => ErrorCode::Unavailable,
        cfyr::Error::Reconcile => ErrorCode::Reconcile,
    }
}

#[cfg(test)]
#[path = "../../tests/support/foyer.rs"]
mod tests;
