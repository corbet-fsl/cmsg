use super::*;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Local,
    Vault,
    Mesh,
    Foyer,
    Board,
    Inbox,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    LocalClient,
}

impl Authority {
    pub(super) fn permits(self, _role: Role) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Read,
    LocalRevocation,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionDescription {
    pub action: String,
    pub version: u16,
    pub family: Family,
    pub authority: Authority,
    pub effect: Effect,
    pub body: Value,
    pub result: Value,
    pub event: Value,
    pub error: Value,
}

type Handler = fn(&mut Door, &[u8; 32], &str) -> Result<(Value, Vec<Event>)>;

pub(super) struct Action {
    name: &'static str,
    pub version: u16,
    family: Family,
    pub authority: Authority,
    effect: Effect,
    body: fn() -> Value,
    result: fn() -> Value,
    pub handler: Handler,
}

fn schema<T: JsonSchema>() -> Value {
    schemars::schema_for!(T).to_value()
}

fn status(door: &mut Door, _: &[u8; 32], _: Empty) -> Result<(RuntimeStatus, Vec<Event>)> {
    Ok((door.status(), vec![]))
}

fn describe(_: &mut Door, _: &[u8; 32], _: Empty) -> Result<(Vec<ActionDescription>, Vec<Event>)> {
    Ok((catalog(), vec![]))
}

fn revoke(door: &mut Door, key: &[u8; 32], _: Empty) -> Result<(Revoked, Vec<Event>)> {
    door.grants.remove(key);
    Ok((Revoked { revoked: true }, vec![Event::ClientRevoked]))
}

// Each row is the sole definition of the action's typed body/result, authority,
// scope family, effect and dispatch. Projection code reads these same entries.
macro_rules! actions {
    ($($name:literal => $handler:ident ($body:ty) -> $result:ty, $effect:ident;)+) => {
        pub(super) static ACTIONS: &[Action] = &[$(Action {
            name: $name, version: 1, family: Family::Local,
            authority: Authority::LocalClient, effect: Effect::$effect,
            body: schema::<$body>, result: schema::<$result>,
            handler: |door, key, body| {
                let body = serde_json::from_str::<$body>(body).map_err(|_| ErrorCode::InvalidRequest)?;
                let (result, events) = $handler(door, key, body)?;
                Ok((serde_json::to_value(result).map_err(|_| ErrorCode::Unavailable)?, events))
            },
        }),+];
    };
}

actions! {
    "runtime.status" => status(Empty) -> RuntimeStatus, Read;
    "runtime.describe" => describe(Empty) -> Vec<ActionDescription>, Read;
    "client.revoke" => revoke(Empty) -> Revoked, LocalRevocation;
}

pub(super) fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}

pub fn catalog() -> Vec<ActionDescription> {
    ACTIONS
        .iter()
        .map(|a| ActionDescription {
            action: a.name.into(),
            version: a.version,
            family: a.family,
            authority: a.authority,
            effect: a.effect,
            body: (a.body)(),
            result: (a.result)(),
            event: schema::<Event>(),
            error: schema::<ErrorCode>(),
        })
        .collect()
}
