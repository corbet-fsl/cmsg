use super::*;
use board::{
    attend as board_attend, depart as board_depart, discovery as board_discovery,
    heartbeat as board_heartbeat, search as board_search, watch as board_watch,
};
use foyer::refresh as foyer_refresh;
use login::{cancel as login_cancel, poll as login_poll, start as login_start};

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
    Foyer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Read,
    LocalRevocation,
    FoyerCheck,
    FoyerRecord,
    LocalBootstrap,
    LocalLifecycle,
    VaultAccess,
    BoardRecord,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<Value>,
}

type Handler = for<'a> fn(
    &'a mut Door,
    &'a [u8; 32],
    &'a str,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(Value, Vec<Event>)>> + 'a>,
>;

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

pub(super) fn schema<T: JsonSchema>() -> Value {
    // These schemas are embedded in multiple documents. Inline references so
    // their meaning does not change when nested under an OpenAPI operation.
    schemars::generate::SchemaSettings::draft2020_12()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}

async fn status(door: &mut Door, _: &[u8; 32], _: Empty) -> Result<(RuntimeStatus, Vec<Event>)> {
    Ok((door.status(), vec![]))
}

async fn describe(
    _: &mut Door,
    _: &[u8; 32],
    _: Empty,
) -> Result<(Vec<ActionDescription>, Vec<Event>)> {
    Ok((catalog(), vec![]))
}

fn origin<'a>(door: &'a Door, key: &[u8; 32]) -> Result<&'a str> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.as_str())
        .ok_or(ErrorCode::Unauthorized)
}

async fn board_status(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cbrd::Status, Vec<Event>)> {
    let board = door
        .boards
        .get(origin(door, key)?)
        .ok_or(ErrorCode::Unavailable)?;
    Ok((board.status(), vec![]))
}
async fn board_disconnect(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cbrd::Status, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    Ok((board.disconnect(), vec![]))
}
async fn inbox_snapshot(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Relation,
) -> Result<(cnbx::ConversationView, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    Ok((vault.snapshot(request).await?, vec![]))
}
async fn inbox_history(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Conversation,
) -> Result<(Vec<cnbx::Message>, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    Ok((vault.history(request).await?, vec![]))
}
async fn inbox_relation(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Relation,
) -> Result<(cnbx::Relation, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    Ok((vault.relation(request).await?, vec![]))
}
async fn inbox_delivery(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Delivery,
) -> Result<(Option<cnbx::DeliveryStatus>, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    Ok((vault.delivery(request).await?, vec![]))
}
async fn vault_lock(door: &mut Door, key: &[u8; 32], _: Empty) -> Result<(Empty, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let vault = door.vaults.remove(&origin).ok_or(ErrorCode::Unavailable)?;
    vault.lock().await;
    Ok((Empty {}, vec![Event::VaultLocked]))
}

async fn mesh_status(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<cmsh::BackendView>, Vec<Event>)> {
    let mesh = door
        .meshes
        .get(origin(door, key)?)
        .ok_or(ErrorCode::Unavailable)?;
    Ok((mesh.view(), vec![]))
}

async fn mesh_disconnect(door: &mut Door, key: &[u8; 32], _: Empty) -> Result<(Empty, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    let mesh = door.meshes.remove(&origin).ok_or(ErrorCode::Unavailable)?;
    mesh.close();
    Ok((Empty {}, vec![Event::MeshDisconnected]))
}

pub(super) fn owner_types() -> Value {
    serde_json::json!({"CliLoginConfiguration": schema::<login::Configuration>(), "CliCallbackStatus": schema::<login::CallbackStatus>(), "GroupView": schema::<cbrd::GroupView>(), "DiscoveryPage": schema::<cbrd::DiscoveryPage>(), "BrowserConfiguration": schema::<browser::Configuration>(), "VaultBridgeConfiguration": schema::<browser::VaultBridgeConfiguration>(), "VaultHostConfiguration": schema::<browser::VaultHostConfiguration>(), "VaultBridgeRequest": schema::<browser::VaultBridgeRequest>(), "VaultBridgeReply": schema::<browser::VaultBridgeReply>()})
}

async fn revoke(door: &mut Door, key: &[u8; 32], _: Empty) -> Result<(Revoked, Vec<Event>)> {
    login::session::retire(door, key);
    door.grants.remove(key);
    Ok((Revoked { revoked: true }, vec![Event::ClientRevoked]))
}

// Each row is the sole definition of the action's typed body/result, authority,
// scope family, effect and dispatch. Projection code reads these same entries.
macro_rules! actions {
    ($($name:literal => $handler:ident ($body:ty) -> $result:ty, $effect:ident, $family:ident;)+) => {
        pub(super) static ACTIONS: &[Action] = &[$(Action {
            name: $name, version: 1, family: Family::$family,
            authority: Authority::LocalClient, effect: Effect::$effect,
            body: schema::<$body>, result: schema::<$result>,
            handler: |door, key, body| Box::pin(async move {
                let body = serde_json::from_str::<$body>(body).map_err(|_| ErrorCode::InvalidRequest)?;
                let (result, events) = $handler(door, key, body).await?;
                Ok((serde_json::to_value(result).map_err(|_| ErrorCode::Unavailable)?, events))
            }),
        }),+];
    };
}

actions! {
    "runtime.status" => status(Empty) -> RuntimeStatus, Read, Local;
    "runtime.describe" => describe(Empty) -> Vec<ActionDescription>, Read, Local;
    "client.revoke" => revoke(Empty) -> Revoked, LocalRevocation, Local;
    "foyer.refresh" => foyer_refresh(Empty) -> Empty, FoyerCheck, Foyer;
    "board.status" => board_status(Empty) -> cbrd::Status, Read, Board;
    "board.attend" => board_attend(Empty) -> cbrd::Status, BoardRecord, Board;
    "board.search" => board_search(board::Search) -> cbrd::DiscoveryPage, BoardRecord, Board;
    "board.watch" => board_watch(board::Watch) -> cbrd::DiscoveryPage, BoardRecord, Board;
    "board.discovery" => board_discovery(Empty) -> Vec<cbrd::Discovery>, VaultAccess, Board;
    "board.heartbeat" => board_heartbeat(Empty) -> cbrd::cfrm::LiveOutput, BoardRecord, Board;
    "board.depart" => board_depart(Empty) -> cbrd::cfrm::EmptyOutput, BoardRecord, Board;
    "board.disconnect" => board_disconnect(Empty) -> cbrd::Status, LocalLifecycle, Board;
    "inbox.snapshot" => inbox_snapshot(facades::Relation) -> cnbx::ConversationView, VaultAccess, Inbox;
    "inbox.history" => inbox_history(facades::Conversation) -> Vec<cnbx::Message>, VaultAccess, Inbox;
    "inbox.relation" => inbox_relation(facades::Relation) -> cnbx::Relation, VaultAccess, Inbox;
    "inbox.delivery_status" => inbox_delivery(facades::Delivery) -> Option<cnbx::DeliveryStatus>, VaultAccess, Inbox;
    "mesh.status" => mesh_status(Empty) -> Vec<cmsh::BackendView>, Read, Mesh;
    "mesh.disconnect" => mesh_disconnect(Empty) -> Empty, LocalLifecycle, Mesh;
    "vault.lock" => vault_lock(Empty) -> Empty, LocalLifecycle, Vault;
    "login.start" => login_start(super::login::Start) -> super::login::Status, LocalBootstrap, Foyer;
    "login.poll" => login_poll(super::login::Poll) -> super::login::Status, LocalBootstrap, Foyer;
    "login.cancel" => login_cancel(super::login::Cancel) -> super::login::Status, LocalBootstrap, Foyer;
}

pub(super) fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}

pub(super) fn known(name: &str) -> bool {
    action(name).is_some() || foyer::action(name).is_some()
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
            owner: None,
        })
        .chain(foyer::catalog())
        .collect()
}
