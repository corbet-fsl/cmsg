use super::*;
use board::{
    attend as board_attend, depart as board_depart, discovery as board_discovery,
    group_act as board_group_act, groups as board_groups, heartbeat as board_heartbeat,
    profile_publish as board_profile_publish, room_admit as board_room_admit,
    room_connect as board_room_connect, room_join as board_room_join,
    room_leave as board_room_leave, room_list as board_room_list, room_refs as board_room_refs,
    room_serve as board_room_serve, search as board_search, watch as board_watch,
};
use communities::communities;
use courier::{
    chat_retry as courier_chat_retry, chat_send as courier_chat_send,
    group_answer as courier_group_answer, group_message as courier_group_message,
    group_propose as courier_group_propose, group_welcome as courier_group_welcome,
    room_listing as courier_room_listing,
};
use creating::{
    community_create, community_creation, community_creation_claim, community_creation_finish,
};
use foyer::refresh as foyer_refresh;
use inbox::{blocking_rules as inbox_blocking_rules, contact_act as inbox_contact_act};
use inbox_conversation::{acknowledge as inbox_ack, receive as inbox_receive};
use inbox_waves::{
    wave_decide as inbox_wave_decide, wave_delivered as inbox_wave_delivered,
    wave_job_done as inbox_wave_job_done, wave_job_next as inbox_wave_job_next,
    wave_job_retry as inbox_wave_job_retry, wave_jobs_recover as inbox_wave_jobs_recover,
    wave_outbox as inbox_wave_outbox, wave_punish as inbox_wave_punish,
    wave_receive as inbox_wave_receive, wave_send as inbox_wave_send, waves as inbox_waves_list,
};
use login::{cancel as login_cancel, poll as login_poll, start as login_start};
use vouching::{
    contacts as voucher_contacts, explanation as voucher_explanation,
    link_create as voucher_link_create, link_revoke as voucher_link_revoke, links as voucher_links,
    signoff_decide as voucher_signoff_decide, signoff_list as voucher_signoff_list,
    vouched_by as voucher_vouched_by,
};

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
    GroupRecord,
    ProfileRecord,
    InboxRecord,
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
    inbox_read(door, key, |vault| vault.snapshot(request)).await
}
async fn inbox_history(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Conversation,
) -> Result<(Vec<cnbx::Message>, Vec<Event>)> {
    inbox_read(door, key, |vault| vault.history(request)).await
}
async fn inbox_relation(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Relation,
) -> Result<(cnbx::Relation, Vec<Event>)> {
    inbox_read(door, key, |vault| vault.relation(request)).await
}
async fn inbox_delivery(
    door: &mut Door,
    key: &[u8; 32],
    request: facades::Delivery,
) -> Result<(Option<cnbx::DeliveryStatus>, Vec<Event>)> {
    inbox_read(door, key, |vault| vault.delivery(request)).await
}

pub(super) async fn inbox_read<T: 'static>(
    door: &mut Door,
    key: &[u8; 32],
    read: impl for<'a> FnOnce(&'a mut dyn facades::BoundVault) -> facades::OwnedFuture<'a, T>,
) -> Result<(T, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let mut policy = door.current_policy(&origin)?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let (result, completed) = current::read(
        vault.as_mut(),
        &mut policy,
        current::Scope {
            community: &door.config.community,
            expires,
            floor: door.clock_floor,
        },
        read,
    )
    .await?;
    door.observe(completed)?;
    Ok((result, vec![]))
}
async fn vault_lock(door: &mut Door, key: &[u8; 32], _: Empty) -> Result<(Empty, Vec<Event>)> {
    let origin = origin(door, key)?.to_owned();
    // The account actor holds custody borrowed from this Vault's owners.
    door.accounts.remove(&origin);
    let vault = door.vaults.remove(&origin).ok_or(ErrorCode::Unavailable)?;
    vault.lock().await;
    Ok((Empty {}, vec![Event::VaultLocked]))
}

/// The join's account steps through the origin's actor.
struct JoinSteps<'a> {
    door: &'a mut Door,
    key: &'a [u8; 32],
}

impl account::Steps for JoinSteps<'_> {
    async fn call(&mut self, command: account::Command) -> Result<account::Answer> {
        account_call(self.door, self.key, command).await
    }
}

/// Serve one account action through the origin's actor. An actor past its
/// grant, finished or fenced is dropped here, never reused.
pub(super) async fn account_call(
    door: &mut Door,
    key: &[u8; 32],
    command: account::Command,
) -> Result<account::Answer> {
    let origin = origin(door, key)?.to_owned();
    account_call_at(door, &origin, command).await
}

pub(super) async fn account_call_at(
    door: &mut Door,
    origin: &str,
    command: account::Command,
) -> Result<account::Answer> {
    let actor = door
        .accounts
        .get_mut(origin)
        .ok_or(ErrorCode::Unavailable)?;
    if actor.ended() {
        door.accounts.remove(origin);
        return Err(ErrorCode::Unavailable);
    }
    // An actor past its original session deadline never executes another
    // command: its intents belong to that session alone.
    if actor.deadline_passed(door.clock_floor) {
        door.accounts.remove(origin);
        return Err(ErrorCode::SessionExpired);
    }
    let answer = actor.call(command).await;
    // A finished actor goes now; one past its deadline stays until the next
    // call, which answers `SessionExpired` instead of an unbound `Unavailable`.
    if door.accounts.get(origin).is_some_and(|actor| actor.ended()) {
        door.accounts.remove(origin);
    }
    answer
}

/// Mechanics constant: the lifetime a global session must still have before a
/// long operation (community join, with the creator's genesis) starts under it.
/// Worst join observed under load 480 s (journey board 2026-10-27; all passes
/// <= 482 s) plus the 190 s genesis proof window is 670 s; 900 s keeps about a
/// third above that, so a join started inside the runway ends inside the session.
pub(super) const SESSION_RUNWAY_SECONDS: u64 = 900;
/// Mechanics constant: a session younger than this counts as fresh even when its
/// whole lifetime is shorter than the runway (toy sessions are 600 s). Opening
/// another one cannot give more, and asking again would only make the member
/// wait (stay in flow); a device start or renewal takes far less than 120 s.
pub(super) const SESSION_FRESH_GRACE_SECONDS: u64 = 120;

/// The ONE precondition test of every long operation: is the remaining lifetime
/// of the session (`remaining`, of a session lasting `lifetime` in all) too short
/// to start it? Never asks for more than a just-opened session offers.
pub(super) fn needs_fresh_session(remaining: u64, lifetime: u64) -> bool {
    remaining < SESSION_RUNWAY_SECONDS.min(lifetime.saturating_sub(SESSION_FRESH_GRACE_SECONDS))
}

/// Precondition of a long operation: when the bound session's remaining lifetime
/// is too short, open a FRESH global session (the embedder's passkey path) first.
/// Without a renewal port the state is `SessionExpired` BEFORE the operation starts:
/// the native embedder then restarts the device (a fresh Door, see
/// `native::Client::invoke_bytes`) and repeats it there. Without an actor nothing
/// changes.
pub(super) async fn ensure_session_runway(door: &mut Door, origin: &str) -> Result<()> {
    let Some(actor) = door.accounts.get(origin) else {
        return Ok(());
    };
    let (remaining, lifetime) = actor.lifetime();
    if actor.ended() || !needs_fresh_session(remaining, lifetime) {
        return Ok(());
    }
    // Without a renewal port (a native device restarts on this state) the old actor and its
    // intents are dropped as well: nothing ever runs on the short or passed session.
    renew_session(door, origin).await
}

/// Replace the origin's actor by one rebuilt from a FRESH global session. The
/// old actor, its authority and its one-use intents are dropped first and never
/// reused or re-bound; the old deadline is never extended. A renewal that cannot
/// complete (no port, passkey declined, no new actor) leaves the state
/// "needs a fresh session" (`SessionExpired`) for the frontend to prompt.
async fn renew_session(door: &mut Door, origin: &str) -> Result<()> {
    door.accounts.remove(origin);
    let mut renewal = door
        .session_renewal
        .take()
        .ok_or(ErrorCode::SessionExpired)?;
    let renewed = renewal.renew(door, origin).await;
    door.session_renewal = Some(renewal);
    let fresh = door
        .accounts
        .get(origin)
        .is_some_and(|actor| !actor.ended() && !actor.deadline_passed(door.clock_floor));
    match renewed {
        Ok(()) if fresh => Ok(()),
        _ => {
            door.accounts.remove(origin);
            Err(ErrorCode::SessionExpired)
        }
    }
}
async fn account_enroll(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(account::Enrolled, Vec<Event>)> {
    Ok((
        account_call(door, key, account::Command::Enroll)
            .await?
            .enrolled()?,
        vec![],
    ))
}
async fn account_open(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(account::Opened, Vec<Event>)> {
    Ok((
        account_call(door, key, account::Command::Open)
            .await?
            .opened()?,
        vec![],
    ))
}
async fn account_reopen(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(account::Opened, Vec<Event>)> {
    Ok((
        account_call(door, key, account::Command::Reopen)
            .await?
            .reopened()?,
        vec![],
    ))
}
/// Join the community: reserve the chosen handle, pass the gates (voucher when the lobby asks for it), then
/// run the four account steps. Each step is idempotent, so a call after any
/// interruption resumes where the durable state stands and an active account
/// answers `active` again. Stops, without error, at the first stage that needs
/// the member or time: more gate steps, or the common checkpoint.
async fn community_join(
    door: &mut Door,
    key: &[u8; 32],
    request: account::JoinRequest,
) -> Result<(account::Joined, Vec<Event>)> {
    if request
        .voucher
        .as_ref()
        .is_some_and(|code| code.len() > 512)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let origin = origin(door, key)?.to_owned();
    ensure_session_runway(door, &origin).await?;
    // A deadline that still passes mid-join restarts the join ONCE under a fresh
    // session: authority, intents and actor are rebuilt from that session and
    // the server state (every step is an idempotent state), never carried over.
    match join_once(door, key, request.clone()).await {
        Err(ErrorCode::SessionExpired) if door.session_renewal.is_some() => {
            renew_session(door, &origin).await?;
            join_once(door, key, request).await
        }
        joined => joined,
    }
}

async fn join_once(
    door: &mut Door,
    key: &[u8; 32],
    request: account::JoinRequest,
) -> Result<(account::Joined, Vec<Event>)> {
    // A restarted device presents the creation id it kept for this community.
    creating::rearm(door, key).await?;
    if let Some(code) = request.voucher.as_deref() {
        // The key package for the direct thread goes into the sealed notice.
        // Made and stored once; a device that cannot make one redeems without.
        match vouching::prepare_package(door, key, code).await {
            Ok(()) | Err(ErrorCode::Unavailable) => {}
            Err(error) => return Err(error),
        }
    }
    let gate = account_call(door, key, account::Command::Join(request))
        .await?
        .gate()?;
    if !gate.ready {
        return Ok((account::Joined::NeedsSteps { steps: gate.steps }, vec![]));
    }
    if let account::Checkpoint::Pending { eligible_at } =
        account::enroll_and_open(&mut JoinSteps { door, key }).await?
    {
        return Ok((account::Joined::CheckpointPending { eligible_at }, vec![]));
    }
    let done = account_call(door, key, account::Command::Activate)
        .await?
        .activated()?;
    creating::settle(door, key).await?;
    // The contact with the sponsor exists from the first moment of membership.
    // A step that cannot run now is repeated by the next join or `vouched_by`.
    if let Ok(origin) = door
        .grants
        .get(key)
        .map(|grant| grant.origin.clone())
        .ok_or(())
    {
        let _ = vouching::settle_vouchee(door, &origin).await;
    }
    Ok((
        account::Joined::Active {
            version: done.version,
            accepted_at: done.accepted_at,
            outbox_settled: done.outbox_settled,
        },
        vec![],
    ))
}

async fn account_activate(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(account::Activation, Vec<Event>)> {
    Ok((
        account_call(door, key, account::Command::Activate)
            .await?
            .activated()?,
        vec![],
    ))
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
                let body = serde_json::from_str::<$body>(body).map_err(|__cause| crate::door::cause::emit(file!(), line!(), "ErrorCode::InvalidRequest", ErrorCode::InvalidRequest, &__cause))?;
                let (result, events) = $handler(door, key, body).await?;
                Ok((serde_json::to_value(result).map_err(|__cause| crate::door::cause::emit(file!(), line!(), "ErrorCode::Unavailable", ErrorCode::Unavailable, &__cause))?, events))
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
    "board.groups" => board_groups(Empty) -> Vec<cbrd::GroupView>, VaultAccess, Board;
    "board.group_act" => board_group_act(board::GroupAct) -> Vec<cbrd::GroupView>, GroupRecord, Board;
    "board.group_propose" => courier_group_propose(board::GroupPropose) -> board::GroupProposed, GroupRecord, Board;
    "board.group_message" => courier_group_message(board::GroupMessageIn) -> board::GroupInbound, GroupRecord, Board;
    "board.group_answer" => courier_group_answer(board::GroupAnswer) -> board::GroupAnswered, GroupRecord, Board;
    "board.group_welcome" => courier_group_welcome(board::GroupWelcome) -> board::GroupWelcomes, GroupRecord, Board;
    "board.room_join" => board_room_join(board::RoomJoin) -> board::RoomJoinStatus, GroupRecord, Board;
    "board.room_leave" => board_room_leave(board::RoomRef) -> Vec<cbrd::GroupView>, GroupRecord, Board;
    "board.room_connect" => board_room_connect(board::RoomRef) -> board::RoomConnected, BoardRecord, Board;
    "board.room_listing" => courier_room_listing(Empty) -> board::RoomsListed, GroupRecord, Board;
    "board.room_refs" => board_room_refs(Empty) -> Vec<board::RoomRef>, GroupRecord, Board;
    "board.room_admit" => board_room_admit(board::RoomRef) -> board::RoomAdmitted, GroupRecord, Board;
    "board.room_serve" => board_room_serve(board::RoomRef) -> board::RoomServed, GroupRecord, Board;
    "board.profile_publish" => board_profile_publish(board::ProfilePublish) -> board::ProfilePublished, ProfileRecord, Board;
    "board.heartbeat" => board_heartbeat(Empty) -> cbrd::cfrm::LiveOutput, BoardRecord, Board;
    "board.room_list" => board_room_list(board::Search) -> cbrd::cfrm::RoomListOutput, BoardRecord, Board;
    "board.depart" => board_depart(Empty) -> cbrd::cfrm::EmptyOutput, BoardRecord, Board;
    "board.disconnect" => board_disconnect(Empty) -> cbrd::Status, LocalLifecycle, Board;
    "inbox.snapshot" => inbox_snapshot(facades::Relation) -> cnbx::ConversationView, VaultAccess, Inbox;
    "inbox.history" => inbox_history(facades::Conversation) -> Vec<cnbx::Message>, VaultAccess, Inbox;
    "inbox.relation" => inbox_relation(facades::Relation) -> cnbx::Relation, VaultAccess, Inbox;
    "inbox.delivery_status" => inbox_delivery(facades::Delivery) -> Option<cnbx::DeliveryStatus>, VaultAccess, Inbox;
    "inbox.blocking_rules" => inbox_blocking_rules(Empty) -> Vec<String>, VaultAccess, Inbox;
    "inbox.contact_act" => inbox_contact_act(inbox::ContactAct) -> cnbx::Relation, InboxRecord, Inbox;
    "inbox.send" => courier_chat_send(inbox_conversation::ConversationSend) -> inbox_conversation::Sent, InboxRecord, Inbox;
    "inbox.receive" => inbox_receive(inbox_conversation::Wired) -> inbox_conversation::Received, InboxRecord, Inbox;
    "inbox.ack" => inbox_ack(inbox_conversation::Wired) -> inbox_conversation::Acked, InboxRecord, Inbox;
    "inbox.retry" => courier_chat_retry(inbox_conversation::ConversationRetry) -> inbox_conversation::Retried, VaultAccess, Inbox;
    "inbox.waves" => inbox_waves_list(Empty) -> inbox_waves::WaveList, VaultAccess, Inbox;
    "inbox.wave_send" => inbox_wave_send(inbox_waves::WaveSend) -> inbox_waves::WaveStatus, InboxRecord, Inbox;
    "inbox.wave_decide" => inbox_wave_decide(inbox_waves::WaveDecide) -> inbox_waves::WaveStatus, InboxRecord, Inbox;
    "inbox.wave_punish" => inbox_wave_punish(inbox_waves::WavePunish) -> cnbx::Relation, InboxRecord, Inbox;
    "inbox.wave_receive" => inbox_wave_receive(inbox_waves::WaveIncoming) -> inbox_waves::WaveStatus, InboxRecord, Inbox;
    "inbox.wave_outbox" => inbox_wave_outbox(Empty) -> inbox_waves::Outbox, VaultAccess, Inbox;
    "inbox.wave_delivered" => inbox_wave_delivered(inbox_waves::Delivered) -> Empty, InboxRecord, Inbox;
    "inbox.wave_job_next" => inbox_wave_job_next(Empty) -> inbox_waves::JobOffer, InboxRecord, Inbox;
    "inbox.wave_job_retry" => inbox_wave_job_retry(inbox_waves::JobRef) -> Empty, InboxRecord, Inbox;
    "inbox.wave_jobs_recover" => inbox_wave_jobs_recover(Empty) -> Empty, InboxRecord, Inbox;
    "inbox.wave_job_done" => inbox_wave_job_done(inbox_waves::JobDone) -> inbox_waves::WaveStatus, InboxRecord, Inbox;
    "mesh.status" => mesh_status(Empty) -> Vec<cmsh::BackendView>, Read, Mesh;
    "mesh.disconnect" => mesh_disconnect(Empty) -> Empty, LocalLifecycle, Mesh;
    "vault.lock" => vault_lock(Empty) -> Empty, LocalLifecycle, Vault;
    "account_enroll" => account_enroll(Empty) -> account::Enrolled, VaultAccess, Vault;
    "account_open" => account_open(Empty) -> account::Opened, VaultAccess, Vault;
    "account_reopen" => account_reopen(Empty) -> account::Opened, VaultAccess, Vault;
    "account_activate" => account_activate(Empty) -> account::Activation, VaultAccess, Vault;
    "community_join" => community_join(account::JoinRequest) -> account::Joined, VaultAccess, Vault;
    "foyer.community_create" => community_create(creating::Create) -> creating::Created, VaultAccess, Foyer;
    "foyer.community_creation" => community_creation(Empty) -> creating::Draft, VaultAccess, Foyer;
    "foyer.community_creation_finish" => community_creation_finish(Empty) -> Empty, VaultAccess, Foyer;
    "foyer.communities" => communities(Empty) -> communities::Communities, VaultAccess, Foyer;
    "foyer.community_creation_claim" => community_creation_claim(creating::Claim) -> creating::Claimed, VaultAccess, Foyer;
    "foyer.voucher_link_create" => voucher_link_create(vouching::LinkCreate) -> vouching::LinkInfo, VaultAccess, Foyer;
    "foyer.voucher_links" => voucher_links(Empty) -> vouching::Links, VaultAccess, Foyer;
    "foyer.voucher_contacts" => voucher_contacts(Empty) -> vouching::VoucherContacts, VaultAccess, Foyer;
    "foyer.voucher_link_revoke" => voucher_link_revoke(vouching::LinkRef) -> vouching::LinkRevoked, VaultAccess, Foyer;
    "foyer.voucher_signoff_list" => voucher_signoff_list(Empty) -> vouching::Applicants, VaultAccess, Foyer;
    "foyer.voucher_signoff_decide" => voucher_signoff_decide(vouching::Decide) -> vouching::Decided, VaultAccess, Foyer;
    "foyer.voucher_explanation" => voucher_explanation(vouching::Explanation) -> vouching::Explained, VaultAccess, Foyer;
    "foyer.voucher_vouched_by" => voucher_vouched_by(Empty) -> vouching::VouchedBy, VaultAccess, Foyer;
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

/// Account updates for the trusted embedder (the proof worker of the wallet). They
/// carry proof material and are therefore not callable actions.
impl Door {
    /// Send a proven update. It is signed once, stored before the send and, on a
    /// retry after any failure, re-sent unchanged; the operator then answers
    /// with the original acceptance. Keep the answer until the new state is
    /// durable, then call `account_settle`.
    pub async fn account_update(
        &mut self,
        origin: &str,
        proven: accounting::ProvenUpdate,
    ) -> Result<account::Shared<account::Applied>> {
        account_call_at(
            self,
            origin,
            account::Command::Update(account::Shared::new(proven)),
        )
        .await?
        .updated()
    }

    /// The acceptance of an update whose answer was lost (re-sent unchanged), or
    /// `None` when none is owed. Call after every login before building the next proof.
    pub async fn account_resume(
        &mut self,
        origin: &str,
    ) -> Result<Option<account::Shared<account::Applied>>> {
        account_call_at(self, origin, account::Command::Resume)
            .await?
            .owed()
    }

    /// The caller made the acceptance of `request_id` durable: forget the stored update.
    pub async fn account_settle(&mut self, origin: &str, request_id: [u8; 32]) -> Result<()> {
        account_call_at(self, origin, account::Command::Settle(request_id))
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use account::{Activation, Answer, Checkpoint, Command, Enrolled, Gate, Joined, Opened};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    const ORIGIN: &str = "https://member.example";
    const KEY: [u8; 32] = [7; 32];

    fn door() -> Door {
        let mut door = Door::new(
            Configuration::new(
                "alpha".into(),
                BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
            )
            .unwrap(),
        );
        door.grants.insert(
            KEY,
            super::super::Grant {
                origin: ORIGIN.into(),
                actions: BTreeSet::new(),
                expires: u64::MAX,
            },
        );
        door
    }

    fn answer(command: &Command) -> Reply {
        Ok(match command {
            Command::Join(_) => Answer::Gate(Gate {
                ready: true,
                steps: vec![],
            }),
            Command::Enroll => Answer::Enrolled(Enrolled {
                checkpoint: Checkpoint::Ready,
            }),
            Command::Open => Answer::Opened(Opened { accepted_at: 1 }),
            Command::Activate => Answer::Activated(Activation {
                version: 1,
                accepted_at: 1,
                outbox_settled: true,
            }),
            _ => return Err(ErrorCode::Unavailable),
        })
    }
    type Reply = Result<Answer>;

    /// Every join step answers; the gate step alone takes 700 s (past a 600 s session).
    fn slow_gate(command: &Command, now: &AtomicU64) -> Reply {
        if matches!(command, Command::Join(_)) {
            now.fetch_add(700, Ordering::SeqCst);
        }
        answer(command)
    }

    /// The toy's silent passkey: a fresh session and a new actor rebuilt from it.
    struct Renewal {
        now: Arc<AtomicU64>,
        executed: Arc<AtomicUsize>,
        renewals: Arc<AtomicUsize>,
        fresh: fn(&Command, &AtomicU64) -> Reply,
        binds: bool,
    }
    impl SessionRenewal for Renewal {
        fn renew<'a>(
            &'a mut self,
            door: &'a mut Door,
            origin: &'a str,
        ) -> futures_util::future::LocalBoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.renewals.fetch_add(1, Ordering::SeqCst);
                if !self.binds {
                    return Err(ErrorCode::Unauthorized);
                }
                let actor =
                    account::timed_actor(self.now.clone(), self.executed.clone(), self.fresh);
                door.bind_account(origin, actor)
            })
        }
    }

    struct Setup {
        door: Door,
        now: Arc<AtomicU64>,
        old: Arc<AtomicUsize>,
        fresh: Arc<AtomicUsize>,
        renewals: Arc<AtomicUsize>,
    }

    fn setup(
        old: fn(&Command, &AtomicU64) -> Reply,
        renewal: Option<(fn(&Command, &AtomicU64) -> Reply, bool)>,
    ) -> Setup {
        let now = Arc::new(AtomicU64::new(1_000));
        let (old_count, fresh, renewals) = Default::default();
        let mut door = door();
        door.bind_account(
            ORIGIN,
            account::timed_actor(now.clone(), Arc::clone(&old_count), old),
        )
        .unwrap();
        if let Some((answers, binds)) = renewal {
            door.set_session_renewal(Box::new(Renewal {
                now: now.clone(),
                executed: Arc::clone(&fresh),
                renewals: Arc::clone(&renewals),
                fresh: answers,
                binds,
            }));
        }
        Setup {
            door,
            now,
            old: old_count,
            fresh,
            renewals,
        }
    }

    fn join(door: &mut Door) -> Result<Joined> {
        futures_util::FutureExt::now_or_never(community_join(door, &KEY, Default::default()))
            .expect("the doubles never wait")
            .map(|(joined, _)| joined)
    }

    #[test]
    fn the_runway_never_asks_for_more_than_a_fresh_session_offers() {
        // Toy 600 s sessions: fresh enough for 120 s, then renewed before a join.
        assert!(!needs_fresh_session(600, 600));
        assert!(!needs_fresh_session(480, 600));
        assert!(needs_fresh_session(479, 600));
        // Long sessions: the 900 s runway itself.
        assert!(!needs_fresh_session(900, 3_600));
        assert!(needs_fresh_session(899, 3_600));
    }

    #[test]
    fn a_deadline_passing_mid_join_restarts_the_join_once_under_a_fresh_session() {
        let mut s = setup(slow_gate, Some((|command, _| answer(command), true)));
        assert!(matches!(join(&mut s.door), Ok(Joined::Active { .. })));
        assert_eq!(s.renewals.load(Ordering::SeqCst), 1);
        // The old session's actor ran only the gate; its later intents never ran.
        assert_eq!(s.old.load(Ordering::SeqCst), 1);
        // The restart ran every step again under the fresh session.
        assert_eq!(s.fresh.load(Ordering::SeqCst), 4);
        assert_eq!(s.now.load(Ordering::SeqCst), 1_700);
    }

    #[test]
    fn a_short_runway_opens_a_fresh_session_before_the_join_starts() {
        let ok: fn(&Command, &AtomicU64) -> Reply = |command, _| answer(command);
        // 100 s into a 600 s session it is still fresh: no prompt.
        let mut s = setup(ok, Some((ok, true)));
        s.now.store(1_100, Ordering::SeqCst);
        assert!(matches!(join(&mut s.door), Ok(Joined::Active { .. })));
        assert_eq!(s.renewals.load(Ordering::SeqCst), 0);
        assert_eq!(s.old.load(Ordering::SeqCst), 4);
        // 479 s left (< 480): a fresh session first, nothing runs on the short one.
        let mut s = setup(ok, Some((ok, true)));
        s.now.store(1_121, Ordering::SeqCst);
        assert!(matches!(join(&mut s.door), Ok(Joined::Active { .. })));
        assert_eq!(s.renewals.load(Ordering::SeqCst), 1);
        assert_eq!(s.old.load(Ordering::SeqCst), 0);
        assert_eq!(s.fresh.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn a_short_runway_without_a_renewal_port_is_session_expired_before_the_join_starts() {
        // The native embedder restarts the device on this state; nothing runs on the short one.
        let ok: fn(&Command, &AtomicU64) -> Reply = |command, _| answer(command);
        let mut s = setup(ok, None);
        s.now.store(1_121, Ordering::SeqCst);
        assert_eq!(join(&mut s.door).err(), Some(ErrorCode::SessionExpired));
        assert_eq!(s.old.load(Ordering::SeqCst), 0);
        // A fresh session (within the grace) starts the join directly.
        let mut s = setup(ok, None);
        s.now.store(1_100, Ordering::SeqCst);
        assert!(matches!(join(&mut s.door), Ok(Joined::Active { .. })));
        assert_eq!(s.old.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn an_expired_sessions_intents_are_never_executed() {
        // No renewal port: the state "needs a fresh session" is exposed.
        let mut s = setup(|command, _| answer(command), None);
        s.now.store(1_600, Ordering::SeqCst);
        assert_eq!(join(&mut s.door).err(), Some(ErrorCode::SessionExpired));
        assert_eq!(s.old.load(Ordering::SeqCst), 0);
        assert!(!s.door.accounts.contains_key(ORIGIN));
        // A renewal that cannot open a fresh session (passkey declined) is the same state.
        let mut s = setup(
            |command, _| answer(command),
            Some((|command, _| answer(command), false)),
        );
        s.now.store(1_600, Ordering::SeqCst);
        assert_eq!(join(&mut s.door).err(), Some(ErrorCode::SessionExpired));
        assert_eq!(s.old.load(Ordering::SeqCst), 0);
        assert_eq!(s.fresh.load(Ordering::SeqCst), 0);
        assert!(!s.door.accounts.contains_key(ORIGIN));
    }

    #[test]
    fn the_restart_is_bounded_to_once() {
        // The fresh session also passes its deadline mid-join: exposed, not renewed again.
        let mut s = setup(slow_gate, Some((slow_gate, true)));
        assert_eq!(join(&mut s.door).err(), Some(ErrorCode::SessionExpired));
        assert_eq!(s.renewals.load(Ordering::SeqCst), 1);
        assert_eq!(
            (s.old.load(Ordering::SeqCst), s.fresh.load(Ordering::SeqCst)),
            (1, 1)
        );
    }
}
