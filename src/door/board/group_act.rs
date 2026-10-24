//! Group membership writes for the member: create, fork, join, leave, describe.
//! The caller names the intent only. The local member, every consent signature
//! and every membership decision come from the retained owner and Groups; no
//! raw command, actor, signature or policy is accepted from JSON.
use super::*;

/// One membership write. Joining a public room is itself the consent to
/// visible profiles (decided 2026-10-13); the write carries no switch for it.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAct {
    pub intent: cbrd::GroupIntent,
}

pub(in crate::door) async fn group_act(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupAct,
) -> Result<(Vec<cbrd::GroupView>, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    let views = board.group_act(request.intent, expires).await?;
    Ok((views, vec![]))
}

/// Intent as in `board.group_act`, for
/// commands that need other members: the others answer for themselves.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupPropose {
    pub intent: cbrd::GroupIntent,
}

/// Text for one member's direct conversation; the caller sends it unchanged.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupInvite {
    pub member: String,
    pub text: String,
}

#[derive(Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupProposed {
    pub operation: [u8; 32],
    /// One message per member whose consent is missing.
    pub invitations: Vec<GroupInvite>,
    /// Present when nobody else had to consent and the command is committed.
    pub committed: Option<Vec<cbrd::GroupView>>,
}

/// Welcome messages still owed to members, as text for each member's direct
/// conversation. Sent again until the caller reports them delivered.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupWelcome {
    pub operation: [u8; 32],
    /// Members whose Welcome the caller has delivered; they are not offered again.
    #[serde(default)]
    pub delivered: Vec<String>,
}

#[derive(Clone, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupWelcomes {
    pub operation: [u8; 32],
    /// One message per member that has not yet been reported as served.
    pub pending: Vec<GroupInvite>,
}

/// A text received in the direct conversation with `from` (authenticated by
/// the conversation, never named by the message itself).
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupMessageIn {
    pub from: String,
    pub text: String,
}

#[derive(Clone, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupInbound {
    /// Waiting for this member's own decision (`board.group_answer`).
    Invitation {
        operation: [u8; 32],
        actor: String,
        command: String,
        members: Vec<String>,
    },
    Waiting {
        operation: [u8; 32],
        awaiting: Vec<String>,
    },
    Declined {
        operation: [u8; 32],
    },
    Committed {
        operation: [u8; 32],
        views: Vec<cbrd::GroupView>,
        /// The Welcome each other member needs, to send in its conversation.
        welcomes: Vec<GroupInvite>,
    },
    /// A fellow member's listing key of a public room was adopted.
    Listing {
        group: [u8; 32],
    },
    /// This member joined the group from the actor's Welcome.
    Joined {
        operation: [u8; 32],
        views: Vec<cbrd::GroupView>,
    },
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAnswer {
    pub operation: [u8; 32],
    pub accept: bool,
}

/// The decision to send back to the actor in the same conversation.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAnswered {
    pub actor: String,
    pub text: String,
}

pub(in crate::door) fn board_of<'a>(
    door: &'a mut Door,
    key: &[u8; 32],
) -> Result<(&'a mut Box<dyn crate::door::facades::BoundBoard>, u64)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board, expires))
}

pub(in crate::door) async fn group_propose(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupPropose,
) -> Result<(GroupProposed, Vec<Event>)> {
    let (board, expires) = board_of(door, key)?;
    let proposed = board.group_propose(request.intent, expires).await?;
    Ok((proposed, vec![]))
}

pub(in crate::door) async fn group_message(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupMessageIn,
) -> Result<(GroupInbound, Vec<Event>)> {
    let (board, expires) = board_of(door, key)?;
    let inbound = board
        .group_message(request.from, request.text, expires)
        .await?;
    Ok((inbound, vec![]))
}

pub(in crate::door) async fn group_welcome(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupWelcome,
) -> Result<(GroupWelcomes, Vec<Event>)> {
    let (board, expires) = board_of(door, key)?;
    let pending = board
        .group_welcome(request.operation, request.delivered, expires)
        .await?;
    Ok((pending, vec![]))
}

pub(in crate::door) async fn group_answer(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupAnswer,
) -> Result<(GroupAnswered, Vec<Event>)> {
    let (board, expires) = board_of(door, key)?;
    let answered = board
        .group_answer(request.operation, request.accept, expires)
        .await?;
    Ok((answered, vec![]))
}
