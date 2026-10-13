//! Group membership writes for the member: create, fork, join, leave, describe.
//! The caller names the intent only. The local member, every consent signature
//! and every membership decision come from the retained owner and Groups; no
//! raw command, actor, signature or policy is accepted from JSON.
use super::*;

/// One membership write. `accept_profile_visibility` is the semipublic consent
/// ("members of this group may see my private profile"); rooms refuse without it.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAct {
    pub intent: cbrd::GroupIntent,
    #[serde(default)]
    pub accept_profile_visibility: bool,
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
    let views = board
        .group_act(request.intent, request.accept_profile_visibility, expires)
        .await?;
    Ok((views, vec![]))
}

/// Intent plus the semipublic profile statement, as in `board.group_act`, for
/// commands that need other members: the others answer for themselves.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupPropose {
    pub intent: cbrd::GroupIntent,
    #[serde(default)]
    pub accept_profile_visibility: bool,
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
    },
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAnswer {
    pub operation: [u8; 32],
    pub accept: bool,
    #[serde(default)]
    pub accept_profile_visibility: bool,
}

/// The decision to send back to the actor in the same conversation.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupAnswered {
    pub actor: String,
    pub text: String,
}

fn board_of<'a>(
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
    let proposed = board
        .group_propose(request.intent, request.accept_profile_visibility, expires)
        .await?;
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

pub(in crate::door) async fn group_answer(
    door: &mut Door,
    key: &[u8; 32],
    request: GroupAnswer,
) -> Result<(GroupAnswered, Vec<Event>)> {
    let (board, expires) = board_of(door, key)?;
    let answered = board
        .group_answer(
            request.operation,
            request.accept,
            request.accept_profile_visibility,
            expires,
        )
        .await?;
    Ok((answered, vec![]))
}
