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
