//! Member rooms for the member: join by request and sealed answer, leave, and
//! answering other members' join requests. The caller names the room and the
//! group only. The ephemeral key, the sealing, the consent and the ordered
//! commit all come from the retained owner and the original libraries; nothing
//! is ever published in the clear, and a join with nobody online simply waits.
use super::handlers::{group_error, OwnedBoard, MAX_GROUPS};
use super::*;
use crate::door::RoomLink;
use cbrd::join_seal::{self, JoinKey};
use std::collections::BTreeMap;

/// A room is named by its opaque identifier from the listing and by the group
/// it belongs to. `accept_profile_visibility` is the semipublic consent.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomJoin {
    pub room: [u8; 16],
    pub group: [u8; 32],
    #[serde(default)]
    pub accept_profile_visibility: bool,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomRef {
    pub room: [u8; 16],
    pub group: [u8; 32],
}

/// Where a join stands after this call. Call again until `joined`.
#[derive(Clone, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RoomJoinStatus {
    /// The request is posted; a member online will answer it.
    Requested,
    /// No usable answer yet (nobody online, or the attempt must be retried).
    Waiting,
    Joined {
        groups: Vec<cbrd::GroupView>,
    },
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct RoomServed {
    /// Requests this call answered.
    pub answered: u32,
}

/// One open join request of this device: the private half of the ephemeral key
/// and the relay sequence of the request. Memory only; losing it re-requests.
pub(super) struct PendingJoin {
    key: JoinKey,
    request: u64,
}
#[derive(Default)]
pub(super) struct RoomJoins {
    open: BTreeMap<[u8; 16], PendingJoin>,
    /// Requests this device already answered (room, relay sequence).
    served: std::collections::BTreeSet<([u8; 16], u64)>,
}

fn link(error: cbrd::clnk::ErrorCode) -> ErrorCode {
    use cbrd::clnk::ErrorCode as Link;
    match error {
        Link::Reconcile | Link::Timeout | Link::Transport => ErrorCode::Reconcile,
        Link::Capacity => ErrorCode::Capacity,
        _ => ErrorCode::Unavailable,
    }
}

impl RoomJoins {
    pub(super) fn forget(&mut self, room: [u8; 16]) {
        self.open.remove(&room);
    }
}

impl<T: clnk::Transport, R: RoomLink, O: CommittedOwner> OwnedBoard<T, R, O> {
    pub(super) async fn room_join_step(
        &mut self,
        join: RoomJoin,
        expires: u64,
    ) -> Result<RoomJoinStatus> {
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        let board = &self.inner.board;
        let Some(pending) = self.joins.open.get(&join.room) else {
            let mut seed = [0; 32];
            getrandom::fill(&mut seed).map_err(|_| ErrorCode::Unavailable)?;
            let (key, public) = JoinKey::derive(&seed);
            let request = R::request_room_join(board, join.room, public)
                .await
                .map_err(link)?;
            self.joins
                .open
                .insert(join.room, PendingJoin { key, request });
            return Ok(RoomJoinStatus::Requested);
        };
        let request = pending.request;
        let answers = R::room_join_answers(board, join.room, request)
            .await
            .map_err(link)?;
        let mut evidence = vec![];
        for (_, _, sealed) in answers {
            let Some(plain) = pending.key.open(&join.room, request, &sealed) else {
                continue;
            };
            if let Ok(parsed) = serde_json::from_slice::<cthr::ParentEvidence>(&plain) {
                evidence.push(parsed);
            }
        }
        let mut last = None;
        for parsed in evidence {
            match self.join_with(&join, &parsed, expires).await {
                Ok(groups) => {
                    self.joins.open.remove(&join.room);
                    return Ok(RoomJoinStatus::Joined { groups });
                }
                Err(error) => last = Some(error),
            }
        }
        match last {
            Some(error) => Err(error),
            None => Ok(RoomJoinStatus::Waiting),
        }
    }

    async fn join_with(
        &mut self,
        join: &RoomJoin,
        evidence: &cthr::ParentEvidence,
        expires: u64,
    ) -> Result<Vec<cbrd::GroupView>> {
        let source = self.group_policy(expires).await?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let intent = cbrd::GroupIntent::Join {
            group: join.group,
            vouches: Default::default(),
        };
        let (candidate, current, now, request) = cbrd::prepare_group_intent(
            owner,
            &source,
            intent,
            join.accept_profile_visibility,
            MAX_GROUPS,
        )
        .await
        .map_err(group_error)?;
        // The signed Join request rides with the ordered commit; members admit
        // the newcomer only with it.
        let companion = serde_json::to_vec(&request).map_err(|_| ErrorCode::Unavailable)?;
        let snapshot = self
            .owner
            .join_room(
                &self.inner.board,
                crate::door::facades::RoomJoinTask {
                    room: join.room,
                    group: join.group,
                    candidate,
                    companion,
                    evidence,
                    policy: &source,
                },
            )
            .await?;
        snapshot.views(&current, now).map_err(group_error)
    }

    /// Leave a member room: Groups `Leave`, the Threads state and the Attend
    /// withdrawal in one commit. A device that never joined through Attend
    /// leaves in Groups alone.
    pub(super) async fn room_leave_step(
        &mut self,
        room: RoomRef,
        expires: u64,
    ) -> Result<Vec<cbrd::GroupView>> {
        self.idle()?;
        self.joins.forget(room.room);
        let source = self.group_policy(expires).await?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let intent = cbrd::GroupIntent::Leave { group: room.group };
        let (candidate, current, now, _) =
            cbrd::prepare_group_intent(owner, &source, intent.clone(), false, MAX_GROUPS)
                .await
                .map_err(group_error)?;
        let left = self
            .owner
            .leave_room(crate::door::facades::RoomLeaveTask {
                group: room.group,
                candidate,
                policy: &source,
            })
            .await?;
        match left {
            Some(snapshot) => snapshot.views(&current, now).map_err(group_error),
            None => {
                let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
                let (views, _) =
                    cbrd::execute_group_intent(owner, &source, intent, false, MAX_GROUPS)
                        .await
                        .map_err(group_error)?;
                Ok(views)
            }
        }
    }

    /// Answer the live join requests of `room` with this member's own evidence,
    /// sealed to each request's ephemeral key.
    pub(super) async fn room_serve_step(
        &mut self,
        room: RoomRef,
        expires: u64,
    ) -> Result<RoomServed> {
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        let board = &self.inner.board;
        let requests = R::room_join_requests(board, room.room)
            .await
            .map_err(link)?;
        if requests.is_empty() {
            return Ok(RoomServed { answered: 0 });
        }
        let source = self.group_policy(expires).await?;
        let evidence = self.owner.room_evidence(room.group, &source).await?;
        let state = serde_json::to_vec(&evidence).map_err(|_| ErrorCode::Unavailable)?;
        let board = &self.inner.board;
        let mut answered = 0;
        for (to, public) in requests {
            if !self.joins.served.insert((room.room, to)) {
                continue;
            }
            let sealed =
                join_seal::seal(&public, &room.room, to, &state).ok_or(ErrorCode::Unavailable)?;
            if let Err(error) = R::answer_room_join(board, room.room, to, sealed).await {
                self.joins.served.remove(&(room.room, to));
                return Err(link(error));
            }
            answered += 1;
        }
        Ok(RoomServed { answered })
    }
}

fn handles<'a>(
    door: &'a mut Door,
    key: &[u8; 32],
) -> Result<(&'a mut Box<dyn crate::door::facades::BoundBoard>, u64)> {
    super::group_act::board_of(door, key)
}

pub(in crate::door) async fn room_join(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomJoin,
) -> Result<(RoomJoinStatus, Vec<Event>)> {
    let (board, expires) = handles(door, key)?;
    Ok((board.room_join(request, expires).await?, vec![]))
}

pub(in crate::door) async fn room_serve(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomRef,
) -> Result<(RoomServed, Vec<Event>)> {
    let (board, expires) = handles(door, key)?;
    Ok((board.room_serve(request, expires).await?, vec![]))
}

/// Leaving withdraws Attend, removes this device's Threads state and leaves
/// the room's group in one commit; an open join request for the room is dropped.
pub(in crate::door) async fn room_leave(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomRef,
) -> Result<(Vec<cbrd::GroupView>, Vec<Event>)> {
    let (board, expires) = handles(door, key)?;
    Ok((board.room_leave(request, expires).await?, vec![]))
}
