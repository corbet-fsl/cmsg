//! Member rooms for the member: join by request and sealed answer, leave, and
//! answering other members' join requests. The caller names the room and the
//! group only. The ephemeral key, the sealing, the consent and the ordered
//! commit all come from the retained owner and the original libraries; nothing
//! is ever published in the clear, and a join with nobody online simply waits.
use super::handlers::{group_error, OwnedBoard, MAX_GROUPS};
use super::*;
use crate::door::RoomLink;
use cbrd::cgrp::PolicySource as _;
use cbrd::join_seal::{self, JoinKey};
use std::collections::BTreeMap;

/// A room is named by its opaque identifier from the listing and by the group
/// it belongs to. Joining a public room is the consent to visible profiles.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomJoin {
    pub room: [u8; 16],
    pub group: [u8; 32],
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

/// What one admission call did: newcomers admitted into the room's group.
#[derive(Clone, Serialize, JsonSchema)]
pub struct RoomAdmitted {
    pub admitted: u32,
    /// Ordered joins this device refused (unverifiable newcomer or consent).
    pub refused: u32,
    /// The room's group as this device now holds it.
    pub groups: Vec<cbrd::GroupView>,
}

#[derive(Clone, Serialize, JsonSchema)]
pub struct RoomConnected {
    pub connected: bool,
}

/// What `board.room_listing` did: public rooms published and the key shares
/// this device still owes to fellow members (text for each member's direct
/// conversation, sent unchanged like a Welcome).
#[derive(Clone, Serialize, JsonSchema)]
pub struct RoomsListed {
    pub published: u32,
    pub shares: Vec<super::GroupInvite>,
}

/// One forum listing entry to publish under its room.
pub(in crate::door) struct ListingWork {
    pub room: [u8; 16],
    pub entry: cbrd::clnk::cmbl::listing::SignedEntry,
}

pub(in crate::door) struct ListingPlan {
    pub work: Vec<ListingWork>,
    pub shares: Vec<super::GroupInvite>,
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
    /// How far this device has read each room's ordered joins (relay sequence).
    admitted_through: BTreeMap<[u8; 16], u64>,
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
        self.admitted_through.remove(&room);
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
            if let Ok(parsed) = serde_json::from_slice::<cbrd::RoomState>(&plain) {
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
        state: &cbrd::RoomState,
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
            MAX_GROUPS,
        )
        .await
        .map_err(group_error)?;
        // The signed Join request rides with the ordered commit (the owner adds
        // the handle of this member's own lineage); members admit the newcomer
        // only with it.
        let snapshot = self
            .owner
            .join_room(
                &self.inner.board,
                crate::door::facades::RoomJoinTask {
                    room: join.room,
                    group: join.group,
                    candidate,
                    request,
                    evidence: &state.evidence,
                    transport: &cbrd::TransportKey::from_keys(&state.transport),
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
            cbrd::prepare_group_intent(owner, &source, intent.clone(), MAX_GROUPS)
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
                    cbrd::execute_group_intent(owner, &source, intent, MAX_GROUPS)
                        .await
                        .map_err(group_error)?;
                Ok(views)
            }
        }
    }

    /// Admit the newcomers whose ordered external commits `room` holds beyond
    /// this device's cursor. Each is verified from its own evidence (see
    /// `VaultGroupOwner::admit_room`); a newcomer that fails verification is
    /// skipped for good, while an unavailable or conflicting attempt keeps the
    /// cursor so the next call retries it.
    pub(super) async fn room_admit_step(
        &mut self,
        room: RoomRef,
        expires: u64,
    ) -> Result<RoomAdmitted> {
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        let after = self
            .joins
            .admitted_through
            .get(&room.room)
            .copied()
            .unwrap_or(0);
        let transport = self.owner.room_transport_key(room.group).await?;
        let read = R::room_joins(&self.inner.board, room.room, after, &transport)
            .await
            .map_err(link)?;
        let source = self.group_policy(expires).await?;
        let (mut admitted, mut refused) = (0, 0);
        let mut retry = false;
        for frame in &read.joins {
            let task = crate::door::facades::RoomAdmitTask {
                room: room.room,
                group: room.group,
                frame,
                max_groups: MAX_GROUPS,
                transport: &transport,
                policy: &source,
            };
            match self.owner.admit_room(&self.inner.board, task).await {
                Ok(_) => admitted += 1,
                Err(ErrorCode::Unavailable | ErrorCode::Reconcile) => {
                    retry = true;
                    break;
                }
                Err(_) => refused += 1,
            }
        }
        if !retry {
            self.joins.admitted_through.insert(room.room, read.through);
        }
        let groups = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let snapshot = groups.snapshot().await.map_err(group_error)?;
        let now = groups.now().map_err(group_error)?;
        let current = source
            .current(snapshot.community(), now)
            .map_err(group_error)?;
        Ok(RoomAdmitted {
            admitted,
            refused,
            groups: snapshot.views(&current, now).map_err(group_error)?,
        })
    }

    pub(super) async fn room_refs_step(&mut self) -> Result<Vec<RoomRef>> {
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        self.load_desk().await?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let snapshot = owner.snapshot().await.map_err(group_error)?;
        let Some(listings) = &self.desk.listings else {
            return Ok(vec![]);
        };
        Ok(listings
            .public_groups(&snapshot)
            .into_iter()
            .filter_map(|group| {
                listings
                    .room_id(&group)
                    .ok()
                    .map(|room| RoomRef { room, group })
            })
            .collect())
    }

    /// Keep the listing keys of the public rooms this member belongs to: create
    /// the key of a room without one, rotate a due one (tombstone for the old
    /// entry), sign the current entry, and name the fellow members the key must
    /// still be sent to. Any member holding the key may publish; the entry of a
    /// window is identical whoever signs it.
    pub(super) async fn room_listing_step(&mut self) -> Result<ListingPlan> {
        use cbrd::cgrp::Listings;
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        self.load_desk().await?;
        let now = self.group_clock()?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let me = owner.member().map_err(group_error)?;
        let snapshot = owner.snapshot().await.map_err(group_error)?;
        let mut listings = self
            .desk
            .listings
            .take()
            .unwrap_or_else(|| Listings::new(snapshot.community(), &me));
        listings.prune(&snapshot);
        self.desk
            .listing_sent
            .retain(|group, _| snapshot.members(group).is_ok());
        let mut work = vec![];
        let mut shares = vec![];
        for group in listings.public_groups(&snapshot) {
            let mut originated = false;
            if listings.holds(&group) && listings.rotation_due(&snapshot, &group, now) {
                if let Ok(rotation) = listings.rotate(&snapshot, &group, now) {
                    work.push(ListingWork {
                        room: rotation.tombstone.room(),
                        entry: rotation.tombstone,
                    });
                    originated = true;
                }
            }
            if !listings.holds(&group) {
                // A fellow member may already hold the key and send it; wait one
                // cycle for that before making a second one.
                if self.desk.listing_wait.insert(group) {
                    continue;
                }
                if listings.create(&snapshot, &group).is_err() {
                    continue;
                }
                originated = true;
            }
            if originated {
                self.desk.listing_sent.insert(group, BTreeSet::new());
            }
            if let Ok(entry) = listings.sign_listing(&snapshot, &group, now, false) {
                work.push(ListingWork {
                    room: entry.room(),
                    entry,
                });
            }
            if let Some(sent) = self.desk.listing_sent.get_mut(&group) {
                let members = snapshot.members(&group).map_err(group_error)?.clone();
                let share = listings.share(&group).map_err(group_error)?;
                let text = cbrd::GroupMessage::Listing {
                    version: cbrd::INVITE_VERSION,
                    share,
                }
                .to_text()
                .map_err(group_error)?;
                for member in members {
                    if member != me && sent.insert(member.clone()) {
                        shares.push(super::GroupInvite {
                            member,
                            text: text.clone(),
                        });
                    }
                }
            }
        }
        self.desk.listings = Some(listings);
        self.save_desk().await?;
        Ok(ListingPlan { work, shares })
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
    super::ensure_room(door, key, request.room).await?;
    let (board, expires) = handles(door, key)?;
    Ok((board.room_join(request, expires).await?, vec![]))
}

pub(in crate::door) async fn room_serve(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomRef,
) -> Result<(RoomServed, Vec<Event>)> {
    super::ensure_room(door, key, request.room).await?;
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

pub(in crate::door) async fn room_admit(
    door: &mut Door,
    key: &[u8; 32],
    request: RoomRef,
) -> Result<(RoomAdmitted, Vec<Event>)> {
    super::ensure_room(door, key, request.room).await?;
    let (board, expires) = handles(door, key)?;
    Ok((board.room_admit(request, expires).await?, vec![]))
}

/// `board.room_listing`: publish the listing of every public room this member
/// belongs to and report the key shares owed to fellow members. Publishing
/// needs the room connection (the device makes it) and the listing key.
pub(in crate::door) async fn room_listing(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(RoomsListed, Vec<Event>)> {
    let (board, _) = handles(door, key)?;
    let plan = board.room_listing().await?;
    let mut published = 0;
    for item in plan.work {
        if super::ensure_room(door, key, item.room).await.is_err() {
            continue;
        }
        let (board, _) = handles(door, key)?;
        let mut operation = [0; 16];
        getrandom::fill(&mut operation).map_err(|_| ErrorCode::Unavailable)?;
        let sent = board
            .execute_room(cbrd::clnk::cmbl::Request {
                room: item.room,
                operation,
                action: cbrd::clnk::cmbl::Action::Publish { entry: item.entry },
            })
            .await;
        if sent.is_ok() {
            published += 1;
        }
    }
    Ok((
        RoomsListed {
            published,
            shares: plan.shares,
        },
        vec![],
    ))
}

/// `board.room_refs`: the public rooms this member belongs to and holds the
/// listing key of, as (room, group) pairs, for the serve and admit rounds.
pub(in crate::door) async fn room_refs(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<RoomRef>, Vec<Event>)> {
    let (board, _) = handles(door, key)?;
    Ok((board.room_refs().await?, vec![]))
}
