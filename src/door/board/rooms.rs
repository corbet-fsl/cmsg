//! Member rooms for the member: join by request and sealed answer, leave, and
//! answering other members' join requests. The caller names the room and the
//! group only. The ephemeral key, the sealing, the consent and the ordered
//! commit all come from the retained owner and the original libraries; nothing
//! is ever published in the clear, and a join with nobody online simply waits.
use super::handlers::{group_error, with_context, OwnedBoard, MAX_GROUPS};
use super::room_keys;
use super::ProfileParts;
use super::*;
pub use crate::door::facades::RoomSync;
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
    /// Admissions other members ordered that this device applied to catch up.
    pub caught_up: u32,
    /// Where the room stands for this device after the call.
    pub sync: RoomSync,
    /// Ordered joins this device refused (unverifiable newcomer or consent).
    pub refused: u32,
    /// Profile keys of fellow members this call adopted (row 14.5).
    pub keys_adopted: u32,
    /// Hand-overs this call refused: nothing was stored for them.
    pub keys_refused: u32,
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
    /// Ordered joins this device refused, by (room, ordering, relay sequence):
    /// a refused frame is not verified again.
    refused: std::collections::BTreeSet<([u8; 16], [u8; 16], u64)>,
    /// How far this device has read each room's secrets (relay sequence).
    secrets_through: BTreeMap<[u8; 16], u64>,
    /// The epoch this device last sent its own profile key to each room in.
    key_sent: BTreeMap<[u8; 16], u64>,
    /// The epoch each newcomer this device admitted joined in: the first epoch
    /// its hand-over can be from.
    joined_in: BTreeMap<[u8; 16], BTreeMap<String, u64>>,
}

/// The member's own committed profile key as a room hand-over; `None` when no
/// profile is committed. The current Charter judges the publication exactly as
/// it does for every other read.
fn own_handover<B: cwst::backend::Backend>(
    context: &cbrd::ReadContext<'_, B>,
    custody: &cbrd::cnvl::Custodian<'_>,
    now: u64,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let policy = context
        .charter
        .current_admission_policy(context.policy.admission_action, now)
        .map_err(|_| ErrorCode::Refused)?;
    let signed_schema = context
        .charter
        .publication(cchr::Kind::Schema)
        .signed_bytes();
    let Some(committed) = cpfl::load_current_committed(
        context.store,
        context.binding,
        cpfl::Validation {
            policy,
            signed_schema,
            contact: context.contact,
        },
    )
    .map_err(|_| ErrorCode::Refused)?
    else {
        return Ok(None);
    };
    let verified = committed.verified();
    let wrapped = context
        .store
        .read(
            "profile.keys",
            &verified.transcript().revision.to_be_bytes(),
        )
        .map_err(|_| ErrorCode::Reconcile)?
        .ok_or(ErrorCode::Unavailable)?;
    let key = custody
        .restore(
            verified.context(),
            &cbrd::cnvl::WrappedReadKey::from_bytes(wrapped).map_err(|_| ErrorCode::Refused)?,
        )
        .map_err(|_| ErrorCode::Refused)?;
    room_keys::handover(&key)
        .map(Some)
        .map_err(|_| ErrorCode::Refused)
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
        self.refused.retain(|(held, _, _)| *held != room);
        self.secrets_through.remove(&room);
        self.key_sent.remove(&room);
        self.joined_in.remove(&room);
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
        // Nothing is prepared, signed or sent before the delivered state is
        // authenticated against the MLS evidence it came with.
        let verified = self
            .owner
            .verify_room_state(join.group, &state.evidence, &state.handles)
            .await?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let (candidate, current, now, request) = cbrd::prepare_join_from_state(
            owner,
            &source,
            join.group,
            Default::default(),
            &verified,
            MAX_GROUPS,
        )
        .await
        .map_err(group_error)?;
        // The signed Join request rides with the ordered commit (the owner adds
        // the handle of this member's own lineage); members admit the newcomer
        // only with it.
        // The member's own profile key goes to the room in the epoch of its
        // admission, if it published a profile (joining a public room is the
        // consent to visible profiles).
        let handover = self.own_room_handover(expires).await?;
        let joined = self
            .owner
            .join_room(
                &self.inner.board,
                crate::door::facades::RoomJoinTask {
                    room: join.room,
                    group: join.group,
                    candidate,
                    request,
                    evidence: &state.evidence,
                    parent: &verified,
                    handles: &state.handles,
                    transport: &cbrd::TransportKey::from_keys(&state.transport),
                    policy: &source,
                    handover,
                },
            )
            .await?;
        // The joined member is in; delivering the hand-over is best effort and
        // is repeated by every admit call until it reaches the room.
        self.deliver_handover(join.room, join.group, &joined.handover)
            .await;
        joined.snapshot.views(&current, now).map_err(group_error)
    }

    /// The member's own profile key as a room hand-over: empty when it has not
    /// published a profile or its owner has no profile custody.
    async fn own_room_handover(
        &mut self,
        expires: u64,
    ) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
        let community = self.inner.board.community().to_owned();
        let current = &mut self.current;
        let policy = &self.policy;
        let made = self
            .owner
            .with_profile(|parts| {
                let ProfileParts { read, custody, .. } = parts;
                with_context(
                    current,
                    policy,
                    &community,
                    expires,
                    read,
                    |context, now| own_handover(context, &custody, now),
                )
            })
            .await;
        match made {
            Ok(held) => Ok(held.into_iter().collect()),
            Err(ErrorCode::Unavailable) => Ok(vec![]),
            Err(error) => Err(error),
        }
    }

    /// Relay the sealed hand-over messages of a join to the room, under the
    /// transport key of the epoch they were sealed in.
    async fn deliver_handover(&mut self, room: [u8; 16], group: [u8; 32], sealed: &[Vec<u8>]) {
        if sealed.is_empty() {
            return;
        }
        let Ok(standing) = self.owner.room_keys_standing(group).await else {
            return;
        };
        let Ok(key) = self.owner.room_transport_key(group).await else {
            return;
        };
        for message in sealed {
            if R::relay_room_secret(&self.inner.board, room, &key, message)
                .await
                .is_err()
            {
                return;
            }
        }
        self.joins.key_sent.insert(room, standing.epoch);
    }

    /// The profile-key hand-over of one room (row 14.5), once per call and safe
    /// to repeat: send this member's own key if it has not sent it in the
    /// current epoch, then open the room secrets that arrived and adopt the
    /// keys they hand over. Returns `(adopted, refused)`.
    async fn room_keys_step(
        &mut self,
        room: &RoomRef,
        source: &impl cbrd::cgrp::PolicySource,
        expires: u64,
    ) -> Result<(u32, u32)> {
        let standing = self.owner.room_keys_standing(room.group).await?;
        let transport = self.owner.room_transport_key(room.group).await?;
        // A failed send is repeated by the next call (the epoch is not marked
        // as sent) and never holds back what has already arrived.
        let _ = self
            .send_own_room_key(room, source, expires, standing.epoch, &transport)
            .await;
        let after = self
            .joins
            .secrets_through
            .get(&room.room)
            .copied()
            .unwrap_or(0);
        let read = R::room_secrets(&self.inner.board, room.room, after, &transport)
            .await
            .map_err(link)?;
        let messages: Vec<Vec<u8>> = read
            .secrets
            .into_iter()
            .map(|frame| frame.message)
            .collect();
        let joined = self
            .joins
            .joined_in
            .get(&room.room)
            .cloned()
            .unwrap_or_default();
        let received = self
            .owner
            .receive_room_secrets(crate::door::facades::RoomSecretsTask {
                group: room.group,
                messages: &messages,
                joined: &joined,
                policy: source,
            })
            .await?;
        self.joins.secrets_through.insert(room.room, read.through);
        Ok((received.adopted.len() as u32, received.refused))
    }

    /// Send this member's own profile key to the room, sealed in `epoch`, unless
    /// it already did in that epoch. A member without a published profile has
    /// nothing to send.
    async fn send_own_room_key(
        &mut self,
        room: &RoomRef,
        source: &impl cbrd::cgrp::PolicySource,
        expires: u64,
        epoch: u64,
        transport: &cbrd::TransportKey,
    ) -> Result<()> {
        if self.joins.key_sent.get(&room.room) == Some(&epoch) {
            return Ok(());
        }
        let handover = self.own_room_handover(expires).await?;
        if let Some(payload) = handover.first() {
            let sealed = self
                .owner
                .seal_room_key(crate::door::facades::RoomKeyTask {
                    group: room.group,
                    payload,
                    policy: source,
                })
                .await?;
            R::relay_room_secret(&self.inner.board, room.room, transport, &sealed.message)
                .await
                .map_err(link)?;
        }
        self.joins.key_sent.insert(room.room, epoch);
        Ok(())
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
                let (views, _) = cbrd::execute_group_intent(owner, &source, intent, MAX_GROUPS)
                    .await
                    .map_err(group_error)?;
                Ok(views)
            }
        }
    }

    /// Bring this device to the room's epoch and admit the newcomers waiting
    /// at it. The room holds every join as two ordered commits (the newcomer's
    /// external commit, then the member commit that installs the context), both
    /// sealed under the key of the epoch they were made for. This device opens
    /// the next frame with ITS epoch's key and applies a commit only to exactly
    /// that epoch: a join whose context commit is already in the room was
    /// admitted by another member (a device that was offline, or that lost the
    /// race to commit, catches up by applying it); a join without one is
    /// admitted here (today's path). Each join is verified from its own
    /// evidence (see `VaultGroupOwner::admit_room`); a newcomer that fails
    /// verification is skipped for good, while an unavailable or conflicting
    /// attempt is repeated by the next call. Whatever this device cannot apply
    /// is reported in `sync`, never dropped silently.
    pub(super) async fn room_admit_step(
        &mut self,
        room: RoomRef,
        expires: u64,
    ) -> Result<RoomAdmitted> {
        self.idle()?;
        if !R::ROOMS || self.owner.groups().is_none() {
            return Err(ErrorCode::Unavailable);
        }
        let source = self.group_policy(expires).await?;
        let synced = self
            .owner
            .sync_room(
                &self.inner.board,
                crate::door::facades::RoomSyncTask {
                    room: room.room,
                    group: room.group,
                    max_groups: MAX_GROUPS,
                    policy: &source,
                    refused: &mut self.joins.refused,
                },
            )
            .await?;
        for (actor, epoch) in synced.joined {
            self.joins
                .joined_in
                .entry(room.room)
                .or_default()
                .insert(actor, epoch);
        }
        if synced.advanced {
            // Secrets sealed in the epochs this device just reached were
            // unreadable before: read the room's secrets again from the start.
            self.joins.secrets_through.remove(&room.room);
        }
        let (admitted, caught_up, refused, sync) = (
            synced.admitted,
            synced.caught_up,
            synced.refused,
            synced.sync,
        );
        // Profile keys follow the admissions in the same call. A failure here
        // never undoes an admission (it is committed); the next call repeats it.
        let (keys_adopted, keys_refused) = self
            .room_keys_step(&room, &source, expires)
            .await
            .unwrap_or((0, 0));
        let groups = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let snapshot = groups.snapshot().await.map_err(group_error)?;
        let now = groups.now().map_err(group_error)?;
        let current = source
            .current(snapshot.community(), now)
            .map_err(group_error)?;
        Ok(RoomAdmitted {
            admitted,
            caught_up,
            sync,
            refused,
            keys_adopted,
            keys_refused,
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
