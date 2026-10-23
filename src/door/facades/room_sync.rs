//! Room epoch catch-up on the bound Vault, in one owner-level call.
//!
//! A member that was offline (or lost the race to commit) holds an older MLS
//! epoch than the room. The room keeps the admissions other members ordered as
//! relayed frames sealed under each epoch's transport key. This walks them
//! epoch by epoch with the existing receive and verify paths only: the join
//! that was made for exactly this device's epoch and the member commit that
//! followed it are applied together (`catch_up_room`), a frame that fails
//! verification is refused for good and leaves the state untouched, and a
//! room this device cannot follow is reported as a typed [`RoomSync`] status.
//! No new frame kind and no new key exist for this.
use super::group_custody::{RemoveStep, RoomAdmitTask, RoomRemoveTask};
use super::*;
use cbrd::cgrp;
use std::collections::BTreeSet;

/// Where a room stands for this device after an admission call. Never a silent
/// stall: a device that cannot reach the room's epoch says so here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RoomSync {
    /// This device holds the epoch the room's relayed commits lead to.
    Current,
    /// An admission at this device's epoch is not finished yet (its context
    /// commit is not in the room, or the attempt must be repeated): call again.
    Pending,
    /// This device cannot reach the room's epoch from the commits the room
    /// holds: the room needs a resync (an external rejoin).
    NeedsResync { reason: ResyncReason },
}

/// Why a room needs a resync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResyncReason {
    /// The relay no longer holds the room's oldest frames.
    HistoryGap,
    /// Later frames exist but the commit made for this device's epoch is not
    /// in the room.
    CommitMissing,
    /// The commit made for this device's epoch failed verification here
    /// (forged, tampered or its consent expired) while the room moved on.
    CommitRefused,
}

/// The ordered joins this device refused, by (room, ordering, relay sequence):
/// a refused frame is not verified again.
pub type RefusedJoins = BTreeSet<([u8; 16], [u8; 16], u64)>;

/// What one room sync walks: the room, its group and the admission policy.
pub struct RoomSyncTask<'a> {
    pub room: [u8; 16],
    pub group: cgrp::Id,
    pub max_groups: usize,
    pub policy: &'a dyn cgrp::PolicySource,
    /// Frames refused before; the ones refused by this call are added.
    pub refused: &'a mut RefusedJoins,
}

/// What one room sync did.
#[derive(Debug, PartialEq, Eq)]
pub struct RoomSynced {
    /// Newcomers this device admitted itself (ordered a new commit).
    pub admitted: u32,
    /// Admissions other members ordered that this device applied.
    pub caught_up: u32,
    /// Joins refused by this call.
    pub refused: u32,
    pub sync: RoomSync,
    /// The newcomers this call admitted or applied and the epoch each led to.
    pub joined: Vec<(String, u64)>,
    /// The members this call removed (committed or applied) after they announced
    /// their own leave.
    pub left: Vec<String>,
    /// A remaining member's authentic commit removed THIS device (it announced
    /// its own leave); its state was not changed by this call.
    pub removed: bool,
    /// This device's epoch changed during the call.
    pub advanced: bool,
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Bring this device up to the room: read the room's retained frames once,
    /// then, epoch by epoch, apply the admission made for the epoch this device
    /// holds (the newcomer's join with its consent and the member commit that
    /// followed it) or, when no member ordered one yet, admit the waiting
    /// newcomer itself. Every frame is verified by `admit_room` /
    /// `catch_up_room` exactly as a live admission is; one that fails is added
    /// to `task.refused` and skipped for good, with this device's state
    /// untouched. A lost race re-reads the room once and applies the winner's
    /// context commit instead.
    pub async fn sync_room<T, L>(
        &mut self,
        board: &cbrd::Board<T, L>,
        task: RoomSyncTask<'_>,
    ) -> std::result::Result<RoomSynced, ctnd::Error>
    where
        T: cbrd::clnk::Transport,
        L: crate::door::RoomLink,
    {
        use ctnd::Error as Fail;
        let RoomSyncTask {
            room,
            group,
            max_groups,
            policy,
            refused: refused_set,
        } = task;
        let mut frames = L::room_frames(board, room).await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "Fail::Unavailable",
                Fail::Unavailable,
                &__cause,
            )
        })?;
        let start = self.room_keys_standing(group).await?.epoch;
        let (mut admitted, mut caught_up, mut refused) = (0, 0, 0);
        let (mut pending, mut raced) = (false, false);
        let mut joined = vec![];
        let me = self.own_member().to_owned();
        let mut left = vec![];
        let mut removed = false;
        for _ in 0..MAX_ROOM_APPLY {
            let transport = self.room_transport_key(group).await?;
            let epoch = self.room_keys_standing(group).await?.epoch;
            let Some(next) = next_step(&frames, &room, &transport, epoch, &me, true, |sequence| {
                refused_set.contains(&(room, frames.ordering, sequence))
            }) else {
                break;
            };
            let position = next.position();
            let sequence = frames.frames[position].sequence;
            // Whether this device orders a new commit in this step (and may lose
            // the race to another member that did first).
            let (done, committing) = match next {
                Next::Join { join, .. } => {
                    let context = context_after(&frames, position, &room, &transport, epoch);
                    let frame = cbrd::JoinFrame {
                        ordering: frames.ordering,
                        counter: frames.frames[position].counter,
                        commit: join.commit,
                        companion: join.companion,
                    };
                    let step = RoomAdmitTask {
                        room,
                        group,
                        frame: &frame,
                        max_groups,
                        transport: &transport,
                        policy,
                    };
                    let done = match &context {
                        Some(context) => self.catch_up_room(board, step, context).await,
                        None => self.admit_room(board, step).await,
                    };
                    if done.is_ok() {
                        if context.is_some() {
                            caught_up += 1;
                        } else {
                            admitted += 1;
                        }
                        // The newcomer's hand-over can only be from this epoch on.
                        if let (Some(companion), Ok(standing)) = (
                            cbrd::RoomCompanion::decode(&frame.companion),
                            self.room_keys_standing(group).await,
                        ) {
                            joined.push((companion.request.actor, standing.epoch));
                        }
                    }
                    (done.map(|_| ()), context.is_none())
                }
                Next::Removal {
                    commit, companion, ..
                } if leaver_of(&companion).as_deref() == Some(me.as_str()) => {
                    // The commit removes this device: only an authentic one counts.
                    match self.confirm_room_removal(group, &commit).await {
                        Ok(true) => {
                            removed = true;
                            break;
                        }
                        Ok(false) => (Err(Fail::Authority), false),
                        Err(error) => (Err(error), false),
                    }
                }
                Next::Removal {
                    commit, companion, ..
                } => {
                    let done = self
                        .remove_room(
                            board,
                            RoomRemoveTask {
                                room,
                                group,
                                companion: &companion,
                                max_groups,
                                transport: &transport,
                                policy,
                                step: RemoveStep::Apply { commit: &commit },
                            },
                        )
                        .await;
                    if done.is_ok() {
                        caught_up += 1;
                        left.extend(leaver_of(&companion));
                    }
                    (done.map(|_| ()), false)
                }
                Next::Notice { companion, .. } => {
                    // The counter in force: the room's latest ordered commit.
                    let expected = frames
                        .frames
                        .iter()
                        .map(|frame| frame.counter)
                        .max()
                        .unwrap_or_default();
                    let done = self
                        .remove_room(
                            board,
                            RoomRemoveTask {
                                room,
                                group,
                                companion: &companion,
                                max_groups,
                                transport: &transport,
                                policy,
                                step: RemoveStep::Commit {
                                    ordering: frames.ordering,
                                    expected,
                                },
                            },
                        )
                        .await;
                    if done.is_ok() {
                        admitted += 1;
                        left.extend(leaver_of(&companion));
                    }
                    (done.map(|_| ()), true)
                }
            };
            match done {
                Ok(()) => {}
                // Another member's commit may have been ordered first: read the
                // room once more, then apply it instead.
                Err(Fail::Reconcile | Fail::Storage) if committing && !raced => {
                    raced = true;
                    frames = L::room_frames(board, room).await.map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "Fail::Unavailable",
                            Fail::Unavailable,
                            &__cause,
                        )
                    })?;
                }
                Err(Fail::Unavailable | Fail::Reconcile | Fail::Storage) => {
                    pending = true;
                    break;
                }
                Err(__cause) => {
                    crate::door::cause::print(
                        file!(),
                        line!(),
                        "refused_set insert room frames ordering sequence refused 1",
                        &__cause,
                    );
                    {
                        refused_set.insert((room, frames.ordering, sequence));
                        refused += 1;
                    }
                }
            }
        }
        let end = self.room_keys_standing(group).await?.epoch;
        let advanced = end != start;
        let sync = if pending {
            RoomSync::Pending
        } else {
            let transport = self.room_transport_key(group).await?;
            // A join made for the epoch this device holds exists but failed
            // verification here: this device cannot move on from the room.
            let blocked = next_step(&frames, &room, &transport, end, &me, false, |sequence| {
                !refused_set.contains(&(room, frames.ordering, sequence))
            })
            .is_some();
            sync_status(
                &frames,
                &room,
                &transport,
                advanced,
                blocked,
                refused_set.iter().any(|(held, _, _)| *held == room),
            )
        };
        Ok(RoomSynced {
            admitted,
            caught_up,
            refused,
            sync,
            joined,
            left,
            removed,
            advanced,
        })
    }
}

/// The most joins one call applies (each moves the epoch on by two).
const MAX_ROOM_APPLY: usize = 64;

/// What the room asks of this device at the epoch it holds.
enum Next {
    /// A newcomer's external commit made for exactly this epoch.
    Join { position: usize, join: cbrd::OrderedCommit },
    /// A member commit made for exactly this epoch that removes a leaver (its
    /// companion is the leaver's signed Groups `Leave`).
    Removal {
        position: usize,
        commit: Vec<u8>,
        companion: Vec<u8>,
    },
    /// A member's leave notice with no removal commit after it yet: this device
    /// may commit the removal.
    Notice { position: usize, companion: Vec<u8> },
}

impl Next {
    fn position(&self) -> usize {
        match self {
            Next::Join { position, .. }
            | Next::Removal { position, .. }
            | Next::Notice { position, .. } => *position,
        }
    }
}

/// The member who announced the leave a companion carries.
fn leaver_of(companion: &[u8]) -> Option<String> {
    cbrd::RoomCompanion::decode(companion).map(|decoded| decoded.request.actor)
}

/// The first frame, oldest first, that opens under the key of the epoch this
/// device holds as a join or removal made for exactly that epoch, or as a leave
/// notice nobody has removed yet. A device never acts on its own notice.
fn next_step(
    frames: &cbrd::RoomFrames,
    room: &[u8; 16],
    key: &cbrd::TransportKey,
    epoch: u64,
    me: &str,
    notices: bool,
    refused: impl Fn(u64) -> bool,
) -> Option<Next> {
    let removed_later = |from: usize, leaver: &str| {
        frames.frames[from + 1..].iter().any(|frame| {
            matches!(
                frame.open(room, key),
                Some(cbrd::FrameContent::Commit(ref commit))
                    if cthr::wire_epoch(&commit.commit).ok() == Some(epoch)
                        && leaver_of(&commit.companion).as_deref() == Some(leaver)
                        && cbrd::RoomCompanion::is_leave(&commit.companion)
            )
        })
    };
    frames
        .frames
        .iter()
        .enumerate()
        .find_map(|(position, frame)| {
            if refused(frame.sequence) {
                return None;
            }
            match frame.open(room, key)? {
                cbrd::FrameContent::Commit(commit)
                    if !commit.companion.is_empty()
                        && cthr::wire_epoch(&commit.commit).ok() == Some(epoch) =>
                {
                    Some(if cbrd::RoomCompanion::is_leave(&commit.companion) {
                        Next::Removal {
                            position,
                            commit: commit.commit,
                            companion: commit.companion,
                        }
                    } else {
                        Next::Join {
                            position,
                            join: commit,
                        }
                    })
                }
                cbrd::FrameContent::Notice(companion) => {
                    let leaver = leaver_of(&companion)?;
                    (notices && leaver != me && !removed_later(position, &leaver))
                        .then_some(Next::Notice { position, companion })
                }
                _ => None,
            }
        })
}

/// The member commit that followed the join at `position`: the next frame that
/// opens as a bare commit made for the epoch the join leads to.
fn context_after(
    frames: &cbrd::RoomFrames,
    position: usize,
    room: &[u8; 16],
    key: &cbrd::TransportKey,
    epoch: u64,
) -> Option<Vec<u8>> {
    frames.frames[position + 1..]
        .iter()
        .find_map(|frame| match frame.open(room, key)? {
            cbrd::FrameContent::Commit(context)
                if context.companion.is_empty()
                    && cthr::wire_epoch(&context.commit).ok() == Some(epoch.checked_add(1)?) =>
            {
                Some(context.commit)
            }
            _ => None,
        })
}

/// Where the room stands for a device that applied everything it could. A
/// frame sealed under a key this device does not hold is of a LATER epoch when
/// its counter is above every frame of this device's epoch (a frame of the
/// current epoch carries the counter in force, which only a later commit
/// raises): then the commit that leads on from here is missing or was refused.
/// With nothing readable at all the room's history is judged by the relay's own
/// `gap` flag. `progressed` is a call that moved this device on; `blocked` is a
/// refused join made for the epoch this device still holds.
fn sync_status(
    frames: &cbrd::RoomFrames,
    room: &[u8; 16],
    key: &cbrd::TransportKey,
    progressed: bool,
    blocked: bool,
    refused: bool,
) -> RoomSync {
    if blocked {
        return RoomSync::NeedsResync {
            reason: ResyncReason::CommitRefused,
        };
    }
    let readable = frames
        .frames
        .iter()
        .filter(|frame| frame.open(room, key).is_some())
        .map(|frame| frame.counter)
        .max();
    let ahead = frames.frames.iter().any(|frame| {
        frame.open(room, key).is_none() && readable.is_some_and(|top| frame.counter > top)
    });
    let unreadable = frames
        .frames
        .iter()
        .any(|frame| frame.open(room, key).is_none());
    let reason = if refused {
        ResyncReason::CommitRefused
    } else if frames.gap {
        ResyncReason::HistoryGap
    } else {
        ResyncReason::CommitMissing
    };
    match readable {
        Some(_) if ahead => RoomSync::NeedsResync { reason },
        None if frames.gap && unreadable && !progressed => RoomSync::NeedsResync {
            reason: ResyncReason::HistoryGap,
        },
        _ => RoomSync::Current,
    }
}
