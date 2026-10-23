//! Room epoch catch-up end to end over real owners: a member that was offline
//! while other members admitted newcomers reads the room's retained frames and
//! applies, in order, only the commit made for its own epoch. Every frame goes
//! through the same verification a live admission does; what cannot be applied
//! leaves the state untouched and is reported as a typed status.
use super::*;
use crate::door::facades::{
    RefusedJoins, ResyncReason, RoomAdmitTask, RoomJoined, RoomSync, RoomSyncTask, RoomSynced,
};

/// The room as its online member `a` holds it, and the relay all boards share.
struct Room {
    router: Arc<Router>,
    directory: Directory,
    a: ProfileOwner,
    a_board: RoomBoard,
    cursor: u64,
}

type Mode = Rc<RefCell<Box<dyn Fn(&mut cmbl::Outcome)>>>;

/// A device admitted to the room.
struct Newcomer {
    owner: ProfileOwner,
    board: RoomBoard,
    joined: RoomJoined,
    key: Vec<u8>,
    /// The epoch the room (and this device) stood at right after its admission.
    epoch: u64,
}

impl Room {
    async fn found() -> Room {
        let Scene {
            router,
            directory,
            member,
            member_board,
            ..
        } = scene().await;
        Room {
            router,
            directory,
            a: member,
            a_board: member_board,
            cursor: 0,
        }
    }

    /// A stranger joins and is admitted by `a` alone: every other member is
    /// offline while this happens.
    async fn admit(&mut self, letter: &str, prf: u8) -> Newcomer {
        let (mut owner, _) = stranger(&self.directory, letter, prf).await;
        let board = board(&self.router, 60, false).await;
        let key = own_key(&owner, letter).await;
        let evidence = self
            .a
            .groups
            .as_mut()
            .unwrap()
            .room_evidence(GROUP, &policy_at())
            .await
            .unwrap();
        let (joined, admitted) = attempt(
            &mut owner,
            &board,
            &evidence,
            &mut self.a,
            &self.a_board,
            &mut self.cursor,
            vec![zeroize::Zeroizing::new(key.clone())],
        )
        .await;
        assert_eq!(
            admitted.len(),
            1,
            "admitting {letter}: join error {:?}",
            joined.as_ref().err()
        );
        admitted[0].as_ref().unwrap();
        let joined = joined.unwrap();
        let epoch = standing(&self.a).await.1;
        assert_eq!(standing(&owner).await.1, epoch);
        Newcomer {
            owner,
            board,
            joined,
            key,
            epoch,
        }
    }

    /// One board whose reads go through a relay that changes what they return;
    /// `Mode` switches how (the room admits only a few connections).
    async fn through(&self) -> (RoomBoard, Mode) {
        let mode: Mode = Rc::new(RefCell::new(Box::new(|_: &mut cmbl::Outcome| {})));
        let seen = mode.clone();
        let board = board_through(
            &self.router,
            0,
            false,
            Some(Rc::new(move |outcome: &mut cmbl::Outcome| {
                (seen.borrow())(outcome)
            })),
        )
        .await;
        (board, mode)
    }
}

async fn sync(
    owner: &mut ProfileOwner,
    board: &RoomBoard,
    refused: &mut RefusedJoins,
) -> RoomSynced {
    let policy = policy_at();
    owner
        .groups
        .as_mut()
        .unwrap()
        .sync_room(
            board,
            RoomSyncTask {
                room: ROOM,
                group: GROUP,
                max_groups: 10,
                policy: &policy,
                refused,
            },
        )
        .await
        .unwrap()
}

fn ids(letters: &[&str]) -> BTreeSet<String> {
    letters.iter().map(|letter| member_id(letter)).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn a_member_offline_across_two_admissions_catches_up_adopts_the_keys_and_sends() {
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    // `b` goes offline here; `c` and then `d` are admitted without it.
    let c = room.admit("c", 33).await;
    let d = room.admit("d", 37).await;
    let (_, behind) = standing(&b.owner).await;
    let (members, ahead) = standing(&room.a).await;
    assert_eq!(members, ids(&["a", "x", "y", "b", "c", "d"]));
    assert_eq!(behind, b.epoch);
    assert_eq!(ahead, d.epoch);
    assert!(ahead > behind + 2);
    assert_ne!(standing(&b.owner).await.0, members);

    let mut refused = RefusedJoins::new();
    let synced = sync(&mut b.owner, &b.board, &mut refused).await;
    assert_eq!(
        (synced.admitted, synced.caught_up, synced.refused),
        (0, 2, 0)
    );
    assert_eq!(synced.sync, RoomSync::Current);
    assert!(synced.advanced);
    assert_eq!(
        synced.joined,
        vec![(member_id("c"), c.epoch), (member_id("d"), d.epoch)]
    );
    assert_eq!(standing(&b.owner).await, (members.clone(), ahead));
    assert!(refused.is_empty());

    // Nothing is left to apply: a second call changes nothing.
    let again = sync(&mut b.owner, &b.board, &mut refused).await;
    assert_eq!((again.admitted, again.caught_up, again.refused), (0, 0, 0));
    assert_eq!(again.sync, RoomSync::Current);
    assert!(!again.advanced);
    assert_eq!(standing(&b.owner).await.1, ahead);

    // Back in the room's epoch, `b` reads the keys sent in it and sends its own.
    let policy = policy_at();
    let a_key = own_key(&room.a, "a").await;
    let from_a = room
        .a
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &a_key,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(from_a.epoch, ahead);
    let joined: BTreeMap<String, u64> = synced.joined.iter().cloned().collect();
    let messages = vec![from_a.message, d.joined.handover[0].clone()];
    let adopted = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: &messages,
            joined: &joined,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(adopted.adopted, ids(&["a", "d"]));
    assert_eq!(adopted.refused, 0);
    let held = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .room_keys_standing(GROUP)
        .await
        .unwrap()
        .held;
    assert_eq!(held, ids(&["a", "d"]));

    let from_b = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &b.key,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(from_b.epoch, ahead);
    let received = room
        .a
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&from_b.message),
            joined: &BTreeMap::from([(member_id("b"), b.epoch)]),
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(received.adopted, ids(&["b"]));
    assert_eq!(received.refused, 0);
}

/// Every commit frame of the room that opens under `key`, oldest first:
/// `(relay sequence, counter, commit)`.
async fn commits_at(
    board: &RoomBoard,
    key: &cbrd::TransportKey,
) -> Vec<(u64, u64, cbrd::OrderedCommit)> {
    board
        .room_frames(ROOM)
        .await
        .unwrap()
        .frames
        .iter()
        .filter_map(|frame| match frame.open(&ROOM, key)? {
            cbrd::FrameContent::Commit(commit) => Some((frame.sequence, frame.counter, commit)),
            cbrd::FrameContent::Secret | cbrd::FrameContent::Notice(_) => None,
        })
        .collect()
}

/// A relay that hides the frames with these sequences, puts `forged` frames in
/// front of the rest and may report that it dropped the room's oldest frames.
fn rewrite(
    hide: Vec<u64>,
    forged: Vec<cmbl::RelayFrame>,
    gap: bool,
) -> impl Fn(&mut cmbl::Outcome) {
    move |outcome| {
        outcome
            .frames
            .retain(|frame| !hide.contains(&frame.sequence));
        for (at, frame) in forged.iter().enumerate() {
            outcome.frames.insert(at, frame.clone());
        }
        outcome.gap |= gap;
    }
}

async fn transport(owner: &mut ProfileOwner) -> cbrd::TransportKey {
    owner
        .groups
        .as_mut()
        .unwrap()
        .room_transport_key(GROUP)
        .await
        .unwrap()
}

/// `b` hands its profile key over in its epoch, the way a member does right
/// after it joined: the room carries a frame of that epoch before it goes on.
async fn relay_own_key(b: &mut Newcomer) {
    let key = transport(&mut b.owner).await;
    let sealed = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &b.key,
            policy: &policy_at(),
        })
        .await
        .unwrap();
    b.board
        .relay_room_secret(ROOM, &key, &sealed.message)
        .await
        .unwrap();
}

fn needs(reason: ResyncReason) -> RoomSync {
    RoomSync::NeedsResync { reason }
}

#[tokio::test(flavor = "current_thread")]
async fn forged_commits_are_refused_untouched_and_the_real_ones_still_apply() {
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    room.admit("c", 33).await;
    room.admit("d", 37).await;
    let key = transport(&mut b.owner).await;
    let real = commits_at(&b.board, &key).await;
    assert_eq!(
        real.len(),
        2,
        "the join for b's epoch and its context commit"
    );
    let (_, counter, join) = real
        .iter()
        .find(|(_, _, commit)| !commit.companion.is_empty())
        .cloned()
        .unwrap();
    let forge = |commit: &[u8], companion: &[u8], sequence: u64| cmbl::RelayFrame {
        kind: cmbl::FrameKind::Message,
        sequence,
        counter,
        ciphertext: key
            .wrap(&ROOM, &ctnd::pack_ordered(commit, companion))
            .unwrap(),
    };
    // Sealed under the epoch's own key, as only a holder of it could: one
    // commit with a flipped byte, one real commit with a damaged consent.
    let mut bad_commit = join.commit.clone();
    *bad_commit.last_mut().unwrap() ^= 1;
    let mut bad_companion = join.companion.clone();
    *bad_companion.last_mut().unwrap() ^= 1;
    let forged = vec![
        forge(&bad_commit, &join.companion, u64::MAX - 1),
        forge(&join.commit, &bad_companion, u64::MAX - 2),
    ];
    let (hostile, mode) = room.through().await;
    *mode.borrow_mut() = Box::new(rewrite(
        real.iter().map(|(sequence, _, _)| *sequence).collect(),
        forged,
        false,
    ));
    let before = standing(&b.owner).await;
    let (_, ahead) = standing(&room.a).await;
    let mut refused = RefusedJoins::new();

    let first = sync(&mut b.owner, &hostile, &mut refused).await;
    assert_eq!((first.admitted, first.caught_up, first.refused), (0, 0, 2));
    assert!(!first.advanced);
    assert!(first.joined.is_empty());
    assert_eq!(first.sync, needs(ResyncReason::CommitRefused));
    assert_eq!(standing(&b.owner).await, before);
    // A refused frame is not verified again.
    let second = sync(&mut b.owner, &hostile, &mut refused).await;
    assert_eq!((second.caught_up, second.refused), (0, 0));
    assert_eq!(second.sync, needs(ResyncReason::CommitRefused));
    assert_eq!(standing(&b.owner).await, before);

    // The room's real frames are not poisoned by the refusals.
    let real = sync(&mut b.owner, &b.board, &mut refused).await;
    assert_eq!((real.admitted, real.caught_up, real.refused), (0, 2, 0));
    assert_eq!(real.sync, RoomSync::Current);
    assert_eq!(standing(&b.owner).await.1, ahead);
    assert_eq!(standing(&b.owner).await.0, standing(&room.a).await.0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_commit_for_a_later_epoch_is_skipped_and_the_member_is_told_it_is_behind() {
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    relay_own_key(&mut b).await;
    room.admit("c", 33).await;
    room.admit("d", 37).await;
    let key = transport(&mut b.owner).await;
    let own = commits_at(&b.board, &key).await;
    assert_eq!(
        own.len(),
        2,
        "the join for b's epoch and its context commit"
    );
    // Only the admission of `d` (made for two epochs ahead) reaches `b`.
    let hide: Vec<u64> = own.iter().map(|(sequence, _, _)| *sequence).collect();
    let (hostile, mode) = room.through().await;
    *mode.borrow_mut() = Box::new(rewrite(hide.clone(), vec![], false));
    let before = standing(&b.owner).await;
    let mut refused = RefusedJoins::new();
    let synced = sync(&mut b.owner, &hostile, &mut refused).await;
    assert_eq!(
        (synced.admitted, synced.caught_up, synced.refused),
        (0, 0, 0)
    );
    assert!(!synced.advanced);
    assert_eq!(synced.sync, needs(ResyncReason::CommitMissing));
    assert_eq!(standing(&b.owner).await, before);
    assert!(refused.is_empty());

    // The same room with a relay that admits to having dropped frames: the
    // reason is the gap, whether `b` can still read a frame of its epoch or not.
    *mode.borrow_mut() = Box::new(rewrite(hide, vec![], true));
    let gap = sync(&mut b.owner, &hostile, &mut refused).await;
    assert_eq!(gap.sync, needs(ResyncReason::HistoryGap));
    let oldest = own.last().unwrap().0;
    *mode.borrow_mut() = Box::new(move |outcome: &mut cmbl::Outcome| {
        outcome.frames.retain(|frame| frame.sequence > oldest);
        outcome.gap = true;
    });
    let nothing = sync(&mut b.owner, &hostile, &mut refused).await;
    assert_eq!((nothing.caught_up, nothing.refused), (0, 0));
    assert_eq!(nothing.sync, needs(ResyncReason::HistoryGap));
    assert_eq!(standing(&b.owner).await, before);

    // And once the room is whole again the member catches up as usual.
    let whole = sync(&mut b.owner, &b.board, &mut refused).await;
    assert_eq!(whole.caught_up, 2);
    assert_eq!(whole.sync, RoomSync::Current);
}

#[tokio::test(flavor = "current_thread")]
async fn an_expired_consent_leaves_the_member_behind_and_says_so() {
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    room.admit("c", 33).await;
    let before = standing(&b.owner).await;

    // `b` comes back after the newcomer's consent ran out (an hour).
    crate::door::facades::group_custody::TEST_CONSENT_AGE.set(3_700);
    let mut refused = RefusedJoins::new();
    let late = sync(&mut b.owner, &b.board, &mut refused).await;
    crate::door::facades::group_custody::TEST_CONSENT_AGE.set(0);
    assert_eq!((late.admitted, late.caught_up, late.refused), (0, 0, 1));
    assert!(!late.advanced);
    assert_eq!(late.sync, needs(ResyncReason::CommitRefused));
    assert_eq!(standing(&b.owner).await, before);

    // The very same frames apply while the consent holds: it was the expiry.
    let in_time = sync(&mut b.owner, &b.board, &mut RefusedJoins::new()).await;
    assert_eq!((in_time.caught_up, in_time.refused), (1, 0));
    assert_eq!(in_time.sync, RoomSync::Current);
    assert_eq!(standing(&b.owner).await.1, standing(&room.a).await.1);
}

fn join_frame(ordering: cmbl::Id, commit: &(u64, u64, cbrd::OrderedCommit)) -> cbrd::JoinFrame {
    cbrd::JoinFrame {
        ordering,
        counter: commit.1,
        commit: commit.2.commit.clone(),
        companion: commit.2.companion.clone(),
    }
}

async fn catch_up(
    owner: &mut ProfileOwner,
    board: &RoomBoard,
    join: &cbrd::JoinFrame,
    context: &[u8],
) -> Result<cgrp::Snapshot, ctnd::Error> {
    let key = transport(owner).await;
    let policy = policy_at();
    owner
        .groups
        .as_mut()
        .unwrap()
        .catch_up_room(
            board,
            RoomAdmitTask {
                room: ROOM,
                group: GROUP,
                frame: join,
                max_groups: 10,
                transport: &key,
                policy: &policy,
            },
            context,
        )
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn a_commit_is_applied_only_to_the_epoch_it_was_made_for() {
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    room.admit("c", 33).await;
    let key_d = transport(&mut room.a).await;
    room.admit("d", 37).await;
    let key_c = transport(&mut b.owner).await;
    let ordering = b.board.room_frames(ROOM).await.unwrap().ordering;
    let for_c = commits_at(&b.board, &key_c).await;
    let for_d = commits_at(&b.board, &key_d).await;
    assert_eq!((for_c.len(), for_d.len()), (2, 2));
    assert!(!for_c[0].2.companion.is_empty() && for_c[1].2.companion.is_empty());
    let (join_c, join_d) = (
        join_frame(ordering, &for_c[0]),
        join_frame(ordering, &for_d[0]),
    );
    let (ctx_c, ctx_d) = (&for_c[1].2.commit, &for_d[1].2.commit);
    let before = standing(&b.owner).await;

    // A join made for a later epoch, a context commit made for a later epoch,
    // and a join standing in for the context commit: none touches the state.
    for (join, context) in [
        (&join_d, ctx_d.as_slice()),
        (&join_c, ctx_d.as_slice()),
        (&join_c, join_c.commit.as_slice()),
        (&join_d, ctx_c.as_slice()),
    ] {
        let refused = catch_up(&mut b.owner, &b.board, join, context).await;
        assert!(
            matches!(refused, Err(ctnd::Error::Authority)),
            "{refused:?}"
        );
        assert_eq!(standing(&b.owner).await, before);
    }
    // In order, each applies once; a replay of an epoch left behind is refused.
    catch_up(&mut b.owner, &b.board, &join_c, ctx_c)
        .await
        .unwrap();
    let (_, middle) = standing(&b.owner).await;
    assert_eq!(middle, before.1 + 2);
    let replay = catch_up(&mut b.owner, &b.board, &join_c, ctx_c).await;
    assert!(matches!(replay, Err(ctnd::Error::Authority)), "{replay:?}");
    assert_eq!(standing(&b.owner).await.1, middle);
    catch_up(&mut b.owner, &b.board, &join_d, ctx_d)
        .await
        .unwrap();
    assert_eq!(standing(&b.owner).await, standing(&room.a).await);
}

#[path = "room_leave.rs"]
mod leave;
