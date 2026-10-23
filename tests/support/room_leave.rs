//! Member removal end to end over real owners: a member announces its own leave
//! (its signed Groups `Leave`, one ordinary member frame), another member
//! commits the MLS removal and the rest apply it. Nobody else can be removed
//! this way, a forged notice is refused and a removed device reads and sends
//! nothing in later epochs.
use super::*;
use crate::door::facades::{RefusedJoins, RoomLeaveTask, RoomSync};

/// The Groups `Leave` of `owner`, prepared against the state it holds.
async fn leave_request(owner: &mut ProfileOwner) -> (cgrp::Candidate, cgrp::Request) {
    let policy = policy_at();
    let (candidate, _, _, request) = cbrd::prepare_group_intent(
        owner.groups.as_mut().unwrap(),
        &policy,
        cbrd::GroupIntent::Leave { group: GROUP },
        10,
    )
    .await
    .unwrap();
    (candidate, request)
}

async fn sync_with(
    owner: &mut ProfileOwner,
    board: &RoomBoard,
    refused: &mut RefusedJoins,
) -> crate::door::facades::RoomSynced {
    let policy = policy_at();
    owner
        .groups
        .as_mut()
        .unwrap()
        .sync_room(
            board,
            crate::door::facades::RoomSyncTask {
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

fn members(letters: &[&str]) -> BTreeSet<String> {
    letters.iter().map(|letter| member_id(letter)).collect()
}

/// A room of `a` and the lenders `x`, `y` plus the admitted `b` and `c`, with `a`
/// the only member online.
async fn room_of_five() -> (Room, Newcomer, Newcomer) {
    let mut room = Room::found().await;
    let b = room.admit("b", 32).await;
    let c = room.admit("c", 33).await;
    (room, b, c)
}

#[tokio::test(flavor = "current_thread")]
async fn a_member_who_leaves_is_removed_by_another_and_reads_and_sends_nothing_after() {
    let (mut room, mut b, mut c) = room_of_five().await;
    // `b` was offline while `c` was admitted: it catches up first, so that its
    // notice is sealed under the epoch the room holds.
    let caught_b = sync_with(&mut b.owner, &b.board, &mut RefusedJoins::new()).await;
    assert_eq!(caught_b.sync, RoomSync::Current);
    let before = standing(&room.a).await;
    assert_eq!(standing(&b.owner).await, before);
    assert_eq!(before.0, members(&["a", "x", "y", "b", "c"]));
    let policy = policy_at();

    // `b` announces its own leave; it keeps its old state for now.
    let (_, request) = leave_request(&mut b.owner).await;
    b.owner
        .groups
        .as_mut()
        .unwrap()
        .announce_leave(&b.board, ROOM, &request)
        .await
        .unwrap();
    let b_epoch = standing(&b.owner).await.1;
    let b_transport = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .room_transport_key(GROUP)
        .await
        .unwrap();

    // `a` commits the removal; the notice is its own frame of the same kind.
    let mut refused = RefusedJoins::new();
    let synced = sync_with(&mut room.a, &room.a_board, &mut refused).await;
    assert_eq!(synced.left, vec![member_id("b")]);
    assert_eq!((synced.admitted, synced.refused), (1, 0));
    assert_eq!(synced.sync, RoomSync::Current);
    let after = standing(&room.a).await;
    assert_eq!(after.0, members(&["a", "x", "y", "c"]));
    assert_eq!(after.1, before.1 + 1);
    // A second call finds nothing more to do.
    let again = sync_with(&mut room.a, &room.a_board, &mut refused).await;
    assert_eq!((again.admitted, again.caught_up, again.refused), (0, 0, 0));
    assert!(again.left.is_empty());

    // `c` was offline: it catches the removal up from the room's frames alone.
    let caught = sync_with(&mut c.owner, &c.board, &mut RefusedJoins::new()).await;
    assert_eq!(caught.left, vec![member_id("b")]);
    assert_eq!(caught.sync, RoomSync::Current);
    assert_eq!(standing(&c.owner).await, after);

    // The removed device holds the old epoch only: nothing sealed in the next
    // epoch opens for it, a key it seals in the old epoch is refused by the room,
    // and the key `a` seals in the new epoch is not adopted by it.
    let new_transport = room
        .a
        .groups
        .as_mut()
        .unwrap()
        .room_transport_key(GROUP)
        .await
        .unwrap();
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
    assert_eq!(from_a.epoch, after.1);
    room.a_board
        .relay_room_secret(ROOM, &new_transport, &from_a.message)
        .await
        .unwrap();
    let frames = b.board.room_frames(ROOM).await.unwrap();
    let newest = frames.frames.last().unwrap();
    assert!(newest.open(&ROOM, &new_transport).is_some());
    assert!(newest.open(&ROOM, &b_transport).is_none());
    let b_read = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&from_a.message),
            joined: &BTreeMap::new(),
            policy: &policy,
        })
        .await
        .unwrap();
    assert!(b_read.adopted.is_empty());
    assert_eq!(standing(&b.owner).await.1, b_epoch);
    let b_key = own_key(&b.owner, "b").await;
    let from_b = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &b_key,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(from_b.epoch, b_epoch);
    let a_read = room
        .a
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&from_b.message),
            joined: &BTreeMap::from([(member_id("b"), b_epoch)]),
            policy: &policy,
        })
        .await
        .unwrap();
    assert!(a_read.adopted.is_empty());
    // Its own sync cannot follow either: the commit that removes it is refused
    // here, not applied (it announced the leave itself, so the room says so).
    let own = sync_with(&mut b.owner, &b.board, &mut RefusedJoins::new()).await;
    assert_eq!(own.caught_up, 0);
    assert_eq!(standing(&b.owner).await.1, b_epoch);

    // Leaving locally drops the leaver's room records in one commit.
    let (candidate, _) = leave_request(&mut b.owner).await;
    let left = b
        .owner
        .groups
        .as_mut()
        .unwrap()
        .leave_room(RoomLeaveTask {
            group: GROUP,
            candidate,
            policy: &policy,
        })
        .await
        .unwrap();
    assert!(left.is_some());
}

/// Relay `request` as a leave notice sealed under the epoch key `owner` holds,
/// as any member of the room can.
async fn relay_notice(owner: &mut ProfileOwner, board: &RoomBoard, request: cgrp::Request) {
    let key = transport(owner).await;
    board
        .relay_room_notice(ROOM, &key, &cbrd::RoomCompanion { request })
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn a_forged_notice_or_a_removal_asked_by_another_member_is_refused_untouched() {
    let (mut room, mut b, mut c) = room_of_five().await;
    let caught_b = sync_with(&mut b.owner, &b.board, &mut RefusedJoins::new()).await;
    assert_eq!(caught_b.sync, RoomSync::Current);
    let before = standing(&room.a).await;
    let (_, genuine_c) = leave_request(&mut c.owner).await;

    // (1) c's own request with a damaged consent signature.
    let mut damaged = genuine_c.clone();
    *damaged.consents[0].signature.last_mut().unwrap() ^= 1;
    // (2) c asks for the removal of b: the request names b as the actor but
    // carries c's consent, which b's certified device key did not make.
    let mut other = genuine_c.clone();
    other.actor = member_id("b");
    // (3) the same with the consent relabelled as b's own.
    let mut relabelled = other.clone();
    relabelled.consents[0].member = member_id("b");
    // (4) a leave of a member that is not listed in the room at all.
    let mut stranger = genuine_c.clone();
    stranger.actor = member_id("q");
    stranger.consents[0].member = member_id("q");
    for forged in [damaged, other, relabelled, stranger] {
        relay_notice(&mut c.owner, &c.board, forged).await;
    }

    let mut refused = RefusedJoins::new();
    let synced = sync_with(&mut room.a, &room.a_board, &mut refused).await;
    assert_eq!((synced.admitted, synced.caught_up, synced.refused), (0, 0, 4));
    assert!(synced.left.is_empty());
    assert!(!synced.advanced);
    assert_eq!(standing(&room.a).await, before);
    // A refused frame is not verified again.
    let again = sync_with(&mut room.a, &room.a_board, &mut refused).await;
    assert_eq!((again.admitted, again.refused), (0, 0));
    assert_eq!(standing(&room.a).await, before);

    // The genuine requests are not poisoned by the refusals: b leaves for real.
    let (_, genuine_b) = leave_request(&mut b.owner).await;
    relay_notice(&mut b.owner, &b.board, genuine_b).await;
    let real = sync_with(&mut room.a, &room.a_board, &mut refused).await;
    assert_eq!(real.left, vec![member_id("b")]);
    assert_eq!(
        standing(&room.a).await,
        (members(&["a", "x", "y", "c"]), before.1 + 1)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_forged_removal_commit_is_refused_untouched_and_the_real_one_still_applies() {
    let (mut room, mut b, mut c) = room_of_five().await;
    sync_with(&mut b.owner, &b.board, &mut RefusedJoins::new()).await;
    let (_, genuine_b) = leave_request(&mut b.owner).await;
    relay_notice(&mut b.owner, &b.board, genuine_b).await;
    let key = transport(&mut c.owner).await;
    // `c` stays offline at this epoch while `a` removes `b`.
    let held = standing(&c.owner).await;
    sync_with(&mut room.a, &room.a_board, &mut RefusedJoins::new()).await;
    let real = commits_at(&c.board, &key).await;
    let (sequence, counter, removal) = real
        .iter()
        .find(|(_, _, commit)| cbrd::RoomCompanion::is_leave(&commit.companion))
        .cloned()
        .expect("the removal commit is in the room");
    let forge = |commit: &[u8], companion: &[u8], at: u64| cmbl::RelayFrame {
        kind: cmbl::FrameKind::Message,
        sequence: at,
        counter,
        ciphertext: key
            .wrap(&ROOM, &ctnd::pack_ordered(commit, companion))
            .unwrap(),
    };
    let mut bad_commit = removal.commit.clone();
    *bad_commit.last_mut().unwrap() ^= 1;
    let mut bad_companion = removal.companion.clone();
    *bad_companion.last_mut().unwrap() ^= 1;
    let forged = vec![
        forge(&bad_commit, &removal.companion, u64::MAX - 1),
        forge(&removal.commit, &bad_companion, u64::MAX - 2),
    ];
    let (hostile, mode) = room.through().await;
    // The hostile relay shows neither the real removal nor the notice that asked
    // for it, so that only the forgeries are in front of `c`.
    let mut hidden = vec![sequence];
    for frame in &c.board.room_frames(ROOM).await.unwrap().frames {
        if matches!(frame.open(&ROOM, &key), Some(cbrd::FrameContent::Notice(_))) {
            hidden.push(frame.sequence);
        }
    }
    *mode.borrow_mut() = Box::new(rewrite(hidden, forged, false));
    let mut refused = RefusedJoins::new();
    let first = sync_with(&mut c.owner, &hostile, &mut refused).await;
    assert_eq!((first.caught_up, first.refused), (0, 2));
    assert!(first.left.is_empty());
    assert_eq!(standing(&c.owner).await, held);
    // The room's real frames are not poisoned by the refusals.
    let real = sync_with(&mut c.owner, &c.board, &mut refused).await;
    assert_eq!(real.left, vec![member_id("b")]);
    assert_eq!(standing(&c.owner).await, standing(&room.a).await);
}

async fn advance(
    owner: &mut ProfileOwner,
    board: &RoomBoard,
    refused: &mut RefusedJoins,
) -> crate::door::facades::LeaveProgress {
    let policy = policy_at();
    owner
        .groups
        .as_mut()
        .unwrap()
        .advance_room_leave(
            board,
            crate::door::facades::RoomLeaveSyncTask {
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

#[tokio::test(flavor = "current_thread")]
async fn a_leave_whose_notice_went_stale_is_reissued_until_a_member_removes_it_and_leaves_no_ghost() {
    use crate::door::facades::LeaveProgress;
    let mut room = Room::found().await;
    let mut b = room.admit("b", 32).await;
    let (_, request) = leave_request(&mut b.owner).await;
    assert!(
        b.owner
            .groups
            .as_mut()
            .unwrap()
            .begin_room_leave(&b.board, ROOM, &request)
            .await
            .unwrap()
    );
    assert_eq!(b.owner.groups.as_mut().unwrap().room_leaving(GROUP).await.unwrap(), Some(1));
    // Before any member acted, another newcomer is admitted: b's notice is now
    // sealed under an epoch the room has left.
    let c = room.admit("c", 33).await;
    let mut refused = RefusedJoins::new();
    // b follows the room (adopts nothing), sees the notice is stale and re-issues.
    assert_eq!(
        advance(&mut b.owner, &b.board, &mut refused).await,
        LeaveProgress::Pending { attempts: 2 }
    );
    assert_eq!(standing(&b.owner).await.1, c.epoch);
    // Nothing new to do until a member acts.
    assert_eq!(
        advance(&mut b.owner, &b.board, &mut refused).await,
        LeaveProgress::Pending { attempts: 2 }
    );
    let synced = sync_with(&mut room.a, &room.a_board, &mut RefusedJoins::new()).await;
    assert_eq!(synced.left, vec![member_id("b")]);
    assert_eq!(
        advance(&mut b.owner, &b.board, &mut refused).await,
        LeaveProgress::Left
    );
    assert_eq!(b.owner.groups.as_mut().unwrap().room_leaving(GROUP).await.unwrap(), None);
    assert_eq!(standing(&room.a).await.0, members(&["a", "x", "y", "c"]));
}
