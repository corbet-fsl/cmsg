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
