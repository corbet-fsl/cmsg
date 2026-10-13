//! The room door end to end over real owners: a member holds a standing room,
//! a stranger joins through an ordered external commit that carries its signed
//! Groups consent and the handle of its own lineage, and the member admits it.
//! The room transport is a small router over the genuine Assembly and genuinely
//! blind-issued passes; the Forum answers only the presence and pass calls.
//! What is not exercised here: the Door's Rulebook-backed policy read and the
//! sealed request/answer exchange (they sit above the owners under test).
use super::profile_owner_tests::{open_with, ProfileOwner};
use crate::door::facades::{GroupPeers, RoomAdmitTask, RoomJoinTask};
use blind_rsa_signatures::{DefaultRng, KeyPair, PSS, Randomized, Sha384};
use cbrd::cgrp::{self, Band, Notification, Policy, SeatFormats, DAY};
use cbrd::clnk::{self, cfrm, cmbl};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::Arc,
};

const COMMUNITY: &str = "alpha";
const ROOM: cmbl::Id = [7; 16];
const GROUP: cgrp::Id = [9; 32];
const NOW_MS: u64 = 2_000_000_000_000;

fn member_id(letter: &str) -> String {
    letter.repeat(96)
}

// pending band/split decisions. Both legal vector interpretations are tested.
fn policy() -> Policy {
    let edges = [3, 6, 9, 13, 20, 30, 43, 60, 80];
    let posts = [120, 90, 60, 40, 30, 24, 18, 12, 8];
    let bursts = [20, 15, 12, 10, 8, 6, 5, 4, 3];
    let notifications = [
        Notification::EveryMessage,
        Notification::QuietHours,
        Notification::SilentReactions,
        Notification::MentionsReplies,
        Notification::MentionsRepliesDigest,
        Notification::MentionsDigest,
        Notification::MentionsDaily,
        Notification::MentionsDaily,
        Notification::ContactsWeekly,
    ];
    Policy {
        epoch: 1,
        valid_until: 4_000_000_000,
        cap: 100,
        circle_max: 12,
        ingroup_max: 42,
        shrink_public: 36,
        shrink_ingroup: 10,
        open_seconds: 21 * DAY,
        fork_cooldown: 14 * DAY,
        retarget_cooldown: 28 * DAY,
        listing_wait: 72 * 3_600,
        split_public_min: 43,
        bands: std::array::from_fn(|i| Band {
            lower: edges[i],
            enter_up: edges[i],
            leave_down: edges[i] - 2,
            notification: notifications[i],
            posts_per_hour: posts[i],
            burst: bursts[i],
            vouches: if i == 5 {
                2
            } else if (3..5).contains(&i) {
                1
            } else {
                0
            },
            history_seconds: [0, 0, 0, 14 * DAY, 7 * DAY, 3 * DAY, DAY, DAY / 2, DAY / 4][i],
            history_messages: [0, 0, 0, 200, 200, 200, 100, 50, 50][i],
            joins_per_hour: if i >= 7 { Some(6) } else { None },
        }),
        seats: SeatFormats {
            enabled: false,
            refill_per_day: 1.0,
            capacity: 10.0,
            initial: 5.0,
            minimum: 0.25,
            small: 1.5,
            large: 3.0,
            low: 7,
            high: 60,
            tau: 1.0,
            epoch_days: 7,
            quantum: 0.5,
            warning_days: 2,
        },
        suggest_at: 66,
        pressure_at: 85,
        modularity: 0.3,
        overlap: 0.4,
        suggestion_cooldown: 7 * DAY,
        decline_cooldown: 14 * DAY,
        reciprocity_enabled: true,
        welcome_quarters: 1,
        introduction_quarters: 4,
        week_cap_quarters: 6,
    }
}

#[derive(Clone)]
struct Time;
impl clnk::Clock for Time {
    fn now(&self) -> Result<u64, cmmr::Error> {
        Ok(NOW_MS)
    }
}

/// The room router: one Assembly, one blind-signing epoch key.
struct Router {
    assembly: cmbl::Assembly<Arc<cmmr::Memory<Time>>>,
    verifier: cmbl::passes::Verifier,
    key: KeyPair<Sha384, PSS, Randomized>,
    epoch: cmbl::passes::Epoch,
}

fn router() -> Arc<Router> {
    let key = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 3072).unwrap();
    let epoch = cmbl::passes::Epoch {
        community: COMMUNITY.into(),
        epoch: 1,
        valid_from: NOW_MS - 1_000_000,
        valid_until: NOW_MS + 1_000_000,
        public_key_der: key.pk.to_der().unwrap(),
    };
    let store = Arc::new(
        cmmr::Memory::new(
            cmmr::Scope::new(COMMUNITY, "boot").unwrap(),
            cmmr::Limits {
                records: 8,
                value_bytes: 1_000_000,
                batch: 8,
                indexes_per_record: 1,
                page: 8,
                ttl_ms: 10_000_000,
            },
            Time,
        )
        .unwrap(),
    );
    Arc::new(Router {
        assembly: cmbl::Assembly::new(
            store,
            COMMUNITY.into(),
            "boot".into(),
            cmbl::Limits {
                connections: 8,
                relay_messages: 64,
                message_bytes: 200_000,
                lifetime_ms: 5_000_000,
                proof_bytes: 8192,
                operation_receipts: 64,
            },
        )
        .unwrap(),
        verifier: cmbl::passes::Verifier::new(epoch.clone(), "boot".into()).unwrap(),
        key,
        epoch,
    })
}

fn reply(response: cfrm::Output) -> Result<Vec<u8>, clnk::ErrorCode> {
    Ok(serde_json::to_vec(&cfrm::Reply {
        version: 1,
        response,
    })
    .unwrap())
}

/// The authenticated Forum: presence, the common epoch and pass issuance only.
struct Forum(Arc<Router>);
impl clnk::Transport for Forum {
    async fn post(&self, _: &str, body: Vec<u8>) -> Result<Vec<u8>, clnk::ErrorCode> {
        let call = cfrm::Call::decode(&body, 1 << 20)?;
        match call.request {
            cfrm::Request::Challenge(_) => reply(cfrm::Output::Challenge(cfrm::ChallengeOutput {
                challenge: serde_json::to_vec(&serde_json::json!({
                    "token": vec![1u8; 16],
                    "expires_at_ms": NOW_MS + 60_000,
                }))
                .unwrap(),
            })),
            cfrm::Request::Enter(_) => reply(cfrm::Output::Enter(cfrm::EnterOutput {
                session: serde_json::to_vec(&serde_json::json!({
                    "member": "fixture",
                    "generation": "g",
                    "device": vec![0u8; 32],
                }))
                .unwrap(),
                revision: vec![0; 16],
                expires_at_ms: NOW_MS + 3_600_000,
            })),
            cfrm::Request::RoomEpoch(_) => reply(cfrm::Output::RoomEpoch(cfrm::RoomEpochOutput {
                incarnation: "boot".into(),
                epoch: serde_json::to_vec(&self.0.epoch).unwrap(),
            })),
            cfrm::Request::RoomIssue(input) => {
                let blinded: cmbl::passes::BlindRequest =
                    serde_json::from_slice(&input.blinded_request).unwrap();
                let signed = self.0.key.sk.blind_sign(&blinded.blinded).unwrap();
                reply(cfrm::Output::RoomIssue(cfrm::RoomIssueOutput {
                    signature: signed.0.to_vec(),
                }))
            }
            _ => Err(clnk::ErrorCode::InvalidRequest),
        }
    }
}

/// The anonymous room transport: every call reaches Assembly with its proof.
/// `slow` yields before answering, so a concurrent future (the admitting
/// member) runs while this device waits for the ordered traffic.
struct Rooms {
    router: Arc<Router>,
    slow: usize,
}
impl clnk::Transport for Rooms {
    async fn post(&self, _: &str, body: Vec<u8>) -> Result<Vec<u8>, clnk::ErrorCode> {
        for _ in 0..self.slow {
            tokio::task::yield_now().await;
        }
        let call = cfrm::Call::decode(&body, 1 << 22)?;
        let (input, kind) = match call.request {
            cfrm::Request::RoomConnect(input) => (input, "connect"),
            cfrm::Request::RoomRead(input) => (input, "read"),
            cfrm::Request::RoomOrder(input) => (input, "order"),
            cfrm::Request::RoomRelay(input) => (input, "relay"),
            cfrm::Request::RoomResume(input) => (input, "resume"),
            _ => return Err(clnk::ErrorCode::InvalidRequest),
        };
        let command: cmbl::Request = serde_json::from_slice(&input.command).unwrap();
        let Ok(outcome) = self
            .router
            .assembly
            .execute(&command, &input.room_pass, &self.router.verifier, NOW_MS)
            .await
        else {
            return serde_json::to_vec(&cfrm::Failure {
                error: clnk::ErrorCode::Rejected,
            })
            .map_err(|_| clnk::ErrorCode::Transport);
        };
        let output = cfrm::RoomOutput {
            result: serde_json::to_vec(&outcome).unwrap(),
        };
        reply(match kind {
            "connect" => cfrm::Output::RoomConnect(output),
            "read" => cfrm::Output::RoomRead(output),
            "order" => cfrm::Output::RoomOrder(output),
            "relay" => cfrm::Output::RoomRelay(output),
            _ => cfrm::Output::RoomResume(output),
        })
    }
}

type RoomBoard = cbrd::Board<Forum, clnk::AnonymousRooms<Rooms>>;

/// A Board with presence, the common epoch and a pass for the room.
async fn board(router: &Arc<Router>, slow: usize, resume: bool) -> RoomBoard {
    let link = clnk::Link::at(
        Forum(router.clone()),
        COMMUNITY.into(),
        "https://forum.example.test".into(),
        Time,
    )
    .unwrap()
    .with_anonymous_rooms(Rooms {
        router: router.clone(),
        slow,
    });
    let mut board = cbrd::Board::new(COMMUNITY.into(), link).unwrap();
    board
        .connect(clnk::ChallengeInput {
            publication: vec![1],
        })
        .await
        .unwrap();
    board.enter(vec![0; 64]).await.unwrap();
    let request = board.prepare_room_epoch([1; 16]).unwrap();
    board.receive_room_epoch(request, vec![0; 64]).await.unwrap();
    let request = board.prepare_room_pass(ROOM, [2; 16], [3; 16]).unwrap();
    let connection = board.receive_room_pass(request, vec![0; 64]).await.unwrap();
    let operation = [if resume { 4 } else { 5 }; 16];
    board
        .execute_room(cmbl::Request {
            room: ROOM,
            operation: {
                let mut id = operation;
                id[0] = connection[0];
                id
            },
            action: if resume {
                cmbl::Action::Resume { connection }
            } else {
                cmbl::Action::Connect { connection }
            },
        })
        .await
        .unwrap();
    board
}

/// Reads of other members' lineage records through the handle they supplied.
/// The handle is only a locator: this fixture returns whatever record is
/// registered for it, the way a hostile or confused locator target would, and
/// the owner must still bind the result to the member it asked about.
#[derive(Clone, Default)]
struct Directory(Rc<RefCell<BTreeMap<Vec<u8>, ckmg::Lineage>>>);
impl GroupPeers for Directory {
    fn lineage<'a>(
        &'a mut self,
        _: &'a ckmg::Binding,
        handle: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ckmg::Lineage>> + 'a>> {
        let found = self.0.borrow().get(handle).cloned();
        Box::pin(async move { found })
    }
}

async fn owner(letter: &str, prf: u8, directory: &Directory) -> ProfileOwner {
    let (mut owner, _, _) = open_with(&member_id(letter), true, prf).await;
    owner.enable_groups(Some(Box::new(directory.clone()))).unwrap();
    owner.groups.as_mut().unwrap().found_rooms();
    owner
}

/// The lineage record and the read handle of an owner's own member.
async fn own_lineage(owner: &ProfileOwner) -> (ckmg::Lineage, Vec<u8>) {
    let mut retained = owner.retained.lock().await;
    let keys = retained.as_mut().unwrap().vault.keys();
    let lineage = keys.lineage().await.unwrap();
    let handle = keys
        .export_lineage_read_capability()
        .await
        .unwrap()
        .as_bytes()
        .to_vec();
    (lineage, handle)
}

fn policy_at() -> cbrd::PolicyAt {
    cbrd::PolicyAt::new(COMMUNITY, policy())
}

/// The members of the room group and the MLS epoch this owner holds.
async fn standing(owner: &ProfileOwner) -> (BTreeSet<String>, u64) {
    let mut retained = owner.retained.lock().await;
    let custody = retained.as_mut().unwrap();
    let binding = custody.binding.clone();
    let storage = custody.vault.storage().clone();
    let store = storage.lock().await;
    let snapshot = cgrp::Snapshot::load(COMMUNITY, &store).unwrap();
    let members = snapshot.members(&GROUP).unwrap().clone();
    let epoch = cthr::Threads::load(binding, GROUP, &store)
        .unwrap()
        .epoch()
        .unwrap();
    (members, epoch)
}

/// The unix seconds the owners themselves read.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The member of the room. A public room needs at least three founding members
/// who each consent for themselves; the other two only lend their consent and
/// key package (their devices are not part of the scene afterwards). Fixture
/// only: the product has no seed rooms, a room grows out of a group.
async fn founder(directory: &Directory) -> ProfileOwner {
    let mut founder = owner("a", 31, directory).await;
    let id = member_id("a");
    let policy = policy_at();
    let others = [("x", 34u8), ("y", 35u8)];
    let mut members = BTreeSet::from([id]);
    let mut lenders = vec![];
    for (letter, prf) in others {
        let lender = owner(letter, prf, directory).await;
        let (lineage, handle) = own_lineage(&lender).await;
        directory.0.borrow_mut().insert(handle, lineage);
        members.insert(member_id(letter));
        lenders.push((member_id(letter), lender));
    }
    let groups = founder.groups.as_mut().unwrap();
    let mut proposal = cbrd::propose_group_command(
        groups,
        &policy,
        cgrp::Command::Create {
            id: GROUP,
            members,
            seed: true,
        },
        true,
    )
    .await
    .unwrap();
    // Each lender answers for itself over an invitation built from the exact
    // request (a conversation is not part of this scene).
    let mut open = proposal.request().clone();
    open.consents.clear();
    for (member, lender) in &mut lenders {
        let invitation = cbrd::Invitation::from_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "request": open,
                "community": COMMUNITY,
                "epoch": 1,
                "member": member,
            }))
            .unwrap(),
        )
        .unwrap();
        let reply = invitation
            .answer(lender.groups.as_mut().unwrap(), true, true)
            .await
            .unwrap();
        proposal.admit(member, reply, unix_now()).unwrap();
    }
    cbrd::commit_group_proposal(founder.groups.as_mut().unwrap(), &policy, &proposal, 10)
        .await
        .unwrap();
    founder
}

/// One newcomer's join attempt, run concurrently with the member's admission
/// loop. Returns the join result and what the member did with each frame.
async fn attempt(
    newcomer: &mut ProfileOwner,
    newcomer_board: &RoomBoard,
    evidence: &cthr::ParentEvidence,
    member: &mut ProfileOwner,
    member_board: &RoomBoard,
    cursor: &mut u64,
) -> (
    Result<cgrp::Snapshot, ctnd::Error>,
    Vec<Result<cgrp::Snapshot, ctnd::Error>>,
) {
    let policy = policy_at();
    let groups = newcomer.groups.as_mut().unwrap();
    let (candidate, _, _, request) = cbrd::prepare_group_intent(
        groups,
        &policy,
        cbrd::GroupIntent::Join {
            group: GROUP,
            vouches: Default::default(),
        },
        true,
        10,
    )
    .await
    .unwrap();
    let join = groups.join_room(
        newcomer_board,
        RoomJoinTask {
            room: ROOM,
            group: GROUP,
            candidate,
            request,
            evidence,
            policy: &policy,
        },
    );
    let admit = async {
        let groups = member.groups.as_mut().unwrap();
        let mut results = vec![];
        for _ in 0..400 {
            let read = member_board.room_joins(ROOM, *cursor).await.unwrap();
            for frame in &read.joins {
                results.push(
                    groups
                        .admit_room(
                            member_board,
                            RoomAdmitTask {
                                room: ROOM,
                                group: GROUP,
                                frame,
                                max_groups: 10,
                                policy: &policy,
                            },
                        )
                        .await,
                );
            }
            *cursor = read.through;
            if !results.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        results
    };
    futures_util::future::join(join, admit).await
}

#[tokio::test(flavor = "current_thread")]
async fn a_stranger_is_admitted_through_its_own_lineage_and_a_substituted_handle_is_refused() {
    let router = router();
    let directory = Directory::default();
    let mut member = founder(&directory).await;
    let (member_lineage, _) = own_lineage(&member).await;
    let member_board = board(&router, 0, true).await;
    let evidence = member
        .groups
        .as_mut()
        .unwrap()
        .room_evidence(GROUP, &policy_at())
        .await
        .unwrap();
    let (_, epoch_before) = standing(&member).await;
    let mut cursor = 0;

    // A stranger whose handle leads to someone else's record: refused, and the
    // room is left exactly as it was.
    let mut impostor = owner("c", 33, &directory).await;
    let (_, impostor_handle) = own_lineage(&impostor).await;
    directory
        .0
        .borrow_mut()
        .insert(impostor_handle, member_lineage);
    let impostor_board = board(&router, 60, false).await;
    let (joined, admitted) = attempt(
        &mut impostor,
        &impostor_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
    )
    .await;
    assert!(joined.is_err());
    assert_eq!(admitted.len(), 1);
    assert!(admitted[0].is_err());
    let (members, epoch) = standing(&member).await;
    assert_eq!(members.len(), 3);
    assert_eq!(epoch, epoch_before);

    // The stranger that supplies the handle of its OWN record is admitted.
    let mut joiner = owner("b", 32, &directory).await;
    let (joiner_lineage, joiner_handle) = own_lineage(&joiner).await;
    directory
        .0
        .borrow_mut()
        .insert(joiner_handle, joiner_lineage);
    let joiner_board = board(&router, 60, false).await;
    let (joined, admitted) = attempt(
        &mut joiner,
        &joiner_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
    )
    .await;
    joined.unwrap();
    assert_eq!(admitted.len(), 1);
    admitted[0].as_ref().unwrap();
    let both = BTreeSet::from([member_id("a"), member_id("x"), member_id("y"), member_id("b")]);
    let (joiner_members, joiner_epoch) = standing(&joiner).await;
    let (member_members, member_epoch) = standing(&member).await;
    assert_eq!(joiner_members, both);
    assert_eq!(member_members, both);
    assert_eq!(joiner_epoch, member_epoch);
    assert!(member_epoch > epoch_before);
}
