//! The room door end to end over real owners: a member holds a standing room,
//! a stranger joins through an ordered external commit that carries its signed
//! Groups consent and the handle of its own lineage, and the member admits it.
//! The room transport is a small router over the genuine Assembly and genuinely
//! blind-issued passes; the Forum answers only the presence and pass calls.
//! What is not exercised here: the Door's Rulebook-backed policy read and the
//! sealed request/answer exchange (they sit above the owners under test).
use super::profile_owner_tests::{open_with, ProfileOwner};
use crate::door::facades::{GroupPeers, RoomAdmitTask, RoomJoinTask, RoomKeyTask, RoomSecretsTask};
use blind_rsa_signatures::{DefaultRng, KeyPair, Randomized, Sha384, PSS};
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
const CIRCLE: cgrp::Id = [7; 32];
const INGROUP: cgrp::Id = [8; 32];
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
        // Toy growth thresholds: three in a circle, up to eight in an in-group
        // (the catch-up tests admit three newcomers to a room of three).
        circle_max: 3,
        ingroup_max: 8,
        shrink_public: 4,
        shrink_ingroup: 2,
        open_seconds: 21 * DAY,
        fork_cooldown: 14 * DAY,
        retarget_cooldown: 28 * DAY,
        listing_wait: 72 * 3_600,
        split_public_min: 5,
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
    /// What a hostile or lossy relay does to what a Read returns.
    tamper: Option<Tamper>,
}
type Tamper = std::rc::Rc<dyn Fn(&mut cmbl::Outcome)>;
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
        let Ok(mut outcome) = self
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
        if let (Some(tamper), "read") = (&self.tamper, kind) {
            tamper(&mut outcome);
        }
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
    board_through(router, slow, resume, None).await
}

/// The same Board over a relay that changes what its reads return.
async fn board_through(
    router: &Arc<Router>,
    slow: usize,
    resume: bool,
    tamper: Option<Tamper>,
) -> RoomBoard {
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
        tamper,
    });
    let mut board = cbrd::Board::new(COMMUNITY.into(), link).unwrap();
    board
        .connect(clnk::ChallengeInput {
            publication: vec![1],
        })
        .await
        .unwrap();
    board.enter(vec![0; 64], vec![]).await.unwrap();
    let request = board.prepare_room_epoch([1; 16]).unwrap();
    board
        .receive_room_epoch(request, vec![0; 64])
        .await
        .unwrap();
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
struct Directory {
    records: Rc<RefCell<BTreeMap<Vec<u8>, ckmg::Lineage>>>,
    /// The handles read through THIS view, in order (a clone shares the log).
    reads: Rc<RefCell<Vec<Vec<u8>>>>,
}
impl Directory {
    /// The same records, a log of its own: one owner's reads, told apart.
    fn separate(&self) -> Directory {
        Directory {
            records: self.records.clone(),
            reads: Rc::default(),
        }
    }
    fn publish(&self, handle: Vec<u8>, lineage: ckmg::Lineage) {
        self.records.borrow_mut().insert(handle, lineage);
    }
}
impl GroupPeers for Directory {
    fn lineage<'a>(
        &'a mut self,
        _: &'a ckmg::Binding,
        handle: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ckmg::Lineage>> + 'a>> {
        self.reads.borrow_mut().push(handle.to_vec());
        let found = self.records.borrow().get(handle).cloned();
        Box::pin(async move { found })
    }
}

async fn owner(letter: &str, prf: u8, directory: &Directory) -> ProfileOwner {
    let (mut owner, _, _) = open_with(&member_id(letter), true, prf).await;
    owner
        .enable_groups(Some(Box::new(directory.clone())))
        .unwrap();
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

/// A real profile key of `owner` (member `letter`), as the hand-over it would
/// send to a room: Envelope custody is lent exactly as the product lends it.
async fn own_key(owner: &ProfileOwner, letter: &str) -> Vec<u8> {
    let mut retained = owner.retained.lock().await;
    let custody = retained.as_mut().unwrap();
    custody
        .with_custodian_owned("https://member.example.test", |custodian| {
            let (_, key) = custodian
                .seal(
                    cbrd::cnvl::Context {
                        community: COMMUNITY.into(),
                        owner: member_id(letter),
                        profile_revision: 1,
                        schema_revision: 1,
                        key_generation: 1,
                    },
                    b"private profile",
                )
                .unwrap();
            Ok(crate::door::board::room_keys::handover(&key)
                .unwrap()
                .to_vec())
        })
        .await
        .unwrap()
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

/// The member of the room. The product has no seed rooms: the room grows out of
/// a circle of three (`a`, `x`, `y`), an in-group of four (a fourth, `z`, joins
/// by consent) and a consent fork that opens the room with the first three, who
/// each agree to be seen. The others only lend their consent and key package
/// (their devices are not part of the scene afterwards).
async fn founder(directory: &Directory, own_view: &Directory) -> ProfileOwner {
    let mut founder = owner("a", 31, own_view).await;
    let policy = policy_at();
    let mut lenders = BTreeMap::new();
    for (letter, prf) in [("x", 34u8), ("y", 35u8), ("z", 36u8)] {
        let lender = owner(letter, prf, directory).await;
        let (lineage, handle) = own_lineage(&lender).await;
        directory.publish(handle, lineage);
        lenders.insert(member_id(letter), lender);
    }
    // The founder is in contact with everyone it creates a group with or adds.
    founder.groups.as_mut().unwrap().assume_contacts([
        member_id("x"),
        member_id("y"),
        member_id("z"),
    ]);
    let ids = |letters: &[&str]| -> BTreeSet<String> {
        letters.iter().map(|letter| member_id(letter)).collect()
    };
    for (step, command) in [
        cgrp::Command::Create {
            id: CIRCLE,
            members: ids(&["a", "x", "y"]),
        },
        cgrp::Command::Fork {
            id: INGROUP,
            parents: vec![CIRCLE],
            members: ids(&["a", "x", "y", "z"]),
            kind: cgrp::ForkKind::Add,
        },
        cgrp::Command::Fork {
            id: GROUP,
            parents: vec![INGROUP],
            members: ids(&["a", "x", "y"]),
            kind: cgrp::ForkKind::Open,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let others: Vec<String> = match &command {
            cgrp::Command::Create { members, .. } | cgrp::Command::Fork { members, .. } => members
                .iter()
                .filter(|m| **m != member_id("a"))
                .cloned()
                .collect(),
            _ => unreachable!(),
        };
        let mut proposal =
            cbrd::propose_group_command(founder.groups.as_mut().unwrap(), &policy, command)
                .await
                .unwrap();
        // Each lender answers for itself over an invitation built from the exact
        // request (a conversation is not part of this scene).
        let mut open = proposal.request().clone();
        open.consents.clear();
        for member in others {
            let lender = lenders.get_mut(&member).unwrap();
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
                .answer(lender.groups.as_mut().unwrap(), true)
                .await
                .unwrap();
            proposal.admit(&member, reply, unix_now()).unwrap();
        }
        cbrd::commit_group_proposal(founder.groups.as_mut().unwrap(), &policy, &proposal, 10)
            .await
            .unwrap_or_else(|error| panic!("growth step {step}: {error:?}"));
    }
    founder
}

/// One newcomer's join attempt, run concurrently with the member's admission
/// loop. Returns the join result and what the member did with each frame.
async fn attempt(
    newcomer: &mut ProfileOwner,
    newcomer_board: &RoomBoard,
    evidence: &cbrd::RoomState,
    member: &mut ProfileOwner,
    member_board: &RoomBoard,
    cursor: &mut u64,
    handover: Vec<zeroize::Zeroizing<Vec<u8>>>,
) -> (
    Result<crate::door::facades::RoomJoined, ctnd::Error>,
    Vec<Result<cgrp::Snapshot, ctnd::Error>>,
) {
    let policy = policy_at();
    let join_key = cbrd::TransportKey::from_keys(&evidence.transport);
    let groups = newcomer.groups.as_mut().unwrap();
    // A relay that swaps the state next to genuine MLS evidence is refused
    // before anything is prepared, signed or sent.
    let mut swapped = cthr::ParentEvidence {
        state: evidence.evidence.state.clone(),
        group_info: evidence.evidence.group_info.clone(),
        ratchet_tree: evidence.evidence.ratchet_tree.clone(),
    };
    *swapped.state.last_mut().unwrap() ^= 1;
    assert!(groups
        .verify_room_state(GROUP, &swapped, &evidence.handles)
        .await
        .is_err());
    let verified = groups
        .verify_room_state(GROUP, &evidence.evidence, &evidence.handles)
        .await
        .unwrap();
    let (candidate, _, _, request) =
        cbrd::prepare_join_from_state(groups, &policy, GROUP, Default::default(), &verified, 10)
            .await
            .unwrap();
    let join = async {
        groups
            .join_room(
                newcomer_board,
                RoomJoinTask {
                    room: ROOM,
                    group: GROUP,
                    candidate,
                    request,
                    evidence: &evidence.evidence,
                    parent: &verified,
                    handles: &evidence.handles,
                    transport: &join_key,
                    policy: &policy,
                    handover,
                },
            )
            .await
    };
    let admit = async {
        let groups = member.groups.as_mut().unwrap();
        let transport = groups.room_transport_key(GROUP).await.unwrap();
        let mut results = vec![];
        for _ in 0..400 {
            let read = member_board
                .room_joins(ROOM, *cursor, &transport)
                .await
                .unwrap();
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
                                transport: &transport,
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

/// The room a member holds, its first evidence and a board to admit from.
struct Scene {
    router: Arc<Router>,
    directory: Directory,
    /// The reads of the admitting member `a` (founding included).
    member_view: Directory,
    member: ProfileOwner,
    member_board: RoomBoard,
}

async fn scene() -> Scene {
    let router = router();
    let directory = Directory::default();
    let member_view = directory.separate();
    let member = founder(&directory, &member_view).await;
    let (member_lineage, member_handle) = own_lineage(&member).await;
    // The room's members publish their lineage records under their handles.
    directory.publish(member_handle, member_lineage);
    let member_board = board(&router, 0, true).await;
    Scene {
        router,
        directory,
        member_view,
        member,
        member_board,
    }
}

/// A stranger owner whose lineage is published under its own handle.
async fn stranger(directory: &Directory, letter: &str, prf: u8) -> (ProfileOwner, Vec<u8>) {
    let owner = owner(letter, prf, directory).await;
    let (lineage, handle) = own_lineage(&owner).await;
    directory.publish(handle.clone(), lineage);
    (owner, handle)
}

#[tokio::test(flavor = "current_thread")]
async fn a_stranger_is_admitted_through_its_own_lineage_and_a_substituted_handle_is_refused() {
    let Scene {
        router,
        directory,
        member_view,
        mut member,
        member_board,
    } = scene().await;
    let (member_lineage, _) = own_lineage(&member).await;
    // What the member read while the room was founded: it holds the roster
    // since then (row 14.8) and never reads it again for an admission.
    let founded = member_view.reads.borrow().len();
    let evidence = member
        .groups
        .as_mut()
        .unwrap()
        .room_evidence(GROUP, &policy_at())
        .await
        .unwrap();
    assert_eq!(
        member.groups.as_ref().unwrap().roster_members(),
        BTreeSet::from([member_id("x"), member_id("y"), member_id("z")])
    );
    let (_, epoch_before) = standing(&member).await;
    let mut cursor = 0;

    // A stranger whose handle leads to someone else's record: refused, and the
    // room is left exactly as it was.
    let mut impostor = owner("c", 33, &directory).await;
    let (_, impostor_handle) = own_lineage(&impostor).await;
    directory.publish(impostor_handle.clone(), member_lineage);
    let impostor_board = board(&router, 60, false).await;
    let (joined, admitted) = attempt(
        &mut impostor,
        &impostor_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
        vec![],
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
    directory.publish(joiner_handle.clone(), joiner_lineage);
    let joiner_board = board(&router, 60, false).await;
    let joiner_key = own_key(&joiner, "b").await;
    let member_key = own_key(&member, "a").await;
    let (joined, admitted) = attempt(
        &mut joiner,
        &joiner_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
        vec![zeroize::Zeroizing::new(joiner_key.clone())],
    )
    .await;
    let joined = joined.unwrap();
    assert_eq!(admitted.len(), 1);
    admitted[0].as_ref().unwrap();
    let both = BTreeSet::from([
        member_id("a"),
        member_id("x"),
        member_id("y"),
        member_id("b"),
    ]);
    let (joiner_members, joiner_epoch) = standing(&joiner).await;
    let (member_members, member_epoch) = standing(&member).await;
    assert_eq!(joiner_members, both);
    assert_eq!(member_members, both);
    assert_eq!(joiner_epoch, member_epoch);
    assert!(member_epoch > epoch_before);

    // Two evidences and two admissions later the member has read NOTHING of
    // the roster again: only the newcomers, fresh, every time. The newcomer
    // is in the roster now.
    let later: Vec<Vec<u8>> = member_view.reads.borrow()[founded..].to_vec();
    assert!(!later.is_empty());
    assert!(
        later
            .iter()
            .all(|handle| *handle == impostor_handle || *handle == joiner_handle),
        "the roster was read again: {later:?}"
    );
    assert!(later.contains(&joiner_handle));
    assert!(member
        .groups
        .as_ref()
        .unwrap()
        .roster_members()
        .contains(&member_id("b")));

    // Profile keys (row 14.5). The joiner sent its key in the epoch of its
    // admission; the member holds nothing before it opens that message.
    let policy = policy_at();
    let nobody = BTreeMap::new();
    assert_eq!(joined.handover.len(), 1);
    let held = |standing: crate::door::facades::RoomKeysStanding| standing.held;
    assert!(held(
        member
            .groups
            .as_mut()
            .unwrap()
            .room_keys_standing(GROUP)
            .await
            .unwrap()
    )
    .is_empty());
    let adopted = member
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: &joined.handover,
            joined: &BTreeMap::from([(member_id("b"), member_epoch)]),
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(adopted.adopted, BTreeSet::from([member_id("b")]));
    assert_eq!(
        held(
            member
                .groups
                .as_mut()
                .unwrap()
                .room_keys_standing(GROUP)
                .await
                .unwrap()
        ),
        BTreeSet::from([member_id("b")])
    );
    // The message is spent: opened once, never again.
    let again = member
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: &joined.handover,
            joined: &nobody,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!((again.adopted.len(), again.unread), (0, 1));
    // A hand-over from before the sender's membership is refused (and spent).
    let sealed = joiner
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &joiner_key,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(sealed.epoch, member_epoch);
    let early = member
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&sealed.message),
            joined: &BTreeMap::from([(member_id("b"), member_epoch + 1)]),
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!((early.adopted.len(), early.refused), (0, 1));

    // The member answers with its own key; the joiner adopts it.
    let sealed = member
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &member_key,
            policy: &policy,
        })
        .await
        .unwrap();
    let adopted = joiner
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&sealed.message),
            joined: &nobody,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!(adopted.adopted, BTreeSet::from([member_id("a")]));

    // A member cannot hand over a key that is not its own: the MLS sender is
    // the member, the key belongs to the joiner, which refuses it.
    let forged = member
        .groups
        .as_mut()
        .unwrap()
        .seal_room_key(RoomKeyTask {
            group: GROUP,
            payload: &joiner_key,
            policy: &policy,
        })
        .await
        .unwrap();
    let refused = joiner
        .groups
        .as_mut()
        .unwrap()
        .receive_room_secrets(RoomSecretsTask {
            group: GROUP,
            messages: std::slice::from_ref(&forged.message),
            joined: &nobody,
            policy: &policy,
        })
        .await
        .unwrap();
    assert_eq!((refused.adopted.len(), refused.refused), (0, 1));
    assert_eq!(
        held(
            joiner
                .groups
                .as_mut()
                .unwrap()
                .room_keys_standing(GROUP)
                .await
                .unwrap()
        ),
        BTreeSet::from([member_id("a")])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_admission_makes_the_member_read_the_roster_again() {
    let Scene {
        router,
        directory,
        member_view,
        mut member,
        member_board,
    } = scene().await;
    let evidence = member
        .groups
        .as_mut()
        .unwrap()
        .room_evidence(GROUP, &policy_at())
        .await
        .unwrap();
    let (_, epoch_before) = standing(&member).await;
    let mut cursor = 0;

    // One roster lineage moved on since the member read it: Threads refuses the
    // leaf it certifies, the admission is refused and the roster is forgotten.
    member
        .groups
        .as_mut()
        .unwrap()
        .make_roster_lineage_stale(&member_id("x"));
    let (mut joiner, _) = stranger(&directory, "b", 32).await;
    let joiner_board = board(&router, 60, false).await;
    let (joined, admitted) = attempt(
        &mut joiner,
        &joiner_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
        vec![],
    )
    .await;
    assert!(joined.is_err());
    assert_eq!(admitted.len(), 1);
    assert!(admitted[0].is_err());
    let (members, epoch) = standing(&member).await;
    assert_eq!(members.len(), 3);
    assert_eq!(epoch, epoch_before);
    assert!(member.groups.as_ref().unwrap().roster_members().is_empty());

    // The next attempt reads the roster again (Charter-verified) and succeeds.
    let reads_before = member_view.reads.borrow().len();
    let evidence = member
        .groups
        .as_mut()
        .unwrap()
        .room_evidence(GROUP, &policy_at())
        .await
        .unwrap();
    assert_eq!(
        member.groups.as_ref().unwrap().roster_members(),
        BTreeSet::from([member_id("x"), member_id("y")])
    );
    assert_eq!(member_view.reads.borrow().len() - reads_before, 2);
    let (mut second, second_handle) = stranger(&directory, "d", 37).await;
    let second_board = board(&router, 60, false).await;
    let (joined, admitted) = attempt(
        &mut second,
        &second_board,
        &evidence,
        &mut member,
        &member_board,
        &mut cursor,
        vec![],
    )
    .await;
    joined.unwrap();
    admitted[0].as_ref().unwrap();
    let both = BTreeSet::from([
        member_id("a"),
        member_id("x"),
        member_id("y"),
        member_id("d"),
    ]);
    assert_eq!(standing(&member).await.0, both);
    assert_eq!(standing(&second).await.0, both);
    assert!(member_view.reads.borrow().contains(&second_handle));
}

#[path = "room_catch_up.rs"]
mod catch_up;
