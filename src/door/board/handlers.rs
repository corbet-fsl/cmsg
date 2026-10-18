//! Concrete Board orchestration; domain checks remain in the original owners.
use super::*;
use crate::door::facades::{BoardBinding, BoundBoard, OwnedFuture};
use std::{future::Future, pin::Pin};

/// Future on the custody-owning local task; no Send requirement is imposed on
/// Keys, Store guards or their scoped callbacks.
pub type OwnerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Borrowed only after the parent has reconciled the actual compound checkpoint
/// and freshly authorized current Keys. Keep the Store guard through the callback.
/// The contact callback checks profile text for prohibited contact details;
/// it is not the Contacts relationship journal and must refuse if unavailable.
pub struct CommittedRead<'a, B: cwst::backend::Backend> {
    pub store: &'a cwst::Store<B>,
    pub binding: &'a ckmg::Binding,
    pub contact: &'a dyn Fn(&str) -> cshm::ContactCheck,
    /// Members the Contacts journal blocks, read in this same snapshot.
    pub blocked: &'a [String],
}

impl<B: cwst::backend::Backend> CommittedRead<'_, B> {
    /// Call this with the sender's member id BEFORE opening, decrypting or
    /// caching anything that sender produced (profile, key transfer, reply).
    /// A blocked sender is refused and nothing of theirs is read.
    pub fn refuse_blocked(&self, sender: &str) -> Result<()> {
        if self.blocked.iter().any(|blocked| blocked == sender) {
            Err(ErrorCode::Refused)
        } else {
            Ok(())
        }
    }
}

/// Explicit trusted deployment policy. No default action or snapshot age exists;
/// neither field is accepted by a public Board action.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadPolicy {
    pub admission_action: String,
    pub maximum_snapshot_age: u64,
}

/// Original device signature with its live exact-command signing intent. The
/// parent constructs this only through Keys for the original Challenge message.
/// It is not serializable and the intent stays alive through remote completion.
pub struct SignedAttendance {
    pub signature: Vec<u8>,
    pub admitted: ckmg::IntentGuard,
}

/// Parent-owned production capability retained with Board. There is deliberately
/// no default/accepting implementation. It must share Vault's lock/revoke/restore
/// lifetime and check it at each use. Binding this trait does not make an account
/// ready or authenticate a member.
///
/// `with_current` must perform all asynchronous Store/Keys freshness checks before
/// invoking the synchronous callback exactly once, with the actual committed
/// Store and current lineage Binding. It must return the callback's result
/// unchanged, without awaiting afterward or retaining any borrowed input/output.
/// CMSG borrows the one Foyer Charter inside that callback, after those waits.
///
/// `sign_attendance` must admit precisely this origin, expiry and original
/// Challenge transcript, using the original credential-authorized device signer.
/// It must not manufacture an intent, accept a raw signature from JSON, or use a
/// generic policy accepting every signing command. The parent owns that security
/// integration; the existing Prepared-request Vault signer is not a substitute.
pub trait CommittedOwner {
    type Backend: cwst::backend::Backend;

    fn with_current<'a, T: 'a, F>(&'a mut self, read: F) -> OwnerFuture<'a, T>
    where
        F: for<'read> FnOnce(CommittedRead<'read, Self::Backend>) -> Result<T> + 'a;

    fn sign_attendance<'a>(
        &'a mut self,
        challenge: &'a clnk::Challenge,
        origin: &'a str,
        expires: u64,
    ) -> OwnerFuture<'a, SignedAttendance>;

    /// The Forum Enter `record_proof`: the member's cached record of the current
    /// `epoch` bound to the challenge's record context (JSON presentation). Nothing
    /// is proven on this path; owners without record custody refuse.
    fn present_record<'a>(
        &'a mut self,
        _challenge: &'a clnk::Challenge,
        _epoch: &'a czkp::record::Epoch,
    ) -> OwnerFuture<'a, Vec<u8>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// Group membership writes: the owner's encrypted checkpoint, device
    /// signer for consents, current Guard/Contacts authority and the atomic
    /// Threads publication. Owners without this integration refuse writes.
    fn groups(&mut self) -> Option<&mut dyn cbrd::GroupOwner> {
        None
    }

    /// Ordered external commit into a member room; see `VaultGroupOwner::join_room`.
    /// Owners without Threads custody refuse.
    fn join_room<'a, T, L>(
        &'a mut self,
        _board: &'a cbrd::Board<T, L>,
        _task: crate::door::facades::RoomJoinTask<'a>,
    ) -> OwnerFuture<'a, cbrd::cgrp::Snapshot>
    where
        T: clnk::Transport,
        L: crate::door::RoomLink,
    {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// Leave a member room in one commit (see `VaultGroupOwner::leave_room`);
    /// `None` when this device never joined that room through Attend.
    fn leave_room<'a>(
        &'a mut self,
        _task: crate::door::facades::RoomLeaveTask<'a>,
    ) -> OwnerFuture<'a, Option<cbrd::cgrp::Snapshot>> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// Admit a newcomer to a member room; see `VaultGroupOwner::admit_room`.
    /// Owners without Threads custody refuse.
    fn admit_room<'a, T, L>(
        &'a mut self,
        _board: &'a cbrd::Board<T, L>,
        _task: crate::door::facades::RoomAdmitTask<'a>,
    ) -> OwnerFuture<'a, cbrd::cgrp::Snapshot>
    where
        T: clnk::Transport,
        L: crate::door::RoomLink,
    {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// This member's evidence for a room it belongs to, for answering joins.
    fn room_evidence<'a>(
        &'a mut self,
        _group: cbrd::cgrp::Id,
        _policy: &'a dyn cbrd::cgrp::PolicySource,
    ) -> OwnerFuture<'a, cthr::ParentEvidence> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// Profile publication. Lend the actual device signer and Envelope custody
    /// together with the committed Store read, after fresh Keys authority, to a
    /// synchronous callback; return its result unchanged. Owners without this
    /// integration refuse.
    fn with_profile<'a, T: 'a, F>(&'a mut self, _prepare: F) -> OwnerFuture<'a, T>
    where
        F: for<'p> FnOnce(super::ProfileParts<'p, Self::Backend>) -> Result<T> + 'a,
    {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }

    /// Commit an authorized profile publication atomically in the Vault Store
    /// (Store version fence), then return the new checkpoint version.
    fn commit_profile(&mut self, _authorized: cbrd::cpfl::Authorized) -> OwnerFuture<'_, u64> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
}

pub(super) struct OwnedBoard<T, R, O> {
    pub(super) inner: BoardBinding<T, R>,
    pub(super) owner: O,
    pub(super) policy: ReadPolicy,
    pub(super) current: cfyr::policy::CurrentPolicy<foyer::Transport>,
    // Original Link does not expose Enter's request for replay. An interrupted
    // attendance attempt is fenced and requires owner reconciliation, not retry.
    attendance_pending: bool,
    pub(super) joins: super::rooms::RoomJoins,
    pub(super) desk: GroupDesk,
    desk_loaded: bool,
}

/// The durable form of the desk, kept by the owner in its encrypted records.
#[derive(Default, Serialize, Deserialize)]
struct DeskRecord {
    proposals: Vec<cbrd::GroupProposal>,
    invitations: Vec<cbrd::Invitation>,
    /// Invitations this member accepted, waiting for the actor's Welcome.
    #[serde(default)]
    accepted: Vec<cbrd::Invitation>,
    /// Welcomes this member, as creator, still owes to other members.
    #[serde(default)]
    welcomes: Vec<PendingWelcome>,
    /// This device's listing keys of public rooms (`cgrp::Listings`, encoded;
    /// holds private keys, lives only in the encrypted owner record).
    #[serde(default)]
    listings: Option<Vec<u8>>,
    /// Members this device, as the creator or last rotator of a room's listing
    /// key, already sent the key to.
    #[serde(default)]
    listing_sent: Vec<([u8; 32], BTreeSet<String>)>,
}

/// How long after the request's consent window a Welcome stays valid to
/// deliver or to join from (the group already exists; members may be offline).
const WELCOME_SECONDS: u64 = 7 * 24 * 3_600;

#[derive(Clone, Serialize, Deserialize)]
struct PendingWelcome {
    operation: [u8; 32],
    until: u64,
    /// Members that have not been reported as served.
    remaining: BTreeSet<String>,
    /// The Welcome message text (the same for every member).
    text: String,
}

/// Group proposals this member made and invitations awaiting this member's own
/// answer. Held in memory only: after a restart a pending consent is gone and
/// the actor must propose again; nothing is ever consented on a member's behalf.
#[derive(Default)]
pub(super) struct GroupDesk {
    proposals: BTreeMap<[u8; 32], cbrd::GroupProposal>,
    invitations: BTreeMap<[u8; 32], cbrd::Invitation>,
    accepted: BTreeMap<[u8; 32], cbrd::Invitation>,
    welcomes: BTreeMap<[u8; 32], PendingWelcome>,
    pub(super) listings: Option<cbrd::cgrp::Listings>,
    pub(super) listing_sent: BTreeMap<[u8; 32], BTreeSet<String>>,
    /// Rooms whose key this device waited one cycle for (memory only).
    pub(super) listing_wait: BTreeSet<[u8; 32]>,
}

/// Open proposals and open invitations each; further ones are refused until
/// answered or expired.
const MAX_PENDING_GROUP: usize = 16;

fn command_summary(command: &cbrd::cgrp::Command) -> (String, Vec<String>) {
    use cbrd::cgrp::Command;
    match command {
        Command::Create { members, .. } => ("create".into(), members.iter().cloned().collect()),
        Command::Fork { members, .. } => ("fork".into(), members.iter().cloned().collect()),
        Command::Join {
            member, vouches, ..
        } => (
            "join".into(),
            vouches.iter().cloned().chain([member.clone()]).collect(),
        ),
        Command::Leave { .. } => ("leave".into(), vec![]),
        Command::Describe { .. } => ("describe".into(), vec![]),
        Command::Tick => ("tick".into(), vec![]),
    }
}

enum PageKind {
    Search,
    Watch,
}

enum PendingPage {
    Search(cbrd::PendingSearch),
    Watch(cbrd::PendingWatch),
}

impl Door {
    /// Bind an original Board together with the parent's scoped committed-read
    /// and attendance-signing owner. The Board must not already be installed.
    /// Use this in trusted construction instead of bind_board/configure_board;
    /// no generated action can install the owner or choose the policy.
    pub fn bind_board_with_owner<T, R, O>(
        &mut self,
        origin: &str,
        board: cbrd::Board<T, R>,
        owner: O,
        policy: ReadPolicy,
    ) -> Result<()>
    where
        T: clnk::Transport + 'static,
        R: crate::door::RoomLink,
        O: CommittedOwner + 'static,
    {
        self.member_origin(origin)?;
        if board.community() != self.config.community
            || self.boards.contains_key(origin)
            || policy.admission_action.is_empty()
            || policy.maximum_snapshot_age == 0
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let current = self.current_policy(origin)?;
        self.boards.insert(
            origin.into(),
            Box::new(OwnedBoard {
                inner: BoardBinding {
                    board,
                    pending: None,
                },
                owner,
                policy,
                current,
                attendance_pending: false,
                joins: Default::default(),
                desk: GroupDesk::default(),
                desk_loaded: false,
            }),
        );
        Ok(())
    }
}

fn now(expires: u64) -> Result<u64> {
    let now = clnk::Clock::now(&SystemClock).map_err(|_| ErrorCode::Clock)? / 1000;
    if now >= expires {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(now)
}

/// No await is permitted inside this function. The actual Foyer weak port refuses
/// after disposal, while refreshing, and on stale/invalid original trust state.
pub(super) fn with_context<B: cwst::backend::Backend, T>(
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    community: &str,
    expires: u64,
    read: CommittedRead<'_, B>,
    finish: impl FnOnce(&cbrd::ReadContext<'_, B>, u64) -> Result<T>,
) -> Result<T> {
    if read.binding.community() != community || !read.store.is_scope(community) {
        return Err(ErrorCode::Unauthorized);
    }
    let started = now(expires)?;
    let result = current
        .with_current(started, |charter| {
            if charter.community() != community {
                return Err(ErrorCode::Unauthorized);
            }
            check_version(charter, started)?;
            let context = cbrd::ReadContext {
                store: read.store,
                binding: read.binding,
                charter,
                policy: cbrd::ReadPolicy {
                    admission_action: &policy.admission_action,
                    maximum_snapshot_age: policy.maximum_snapshot_age,
                },
                contact: read.contact,
            };
            let output = finish(&context, started)?;
            if now(expires)? != started {
                return Err(ErrorCode::Clock);
            }
            Ok(output)
        })
        .map_err(|_| ErrorCode::Unavailable)?;
    result
}

/// The record epoch the community's current signed balance publication names.
fn current_record_epoch(
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    community: &str,
    expires: u64,
) -> Result<czkp::record::Epoch> {
    let started = now(expires)?;
    current
        .with_current(started, |charter| {
            if charter.community() != community {
                return Err(ErrorCode::Unauthorized);
            }
            let balance = charter.balance().ok_or(ErrorCode::Unavailable)?;
            let material: cblc::publication::PublicVerifierMaterial =
                serde_json::from_slice(balance.payload()).map_err(|_| ErrorCode::Unauthorized)?;
            material
                .validate_at(community, started)
                .map_err(|_| ErrorCode::Unauthorized)?;
            material.record_epoch.ok_or(ErrorCode::Unavailable)
        })
        .map_err(|_| ErrorCode::Unavailable)?
}

fn publication<B: cwst::backend::Backend>(
    context: &cbrd::ReadContext<'_, B>,
    now: u64,
) -> Result<Vec<u8>> {
    let policy = context
        .charter
        .admission_policy(
            context.policy.admission_action,
            now,
            context.policy.maximum_snapshot_age,
        )
        .map_err(|_| ErrorCode::Refused)?;
    let signed_schema = context
        .charter
        .publication(cchr::Kind::Schema)
        .signed_bytes();
    let committed = cpfl::load_current_committed(
        context.store,
        context.binding,
        cpfl::Validation {
            policy,
            signed_schema,
            contact: context.contact,
        },
    )
    .map_err(|_| ErrorCode::Refused)?
    .ok_or(ErrorCode::Unavailable)?;
    // Only the original committed Profile crosses the upcoming network await.
    // It is reloaded and compared after each wait, never accepted as an input.
    Ok(committed.bytes().to_vec())
}
/// Upper bound on groups one device keeps (Groups refuses beyond it).
pub(super) const MAX_GROUPS: usize = 256;

pub(super) fn group_error(error: cbrd::cgrp::Error) -> ErrorCode {
    use cbrd::cgrp::Error;
    match error {
        Error::Invalid => ErrorCode::InvalidRequest,
        Error::Policy | Error::Unavailable => ErrorCode::Unavailable,
        Error::Authority => ErrorCode::Unauthorized,
        Error::Conflict | Error::Reconcile => ErrorCode::Reconcile,
        Error::Capacity => ErrorCode::Capacity,
        Error::Clock => ErrorCode::Clock,
    }
}

pub(super) fn board_error(error: cbrd::Error) -> ErrorCode {
    match error {
        cbrd::Error::Scope => ErrorCode::Unauthorized,
        cbrd::Error::Unavailable => ErrorCode::Unavailable,
        cbrd::Error::Rejected => ErrorCode::Refused,
    }
}

impl<T: clnk::Transport, R, O: CommittedOwner> OwnedBoard<T, R, O> {
    pub(super) fn idle(&self) -> Result<()> {
        if self.attendance_pending || self.inner.pending.is_some() {
            Err(ErrorCode::Reconcile)
        } else {
            Ok(())
        }
    }

    async fn attendance(&mut self, origin: &str, expires: u64) -> Result<cbrd::Status> {
        self.idle()?;
        let mut attempt = Disclosure {
            board: &mut self.inner.board,
            completed: false,
        };
        let result = attendance(
            attempt.board,
            &mut self.owner,
            &mut self.current,
            &self.policy,
            &mut self.attendance_pending,
            origin,
            expires,
        )
        .await;
        attempt.completed = result.is_ok();
        result
    }

    async fn page(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
        kind: PageKind,
    ) -> Result<cbrd::DiscoveryPage> {
        self.idle()?;
        let action = match kind {
            PageKind::Search => "search",
            PageKind::Watch => "watch",
        };
        if prepared.action() != action {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut request = prepared.request().clone();
        request
            .possession_mut()
            .ok_or(ErrorCode::InvalidRequest)?
            .signature = signature.clone();
        self.inner.pending = Some(request);
        let mut disclosure = Disclosure {
            board: &mut self.inner.board,
            completed: false,
        };
        let received = match kind {
            PageKind::Search => disclosure
                .board
                .receive_search(prepared, signature)
                .await
                .map(PendingPage::Search),
            PageKind::Watch => disclosure
                .board
                .receive_watch(prepared, signature)
                .await
                .map(PendingPage::Watch),
        };
        // Board hides Link's completion classification. Retain the original
        // request after failure/cancellation; never infer that it is retryable.
        let pending = received.map_err(|_| ErrorCode::Reconcile)?;
        let community = disclosure.board.community().to_owned();
        let board = &mut *disclosure.board;
        let current = &mut self.current;
        let policy = &self.policy;
        let result = self
            .owner
            .with_current(|read| {
                with_context(current, policy, &community, expires, read, |context, _| {
                    match pending {
                        PendingPage::Search(pending) => {
                            board.finish_search_committed(pending, context)
                        }
                        PendingPage::Watch(pending) => {
                            board.finish_watch_committed(pending, context)
                        }
                    }
                    .map(|page| page.discovery())
                    .map_err(board_error)
                })
            })
            .await;
        // A typed pending page proves the read completed. Local disclosure
        // refusal cannot authorize replay of that original network request.
        self.inner.pending = None;
        disclosure.completed = result.is_ok();
        result
    }
}

/// A cancelled/panicked post-network authority read must clear presence/cache,
/// just like an explicit refusal. No stale Link success survives that await.
struct Disclosure<'a, T: clnk::Transport, R> {
    board: &'a mut cbrd::Board<T, R>,
    completed: bool,
}
impl<T: clnk::Transport, R> Drop for Disclosure<'_, T, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.board.disconnect();
        }
    }
}

async fn current_publication<O: CommittedOwner>(
    owner: &mut O,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    community: &str,
    expires: u64,
) -> Result<Vec<u8>> {
    owner
        .with_current(|read| {
            with_context(current, policy, community, expires, read, |context, now| {
                publication(context, now)
            })
        })
        .await
}

async fn attendance<T: clnk::Transport, R, O: CommittedOwner>(
    board: &mut cbrd::Board<T, R>,
    owner: &mut O,
    current: &mut cfyr::policy::CurrentPolicy<foyer::Transport>,
    policy: &ReadPolicy,
    pending: &mut bool,
    origin: &str,
    expires: u64,
) -> Result<cbrd::Status> {
    let community = board.community().to_owned();
    let publication = current_publication(owner, current, policy, &community, expires).await?;
    *pending = true;
    let challenge = board
        .connect(clnk::ChallengeInput {
            publication: publication.clone(),
        })
        .await
        .map_err(after_send)?;
    // These failures precede Enter, so no attendance effect is uncertain.
    let signature = match owner.sign_attendance(&challenge, origin, expires).await {
        Ok(signature) => signature,
        Err(error) => {
            *pending = false;
            return Err(error);
        }
    };
    match current_publication(owner, current, policy, &community, expires).await {
        Ok(current) if current == publication => (),
        Ok(_) => {
            *pending = false;
            return Err(ErrorCode::Refused);
        }
        Err(error) => {
            *pending = false;
            return Err(error);
        }
    }
    // A Forum without accounting sends no record context and takes no proof.
    let record_proof = if challenge.record_context().is_empty() {
        Vec::new()
    } else {
        let proof = match current_record_epoch(current, &community, expires) {
            Ok(epoch) => owner.present_record(&challenge, &epoch).await,
            Err(error) => Err(error),
        };
        match proof {
            Ok(proof) => proof,
            Err(error) => {
                *pending = false;
                return Err(error);
            }
        }
    };
    let SignedAttendance {
        signature,
        admitted: _admitted,
    } = signature;
    // Preserve uncertainty on every failed/cancelled Enter. Never retry a
    // possibly accepted entry after losing its original response.
    board
        .enter(signature, record_proof)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    // An accepted network response alone does not permit reporting presence.
    // Reload current Profile/Keys/Contacts and the same Foyer after this await.
    match current_publication(owner, current, policy, &community, expires).await {
        Ok(current) if current == publication => (),
        _ => return Err(ErrorCode::Reconcile),
    }
    let status = board.status();
    if status.connection != clnk::State::Present {
        return Err(ErrorCode::Reconcile);
    }
    *pending = false;
    Ok(status)
}

impl<T: clnk::Transport, R, O: CommittedOwner> OwnedBoard<T, R, O> {
    /// The signed Rulebook's group policy for the current moment.
    pub(super) async fn group_policy(&mut self, expires: u64) -> Result<cbrd::PolicyAt> {
        let community = self.inner.board.community().to_owned();
        let board = &self.inner.board;
        let current = &mut self.current;
        let policy = &self.policy;
        let projected = self
            .owner
            .with_current(|read| {
                with_context(current, policy, &community, expires, read, |context, _| {
                    board
                        .read_group_policy_committed(context)
                        .map_err(board_error)
                })
            })
            .await?;
        Ok(cbrd::PolicyAt::new(&community, projected))
    }

    /// Read the durable desk once per binding; a restart keeps every pending
    /// invitation and proposal until its own expiry.
    pub(super) async fn load_desk(&mut self) -> Result<()> {
        if self.desk_loaded {
            return Ok(());
        }
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        if let Some(bytes) = owner.desk_load().await.map_err(group_error)? {
            let record: DeskRecord =
                serde_json::from_slice(&bytes).map_err(|_| ErrorCode::Reconcile)?;
            self.desk.proposals = record
                .proposals
                .into_iter()
                .map(|p| (p.operation(), p))
                .collect();
            self.desk.invitations = record
                .invitations
                .into_iter()
                .map(|i| (i.operation(), i))
                .collect();
            self.desk.accepted = record
                .accepted
                .into_iter()
                .map(|i| (i.operation(), i))
                .collect();
            self.desk.welcomes = record
                .welcomes
                .into_iter()
                .map(|w| (w.operation, w))
                .collect();
            self.desk.listing_sent = record.listing_sent.into_iter().collect();
            if let Some(bytes) = record.listings {
                let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
                let me = owner.member().map_err(group_error)?;
                let snapshot = owner.snapshot().await.map_err(group_error)?;
                self.desk.listings = Some(
                    cbrd::cgrp::Listings::decode(snapshot.community(), &me, &bytes)
                        .map_err(group_error)?,
                );
            }
        }
        self.desk_loaded = true;
        Ok(())
    }

    pub(super) async fn save_desk(&mut self) -> Result<()> {
        let record = DeskRecord {
            proposals: self.desk.proposals.values().cloned().collect(),
            invitations: self.desk.invitations.values().cloned().collect(),
            accepted: self.desk.accepted.values().cloned().collect(),
            welcomes: self.desk.welcomes.values().cloned().collect(),
            listings: match &self.desk.listings {
                Some(listings) => Some(listings.encode().map_err(group_error)?),
                None => None,
            },
            listing_sent: self
                .desk
                .listing_sent
                .iter()
                .map(|(group, sent)| (*group, sent.clone()))
                .collect(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| ErrorCode::Reconcile)?;
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        owner.desk_save(&bytes).await.map_err(group_error)
    }

    pub(super) fn group_clock(&mut self) -> Result<u64> {
        self.owner
            .groups()
            .ok_or(ErrorCode::Unavailable)?
            .now()
            .map_err(group_error)
    }

    fn prune_group_desk(&mut self, now: u64) {
        self.desk.proposals.retain(|_, p| p.expires_at() >= now);
        self.desk.invitations.retain(|_, i| i.expires_at() >= now);
        self.desk
            .accepted
            .retain(|_, i| i.expires_at().saturating_add(WELCOME_SECONDS) >= now);
        self.desk.welcomes.retain(|_, w| w.until >= now);
    }

    async fn commit_proposal(
        &mut self,
        operation: [u8; 32],
        expires: u64,
    ) -> Result<(Vec<cbrd::GroupView>, Vec<GroupInvite>)> {
        let source = self.group_policy(expires).await?;
        let proposal = self
            .desk
            .proposals
            .get(&operation)
            .ok_or(ErrorCode::Refused)?;
        let others: BTreeSet<String> = proposal
            .request()
            .consents
            .iter()
            .map(|consent| consent.member.clone())
            .filter(|member| member != &proposal.request().actor)
            .collect();
        let until = proposal.expires_at().saturating_add(WELCOME_SECONDS);
        let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
        let outcome = cbrd::commit_group_proposal(owner, &source, proposal, MAX_GROUPS).await;
        // A refused or interrupted commit never leaves a reusable consent set.
        self.desk.proposals.remove(&operation);
        let committed = outcome.map_err(group_error)?;
        let mut welcomes = vec![];
        if let Some(message) = committed.welcome {
            let text = message.to_text().map_err(group_error)?;
            welcomes = others
                .iter()
                .map(|member| GroupInvite {
                    member: member.clone(),
                    text: text.clone(),
                })
                .collect();
            self.desk.welcomes.insert(
                operation,
                PendingWelcome {
                    operation,
                    until,
                    remaining: others,
                    text,
                },
            );
        }
        Ok((committed.views, welcomes))
    }
}

impl<T: clnk::Transport, R: crate::door::RoomLink, O: CommittedOwner> BoundBoard
    for OwnedBoard<T, R, O>
{
    fn has_rooms(&self) -> bool {
        self.inner.has_rooms()
    }
    fn room_join(
        &mut self,
        join: super::RoomJoin,
        expires: u64,
    ) -> OwnedFuture<'_, super::RoomJoinStatus> {
        Box::pin(self.room_join_step(join, expires))
    }
    fn room_serve(
        &mut self,
        room: super::RoomRef,
        expires: u64,
    ) -> OwnedFuture<'_, super::RoomServed> {
        Box::pin(self.room_serve_step(room, expires))
    }
    fn room_admit(
        &mut self,
        room: super::RoomRef,
        expires: u64,
    ) -> OwnedFuture<'_, super::RoomAdmitted> {
        Box::pin(self.room_admit_step(room, expires))
    }
    fn room_leave(
        &mut self,
        room: super::RoomRef,
        expires: u64,
    ) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(self.room_leave_step(room, expires))
    }
    fn execute_room(
        &self,
        command: cbrd::clnk::cmbl::Request,
    ) -> crate::door::rooms::RoomFuture<'_, cbrd::clnk::cmbl::Outcome> {
        self.inner.execute_room(command)
    }
    fn require_committed(&self) -> Result<()> {
        self.idle()
    }
    fn status(&self) -> cbrd::Status {
        self.inner.status()
    }
    fn disconnect(&mut self) -> cbrd::Status {
        self.inner.disconnect()
    }
    fn prepare(&mut self, request: cfrm::Request, nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        self.idle()?;
        self.inner.prepare(request, nonce)
    }
    fn execute(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, cfrm::Reply> {
        if let Err(error) = self.idle() {
            return Box::pin(async move { Err(error) });
        }
        self.inner.execute(prepared, signature)
    }
    fn room_refs(&mut self) -> OwnedFuture<'_, Vec<super::rooms::RoomRef>> {
        Box::pin(self.room_refs_step())
    }
    fn room_listing(&mut self) -> OwnedFuture<'_, super::rooms::ListingPlan> {
        Box::pin(self.room_listing_step())
    }
    fn room_connection(&self, room: [u8; 16]) -> Result<[u8; 16]> {
        self.inner.room_connection(room)
    }
    fn room_prepare_epoch(&mut self, nonce: [u8; 16]) -> Result<cbrd::Prepared> {
        self.idle()?;
        self.inner.room_prepare_epoch(nonce)
    }
    fn room_receive_epoch(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, ()> {
        if let Err(error) = self.idle() {
            return Box::pin(async move { Err(error) });
        }
        self.inner.room_receive_epoch(prepared, signature)
    }
    fn room_prepare_pass(
        &mut self,
        room: [u8; 16],
        operation: [u8; 16],
        nonce: [u8; 16],
    ) -> Result<cbrd::Prepared> {
        self.idle()?;
        self.inner.room_prepare_pass(room, operation, nonce)
    }
    fn room_receive_pass(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> OwnedFuture<'_, [u8; 16]> {
        if let Err(error) = self.idle() {
            return Box::pin(async move { Err(error) });
        }
        self.inner.room_receive_pass(prepared, signature)
    }
    fn attend(&mut self, origin: &str, expires: u64) -> OwnedFuture<'_, cbrd::Status> {
        let origin = origin.to_owned();
        Box::pin(async move {
            let result = self.attendance(&origin, expires).await;
            if result.is_err() {
                self.inner.board.disconnect();
            }
            result
        })
    }
    fn search(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(self.page(prepared, signature, expires, PageKind::Search))
    }
    fn watch(
        &mut self,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
        expires: u64,
    ) -> OwnedFuture<'_, cbrd::DiscoveryPage> {
        Box::pin(self.page(prepared, signature, expires, PageKind::Watch))
    }
    fn groups(&mut self, expires: u64) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async move {
            self.idle()?;
            let community = self.inner.board.community().to_owned();
            let board = &self.inner.board;
            let current = &mut self.current;
            let policy = &self.policy;
            self.owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board.read_groups_committed(context).map_err(board_error)
                    })
                })
                .await
        })
    }
    fn group_act(
        &mut self,
        intent: cbrd::GroupIntent,
        expires: u64,
    ) -> OwnedFuture<'_, Vec<cbrd::GroupView>> {
        Box::pin(async move {
            self.idle()?;
            if self.owner.groups().is_none() {
                return Err(ErrorCode::Unavailable);
            }
            let community = self.inner.board.community().to_owned();
            let board = &self.inner.board;
            let current = &mut self.current;
            let policy = &self.policy;
            // The signed Rulebook is read synchronously; consent gathering and
            // publication then run against that exact policy, which Groups
            // re-validates against its own expiry at every step.
            let projected = self
                .owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board
                            .read_group_policy_committed(context)
                            .map_err(board_error)
                    })
                })
                .await?;
            let source = cbrd::PolicyAt::new(&community, projected);
            let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
            let (views, _) =
                cbrd::execute_group_intent(owner, &source, intent, MAX_GROUPS)
                    .await
                    .map_err(group_error)?;
            Ok(views)
        })
    }
    fn group_propose(
        &mut self,
        intent: cbrd::GroupIntent,
        expires: u64,
    ) -> OwnedFuture<'_, GroupProposed> {
        Box::pin(async move {
            self.idle()?;
            if self.owner.groups().is_none() {
                return Err(ErrorCode::Unavailable);
            }
            self.load_desk().await?;
            let now = self.group_clock()?;
            self.prune_group_desk(now);
            if self.desk.proposals.len() >= MAX_PENDING_GROUP {
                return Err(ErrorCode::Capacity);
            }
            let source = self.group_policy(expires).await?;
            let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
            let command = intent.command(&owner.member().map_err(group_error)?);
            let proposal = cbrd::propose_group_command(owner, &source, command)
                .await
                .map_err(group_error)?;
            let operation = proposal.operation();
            if proposal.complete() {
                self.desk.proposals.insert(operation, proposal);
                let (views, _) = self.commit_proposal(operation, expires).await?;
                self.save_desk().await?;
                return Ok(GroupProposed {
                    operation,
                    invitations: vec![],
                    committed: Some(views),
                });
            }
            let text = proposal.invitation().to_text().map_err(group_error)?;
            let invitations = proposal
                .awaiting()
                .iter()
                .map(|member| GroupInvite {
                    member: member.clone(),
                    text: text.clone(),
                })
                .collect();
            self.desk.proposals.insert(operation, proposal);
            self.save_desk().await?;
            Ok(GroupProposed {
                operation,
                invitations,
                committed: None,
            })
        })
    }
    fn group_message(
        &mut self,
        from: String,
        text: String,
        expires: u64,
    ) -> OwnedFuture<'_, GroupInbound> {
        Box::pin(async move {
            self.idle()?;
            if self.owner.groups().is_none() {
                return Err(ErrorCode::Unavailable);
            }
            self.load_desk().await?;
            let now = self.group_clock()?;
            self.prune_group_desk(now);
            let message = cbrd::GroupMessage::from_text(&text).map_err(group_error)?;
            if let cbrd::GroupMessage::Invite { request, .. } = &message {
                if self.desk.invitations.len() >= MAX_PENDING_GROUP
                    || self.desk.invitations.contains_key(&request.operation)
                {
                    return Err(ErrorCode::Capacity);
                }
                let source = self.group_policy(expires).await?;
                let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
                let invitation = cbrd::Invitation::receive(owner, &source, &from, message)
                    .await
                    .map_err(group_error)?;
                let (command, members) = command_summary(&invitation.request().command);
                let operation = invitation.operation();
                let actor = invitation.actor().to_owned();
                self.desk.invitations.insert(operation, invitation);
                self.save_desk().await?;
                return Ok(GroupInbound::Invitation {
                    operation,
                    actor,
                    command,
                    members,
                });
            }
            if let cbrd::GroupMessage::Listing { share, .. } = &message {
                // A listing key counts only from a current fellow member of that
                // very room, never from anyone else and never from this device.
                let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
                let me = owner.member().map_err(group_error)?;
                let snapshot = owner.snapshot().await.map_err(group_error)?;
                let sender_is_member = snapshot
                    .members(&share.group)
                    .map(|members| members.contains(&from) && members.contains(&me))
                    .unwrap_or(false);
                if from == me || !sender_is_member {
                    return Err(ErrorCode::Refused);
                }
                let mut listings = self.desk.listings.take().unwrap_or_else(|| {
                    cbrd::cgrp::Listings::new(snapshot.community(), &me)
                });
                let adopted = listings.adopt(&snapshot, share).map_err(group_error);
                self.desk.listings = Some(listings);
                adopted?;
                let group = share.group;
                self.save_desk().await?;
                return Ok(GroupInbound::Listing { group });
            }
            if let cbrd::GroupMessage::Welcome { request, .. } = &message {
                // Only an invitation this member accepted can be joined from, and
                // only the actor's own Welcome (checked again by the join).
                let operation = request.operation;
                let invitation = self
                    .desk
                    .accepted
                    .get(&operation)
                    .ok_or(ErrorCode::Refused)?
                    .clone();
                let source = self.group_policy(expires).await?;
                let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
                let (views, _) = invitation
                    .join(owner, &source, &from, message, MAX_GROUPS)
                    .await
                    .map_err(group_error)?;
                self.desk.accepted.remove(&operation);
                self.save_desk().await?;
                return Ok(GroupInbound::Joined { operation, views });
            }
            let operation = match &message {
                cbrd::GroupMessage::Consent { consent, .. } => consent.operation,
                cbrd::GroupMessage::Decline { operation, .. } => *operation,
                cbrd::GroupMessage::Invite { .. }
                | cbrd::GroupMessage::Welcome { .. }
                | cbrd::GroupMessage::Listing { .. } => {
                    return Err(ErrorCode::InvalidRequest);
                }
            };
            let proposal = self
                .desk
                .proposals
                .get_mut(&operation)
                .ok_or(ErrorCode::Refused)?;
            proposal.admit(&from, message, now).map_err(group_error)?;
            if proposal.declined() {
                self.desk.proposals.remove(&operation);
                self.save_desk().await?;
                return Ok(GroupInbound::Declined { operation });
            }
            if proposal.complete() {
                let (views, welcomes) = self.commit_proposal(operation, expires).await?;
                self.save_desk().await?;
                return Ok(GroupInbound::Committed {
                    operation,
                    views,
                    welcomes,
                });
            }
            let awaiting = proposal.awaiting().iter().cloned().collect();
            self.save_desk().await?;
            Ok(GroupInbound::Waiting {
                operation,
                awaiting,
            })
        })
    }
    fn group_answer(
        &mut self,
        operation: [u8; 32],
        accept: bool,
        _expires: u64,
    ) -> OwnedFuture<'_, GroupAnswered> {
        Box::pin(async move {
            self.idle()?;
            self.load_desk().await?;
            let now = self.group_clock()?;
            self.prune_group_desk(now);
            let invitation = self
                .desk
                .invitations
                .remove(&operation)
                .ok_or(ErrorCode::Refused)?;
            let owner = self.owner.groups().ok_or(ErrorCode::Unavailable)?;
            let message = invitation
                .answer(owner, accept)
                .await
                .map_err(group_error)?;
            // A group that needs MLS follows with the actor's Welcome.
            if accept && cbrd::created_group(&invitation.request().command).is_some() {
                self.desk.accepted.insert(operation, invitation.clone());
            }
            self.save_desk().await?;
            Ok(GroupAnswered {
                actor: invitation.actor().to_owned(),
                text: message.to_text().map_err(group_error)?,
            })
        })
    }
    fn group_welcome(
        &mut self,
        operation: [u8; 32],
        delivered: Vec<String>,
        _expires: u64,
    ) -> OwnedFuture<'_, GroupWelcomes> {
        Box::pin(async move {
            self.idle()?;
            if self.owner.groups().is_none() {
                return Err(ErrorCode::Unavailable);
            }
            self.load_desk().await?;
            let now = self.group_clock()?;
            self.prune_group_desk(now);
            let pending = self
                .desk
                .welcomes
                .get_mut(&operation)
                .ok_or(ErrorCode::Refused)?;
            for member in &delivered {
                pending.remaining.remove(member);
            }
            let offered = pending
                .remaining
                .iter()
                .map(|member| GroupInvite {
                    member: member.clone(),
                    text: pending.text.clone(),
                })
                .collect();
            if pending.remaining.is_empty() {
                self.desk.welcomes.remove(&operation);
            }
            self.save_desk().await?;
            Ok(GroupWelcomes {
                operation,
                pending: offered,
            })
        })
    }
    fn profile_publish(&mut self, edit: cbrd::Edit, expires: u64) -> OwnedFuture<'_, u64> {
        Box::pin(self.publish_profile(edit, expires))
    }
    fn discovery(&mut self, expires: u64) -> OwnedFuture<'_, Vec<cbrd::Discovery>> {
        Box::pin(async move {
            self.idle()?;
            let community = self.inner.board.community().to_owned();
            let mut disclosure = Disclosure {
                board: &mut self.inner.board,
                completed: false,
            };
            let board = &mut *disclosure.board;
            let current = &mut self.current;
            let policy = &self.policy;
            let result = self
                .owner
                .with_current(|read| {
                    with_context(current, policy, &community, expires, read, |context, _| {
                        board.read_discovery_committed(context).map_err(board_error)
                    })
                })
                .await;
            disclosure.completed = result.is_ok();
            result
        })
    }
}

pub(in crate::door) async fn attend(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(cbrd::Status, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    // A Vault removed by lock cannot continue using a retained Board capability.
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board.attend(&origin, expires).await?, vec![]))
}
pub(in crate::door) async fn search(
    door: &mut Door,
    key: &[u8; 32],
    request: Search,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    page(
        door,
        key,
        cfrm::Request::Search(cfrm::SearchInput {
            possession: possession(),
            cursor: request.cursor,
            page_size: request.page_size,
        }),
    )
    .await
}

pub(in crate::door) async fn watch(
    door: &mut Door,
    key: &[u8; 32],
    request: Watch,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    page(
        door,
        key,
        cfrm::Request::Watch(cfrm::WatchInput {
            possession: possession(),
            cursor: request.cursor,
        }),
    )
    .await
}

async fn page(
    door: &mut Door,
    key: &[u8; 32],
    request: cfrm::Request,
) -> Result<(cbrd::DiscoveryPage, Vec<Event>)> {
    let watch = matches!(request, cfrm::Request::Watch(_));
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let foyer = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let now = current::version(foyer, &door.config.community, expires, door.clock_floor)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| ErrorCode::Unavailable)?;
    let prepared = board.prepare(request, nonce)?;
    let facades::SignedBoard {
        signature,
        admitted: _admitted,
    } = vault.sign_board(&prepared, &origin, now, expires).await?;
    current::version(foyer, &door.config.community, expires, now)?;
    let result = if watch {
        board.watch(prepared, signature, expires).await?
    } else {
        board.search(prepared, signature, expires).await?
    };
    Ok((result, vec![]))
}
pub(in crate::door) async fn discovery(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Vec<cbrd::Discovery>, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    if !door.vaults.contains_key(&origin) {
        return Err(ErrorCode::Unavailable);
    }
    let board = door.boards.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    board.require_committed()?;
    Ok((board.discovery(expires).await?, vec![]))
}
