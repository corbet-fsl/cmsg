//! Group membership authority on the bound Vault: the Keys and Devices ports
//! of the group owner.
//!
//! What may be signed: only the local member's own consent, as the exact
//! `cgrp.consent.v3` statement bytes (which cover the member's MLS key package) Groups built for one command, signed with
//! the member's device key through the same single-use `SignDeviceEd25519`
//! intent as every other exact signature (one admission, one signature; the
//! statement is bound to community, member, operation, policy epoch and the
//! command digest). Nothing is signed for another member and no generic
//! signing callback escapes.
//!
//! Who is believed: Groups' synchronous `Authority` reads caches that
//! `refresh` fills from fresh reads at the start of each operation (own
//! lineage from Keys, peer lineage through the injected [`GroupPeers`] port,
//! contact relations from the Contacts journal) and clears afterwards. A
//! consent counts only if its device key is in that member's freshly read,
//! Charter-verified lineage. Vouches by other members' contacts are refused
//! until their evidence exists.
use super::*;
use crate::door::inbox_lineage::{
    CharterView, HandleOpener, PeerLineage, PeerUnavailable, StoredHandleRecords,
};
use cbrd::cgrp::{self, Snapshot};
use futures_util::lock::Mutex;
use std::{cell::RefCell, collections::BTreeMap, collections::BTreeSet, rc::Rc};

/// A lineage read older than this at verification is not current.
const LINEAGE_FRESH_SECONDS: u64 = 120;
const DESK_OWNER: &str = "cbrd";
const DESK_KEY: &[u8] = b"groups.desk.v1";

/// Forced, Charter-verified read of a peer's current lineage. `handle` is the
/// lineage-read capability this member's own Contacts journal retained for
/// that peer; no handle, no read. Any failure is `None`, so a missing lineage
/// makes that member's consent unverifiable.
pub trait GroupPeers {
    fn lineage<'a>(
        &'a mut self,
        binding: &'a ckmg::Binding,
        handle: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Option<ckmg::Lineage>> + 'a>>;
}

struct OpenerRef<'a, O>(&'a mut O);
impl<O: HandleOpener> HandleOpener for OpenerRef<'_, O> {
    async fn read(
        &mut self,
        binding: &ckmg::Binding,
        handle: &[u8],
    ) -> std::result::Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
        self.0.read(binding, handle).await
    }
}
struct ViewRef<'a, V>(&'a mut V);
impl<V: CharterView> CharterView for ViewRef<'_, V> {
    fn with_current<T>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&cchr::VerifiedCharter) -> std::result::Result<T, cnbx::ContactError>,
    ) -> std::result::Result<T, cnbx::ContactError> {
        self.0.with_current(community, now, inspect)
    }
}

/// Production peers: the peer's lineage records are read through the handle
/// this member's Contacts journal retained (never a claim the peer sends us)
/// and every item is reverified against the door-held community Charter,
/// including its passkey revocations (`PeerLineage`). Anything unreadable,
/// stale, revoked or foreign is refused.
pub struct VerifiedPeers<O, V, C> {
    opener: O,
    view: V,
    clock: C,
}
impl<O, V, C> VerifiedPeers<O, V, C> {
    pub fn new(opener: O, view: V, clock: C) -> Self {
        Self {
            opener,
            view,
            clock,
        }
    }
}
impl<O, V, C> GroupPeers for VerifiedPeers<O, V, C>
where
    O: HandleOpener,
    V: CharterView,
    C: FnMut() -> Option<u64>,
{
    fn lineage<'a>(
        &'a mut self,
        binding: &'a ckmg::Binding,
        handle: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Option<ckmg::Lineage>> + 'a>> {
        Box::pin(async move {
            let records = StoredHandleRecords::new(
                BTreeMap::from([(binding.member().to_owned(), handle.to_vec())]),
                OpenerRef(&mut self.opener),
            );
            let mut port = PeerLineage::new(records, ViewRef(&mut self.view), &mut self.clock);
            cnbx::DeviceAuthority::current(&mut port, binding)
                .await
                .ok()
        })
    }
}

#[derive(Default)]
struct Cache {
    lineages: BTreeMap<String, (ckmg::Lineage, u64)>,
    contacts: BTreeSet<String>,
}

/// What a member remembers of the other members of the rooms it takes part in,
/// across operations (row 14.8): the lineage-read handles it was given (locators
/// only) and the lineages read through them. Every stored lineage was read and
/// Charter-verified once and is bound to the member it names; it serves ONLY
/// the certification of MLS leaves (`GroupDevices`), never a consent decision
/// (those use the per-operation `Cache`, read fresh every time). It is dropped
/// whenever Threads refuses a certification (the lineage moved on), so the next
/// attempt reads it again.
#[derive(Default)]
struct Roster {
    handles: BTreeMap<String, Vec<u8>>,
    lineages: BTreeMap<String, ckmg::Lineage>,
}

impl Roster {
    /// Forget everything learned; the next operation reads again.
    fn forget(&mut self) {
        self.handles.clear();
        self.lineages.clear();
    }
}

struct CacheDevices(Rc<RefCell<Cache>>);
impl cbrd::Devices for CacheDevices {
    fn verify(
        &self,
        community: &str,
        member: &str,
        message: &[u8],
        signature: &[u8],
        authority: &[u8],
        now: u64,
    ) -> cgrp::Result<()> {
        let cache = self.0.borrow();
        let (lineage, read_at) = cache.lineages.get(member).ok_or(cgrp::Error::Authority)?;
        let key: [u8; 32] = authority.try_into().map_err(|_| cgrp::Error::Authority)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| cgrp::Error::Authority)?;
        if lineage.binding.community() != community
            || lineage.binding.member() != member
            || now.saturating_sub(*read_at) > LINEAGE_FRESH_SECONDS
            || !lineage.devices.iter().any(|device| device.value() == &key)
        {
            return Err(cgrp::Error::Authority);
        }
        ckmg::verify_ed25519(&key, message, &signature).map_err(|_| cgrp::Error::Authority)
    }
}

struct CacheContacts(Rc<RefCell<Cache>>, String);
impl cbrd::Contacts for CacheContacts {
    fn established(
        &self,
        _community: &str,
        member: &str,
        contact: &str,
        _now: u64,
    ) -> cgrp::Result<()> {
        // Only this member's own journal is known; another member's contacts
        // are not evidence this device holds.
        if member == self.1 && self.0.borrow().contacts.contains(contact) {
            Ok(())
        } else {
            Err(cgrp::Error::Authority)
        }
    }
}

/// Authority for a newcomer's consent in a member room. The device key is the
/// one the newcomer's certified MLS leaf credential names; that certificate was
/// verified against the newcomer's Charter-verified lineage before this value
/// exists, so the consent counts only when it comes from exactly that member,
/// is signed by exactly that device key and is unexpired. Contacts are
/// never consulted for rooms.
struct RoomAuthority {
    member: String,
    device: [u8; 32],
}
impl cgrp::Authority for RoomAuthority {
    fn consent(&self, consent: &cgrp::Consent, now: u64) -> cgrp::Result<()> {
        if consent.valid_until <= now
            || consent.member != self.member
            || consent.authority != self.device
        {
            return Err(cgrp::Error::Authority);
        }
        let signature: [u8; 64] = consent
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| cgrp::Error::Authority)?;
        ckmg::verify_ed25519(&self.device, &consent.signing_bytes()?, &signature)
            .map_err(|_| cgrp::Error::Authority)
    }
    fn contact(&self, _: &str, _: &str, _: &str, _: u64) -> cgrp::Result<()> {
        Err(cgrp::Error::Authority)
    }
}

/// Current lineages for Threads: this member's own and the peers' lineages the
/// last `refresh` read (Charter-verified, fresh). In a room operation the
/// roster's lineages verified earlier serve too (`roster`); anything else is
/// unavailable.
struct GroupDevices {
    own: ckmg::Lineage,
    cache: Rc<RefCell<Cache>>,
    /// Set only by room operations: the lineages of the room's members.
    roster: Option<Rc<RefCell<Roster>>>,
}
impl cnbx::DeviceAuthority for GroupDevices {
    async fn current(
        &mut self,
        binding: &ckmg::Binding,
    ) -> std::result::Result<ckmg::Lineage, cnbx::ContactError> {
        if binding.member() == self.own.binding.member() {
            return if *binding == self.own.binding {
                Ok(self.own.clone())
            } else {
                Err(cnbx::ContactError::Authority)
            };
        }
        let now = ckmg::Clock::now(&mut crate::door::custody::SystemClock)
            .map_err(|_| cnbx::ContactError::Unavailable)?;
        if let Some((lineage, read_at)) = self.cache.borrow().lineages.get(binding.member()) {
            if lineage.binding == *binding && now.saturating_sub(*read_at) <= LINEAGE_FRESH_SECONDS
            {
                return Ok(lineage.clone());
            }
        }
        match &self.roster {
            Some(roster) => match roster.borrow().lineages.get(binding.member()) {
                Some(lineage) if lineage.binding == *binding => Ok(lineage.clone()),
                _ => Err(cnbx::ContactError::Unavailable),
            },
            None => Err(cnbx::ContactError::Unavailable),
        }
    }
}

/// Sized view of the unsized policy the Board hands to the owner.
struct PolicyRef<'a>(&'a dyn cgrp::PolicySource);
impl cgrp::PolicySource for PolicyRef<'_> {
    fn current(&self, community: &str, now: u64) -> cgrp::Result<cgrp::Policy> {
        self.0.current(community, now)
    }
}

fn mls_error(error: cthr::Error) -> cgrp::Error {
    match error {
        cthr::Error::Authority | cthr::Error::Scope => cgrp::Error::Authority,
        cthr::Error::Conflict => cgrp::Error::Reconcile,
        cthr::Error::Storage => cgrp::Error::Reconcile,
        _ => cgrp::Error::Unavailable,
    }
}

fn mls_operation(label: &str, group: &cgrp::Id, operation: &cgrp::Id) -> [u8; 32] {
    let mut bytes = b"cmsg.group.mls.v1\0".to_vec();
    bytes.extend_from_slice(label.as_bytes());
    bytes.extend_from_slice(group);
    bytes.extend_from_slice(operation);
    *ckmg::hash(&bytes).value()
}

type Retained<B, C, E, A, R, W> = Rc<Mutex<Option<Custody<B, C, E, A, R, W>>>>;

/// The group owner of one bound Vault.
pub struct VaultGroupOwner<B: cwst::backend::Backend, C, E, A, R, W> {
    retained: Retained<B, C, E, A, R, W>,
    lifetime: crate::door::custody::CustodyLifetime,
    origin: String,
    member: String,
    peers: Option<Rc<Mutex<Box<dyn GroupPeers>>>>,
    cache: Rc<RefCell<Cache>>,
    /// Lineages of the rooms' members, kept across operations (row 14.8).
    roster: Rc<RefCell<Roster>>,
    authority: cbrd::BoardAuthority<CacheDevices, CacheContacts>,
    version: u64,
    /// Handles the signers attached to their own consents; they win over the journal.
    provided: BTreeMap<String, Vec<u8>>,
    /// Tests only: members treated as established contacts.
    #[cfg(test)]
    assumed_contacts: BTreeSet<String>,
}

impl<B: cwst::backend::Backend, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W> {
    pub(super) fn new(
        retained: Retained<B, C, E, A, R, W>,
        lifetime: crate::door::custody::CustodyLifetime,
        origin: String,
        member: String,
        peers: Option<Box<dyn GroupPeers>>,
    ) -> Self {
        let cache = Rc::new(RefCell::new(Cache::default()));
        Self {
            retained,
            lifetime,
            origin,
            authority: cbrd::BoardAuthority::new(
                CacheDevices(cache.clone()),
                CacheContacts(cache.clone(), member.clone()),
            ),
            member,
            peers: peers.map(|peers| Rc::new(Mutex::new(peers))),
            cache,
            roster: Rc::new(RefCell::new(Roster::default())),
            version: 0,
            provided: BTreeMap::new(),
            #[cfg(test)]
            assumed_contacts: BTreeSet::new(),
        }
    }
    /// Tests only: treat these members as established contacts, as if the
    /// Contacts journal held them (the contact exchange is not under test).
    #[cfg(test)]
    pub(crate) fn assume_contacts(&mut self, contacts: impl IntoIterator<Item = String>) {
        self.assumed_contacts.extend(contacts);
    }
    fn open(&self) -> cgrp::Result<()> {
        if self.lifetime.is_closed() {
            Err(cgrp::Error::Authority)
        } else {
            Ok(())
        }
    }
}

enum MlsStep<'a> {
    Create(&'a [Vec<u8>]),
    Join(&'a [u8]),
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Groups and the MLS group of `group` become visible in ONE Store commit
    /// (`Candidate::commit_groups`), after Threads built them from the same
    /// decision Groups prepared. Current authority is repeated inside.
    async fn mls_commit(
        &mut self,
        candidate: cgrp::Candidate,
        group: cgrp::Id,
        operation: cgrp::Id,
        step: MlsStep<'_>,
        policy: &dyn cgrp::PolicySource,
    ) -> cgrp::Result<(Snapshot, Vec<cgrp::CommittedEffect>, cthr::Committed)> {
        self.open()?;
        let mut retained = self.retained.lock().await;
        self.open()?;
        let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
        let binding = custody.binding.clone();
        let handle = custody
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(|_| cgrp::Error::Authority)?;
        let own = custody
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| cgrp::Error::Authority)?;
        let storage = custody.vault.storage().clone();
        let mut store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| cgrp::Error::Authority)?;
        let mut devices = GroupDevices {
            own,
            cache: self.cache.clone(),
            roster: None,
        };
        let mut port = cnbx::KeyPort {
            keys: custody.vault.keys(),
            handle: &handle,
            devices: &mut devices,
        };
        let mut clock = crate::door::custody::SystemClock;
        let threads = cthr::Threads::load(binding, group, &store).map_err(mls_error)?;
        let step_label = match step {
            MlsStep::Create(_) => "create",
            MlsStep::Join(_) => "join",
        };
        let prepared = {
            let effects = candidate.prepare_effects();
            let decision = effects
                .iter()
                .find(|effect| {
                    matches!(effect.event(), cgrp::Effect::Membership { group: g, .. } if g == &group)
                })
                .ok_or(cgrp::Error::Authority)?;
            // A room (a fork that opens, or a public room) is a different MLS
            // genesis from a hidden group; the level of the decision tells which.
            let room = matches!(
                decision.event(),
                cgrp::Effect::Membership {
                    level: cgrp::Level::Opening | cgrp::Level::Public,
                    ..
                }
            );
            match (step, room) {
                (MlsStep::Create(packages), false) => {
                    threads
                        .create_fork(&mut port, decision, packages, &mut clock)
                        .await
                }
                (MlsStep::Create(packages), true) => {
                    threads
                        .create_room(&mut port, decision, packages, &mut clock)
                        .await
                }
                (MlsStep::Join(welcome), false) => {
                    threads
                        .join_fork(&mut port, decision, welcome, &mut clock)
                        .await
                }
                (MlsStep::Join(welcome), true) => {
                    threads
                        .join_room(&mut port, decision, welcome, &mut clock)
                        .await
                }
            }
            .map_err(mls_error)?
        };
        let commit_operation = match step_label {
            "join" => mls_operation("join", &group, &group),
            _ => mls_operation("create", &group, &operation),
        };
        let (committed, snapshot, effects) = prepared
            .commit_groups(
                &mut port,
                candidate,
                &mut store,
                commit_operation,
                (&PolicyRef(policy), &self.authority),
                &mut clock,
            )
            .await
            .map_err(mls_error)?;
        self.open()?;
        Ok((snapshot, effects, committed))
    }
}

/// What a member-room join takes from the member's own devices: the sealed
/// state a member answered with, and the Groups decision already prepared.
pub struct RoomJoinTask<'a> {
    pub room: [u8; 16],
    pub group: cgrp::Id,
    pub candidate: cgrp::Candidate,
    /// The signed Groups `Join` request. The owner attaches it, together with
    /// the lineage-read handle of its OWN certified lineage, as the companion
    /// the external commit authenticates; admitting members read the newcomer's
    /// consent from it and its lineage through the handle.
    pub request: cgrp::Request,
    pub evidence: &'a cthr::ParentEvidence,
    /// The state `verify_room_state` authenticated: the only parent this Join may name.
    pub parent: &'a cgrp::GroupState,
    /// The lineage-read handles of the room's roster from the sealed room
    /// state (locators only; every lineage is read and Charter-verified).
    pub handles: &'a BTreeMap<String, Vec<u8>>,
    /// The room's transport key from the sealed room state.
    pub transport: &'a cbrd::TransportKey,
    pub policy: &'a dyn cgrp::PolicySource,
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Read the lineages of `members` this device does not hold yet (each
    /// Charter-verified and bound to its member by `refresh`); the ones it
    /// holds are kept as they are (row 14.8). Members whose lineage cannot be
    /// read stay missing, which makes Threads refuse the leaves they own.
    async fn ensure_roster(&mut self, members: &BTreeSet<String>) -> cgrp::Result<()> {
        let missing: BTreeSet<String> = {
            let roster = self.roster.borrow();
            members
                .iter()
                .filter(|member| **member != self.member && !roster.lineages.contains_key(*member))
                .cloned()
                .collect()
        };
        if missing.is_empty() {
            return Ok(());
        }
        cbrd::GroupOwner::refresh(self, &BTreeSet::new(), &missing).await
    }

    /// Newcomer: authenticate the delivered room state against its MLS evidence
    /// (same group, state commitment carried in the authenticated GroupInfo
    /// context, roster certified) before anything is prepared, sent or stored.
    pub async fn verify_room_state(
        &mut self,
        group: cgrp::Id,
        evidence: &cthr::ParentEvidence,
        handles: &BTreeMap<String, Vec<u8>>,
    ) -> std::result::Result<cgrp::GroupState, ctnd::Error> {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        // The handles are locators only; every lineage they yield is read and
        // Charter-verified, and must bind to the roster member asked for. The
        // state decoded here only selects whom to read; Threads authenticates it.
        let roster = cgrp::GroupState::decode(&evidence.state)
            .map_err(|_| Fail::Authority)?
            .members()
            .clone();
        cbrd::GroupOwner::provide_handles(self, handles.clone());
        let read = self.ensure_roster(&roster).await;
        self.provided.clear();
        if read.is_err() {
            *self.cache.borrow_mut() = Cache::default();
            return Err(Fail::Authority);
        }
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let handle = custody
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(|_| Fail::Authority)?;
        let own = custody
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| Fail::Authority)?;
        let storage = custody.vault.storage().clone();
        let store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let mut devices = GroupDevices {
            own,
            cache: self.cache.clone(),
            roster: Some(self.roster.clone()),
        };
        let mut port = cnbx::KeyPort {
            keys: custody.vault.keys(),
            handle: &handle,
            devices: &mut devices,
        };
        let threads = cthr::Threads::load(binding, group, &store).map_err(|_| Fail::Storage)?;
        let state = threads.verify_room_state(&mut port, evidence).await;
        *self.cache.borrow_mut() = Cache::default();
        if state.is_err() {
            self.roster.borrow_mut().forget();
        }
        state.map_err(|_| Fail::Authority)
    }

    /// Ordered external commit into a member room. Keys custody, the Store
    /// guard and this member's Threads come from the retained Vault; Groups,
    /// Threads and the Attend checkpoint become visible in ONE Store commit
    /// (`cthr::JoinSession`). A failed attempt leaves at most the Joining
    /// checkpoint, which the next attempt discards. The hand-over of profile
    /// keys is empty until Envelope supplies its content.
    pub async fn join_room<T, L>(
        &mut self,
        board: &cbrd::Board<T, L>,
        task: RoomJoinTask<'_>,
    ) -> std::result::Result<Snapshot, ctnd::Error>
    where
        T: cbrd::clnk::Transport,
        L: crate::door::RoomLink,
    {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        let operation = {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| Fail::Unavailable)?;
            bytes
        };
        // The roster's lineages are Charter-verified once and kept (row 14.8):
        // only the ones this device does not hold yet are read here. Threads
        // certifies every leaf of the room's tree against them.
        cbrd::GroupOwner::provide_handles(self, task.handles.clone());
        let read = self.ensure_roster(task.parent.members()).await;
        self.provided.clear();
        if read.is_err() {
            *self.cache.borrow_mut() = Cache::default();
            return Err(Fail::Authority);
        }
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let handle = custody
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(|_| Fail::Authority)?;
        let own = custody
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| Fail::Authority)?;
        let storage = custody.vault.storage().clone();
        let mut store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let mut devices = GroupDevices {
            own,
            cache: self.cache.clone(),
            roster: Some(self.roster.clone()),
        };
        let mut port = cnbx::KeyPort {
            keys: custody.vault.keys(),
            handle: &handle,
            devices: &mut devices,
        };
        let mut clock = crate::door::custody::SystemClock;
        let threads =
            cthr::Threads::load(binding, task.group, &store).map_err(|_| Fail::Storage)?;
        let mut attend = ctnd::Attend::new();
        let source = PolicyRef(task.policy);
        let companion = cbrd::RoomCompanion {
            request: task.request,
        }
        .encode()
        .ok_or(Fail::Invalid)?;
        let joined = L::join_room(
            board,
            cbrd::RoomJoinInput {
                attend: &mut attend,
                member: &self.member,
                room: task.room,
                keys: &mut port,
                clock: &mut clock,
                store: &mut store,
                threads: &threads,
                groups: task.candidate,
                evidence: task.evidence,
                source: &source,
                authority: &cbrd::JoinParent::new(&self.authority, task.parent),
                handover: vec![],
                companion,
                operation,
                attempts: ROOM_CONTEXT_ATTEMPTS,
                pause: crate::door::rooms::NoPause,
                transport: task.transport,
            },
        )
        .await;
        *self.cache.borrow_mut() = Cache::default();
        if joined.is_err() {
            self.roster.borrow_mut().forget();
        }
        self.open().map_err(|_| Fail::Authority)?;
        Ok(joined?.snapshot)
    }
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// A member's public MLS evidence for `group`, exported only when its roster
    /// and context match the committed Groups record (Threads checks that).
    pub async fn room_evidence(
        &mut self,
        group: cgrp::Id,
        policy: &dyn cgrp::PolicySource,
    ) -> std::result::Result<cbrd::RoomState, ctnd::Error> {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        // The roster's current lineages are read first (Charter-verified), so
        // Threads can certify every leaf of the room against them.
        let (roster, mut handles) = {
            let mut retained = self.retained.lock().await;
            let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let store = storage.lock().await;
            let roster = cgrp::Snapshot::load(custody.binding.community(), &store)
                .map_err(|_| Fail::Storage)?
                .members(&group)
                .map_err(|_| Fail::Authority)?
                .clone();
            // Lineage-read handles of the roster this member holds: a locator
            // for the newcomer, who reads and Charter-verifies each lineage itself.
            let journal = custody.inbox.contacts(&store).map_err(|_| Fail::Storage)?;
            let mut handles = BTreeMap::new();
            for peer in roster.iter().filter(|peer| **peer != self.member) {
                if let Some(handle) = self.provided.get(peer) {
                    handles.insert(peer.clone(), handle.clone());
                } else if let Some(handle) = self.roster.borrow().handles.get(peer) {
                    handles.insert(peer.clone(), handle.clone());
                } else if let Some(handle) = journal.handle(peer).map_err(|_| Fail::Storage)? {
                    handles.insert(peer.clone(), handle);
                }
            }
            (roster, handles)
        };
        let own_handle = cbrd::GroupOwner::own_handle(self)
            .await
            .map_err(|_| Fail::Authority)?;
        handles.insert(self.member.clone(), own_handle);
        // What the handles above name is kept, so the lineages are read once.
        self.roster
            .borrow_mut()
            .handles
            .extend(handles.iter().map(|(m, h)| (m.clone(), h.clone())));
        self.ensure_roster(&roster)
            .await
            .map_err(|_| Fail::Authority)?;
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let handle = custody
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(|_| Fail::Authority)?;
        let own = custody
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| Fail::Authority)?;
        let storage = custody.vault.storage().clone();
        let store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let mut devices = GroupDevices {
            own,
            cache: self.cache.clone(),
            roster: Some(self.roster.clone()),
        };
        let mut port = cnbx::KeyPort {
            keys: custody.vault.keys(),
            handle: &handle,
            devices: &mut devices,
        };
        let mut clock = crate::door::custody::SystemClock;
        let threads = cthr::Threads::load(binding, group, &store).map_err(|_| Fail::Storage)?;
        let evidence = threads
            .parent_evidence(&mut port, &store, &PolicyRef(policy), &mut clock)
            .await
            .map_err(|_| Fail::Authority);
        *self.cache.borrow_mut() = Cache::default();
        if evidence.is_err() {
            self.roster.borrow_mut().forget();
        }
        Ok(cbrd::RoomState {
            evidence: evidence?,
            transport: threads.transport_keys().map_err(|_| Fail::Authority)?,
            handles,
        })
    }

    /// The transport key of this member's current epoch of `group`: it opens
    /// the ordered join frames of the newcomers waiting at that epoch.
    pub async fn room_transport_key(
        &mut self,
        group: cgrp::Id,
    ) -> std::result::Result<cbrd::TransportKey, ctnd::Error> {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let storage = custody.vault.storage().clone();
        let store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let threads = cthr::Threads::load(binding, group, &store).map_err(|_| Fail::Storage)?;
        let key = threads.transport_keys().map_err(|_| Fail::Authority)?;
        Ok(cbrd::TransportKey::from_keys(&key))
    }
}

/// What admitting a newcomer to a member room takes: its ordered external
/// commit with the companion (the signed Groups `Join` request).
pub struct RoomAdmitTask<'a> {
    pub room: [u8; 16],
    pub group: cgrp::Id,
    pub frame: &'a cbrd::JoinFrame,
    pub max_groups: usize,
    /// The room's transport key at the epoch the newcomer joins from.
    pub transport: &'a cbrd::TransportKey,
    pub policy: &'a dyn cgrp::PolicySource,
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Admit one newcomer to a member room as an existing member. The newcomer
    /// is believed only through evidence this device verifies itself: its
    /// lineage is read through the handle its signed consent names, Charter-verified
    /// and bound to the pseudonym its signed request names (a substituted
    /// handle reads another member's record or none and the admission is
    /// refused); its MLS leaf certificate must verify against that lineage; and
    /// its consent counts only from that certificate's device key.
    pub async fn admit_room<T, L>(
        &mut self,
        board: &cbrd::Board<T, L>,
        task: RoomAdmitTask<'_>,
    ) -> std::result::Result<Snapshot, ctnd::Error>
    where
        T: cbrd::clnk::Transport,
        L: crate::door::RoomLink,
    {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        let companion =
            cbrd::RoomCompanion::decode(&task.frame.companion).ok_or(Fail::Authority)?;
        let newcomer = companion.request.actor.clone();
        if newcomer == self.member {
            return Err(Fail::Authority);
        }
        // The roster's lineages first (read once, kept: row 14.8); they only
        // certify the leaves already in the tree. A room this device holds has a
        // roster in Groups.
        let roster = {
            let mut retained = self.retained.lock().await;
            let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let store = storage.lock().await;
            cgrp::Snapshot::load(custody.binding.community(), &store)
                .map_err(|_| Fail::Storage)?
                .members(&task.group)
                .map_err(|_| Fail::Authority)?
                .clone()
        };
        if self.ensure_roster(&roster).await.is_err() {
            *self.cache.borrow_mut() = Cache::default();
            return Err(Fail::Unavailable);
        }
        // Then the newcomer's lineage (ALWAYS a fresh, Charter-verified read
        // through the locator it supplied); the per-operation cache serves only
        // this admission and the consent decision.
        // The newcomer's own handle rides inside its signed consent.
        let handle = companion
            .request
            .consents
            .iter()
            .find(|consent| consent.member == newcomer)
            .map(|consent| consent.lineage_handle.clone())
            .filter(|handle| !handle.is_empty())
            .ok_or(Fail::Authority)?;
        self.roster
            .borrow_mut()
            .handles
            .insert(newcomer.clone(), handle.clone());
        self.provided = BTreeMap::from([(newcomer.clone(), handle)]);
        let read = cbrd::GroupOwner::refresh(
            self,
            &BTreeSet::new(),
            &BTreeSet::from([newcomer.clone()]),
        )
        .await;
        self.provided.clear();
        if read.is_err() {
            *self.cache.borrow_mut() = Cache::default();
            return Err(Fail::Unavailable);
        }
        let operation = {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| Fail::Unavailable)?;
            bytes
        };
        let admitted = self
            .admit_verified(board, &task, &companion.request, operation)
            .await;
        *self.cache.borrow_mut() = Cache::default();
        self.open().map_err(|_| Fail::Authority)?;
        admitted
    }

    async fn admit_verified<T, L>(
        &mut self,
        board: &cbrd::Board<T, L>,
        task: &RoomAdmitTask<'_>,
        request: &cgrp::Request,
        operation: [u8; 32],
    ) -> std::result::Result<Snapshot, ctnd::Error>
    where
        T: cbrd::clnk::Transport,
        L: crate::door::RoomLink,
    {
        use ctnd::Error as Fail;
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let handle = custody
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(|_| Fail::Authority)?;
        let own = custody
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| Fail::Authority)?;
        let storage = custody.vault.storage().clone();
        let mut store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let mut devices = GroupDevices {
            own,
            cache: self.cache.clone(),
            roster: Some(self.roster.clone()),
        };
        let mut port = cnbx::KeyPort {
            keys: custody.vault.keys(),
            handle: &handle,
            devices: &mut devices,
        };
        let mut clock = crate::door::custody::SystemClock;
        let threads =
            cthr::Threads::load(binding.clone(), task.group, &store).map_err(|_| Fail::Storage)?;
        // The leaf credential first, then the consent: Groups decides only on a
        // newcomer whose certificate this device verified.
        let credential = threads
            .room_join_credential(&task.frame.commit, &task.frame.companion)
            .map_err(|_| Fail::Authority)?;
        if credential.binding.community() != binding.community()
            || credential.binding.member() != request.actor
        {
            return Err(Fail::Authority);
        }
        cthr::keys::Custody::verify(&mut port, &credential)
            .await
            .map_err(|_| Fail::Authority)?;
        let authority = RoomAuthority {
            member: request.actor.clone(),
            device: *credential.device.value(),
        };
        let source = PolicyRef(task.policy);
        let now = ckmg::Clock::now(&mut clock).map_err(|_| Fail::Unavailable)?;
        let snapshot = Snapshot::load(binding.community(), &store).map_err(|_| Fail::Storage)?;
        let groups = cgrp::prepare(&snapshot, request, &source, &authority, now, task.max_groups)
            .map_err(|_| Fail::Authority)?;
        let admitted = L::admit_room(
            board,
            cbrd::RoomAdmitInput {
                keys: &mut port,
                clock: &mut clock,
                store: &mut store,
                threads: &threads,
                groups,
                frame: task.frame,
                room: task.room,
                source: &source,
                authority: &authority,
                operation,
                transport: task.transport,
            },
        )
        .await;
        // The leaves of the tree were certified against the roster lineages this
        // device holds; a refusal here may mean one moved on, so they are read
        // again next time (the newcomer was verified fresh above).
        if admitted.is_err() {
            self.roster.borrow_mut().forget();
        }
        Ok(admitted?.snapshot)
    }
}

/// What leaving a member room takes: the Groups `Leave` already prepared.
pub struct RoomLeaveTask<'a> {
    pub group: cgrp::Id,
    pub candidate: cgrp::Candidate,
    pub policy: &'a dyn cgrp::PolicySource,
}

impl<B, C, E, A, R, W> VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Leave a member room in ONE Store commit: Groups, this device's Threads
    /// state and the Attend withdrawal (`cthr::leave_room`). Returns `None`
    /// without touching anything when this device holds no Attend record for the
    /// group (it never joined through a room); the caller then leaves in Groups
    /// alone.
    pub async fn leave_room(
        &mut self,
        task: RoomLeaveTask<'_>,
    ) -> std::result::Result<Option<Snapshot>, ctnd::Error> {
        use ctnd::Error as Fail;
        self.open().map_err(|_| Fail::Authority)?;
        let operation = {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes).map_err(|_| Fail::Unavailable)?;
            bytes
        };
        let mut retained = self.retained.lock().await;
        self.open().map_err(|_| Fail::Authority)?;
        let custody = retained.as_mut().ok_or(Fail::Unavailable)?;
        let binding = custody.binding.clone();
        let storage = custody.vault.storage().clone();
        let mut store = storage.lock().await;
        custody
            .check_scope(&store)
            .await
            .map_err(|_| Fail::Authority)?;
        let threads =
            cthr::Threads::load(binding, task.group, &store).map_err(|_| Fail::Storage)?;
        let Some(mut attend) = threads.stored_attend(&store).map_err(|_| Fail::Storage)? else {
            return Ok(None);
        };
        let mut clock = crate::door::custody::SystemClock;
        let source = PolicyRef(task.policy);
        let left = cthr::leave_room(
            &mut attend,
            cthr::LeaveParts {
                store: &mut store,
                threads: &threads,
                groups: task.candidate,
                source: &source,
                authority: &self.authority,
                clock: &mut clock,
                operation,
            },
        )
        .await;
        *self.cache.borrow_mut() = Cache::default();
        self.open().map_err(|_| Fail::Authority)?;
        left.map(Some)
    }
}

/// Reads of the room's traffic per join attempt, for the member's context commit.
const ROOM_CONTEXT_ATTEMPTS: u8 = 3;

struct StorePersistence<'a, B: cwst::backend::Backend> {
    store: &'a mut cwst::Store<B>,
    version: u64,
}
impl<B: cwst::backend::Backend> cgrp::Persistence for StorePersistence<'_, B> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        candidate: &'a Snapshot,
        _effects: &'a [cgrp::Effect],
    ) -> cgrp::CommitFuture<'a> {
        Box::pin(async move {
            let current = Snapshot::load(candidate.community(), self.store)?;
            if current.revision() != expected {
                return Ok(cgrp::Commit::Conflict);
            }
            let bytes = candidate.checkpoint_bytes()?;
            let mut operation = [0u8; 32];
            getrandom::fill(&mut operation).map_err(|_| cgrp::Error::Unavailable)?;
            let change = cwst::Change::Put {
                owner: Snapshot::STORE_OWNER,
                key: Snapshot::STORE_KEY,
                value: &bytes,
            };
            match self
                .store
                .commit(self.version, operation, &[change], &[])
                .await
            {
                Ok(_) => Ok(cgrp::Commit::Applied),
                Err(cwst::Error::Conflict) => Ok(cgrp::Commit::Conflict),
                Err(_) => Ok(cgrp::Commit::Unknown),
            }
        })
    }
}

impl<B, C, E, A, R, W> cbrd::GroupOwner for VaultGroupOwner<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    fn member(&mut self) -> cgrp::Result<String> {
        self.open()?;
        Ok(self.member.clone())
    }
    fn authority(&self) -> &dyn cgrp::Authority {
        &self.authority
    }
    fn now(&mut self) -> cgrp::Result<u64> {
        ckmg::Clock::now(&mut crate::door::custody::SystemClock).map_err(|_| cgrp::Error::Clock)
    }
    fn operation(&mut self) -> cgrp::Result<cgrp::Id> {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id).map_err(|_| cgrp::Error::Unavailable)?;
        Ok(id)
    }
    fn snapshot(&mut self) -> cbrd::PortFuture<'_, Snapshot> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let store = storage.lock().await;
            custody
                .check_scope(&store)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let snapshot = Snapshot::load(custody.binding.community(), &store)?;
            self.version = store.version().map_err(|_| cgrp::Error::Reconcile)?;
            Ok(snapshot)
        })
    }
    fn refresh<'a>(
        &'a mut self,
        contacts: &'a BTreeSet<String>,
        devices: &'a BTreeSet<String>,
    ) -> cbrd::PortFuture<'a, ()> {
        Box::pin(async move {
            self.open()?;
            *self.cache.borrow_mut() = Cache::default();
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let now = ckmg::Clock::now(&mut crate::door::custody::SystemClock)
                .map_err(|_| cgrp::Error::Clock)?;
            let mut handles = BTreeMap::new();
            {
                let storage = custody.vault.storage().clone();
                let store = storage.lock().await;
                custody
                    .check_scope(&store)
                    .await
                    .map_err(|_| cgrp::Error::Authority)?;
                let journal = custody
                    .inbox
                    .contacts(&store)
                    .map_err(|_| cgrp::Error::Unavailable)?;
                for peer in devices {
                    if peer != &self.member {
                        // The handle the peer attached to its own consent wins
                        // (its current locator); a locator only: the lineage it
                        // yields is still Charter-verified and must bind to `peer`.
                        if let Some(handle) = self.provided.get(peer) {
                            handles.insert(peer.clone(), handle.clone());
                        } else if let Some(handle) = self.roster.borrow().handles.get(peer) {
                            handles.insert(peer.clone(), handle.clone());
                        } else if let Some(handle) =
                            journal.handle(peer).map_err(|_| cgrp::Error::Unavailable)?
                        {
                            handles.insert(peer.clone(), handle);
                        }
                    }
                }
                let mut cache = self.cache.borrow_mut();
                for peer in contacts {
                    // The own journal holds no relation to oneself.
                    if peer == &self.member {
                        continue;
                    }
                    let relation = journal
                        .relation(peer)
                        .map_err(|_| cgrp::Error::Unavailable)?;
                    if relation.state == ctcs::State::Established && !relation.conflicted {
                        cache.contacts.insert(peer.clone());
                    }
                    #[cfg(test)]
                    if self.assumed_contacts.contains(peer) {
                        cache.contacts.insert(peer.clone());
                    }
                }
            }
            let community = custody.binding.community().to_owned();
            for member in devices {
                let lineage = if member == &self.member {
                    Some(
                        custody
                            .vault
                            .keys()
                            .lineage()
                            .await
                            .map_err(|_| cgrp::Error::Authority)?,
                    )
                } else if let (Some(peers), Some(handle)) = (&self.peers, handles.get(member)) {
                    let binding =
                        ckmg::Binding::new(&community, member).map_err(|_| cgrp::Error::Invalid)?;
                    peers.lock().await.lineage(&binding, handle).await
                } else {
                    None
                };
                // A lineage that is missing, or that belongs to another member
                // (a substituted locator), leaves that member unverifiable.
                let asked = ckmg::Binding::new(&community, member).ok();
                if let Some(lineage) = lineage.filter(|l| Some(&l.binding) == asked.as_ref()) {
                    let read_at = ckmg::Clock::now(&mut crate::door::custody::SystemClock)
                        .map_err(|_| cgrp::Error::Clock)?;
                    let _ = now;
                    // Verified once: the roster keeps it for the leaf
                    // certification of later room operations. Consent
                    // decisions use only the per-operation cache below.
                    if member != &self.member {
                        self.roster
                            .borrow_mut()
                            .lineages
                            .insert(member.clone(), lineage.clone());
                    }
                    self.cache
                        .borrow_mut()
                        .lineages
                        .insert(member.clone(), (lineage, read_at));
                }
            }
            self.open()
        })
    }
    fn sign_consent<'a>(
        &'a mut self,
        member: &'a str,
        statement: &'a [u8],
        expires: u64,
    ) -> cbrd::PortFuture<'a, cbrd::Signed> {
        Box::pin(async move {
            self.open()?;
            if member != self.member {
                // Another member's consent is never produced by this device.
                return Err(cgrp::Error::Unavailable);
            }
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let now = ckmg::Clock::now(&mut crate::door::custody::SystemClock)
                .map_err(|_| cgrp::Error::Clock)?;
            let public = custody
                .vault
                .keys()
                .device_public_key()
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let signed = custody
                .sign_transcript(statement, &self.origin, now, expires)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            self.open()?;
            drop(signed.admitted);
            Ok(cbrd::Signed {
                signature: signed.signature,
                authority: public.value().to_vec(),
            })
        })
    }
    fn own_handle(&mut self) -> cbrd::PortFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            // The locator of this member's own certified lineage record:
            // read-only, never secret material.
            let handle = custody
                .vault
                .keys()
                .export_lineage_read_capability()
                .await
                .map_err(|_| cgrp::Error::Authority)?
                .as_bytes()
                .to_vec();
            self.open()?;
            Ok(handle)
        })
    }
    fn provide_handles(&mut self, handles: BTreeMap<String, Vec<u8>>) {
        // Locators only, kept beside the lineages read through them.
        self.roster
            .borrow_mut()
            .handles
            .extend(handles.iter().map(|(m, h)| (m.clone(), h.clone())));
        self.provided = handles;
    }
    fn key_package(
        &mut self,
        group: cgrp::Id,
        operation: cgrp::Id,
    ) -> cbrd::PortFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let binding = custody.binding.clone();
            // Keys first: creating a key checkpoints through the Store.
            let handle = custody
                .vault
                .keys()
                .key(cnbx::threads_purpose())
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let own = custody
                .vault
                .keys()
                .lineage()
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let storage = custody.vault.storage().clone();
            let mut store = storage.lock().await;
            custody
                .check_scope(&store)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let mut devices = GroupDevices {
                own,
                cache: self.cache.clone(),
                roster: None,
            };
            let mut port = cnbx::KeyPort {
                keys: custody.vault.keys(),
                handle: &handle,
                devices: &mut devices,
            };
            let threads = cthr::Threads::load(binding, group, &store).map_err(mls_error)?;
            let committed = threads
                .key_package(&mut port)
                .await
                .map_err(mls_error)?
                .commit(
                    &mut port,
                    &mut cthr::Unavailable,
                    &mut store,
                    mls_operation("key-package", &group, &operation),
                    &[],
                )
                .await
                .map_err(mls_error)?;
            self.open()?;
            committed
                .events()
                .iter()
                .find_map(|event| match event {
                    cthr::Event::KeyPackage { bytes } => Some(bytes.clone()),
                    _ => None,
                })
                .ok_or(cgrp::Error::Unavailable)
        })
    }
    fn publish_request<'a>(
        &'a mut self,
        candidate: cgrp::Candidate,
        request: &'a cgrp::Request,
        policy: &'a dyn cgrp::PolicySource,
        now: u64,
    ) -> cbrd::PortFuture<'a, cbrd::Published> {
        Box::pin(async move {
            let Some(group) = cbrd::created_group(&request.command) else {
                let (snapshot, effects) = cbrd::GroupOwner::publish(self, candidate, now).await?;
                return Ok(cbrd::Published {
                    snapshot,
                    effects,
                    welcome: None,
                });
            };
            // Every other member's package, each covered by its signed consent.
            let packages: Vec<Vec<u8>> = request
                .consents
                .iter()
                .filter(|consent| consent.member != request.actor)
                .map(|consent| consent.key_package.clone())
                .collect();
            let published = self
                .mls_commit(
                    candidate,
                    group,
                    request.operation,
                    MlsStep::Create(&packages),
                    policy,
                )
                .await;
            // Whatever was read for this operation is gone with it.
            *self.cache.borrow_mut() = Cache::default();
            let (snapshot, effects, committed) = published?;
            let welcome = committed.events().iter().find_map(|event| match event {
                cthr::Event::Invitation { welcome, .. } => Some(welcome.clone()),
                _ => None,
            });
            Ok(cbrd::Published {
                snapshot,
                effects,
                welcome,
            })
        })
    }
    fn publish_welcome<'a>(
        &'a mut self,
        candidate: cgrp::Candidate,
        group: cgrp::Id,
        welcome: &'a [u8],
        policy: &'a dyn cgrp::PolicySource,
        _now: u64,
    ) -> cbrd::PortFuture<'a, (Snapshot, Vec<cgrp::CommittedEffect>)> {
        Box::pin(async move {
            let outcome = self
                .mls_commit(candidate, group, [0; 32], MlsStep::Join(welcome), policy)
                .await;
            *self.cache.borrow_mut() = Cache::default();
            let (snapshot, effects, _) = outcome?;
            Ok((snapshot, effects))
        })
    }
    fn desk_load(&mut self) -> cbrd::PortFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let store = storage.lock().await;
            custody
                .check_scope(&store)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            store
                .read(DESK_OWNER, DESK_KEY)
                .map(|bytes| bytes.map(<[u8]>::to_vec))
                .map_err(|_| cgrp::Error::Reconcile)
        })
    }
    fn desk_save<'a>(&'a mut self, bytes: &'a [u8]) -> cbrd::PortFuture<'a, ()> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let mut store = storage.lock().await;
            custody
                .check_scope(&store)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let version = store.version().map_err(|_| cgrp::Error::Reconcile)?;
            let mut operation = [0u8; 32];
            getrandom::fill(&mut operation).map_err(|_| cgrp::Error::Unavailable)?;
            store
                .commit(
                    version,
                    operation,
                    &[cwst::Change::Put {
                        owner: DESK_OWNER,
                        key: DESK_KEY,
                        value: bytes,
                    }],
                    &[],
                )
                .await
                .map(|_| ())
                .map_err(|_| cgrp::Error::Reconcile)
        })
    }
    fn publish(
        &mut self,
        candidate: cgrp::Candidate,
        now: u64,
    ) -> cbrd::PortFuture<'_, (Snapshot, Vec<cgrp::CommittedEffect>)> {
        Box::pin(async move {
            self.open()?;
            let mut retained = self.retained.lock().await;
            self.open()?;
            let custody = retained.as_mut().ok_or(cgrp::Error::Unavailable)?;
            let storage = custody.vault.storage().clone();
            let mut store = storage.lock().await;
            custody
                .check_scope(&store)
                .await
                .map_err(|_| cgrp::Error::Authority)?;
            let outcome = candidate
                .persist(
                    &mut StorePersistence {
                        store: &mut store,
                        version: self.version,
                    },
                    now,
                )
                .await;
            // Whatever was read for this operation is gone with it.
            *self.cache.borrow_mut() = Cache::default();
            outcome
        })
    }
}
