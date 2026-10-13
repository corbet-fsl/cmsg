//! Group membership authority on the bound Vault: the Keys and Devices ports
//! of the group owner.
//!
//! What may be signed: only the local member's own consent, as the exact
//! `cgrp.consent.v2` statement bytes Groups built for one command, signed with
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
//! Charter-verified lineage. Standing-room (seed) authority and vouches by
//! other members' contacts are refused until their evidence exists.
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

struct NoSeeds;
impl cbrd::Seeds for NoSeeds {
    fn authorized(&self, _: &str, _: &cgrp::Id, _: u64) -> cgrp::Result<()> {
        Err(cgrp::Error::Authority)
    }
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
    authority: cbrd::BoardAuthority<CacheDevices, CacheContacts, NoSeeds>,
    version: u64,
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
                NoSeeds,
            ),
            member,
            peers: peers.map(|peers| Rc::new(Mutex::new(peers))),
            cache,
            version: 0,
        }
    }
    fn open(&self) -> cgrp::Result<()> {
        if self.lifetime.is_closed() {
            Err(cgrp::Error::Authority)
        } else {
            Ok(())
        }
    }
}

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
                        if let Some(handle) =
                            journal.handle(peer).map_err(|_| cgrp::Error::Unavailable)?
                        {
                            handles.insert(peer.clone(), handle);
                        }
                    }
                }
                let mut cache = self.cache.borrow_mut();
                for peer in contacts {
                    let relation = journal
                        .relation(peer)
                        .map_err(|_| cgrp::Error::Unavailable)?;
                    if relation.state == ctcs::State::Established && !relation.conflicted {
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
                // A lineage that is missing leaves that member unverifiable.
                if let Some(lineage) = lineage {
                    let read_at = ckmg::Clock::now(&mut crate::door::custody::SystemClock)
                        .map_err(|_| cgrp::Error::Clock)?;
                    let _ = now;
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
