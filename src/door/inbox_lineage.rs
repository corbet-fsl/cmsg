//! Current lineage of a PEER for the Inbox authority ports (decided G3).
//!
//! Evidence comes only from a forced read of the peer's certified lineage
//! records (never a cache). Every item is reverified against the door-held
//! Charter of the community scope, which is the Envoy-followed trust feed and
//! carries the passkey revocation list. Concurrent valid lineages resolve by
//! greater epoch, then smaller digest. Anything missing, stale, unreadable or
//! beyond validity is refused: this port never answers permissively. Missing or
//! stale evidence is `Unavailable`; `Authority` only for present, negative
//! evidence (invalid, revoked, wrong binding).
use super::foyer;
use cchr::VerifiedCharter;
use ckmg::{Binding, Lineage};

/// Forced read of one peer's certified lineage slots.
#[allow(async_fn_in_trait)]
pub trait PeerRecords {
    /// A fresh network read. An unreadable record is an error, never a stale value.
    async fn read(
        &mut self,
        binding: &Binding,
    ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable>;
}

/// The forced read could not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerUnavailable;

/// The door-held trust view of one community scope at a point of use.
pub trait CharterView {
    /// Run `inspect` against the current Charter. Stale or absent trust is an error.
    fn with_current<T>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&VerifiedCharter) -> Result<T, cnbx::ContactError>,
    ) -> Result<T, cnbx::ContactError>;
}

/// The weak scoped read of the community's one current Charter that the Door
/// lends to trusted composers. It holds no policy: once the Foyer is gone or
/// stale every inspection is `Unavailable`.
impl CharterView for cfyr::policy::CurrentPolicy<foyer::Transport> {
    fn with_current<T>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&VerifiedCharter) -> Result<T, cnbx::ContactError>,
    ) -> Result<T, cnbx::ContactError> {
        let mut inner = None;
        let outer = cfyr::policy::CurrentPolicy::with_current(self, now, |charter| {
            inner = Some(if charter.community() == community {
                inspect(charter)
            } else {
                Err(cnbx::ContactError::Unavailable)
            });
        });
        match (outer, inner) {
            (Ok(()), Some(result)) => result,
            _ => Err(cnbx::ContactError::Unavailable),
        }
    }
}

/// The original Foyer-retained Envoy view; its own freshness rules apply.
impl CharterView for foyer::Binding {
    fn with_current<T>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&VerifiedCharter) -> Result<T, cnbx::ContactError>,
    ) -> Result<T, cnbx::ContactError> {
        // The Foyer reports its own staleness as an error code; the inner
        // refusal is carried out through a cell so that no variant is lost.
        let mut inner = None;
        let outer = self.current(community, now, |charter| {
            inner = Some(inspect(charter));
            Ok(())
        });
        match (outer, inner) {
            (Ok(()), Some(result)) => result,
            _ => Err(cnbx::ContactError::Unavailable),
        }
    }
}

/// Reads a peer's lineage records through the handle retained in Contacts for
/// that peer (decided: handles travel signed, nothing is looked up by pseudonym).
/// `opener` turns the retained opaque handle into the read-only records.
pub struct StoredHandleRecords<O> {
    handles: std::collections::BTreeMap<String, Vec<u8>>,
    opener: O,
}

/// Opens the read-only lineage records named by one retained handle.
#[allow(async_fn_in_trait)]
pub trait HandleOpener {
    /// Perform the forced read for `handle` of `binding`; any failure is `PeerUnavailable`.
    async fn read(
        &mut self,
        binding: &Binding,
        handle: &[u8],
    ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable>;
}

impl<O: HandleOpener> StoredHandleRecords<O> {
    /// `handles` are the Contacts-retained handles of the peers in use, as read
    /// from the same committed journal snapshot as the relation.
    pub fn new(handles: std::collections::BTreeMap<String, Vec<u8>>, opener: O) -> Self {
        Self { handles, opener }
    }
}

impl<O: HandleOpener> PeerRecords for StoredHandleRecords<O> {
    async fn read(
        &mut self,
        binding: &Binding,
    ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
        // No retained handle: nothing is looked up elsewhere.
        let handle = self
            .handles
            .get(binding.member())
            .ok_or(PeerUnavailable)?
            .clone();
        self.opener.read(binding, &handle).await
    }
}

/// Production opener: a retained handle is the peer's lineage read capability
/// (exported by the peer's `ckmg::Keys` under current authority). It conveys
/// decryption of that one record only; every read is a forced network read and
/// the evidence is copied out, so nothing from the read is retained.
#[derive(Clone)]
pub struct TorHandleOpener<N: cdht::Network> {
    network: N,
}

impl<N: cdht::Network> TorHandleOpener<N> {
    /// `network` is the door's Tor network handle.
    pub fn new(network: N) -> Self {
        Self { network }
    }
}

impl<N: cdht::Network + Clone> HandleOpener for TorHandleOpener<N> {
    async fn read(
        &mut self,
        binding: &Binding,
        handle: &[u8],
    ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
        // Strict: domain, exact length, and the binding must be the asked peer's.
        let reader =
            ckmg::LineageReadCustody::from_capability(handle, binding).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "PeerUnavailable",
                    PeerUnavailable,
                    &__cause,
                )
            })?;
        let backend = cvlt::TorLineageRecord::member_lineage(self.network.clone(), reader)
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "PeerUnavailable",
                    PeerUnavailable,
                    &__cause,
                )
            })?;
        let record = cdht::runtime::Record::new(backend).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "PeerUnavailable",
                PeerUnavailable,
                &__cause,
            )
        })?;
        let mut records = cvlt::LineageRecords::new(vec![record]).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "PeerUnavailable",
                PeerUnavailable,
                &__cause,
            )
        })?;
        let read = records.read().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "PeerUnavailable",
                PeerUnavailable,
                &__cause,
            )
        })?;
        read.evidence()
            .iter()
            .map(|item| {
                item.to_bytes()
                    .and_then(|bytes| cvlt::LineageEvidence::from_bytes(&bytes))
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "PeerUnavailable",
                            PeerUnavailable,
                            &__cause,
                        )
                    })
            })
            .collect()
    }
}

/// Fills `cnbx::DeviceAuthority` for peers; `ContactAuthority` and release use it.
pub struct PeerLineage<R, V, C> {
    records: R,
    view: V,
    clock: C,
}

impl<R, V, C> PeerLineage<R, V, C>
where
    R: PeerRecords,
    V: CharterView,
    C: FnMut() -> Option<u64>,
{
    /// `clock` returns Unix seconds, or `None` when no trustworthy time exists.
    pub fn new(records: R, view: V, clock: C) -> Self {
        Self {
            records,
            view,
            clock,
        }
    }
}

impl<R, V, C> cnbx::DeviceAuthority for PeerLineage<R, V, C>
where
    R: PeerRecords,
    V: CharterView,
    C: FnMut() -> Option<u64>,
{
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, cnbx::ContactError> {
        let started = (self.clock)().ok_or(cnbx::ContactError::Unavailable)?;
        let read = self.records.read(binding).await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "cnbx::ContactError::Unavailable",
                cnbx::ContactError::Unavailable,
                &__cause,
            )
        })?;
        // Time is taken again after the await; a clock that went backwards
        // cannot extend any validity.
        let now = (self.clock)().ok_or(cnbx::ContactError::Unavailable)?;
        if now < started {
            return Err(cnbx::ContactError::Unavailable);
        }
        self.view.with_current(binding.community(), now, |charter| {
            select(&read, charter, binding, now)
        })
    }
}

/// Choose the winning valid lineage for `binding`, or refuse.
/// Stale or not-yet-fresh evidence is `Unavailable`; invalid or revoked is `Authority`.
fn classify(error: cvlt::LineageError) -> cnbx::ContactError {
    match error {
        cvlt::LineageError::Clock
        | cvlt::LineageError::Policy(
            cchr::Error::Expired | cchr::Error::Unavailable | cchr::Error::ClockRegression,
        ) => cnbx::ContactError::Unavailable,
        _ => cnbx::ContactError::Authority,
    }
}

fn select(
    evidence: &[cvlt::LineageEvidence],
    charter: &VerifiedCharter,
    binding: &Binding,
    now: u64,
) -> Result<Lineage, cnbx::ContactError> {
    if charter.community() != binding.community() {
        return Err(cnbx::ContactError::Authority);
    }
    let mut selected: Option<cvlt::VerifiedLineageObservation<'_>> = None;
    for item in evidence {
        // One invalid item refuses the whole read: nothing partial is trusted.
        let candidate = item
            .verify(charter, binding.member(), now)
            .map_err(classify)?;
        let wins = match &selected {
            None => true,
            Some(previous) => candidate
                .compare_conflict(previous, now)
                .map_err(classify)?
                .is_gt(),
        };
        if wins {
            selected = Some(candidate);
        }
    }
    let selected = selected.ok_or(cnbx::ContactError::Unavailable)?;
    // Beyond the exclusive validity bound of the evidence or the Charter: stale.
    if now >= selected.valid_until().min(charter.valid_until()) {
        return Err(cnbx::ContactError::Unavailable);
    }
    let lineage = selected.lineage(now).map_err(classify)?;
    if &lineage.binding != binding {
        return Err(cnbx::ContactError::Authority);
    }
    Ok(lineage.clone())
}

/// The handles the wave ports may read peers through: only handles this member
/// retained after verifying them (Contacts), shared with whoever refreshes them.
/// Nothing is looked up by pseudonym; a peer without a handle is `Unavailable`.
#[derive(Clone, Default)]
pub struct HandleBook(std::rc::Rc<std::cell::RefCell<std::collections::BTreeMap<String, Vec<u8>>>>);

impl HandleBook {
    /// Replace the book with the handles of one committed Contacts snapshot.
    pub fn replace(&self, handles: std::collections::BTreeMap<String, Vec<u8>>) {
        *self.0.borrow_mut() = handles;
    }
    fn get(&self, member: &str) -> Option<Vec<u8>> {
        self.0.borrow().get(member).cloned()
    }
    /// Retain the handle of one member whose signed announcement was verified (or that
    /// the Contacts journal retained after verifying it). It replaces an older one.
    pub fn learn(&self, member: &str, handle: Vec<u8>) {
        self.0.borrow_mut().insert(member.to_owned(), handle);
    }
}

/// Borrows the door-held trust view only inside one synchronous inspection.
struct CellView<'a, V>(&'a std::cell::RefCell<V>);
impl<V: CharterView> CharterView for CellView<'_, V> {
    fn with_current<T>(
        &mut self,
        community: &str,
        now: u64,
        inspect: impl FnOnce(&VerifiedCharter) -> Result<T, cnbx::ContactError>,
    ) -> Result<T, cnbx::ContactError> {
        let mut view = self.0.try_borrow_mut().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "cnbx::ContactError::Unavailable",
                cnbx::ContactError::Unavailable,
                &__cause,
            )
        })?;
        view.with_current(community, now, inspect)
    }
}

/// The wave ports' peer lineage: a forced read through the peer's retained handle,
/// every item reverified against the community Charter (`PeerLineage`). Refused
/// (`Refused`) only for present negative evidence; anything else is `Unavailable`.
pub struct WavePeerLineage<O, V> {
    handles: HandleBook,
    opener: O,
    view: std::cell::RefCell<V>,
}

impl<O, V> WavePeerLineage<O, V> {
    pub fn new(handles: HandleBook, opener: O, view: V) -> Self {
        Self {
            handles,
            opener,
            view: std::cell::RefCell::new(view),
        }
    }
}

impl<O, V> super::inbox_waves::production::PeerLineageRead for WavePeerLineage<O, V>
where
    O: HandleOpener + Clone,
    V: CharterView,
{
    fn read<'a>(&'a self, binding: &'a Binding) -> super::facades::OwnedFuture<'a, Lineage> {
        Box::pin(async move {
            let handle = self
                .handles
                .get(binding.member())
                .ok_or(super::ErrorCode::Unavailable)?;
            let records = StoredHandleRecords::new(
                std::collections::BTreeMap::from([(binding.member().to_owned(), handle)]),
                self.opener.clone(),
            );
            let mut port = PeerLineage::new(records, CellView(&self.view), || {
                ckmg::Clock::now(&mut super::custody::SystemClock).ok()
            });
            cnbx::DeviceAuthority::current(&mut port, binding)
                .await
                .map_err(|error| match error {
                    cnbx::ContactError::Authority => super::ErrorCode::Refused,
                    _ => super::ErrorCode::Unavailable,
                })
        })
    }

    /// The first wave's handle: verified on receipt, before the HandleBook learns it.
    /// Refused (`Refused`): an announcement that is not for this peer and conversation,
    /// a handle that is not a read capability for this peer's own record, or one the
    /// charter-verified lineage read through it does not vouch for. Nothing is read from
    /// the network for the first three; an unreadable record is `Unavailable` (retry).
    fn accept<'a>(
        &'a self,
        request: super::inbox_waves::HandleRequest<'a>,
    ) -> super::facades::OwnedFuture<'a, ()> {
        Box::pin(async move {
            let refused = super::ErrorCode::Refused;
            let announcement: cnbx::HandleAnnouncement =
                serde_json::from_slice(request.announcement).map_err(|__cause| {
                    crate::door::cause::emit(file!(), line!(), "refused", refused, &__cause)
                })?;
            if announcement.binding() != request.peer
                || announcement.conversation() != request.conversation
                || ckmg::LineageReadCustody::from_capability(announcement.handle(), request.peer)
                    .is_err()
            {
                return Err(refused);
            }
            let records = StoredHandleRecords::new(
                std::collections::BTreeMap::from([(
                    request.peer.member().to_owned(),
                    announcement.handle().to_vec(),
                )]),
                self.opener.clone(),
            );
            let mut port = PeerLineage::new(records, CellView(&self.view), || {
                ckmg::Clock::now(&mut super::custody::SystemClock).ok()
            });
            announcement
                .verify(request.own, &mut port)
                .await
                .map_err(|error| match error {
                    cnbx::Error::Contacts(cnbx::ContactError::Authority) => refused,
                    _ => super::ErrorCode::Unavailable,
                })?;
            self.handles
                .learn(request.peer.member(), announcement.handle().to_vec());
            Ok(())
        })
    }

    fn retain(&self, peer: &Binding, handle: &[u8]) {
        self.handles.learn(peer.member(), handle.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnbx::DeviceAuthority;

    struct Failing;
    impl PeerRecords for Failing {
        async fn read(
            &mut self,
            _: &Binding,
        ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
            Err(PeerUnavailable)
        }
    }
    struct NoTrust;
    impl CharterView for NoTrust {
        fn with_current<T>(
            &mut self,
            _: &str,
            _: u64,
            _: impl FnOnce(&VerifiedCharter) -> Result<T, cnbx::ContactError>,
        ) -> Result<T, cnbx::ContactError> {
            Err(cnbx::ContactError::Authority)
        }
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
    }

    #[test]
    fn unreadable_record_is_refused_never_stale() {
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let mut port = PeerLineage::new(Failing, NoTrust, || Some(10));
        assert_eq!(
            block_on(port.current(&binding)).err(),
            Some(cnbx::ContactError::Unavailable)
        );
    }

    #[test]
    fn missing_clock_and_regressing_clock_are_refused() {
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let mut none = PeerLineage::new(Failing, NoTrust, || None);
        assert_eq!(
            block_on(none.current(&binding)).err(),
            Some(cnbx::ContactError::Unavailable)
        );
        let mut times = [10u64, 9].into_iter();
        let mut back = PeerLineage::new(Failing, NoTrust, move || times.next());
        assert_eq!(
            block_on(back.current(&binding)).err(),
            Some(cnbx::ContactError::Unavailable)
        );
    }

    #[derive(Clone)]
    struct NoOpen;
    impl HandleOpener for NoOpen {
        async fn read(
            &mut self,
            _: &Binding,
            _: &[u8],
        ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
            panic!("no handle may be opened without a retained handle")
        }
    }

    #[test]
    fn a_peer_without_a_retained_handle_is_never_looked_up() {
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let mut records = StoredHandleRecords::new(Default::default(), NoOpen);
        assert!(block_on(records.read(&binding)).is_err());
    }

    #[test]
    fn stale_is_unavailable_and_negative_evidence_is_authority() {
        use cvlt::LineageError::*;
        for stale in [
            Clock,
            Policy(cchr::Error::Expired),
            Policy(cchr::Error::Unavailable),
        ] {
            assert_eq!(classify(stale), cnbx::ContactError::Unavailable);
        }
        for negative in [Receipt, Scope, Assertion, Policy(cchr::Error::Signature)] {
            assert_eq!(classify(negative), cnbx::ContactError::Authority);
        }
    }

    /// A network with no reachable node: any use of it is `Unavailable`.
    #[derive(Clone)]
    struct Dead;
    impl cdht::Network for Dead {
        fn now_ms(&self) -> u64 {
            0
        }
        async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn descriptor(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
        ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn get(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
            _: u32,
        ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn set(
            &self,
            _: &cdht::NodeId,
            _: &cdht::Descriptor,
            _: u32,
            _: &cdht::SignedValue,
        ) -> Result<cdht::SetOutcome, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn watch(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
        ) -> Result<cdht::WatchId, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn cancel_watch(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> Result<(), cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn changes(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> Result<Vec<cdht::Change>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
    }

    #[test]
    fn tor_opener_refuses_anything_that_is_not_a_capability_for_the_binding() {
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let mut opener = TorHandleOpener::new(Dead);
        for handle in [&b""[..], b"not a capability", &[0u8; 300][..]] {
            assert_eq!(
                block_on(opener.read(&binding, handle)).err(),
                Some(PeerUnavailable)
            );
        }
    }

    /// Opens every handle to an empty read.
    #[derive(Clone)]
    struct Empty;
    impl HandleOpener for Empty {
        async fn read(
            &mut self,
            _: &Binding,
            _: &[u8],
        ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn the_wave_port_reads_only_peers_with_a_retained_handle() {
        use crate::door::inbox_waves::production::PeerLineageRead;
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let port = WavePeerLineage::new(HandleBook::default(), NoOpen, NoTrust);
        assert_eq!(
            block_on(port.read(&binding)).err(),
            Some(crate::door::ErrorCode::Unavailable)
        );
        // A handle of another member does not open this one.
        let book = HandleBook::default();
        book.replace(std::collections::BTreeMap::from([(
            "b".repeat(96),
            vec![1],
        )]));
        let port = WavePeerLineage::new(book, NoOpen, NoTrust);
        assert!(block_on(port.read(&binding)).is_err());
    }

    #[test]
    fn the_wave_port_is_unavailable_on_a_failed_read_and_refuses_negative_evidence() {
        use crate::door::inbox_waves::production::PeerLineageRead;
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let book = HandleBook::default();
        book.replace(std::collections::BTreeMap::from([(
            "a".repeat(96),
            b"not a capability".to_vec(),
        )]));
        let unreadable = WavePeerLineage::new(book.clone(), TorHandleOpener::new(Dead), NoTrust);
        assert_eq!(
            block_on(unreadable.read(&binding)).err(),
            Some(crate::door::ErrorCode::Unavailable)
        );
        // Read, then judged by the Charter view: its negative verdict is a refusal.
        let judged = WavePeerLineage::new(book, Empty, NoTrust);
        assert_eq!(
            block_on(judged.read(&binding)).err(),
            Some(crate::door::ErrorCode::Refused)
        );
    }

    /// A read capability shaped as `ckmg` exports it (domain, binding, owner, read key),
    /// for the base point as record owner: it passes the strict parse, nothing more.
    fn capability_of(binding: &Binding) -> Vec<u8> {
        let mut out = b"ckmg.lineage-read.v1\0".to_vec();
        for part in [binding.community(), binding.member()] {
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        out.extend_from_slice(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        out.extend_from_slice(&[7; 32]);
        out
    }

    /// A structurally complete announcement with a worthless signature: enough to reach
    /// every check that runs before the lineage vouches for it.
    fn announcement(binding: &Binding, conversation: [u8; 32], handle: &[u8]) -> Vec<u8> {
        let key = ckmg::PublicKey::new(ckmg::VLD0, [3; 32]);
        let signature = ckmg::Signature::new(ckmg::VLD0, [4; 64]);
        let certificate = ckmg::KeyCertificate {
            binding: binding.clone(),
            epoch: 0,
            device: key,
            purpose: ctcs::purpose(),
            key,
            signature,
        };
        serde_json::to_vec(&serde_json::json!({
            "binding": binding,
            "conversation": conversation,
            "handle": handle,
            "certificate": certificate,
            "signature": signature,
        }))
        .unwrap()
    }

    /// Every read is unreadable.
    #[derive(Clone)]
    struct Unreadable;
    impl HandleOpener for Unreadable {
        async fn read(
            &mut self,
            _: &Binding,
            _: &[u8],
        ) -> Result<Vec<cvlt::LineageEvidence>, PeerUnavailable> {
            Err(PeerUnavailable)
        }
    }

    fn request<'a>(
        peer: &'a Binding,
        own: &'a Binding,
        conversation: &'a [u8; 32],
        announcement: &'a [u8],
    ) -> crate::door::inbox_waves::HandleRequest<'a> {
        crate::door::inbox_waves::HandleRequest {
            peer,
            own,
            conversation,
            announcement,
        }
    }

    #[test]
    fn a_substituted_handle_is_refused_without_reading_anything() {
        use crate::door::inbox_waves::production::PeerLineageRead;
        use crate::door::ErrorCode;
        let (own, peer) = (
            Binding::new("c", &"b".repeat(96)).unwrap(),
            Binding::new("c", &"a".repeat(96)).unwrap(),
        );
        let stranger = Binding::new("c", &"d".repeat(96)).unwrap();
        let conversation = [5u8; 32];
        let book = HandleBook::default();
        // NoOpen panics on any read: every refusal below happens before the network.
        let port = WavePeerLineage::new(book.clone(), NoOpen, NoTrust);
        let genuine = capability_of(&peer);
        let cases: [(&str, Vec<u8>); 6] = [
            ("not json", b"not an announcement".to_vec()),
            // The announcement was made by another member than the one that sent it.
            (
                "other member",
                announcement(&stranger, conversation, &capability_of(&stranger)),
            ),
            // A genuine announcement of the peer, replayed for another conversation.
            ("other conversation", announcement(&peer, [6; 32], &genuine)),
            // The peer's announcement carrying a handle that is not a read capability.
            (
                "not a capability",
                announcement(&peer, conversation, b"attacker record"),
            ),
            // The peer's announcement carrying another member's read capability.
            (
                "foreign capability",
                announcement(&peer, conversation, &capability_of(&stranger)),
            ),
            ("empty", Vec::new()),
        ];
        for (name, bytes) in cases {
            assert_eq!(
                block_on(port.accept(request(&peer, &own, &conversation, &bytes))).err(),
                Some(ErrorCode::Refused),
                "{name}"
            );
        }
        assert_eq!(book.get(peer.member()), None);
    }

    #[test]
    fn a_handle_the_lineage_does_not_vouch_for_is_never_retained() {
        use crate::door::inbox_waves::production::PeerLineageRead;
        use crate::door::ErrorCode;
        let (own, peer) = (
            Binding::new("c", &"b".repeat(96)).unwrap(),
            Binding::new("c", &"a".repeat(96)).unwrap(),
        );
        let conversation = [5u8; 32];
        let bytes = announcement(&peer, conversation, &capability_of(&peer));
        // Read through the announced handle, the Charter view judges it: negative
        // evidence refuses; a record that cannot be read is retried later.
        let book = HandleBook::default();
        let judged = WavePeerLineage::new(book.clone(), Empty, NoTrust);
        assert_eq!(
            block_on(judged.accept(request(&peer, &own, &conversation, &bytes))).err(),
            Some(ErrorCode::Refused)
        );
        let unreadable = WavePeerLineage::new(book.clone(), Unreadable, NoTrust);
        assert_eq!(
            block_on(unreadable.accept(request(&peer, &own, &conversation, &bytes))).err(),
            Some(ErrorCode::Unavailable)
        );
        assert_eq!(book.get(peer.member()), None);
    }

    #[test]
    fn a_handle_retained_earlier_is_installed_again_and_replaced_by_a_newer_one() {
        use crate::door::inbox_waves::production::PeerLineageRead;
        let peer = Binding::new("c", &"a".repeat(96)).unwrap();
        let book = HandleBook::default();
        let port = WavePeerLineage::new(book.clone(), NoOpen, NoTrust);
        port.retain(&peer, b"first");
        assert_eq!(book.get(peer.member()), Some(b"first".to_vec()));
        port.retain(&peer, b"second");
        assert_eq!(book.get(peer.member()), Some(b"second".to_vec()));
    }
}
