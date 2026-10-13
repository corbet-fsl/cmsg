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
        let reader = ckmg::LineageReadCustody::from_capability(handle, binding)
            .map_err(|_| PeerUnavailable)?;
        let backend = cvlt::TorLineageRecord::member_lineage(self.network.clone(), reader)
            .await
            .map_err(|_| PeerUnavailable)?;
        let record = cdht::runtime::Record::new(backend).map_err(|_| PeerUnavailable)?;
        let mut records = cvlt::LineageRecords::new(vec![record]).map_err(|_| PeerUnavailable)?;
        let read = records.read().await.map_err(|_| PeerUnavailable)?;
        read.evidence()
            .iter()
            .map(|item| {
                item.to_bytes()
                    .and_then(|bytes| cvlt::LineageEvidence::from_bytes(&bytes))
                    .map_err(|_| PeerUnavailable)
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
        let read = self
            .records
            .read(binding)
            .await
            .map_err(|_| cnbx::ContactError::Unavailable)?;
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
}
