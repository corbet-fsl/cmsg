//! Current lineage of a PEER for the Inbox authority ports (decided G3).
//!
//! Evidence comes only from a forced read of the peer's certified lineage
//! records (never a cache). Every item is reverified against the door-held
//! Charter of the community scope, which is the Envoy-followed trust feed and
//! carries the passkey revocation list. Concurrent valid lineages resolve by
//! greater epoch, then smaller digest. Anything missing, stale, unreadable or
//! beyond validity is refused: this port never answers permissively.
use super::foyer;
use cchr::VerifiedCharter;
use ckmg::{Binding, Lineage};

/// Forced read of one peer's certified lineage slots.
#[allow(async_fn_in_trait)]
pub trait PeerRecords {
    /// A fresh network read. An unreadable record is an error, never a stale value.
    async fn read(&mut self, binding: &Binding) -> Result<cvlt::LineageRead, PeerUnavailable>;
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
            _ => Err(cnbx::ContactError::Authority),
        }
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
        let started = (self.clock)().ok_or(cnbx::ContactError::Authority)?;
        let read = self
            .records
            .read(binding)
            .await
            .map_err(|_| cnbx::ContactError::Authority)?;
        // Time is taken again after the await; a clock that went backwards
        // cannot extend any validity.
        let now = (self.clock)().ok_or(cnbx::ContactError::Authority)?;
        if now < started {
            return Err(cnbx::ContactError::Authority);
        }
        self.view.with_current(binding.community(), now, |charter| {
            select(read.evidence(), charter, binding, now)
        })
    }
}

/// Choose the winning valid lineage for `binding`, or refuse.
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
            .map_err(|_| cnbx::ContactError::Authority)?;
        let wins = match &selected {
            None => true,
            Some(previous) => candidate
                .compare_conflict(previous, now)
                .map_err(|_| cnbx::ContactError::Authority)?
                .is_gt(),
        };
        if wins {
            selected = Some(candidate);
        }
    }
    let selected = selected.ok_or(cnbx::ContactError::Authority)?;
    // Beyond the exclusive validity bound of the evidence or the Charter: refuse.
    if now >= selected.valid_until().min(charter.valid_until()) {
        return Err(cnbx::ContactError::Authority);
    }
    let lineage = selected
        .lineage(now)
        .map_err(|_| cnbx::ContactError::Authority)?;
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
        async fn read(&mut self, _: &Binding) -> Result<cvlt::LineageRead, PeerUnavailable> {
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
            Some(cnbx::ContactError::Authority)
        );
    }

    #[test]
    fn missing_clock_and_regressing_clock_are_refused() {
        let binding = Binding::new("c", &"a".repeat(96)).unwrap();
        let mut none = PeerLineage::new(Failing, NoTrust, || None);
        assert_eq!(
            block_on(none.current(&binding)).err(),
            Some(cnbx::ContactError::Authority)
        );
        let mut times = [10u64, 9].into_iter();
        let mut back = PeerLineage::new(Failing, NoTrust, move || times.next());
        assert_eq!(
            block_on(back.current(&binding)).err(),
            Some(cnbx::ContactError::Authority)
        );
    }
}
