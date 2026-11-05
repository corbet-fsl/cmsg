//! The browser vault frame's wave stack: the same ports and worker as the native device
//! (`inbox_waves::device`), over the browser records network. The runtime contributes
//! only its provers and the counterpart verifier ([`WaveCapabilities`]); the restoring
//! composer binds them once the member's network is up, beside the Mesh.
//!
//! The wave and outcome proofs and the counterpart check run in the existing prover
//! worker; their capabilities come from the deployment's pinned artifacts
//! (`browser::prover`). Without them nothing is bound, as natively: a device never
//! half-runs waves.
use super::{identity::TransportClient, records};
use crate::door::{
    inbox_lineage::TorHandleOpener,
    inbox_waves::{
        device::{self, WaveCapabilities},
        wallet::WaveProver,
    },
    record::RecordCurrent,
    Door, Result,
};
use cmsh::{tor_discovery::TorWatcher, tor_records::TorRecordNetwork};
use cwlt::wave::ProofCheck;

/// The records network the browser member reads peers' handles over.
pub type RecordsNetwork<W> = TorRecordNetwork<TransportClient, records::Verifier, W>;

type Bind<W> = Box<dyn FnOnce(&mut Door, &str, RecordsNetwork<W>) -> Result<()>>;

/// The wave stack of one member origin, waiting for the member's network.
pub struct Waves<W: TorWatcher + 'static>(Bind<W>);

impl<W: TorWatcher + 'static> Waves<W> {
    /// `record` is the record-currency mark the device's record job keeps.
    pub fn new<P, C>(capabilities: WaveCapabilities<P, C>, record: RecordCurrent) -> Self
    where
        P: WaveProver + 'static,
        C: ProofCheck + 'static,
    {
        Self(Box::new(move |door, origin, network| {
            let charter = door.current_policy(origin)?;
            device::bind(
                door,
                origin,
                capabilities,
                record,
                TorHandleOpener::new(network),
                charter,
            )
        }))
    }

    /// Install the ports and the worker over the member's network.
    pub(super) fn bind(
        self,
        door: &mut Door,
        origin: &str,
        network: RecordsNetwork<W>,
    ) -> Result<()> {
        (self.0)(door, origin, network)
    }
}
