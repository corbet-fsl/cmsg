//! Next lineage record revision on the bound Vault: after a pending device authorization,
//! Keys signs the strictly next record value for it under a distinct single-use
//! `PublishLineage` admission naming the previous head. Only the signed value leaves.
use super::*;

/// How long the single-use admission stays valid, in seconds.
const PUBLISH_ADMISSION_SECONDS: u64 = 30;

impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    pub(super) async fn revision_record_owned(
        &mut self,
        receipt: &ckmg::Receipt,
        previous: &ckmg::Lineage,
        canonical_evidence: &[u8],
        origin: &str,
    ) -> Result<cdht::SignedValue> {
        // Keys verifies the chain from `previous` to its pending checkpoint; the admission
        // names the head being extended.
        let (binding, root, epoch) = (previous.binding.clone(), previous.root, previous.epoch);
        if binding != self.binding {
            return Err(ErrorCode::Unauthorized);
        }
        let device = self
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(keys_error)?;
        let now = ckmg::Clock::now(&mut super::super::custody::SystemClock).map_err(keys_error)?;
        let intent = self.intent.as_mut().ok_or(ErrorCode::Unavailable)?;
        let admitted = intent
            .admit(
                ckmg::AdmittedCommand {
                    binding,
                    origin: origin.into(),
                    action: ckmg::Action::PublishLineage,
                    device,
                    root: Some(root),
                    epoch,
                    target: None,
                    statement: Some(previous.digest().map_err(keys_error)?),
                    transcript: None,
                    expires: now.saturating_add(PUBLISH_ADMISSION_SECONDS),
                },
                now,
            )
            .map_err(keys_error)?;
        let value = self
            .vault
            .keys()
            .prepare_lineage_revision_record(receipt, previous, canonical_evidence, &[])
            .await
            .map_err(keys_error);
        drop(admitted);
        value
    }
}
