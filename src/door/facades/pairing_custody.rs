//! Device pairing on the bound Vault, existing-device side. The one authority-bearing step:
//! after the member's explicit approval, Keys adds exactly the proven new device and seals
//! the root to it. Admission is a distinct single-use `Pair` command naming that target and
//! the digest of that exact request; nothing here is automatic or reusable.
use super::*;

/// How long the single-use Pair admission stays valid, in seconds. Keys runs right after
/// admission; this only bounds waits.
const PAIR_ADMISSION_SECONDS: u64 = 30;

/// A committed approval: the grant to send and the receipt whose passkey challenge the
/// member's passkey must still sign before the new lineage revision is published.
pub struct PairApproved {
    pub grant: ckmg::PairingGrant,
    pub receipt: ckmg::Receipt,
}

impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    pub(super) async fn pair_owned(
        &mut self,
        request: &ckmg::PairingRequest,
        origin: &str,
    ) -> Result<PairApproved> {
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        // The request must be for exactly this member's current root and epoch.
        if lineage.binding != self.binding
            || request.binding != lineage.binding
            || request.root != lineage.root
            || request.epoch != lineage.epoch
        {
            return Err(ErrorCode::Unauthorized);
        }
        let statement = request.digest().map_err(keys_error)?;
        let base = lineage.digest().map_err(keys_error)?;
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
                    binding: lineage.binding.clone(),
                    origin: origin.into(),
                    action: ckmg::Action::Pair,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: Some(request.device),
                    statement: Some(statement),
                    transcript: None,
                    format: None,
                    expires: now.saturating_add(PAIR_ADMISSION_SECONDS),
                },
                now,
            )
            .map_err(keys_error)?;
        let receipt = self
            .vault
            .keys()
            // The evidence is the digest of the lineage this pairing extends; the authority
            // requires it to equal the live head, so a stale or replayed Pair never applies.
            .authorize_device(request, &base)
            .await
            .map_err(keys_error);
        drop(admitted);
        let receipt = receipt?;
        let ckmg::Change::DeviceAuthorized(grant) = &receipt.change else {
            return Err(ErrorCode::Reconcile);
        };
        Ok(PairApproved {
            grant: (**grant).clone(),
            receipt,
        })
    }
}
