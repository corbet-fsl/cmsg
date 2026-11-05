//! Remote device delegation on the bound Vault, wallet side (A11). The authority-bearing steps:
//! Keys enrols the CLI's `K_d` as a delegate and seals the granted custody to the CLI, or
//! removes a delegate. Admission is a distinct single-use `DelegateDevice` command naming the
//! target key and the exact statement, and the evidence is the digest of the lineage the change
//! extends, which the authority requires to equal the live head (decided 2026-11-05, Q1).
//! Nothing here is automatic or reusable.
use super::*;

/// How long the single-use admission stays valid, in seconds. Keys runs right after it.
const DELEGATE_ADMISSION_SECONDS: u64 = 30;

impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    /// Admit exactly one `DelegateDevice` change of `target` with `statement` over the current
    /// lineage, and return that lineage's digest (the evidence).
    async fn admit_delegation(
        &mut self,
        target: ckmg::PublicKey,
        statement: [u8; 32],
        origin: &str,
    ) -> Result<([u8; 32], ckmg::IntentGuard)> {
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        if lineage.binding != self.binding {
            return Err(ErrorCode::Unauthorized);
        }
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
                    action: ckmg::Action::DelegateDevice,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: Some(target),
                    statement: Some(statement),
                    transcript: None,
                    format: None,
                    expires: now.saturating_add(DELEGATE_ADMISSION_SECONDS),
                },
                now,
            )
            .map_err(keys_error)?;
        Ok((base, admitted))
    }

    /// Enrol the offer's `K_d` for `purposes` and seal the granted custody to the CLI.
    pub(super) async fn delegate_remote_owned(
        &mut self,
        offer: &ckmg::DelegationOffer,
        purposes: &[ckmg::Purpose],
        origin: &str,
    ) -> Result<(ckmg::Receipt, ckmg::SealedDelegation)> {
        offer.check().map_err(keys_error)?;
        let statement = offer.statement(purposes).map_err(keys_error)?;
        let (base, admitted) = self
            .admit_delegation(offer.device, statement, origin)
            .await?;
        let delegated = self
            .vault
            .keys()
            .delegate_remote_device(offer, purposes, &base)
            .await
            .map_err(keys_error);
        drop(admitted);
        let (receipt, sealed) = delegated?;
        if !matches!(receipt.change, ckmg::Change::DeviceDelegated(_)) {
            return Err(ErrorCode::Reconcile);
        }
        Ok((receipt, sealed))
    }

    /// Remove the delegate `key` from the lineage (a pure delegate revocation, Q2).
    pub(super) async fn remove_delegate_owned(
        &mut self,
        key: ckmg::PublicKey,
        origin: &str,
    ) -> Result<ckmg::Receipt> {
        let statement = ckmg::delegate_removal_statement(&key).map_err(keys_error)?;
        let (base, admitted) = self.admit_delegation(key, statement, origin).await?;
        let removed = self
            .vault
            .keys()
            .remove_delegate(key, &base)
            .await
            .map_err(keys_error);
        drop(admitted);
        removed
    }
}
