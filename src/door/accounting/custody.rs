//! Original community account paired with its authenticated recovery origin.
use super::*;

/// Receipt-restored community account under its original certified lineage and
/// HTTPS origin. No caller routing value or replaceable Vault constructs this
/// owner. The retained public identity grants nothing without fresh Keys Use.
pub struct CommunityAccount<B: cwst::backend::Backend, C, E, A, R> {
    pub(super) vault: Vault<B, C, E, A, R, CommunityAccountCustody>,
    origin: String,
    lineage: ckmg::Lineage,
    device: ckmg::PublicKey,
    credential: Vec<u8>,
}

impl<B, C, E, A, R> CommunityAccount<B, C, E, A, R>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    // Only the original certified recovery composer supplies this origin after
    // opening the actual winner and restoring its existing account capsule.
    pub(crate) async fn recovered(
        origin: String,
        mut vault: Vault<B, C, E, A, R, CommunityAccountCustody>,
    ) -> Result<Self> {
        let lineage = vault
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let credential = vault
            .keys()
            .device_info()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?
            .authority_reference()
            .to_vec();
        let device = vault
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage.binding.community() == "wallet"
            || credential.is_empty()
            || !lineage.devices.contains(&device)
        {
            return Err(ErrorCode::Unauthorized);
        }
        let mut result = Self {
            vault,
            origin,
            lineage,
            device,
            credential,
        };
        let expected = result.origin.clone();
        result.check(&expected).await?;
        Ok(result)
    }

    pub(super) async fn check(&mut self, origin: &str) -> Result<()> {
        if origin != self.origin {
            return Err(ErrorCode::Unauthorized);
        }
        let lineage = self
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let reference = self
            .vault
            .keys()
            .device_info()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = self
            .vault
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage != self.lineage
            || reference.authority_reference() != self.credential
            || device != self.device
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }

    /// Bind this exact recovered account (origin, Lineage, device, credential),
    /// the pinned Balance payload digest and the digest of the original signed
    /// ApplyExtended outbox into the data sealed with the pending companion. Fresh
    /// original Keys authority is rechecked first; nothing is cached or regenerated.
    pub async fn pending_binding(
        &mut self,
        balance_payload: [u8; 32],
        outbox: &[u8],
    ) -> Result<PendingBinding> {
        let origin = self.origin.clone();
        self.check(&origin).await?;
        PendingBinding::from_parts(
            origin,
            &self.lineage,
            &self.device,
            self.credential.clone(),
            balance_payload,
            outbox,
        )
    }

    /// Require that a reopened companion belongs to this exact account, origin
    /// and that the Store's outbox is the unchanged one it was sealed with. Any
    /// difference refuses; the companion is not edited.
    pub async fn check_pending(
        &mut self,
        pending: &PendingBinding,
        balance_payload: [u8; 32],
        outbox: &[u8],
    ) -> Result<()> {
        let fresh = self.pending_binding(balance_payload, outbox).await?;
        if &fresh != pending {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }
}
