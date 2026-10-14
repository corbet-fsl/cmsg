//! Original community account paired with its authenticated recovery origin.
use super::*;
use crate::door::facades::{AccountPort, PortVault};
use cvlt::WalletCustody;

/// Receipt-restored community account under its original certified lineage and
/// HTTPS origin. No caller routing value or replaceable Vault constructs this
/// owner. The retained public identity grants nothing without fresh Keys Use.
pub struct CommunityAccount<B: cwst::backend::Backend, C, E, A, R> {
    vault: AccountVault<B, C, E, A, R>,
    origin: String,
    lineage: ckmg::Lineage,
    device: ckmg::PublicKey,
    credential: Vec<u8>,
}

impl<B: cwst::backend::Backend, C, E, A, R> AccountVault<B, C, E, A, R> {
    pub(super) async fn open(&mut self) -> Result<VaultRef<'_, B, C, E, A, R>> {
        Ok(match self {
            Self::Owned(vault) => VaultRef::Owned(vault),
            Self::Port(port) => VaultRef::Port(port.vault().await?),
        })
    }
}

/// Where the account's Vault lives: an owned one (the registration composer, which
/// has no Door yet) or the Door's own Vault through a port. The port is the only
/// form on a running device: the Door's Vault stays the one owner of its Store.
pub enum AccountVault<B: cwst::backend::Backend, C, E, A, R> {
    Owned(Vault<B, C, E, A, R, WalletCustody>),
    Port(AccountPort<B, C, E, A, R>),
}

/// The account's Vault borrowed for one use.
pub(super) enum VaultRef<'a, B: cwst::backend::Backend, C, E, A, R> {
    Owned(&'a mut Vault<B, C, E, A, R, WalletCustody>),
    Port(PortVault<'a, B, C, E, A, R>),
}
impl<B: cwst::backend::Backend, C, E, A, R> std::ops::Deref for VaultRef<'_, B, C, E, A, R> {
    type Target = Vault<B, C, E, A, R, WalletCustody>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(vault) => vault,
            Self::Port(vault) => vault,
        }
    }
}
impl<B: cwst::backend::Backend, C, E, A, R> std::ops::DerefMut for VaultRef<'_, B, C, E, A, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(vault) => vault,
            Self::Port(vault) => vault,
        }
    }
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
        vault: AccountVault<B, C, E, A, R>,
    ) -> Result<Self> {
        let mut vault = vault;
        let (lineage, credential, device) = {
            let mut vault = vault.open().await?;
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
            (lineage, credential, device)
        };
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

    /// The account's Vault for one use: the Door's own Vault through the port.
    pub(super) async fn vault(&mut self) -> Result<VaultRef<'_, B, C, E, A, R>> {
        self.vault.open().await
    }

    pub(super) async fn check(&mut self, origin: &str) -> Result<()> {
        if origin != self.origin {
            return Err(ErrorCode::Unauthorized);
        }
        let lineage = self.vault().await?
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let reference = self.vault().await?
            .keys()
            .device_info()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = self.vault().await?
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

    /// Keep the community credential the server just issued in the Vault, replacing
    /// the stored one by compare-and-swap. The same credential again changes
    /// nothing, so repeating a setup step is safe. Fresh original Keys authority
    /// is rechecked first; the credential never leaves this owner in a reply.
    pub async fn store_community_credential(&mut self, credential: &[u8]) -> Result<()> {
        let origin = self.origin.clone();
        self.check(&origin).await?;
        let current = self.vault().await?
            .community_credential()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        match self.vault().await?
            .replace_community_credential(current.as_ref().map(|c| c.as_slice()), credential)
            .await
        {
            Ok(_) => Ok(()),
            Err(cvlt::CredentialError::Conflict) => Err(ErrorCode::Reconcile),
            Err(cvlt::CredentialError::Invalid) => Err(ErrorCode::Refused),
            Err(_) => Err(ErrorCode::Unavailable),
        }
    }

    /// The voucher custody record (link secrets, bond nonces, bonds), read after
    /// fresh original Keys authority.
    pub async fn voucher_custody(&mut self) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
        let origin = self.origin.clone();
        self.check(&origin).await?;
        self.vault().await?
            .voucher_custody()
            .await
            .map_err(|_| ErrorCode::Unavailable)
    }

    /// Replace the voucher custody by compare-and-swap against what the caller
    /// read. A lost race writes nothing and is `Reconcile`.
    pub async fn replace_voucher_custody(
        &mut self,
        expected: Option<&[u8]>,
        custody: &[u8],
    ) -> Result<()> {
        let origin = self.origin.clone();
        self.check(&origin).await?;
        match self.vault().await?.replace_voucher_custody(expected, custody).await {
            Ok(_) => Ok(()),
            Err(cvlt::CredentialError::Conflict) => Err(ErrorCode::Reconcile),
            Err(cvlt::CredentialError::Invalid) => Err(ErrorCode::Refused),
            Err(_) => Err(ErrorCode::Unavailable),
        }
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
