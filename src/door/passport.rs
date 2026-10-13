//! Original global passport issuance through certified, durable Wallet custody.
use super::{custody::SystemClock, foyer::Transport, ErrorCode, Result};
use cfyr::membership::GlobalPassportIssuance;
use ckmg::{Authority, Clock, Entropy};
use cvlt::{GlobalPassportCustody, Records, Vault};
use cwlt::passport::{self, BlindPassport, IssuanceChallenge, IssuerPublicKey};

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

/// Durable global holder paired with its original recovery endpoint and lineage.
/// Only actual initial recovery constructs this composition. It exposes neither
/// a replaceable Vault nor a constructor from caller routing data. The retained
/// coordinates authorize nothing: every operation still performs fresh Keys Use.
pub struct GlobalPassport<B: cwst::backend::Backend, C, E, A, R> {
    vault: Vault<B, C, E, A, R, GlobalPassportCustody>,
    origin: String,
    lineage: ckmg::Lineage,
    credential: Vec<u8>,
}

impl<B, C, E, A, R> GlobalPassport<B, C, E, A, R>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    // Called only after the original certified recovery owner has opened the
    // exact Store and restored its existing holder. No public data constructor.
    pub(crate) async fn recovered(
        origin: String,
        mut vault: Vault<B, C, E, A, R, GlobalPassportCustody>,
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
        if lineage.binding.community() != "wallet" || credential.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        let mut result = Self {
            vault,
            origin,
            lineage,
            credential,
        };
        result.current().await?;
        Ok(result)
    }

    async fn current(&mut self) -> Result<()> {
        let lineage = self
            .vault
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = self
            .vault
            .keys()
            .device_info()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage != self.lineage || device.authority_reference() != self.credential {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }

    async fn same_wallet(&mut self, issuer: &mut GlobalPassportIssuance<Transport>) -> Result<()> {
        if issuer.origin(now).map_err(|_| ErrorCode::Unauthorized)? != self.origin {
            return Err(ErrorCode::Unauthorized);
        }
        self.current().await?;
        issuer
            .with_current(now, |user, key, _, _, _| {
                if self.lineage.binding.member() != user || self.credential != key {
                    return Err(ErrorCode::Unauthorized);
                }
                Ok(())
            })
            .map_err(|_| ErrorCode::Unauthorized)??;
        if issuer.origin(now).map_err(|_| ErrorCode::Unauthorized)? != self.origin {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }

    /// Borrow the original read/proof session under the retained exact lineage.
    pub async fn with_global_passport<T>(
        &mut self,
        read: impl for<'owner> FnOnce(passport::DurableSession<'owner>) -> T,
    ) -> Result<T> {
        self.current().await?;
        let output = self
            .vault
            .with_global_passport(read)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        self.current().await?;
        Ok(output)
    }

    /// Durably prepare the original opening for this actual same-origin issuer.
    /// A lost issuer answer leaves that pending opening for explicit recovery.
    pub async fn prepare_global_passport_issuance<G>(
        &mut self,
        issuer: &mut GlobalPassportIssuance<Transport>,
        rng: &mut G,
    ) -> Result<passport::IssuanceRequest>
    where
        G: passport::rand::RngCore + passport::rand::CryptoRng,
    {
        self.same_wallet(issuer).await?;
        let (public, challenge) = issuer
            .with_current(now, |_, _, public, challenge, _| {
                Ok((
                    IssuerPublicKey::from_bytes(public).map_err(|_| ErrorCode::Unauthorized)?,
                    IssuanceChallenge::from_bytes(
                        challenge.try_into().map_err(|_| ErrorCode::Unauthorized)?,
                    ),
                ))
            })
            .map_err(|_| ErrorCode::Unauthorized)??;
        let request = self
            .vault
            .begin_global_passport_issuance(operation()?, rng, &public, &challenge)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        self.same_wallet(issuer)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        Ok(request)
    }

    /// Explicitly cancel only the original durable pending issuance.
    pub async fn cancel_global_passport_issuance<G>(
        &mut self,
        operation: [u8; 32],
        rng: &mut G,
    ) -> Result<()>
    where
        G: passport::rand::RngCore + passport::rand::CryptoRng,
    {
        self.current().await?;
        self.vault
            .cancel_global_passport_issuance(operation, rng)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        self.current().await.map_err(|_| ErrorCode::Reconcile)
    }

    /// Destroy this local holder and Keys owner through the original lock path.
    pub async fn lock(self) {
        self.vault.lock().await;
    }
}

fn operation() -> Result<[u8; 32]> {
    let mut operation = [0; 32];
    getrandom::fill(&mut operation).map_err(|_| ErrorCode::Unavailable)?;
    if operation == [0; 32] {
        return Err(ErrorCode::Unavailable);
    }
    Ok(operation)
}

/// Issue or renew the existing global holder using the original HTTPS issuer.
/// The issuer continuation must come from an independently authenticated Foyer:
/// a Foyer already retaining the Wallet's authority lease refuses another lease.
/// Both must name the exact original HTTPS endpoint, Wallet account and passkey.
///
/// The private opening commits before the request is sent. Cancellation or an
/// unknown outcome leaves that original durable state for explicit recovery;
/// this function never retries issuance, cancels it implicitly, or creates a
/// missing holder. Success means the original verified passport is durable.
pub async fn issue_global_passport<B, C, E, A, R, G>(
    mut issuer: GlobalPassportIssuance<Transport>,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    rng: &mut G,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    G: passport::rand::RngCore + passport::rand::CryptoRng,
{
    let request = wallet
        .prepare_global_passport_issuance(&mut issuer, rng)
        .await?;
    let response = issuer
        .issue(request.to_bytes(), now)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    wallet
        .same_wallet(&mut issuer)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    let response = BlindPassport::from_bytes(&response).map_err(|_| ErrorCode::Reconcile)?;
    wallet
        .vault
        .finish_global_passport_issuance(
            operation().map_err(|_| ErrorCode::Reconcile)?,
            rng,
            &response,
        )
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    wallet
        .same_wallet(&mut issuer)
        .await
        .map_err(|_| ErrorCode::Reconcile)
}
