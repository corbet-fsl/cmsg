//! Original global passport issuance through certified, durable Wallet custody.
use super::{custody::SystemClock, foyer::Transport, ErrorCode, Result};
use cfyr::membership::GlobalPassportIssuance;
use ckmg::{Authority, Clock, Entropy};
use cvlt::{GlobalPassportCustody, Records, Vault};
use cwlt::passport::{self, BlindPassport, IssuanceChallenge, IssuerPublicKey};

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

// This compares public coordinates from two genuine owners; neither coordinate
// supplies authority. Keys performs its fresh certified Wallet/lineage checks.
async fn same_wallet<B, C, E, A, R>(
    issuer: &mut GlobalPassportIssuance<Transport>,
    wallet: &mut Vault<B, C, E, A, R, GlobalPassportCustody>,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let lineage = wallet
        .keys()
        .lineage()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    let device = wallet
        .keys()
        .device_info()
        .await
        .map_err(|_| ErrorCode::Unauthorized)?;
    issuer
        .with_current(now, |user, key, _, _, _| {
            if lineage.binding.community() != "wallet"
                || lineage.binding.member() != user
                || device.authority_reference() != key
            {
                return Err(ErrorCode::Unauthorized);
            }
            Ok(())
        })
        .map_err(|_| ErrorCode::Unauthorized)?
}

/// Issue or renew the existing global holder using the original HTTPS issuer.
/// The issuer continuation must come from an independently authenticated Foyer:
/// a Foyer already retaining the Wallet's authority lease refuses another lease.
/// Both must name the exact same original Wallet account and current passkey.
///
/// The private opening commits before the request is sent. Cancellation or an
/// unknown outcome leaves that original durable state for explicit recovery;
/// this function never retries issuance, cancels it implicitly, or creates a
/// missing holder. Success means the original verified passport is durable.
pub async fn issue_global_passport<B, C, E, A, R, G>(
    mut issuer: GlobalPassportIssuance<Transport>,
    wallet: &mut Vault<B, C, E, A, R, GlobalPassportCustody>,
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
    same_wallet(&mut issuer, wallet).await?;
    let (public, challenge) = issuer
        .with_current(now, |_, _, public, challenge, _| {
            let public =
                IssuerPublicKey::from_bytes(public).map_err(|_| ErrorCode::Unauthorized)?;
            let challenge = IssuanceChallenge::from_bytes(
                challenge.try_into().map_err(|_| ErrorCode::Unauthorized)?,
            );
            Ok((public, challenge))
        })
        .map_err(|_| ErrorCode::Unauthorized)??;
    // Owner-generated operation IDs label two separate durable mutations. They
    // do not authorize either mutation or replace the original receipt check.
    let mut operations = [0u8; 64];
    getrandom::fill(&mut operations).map_err(|_| ErrorCode::Unavailable)?;
    let begin: [u8; 32] = operations[..32].try_into().expect("fixed operation width");
    let finish: [u8; 32] = operations[32..].try_into().expect("fixed operation width");
    if begin == [0; 32] || finish == [0; 32] || begin == finish {
        return Err(ErrorCode::Unavailable);
    }
    let request = wallet
        .begin_global_passport_issuance(begin, rng, &public, &challenge)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    same_wallet(&mut issuer, wallet)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    let response = issuer
        .issue(request.to_bytes(), now)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    same_wallet(&mut issuer, wallet)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    let response = BlindPassport::from_bytes(&response).map_err(|_| ErrorCode::Reconcile)?;
    wallet
        .finish_global_passport_issuance(finish, rng, &response)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    same_wallet(&mut issuer, wallet)
        .await
        .map_err(|_| ErrorCode::Reconcile)
}
