//! The account actor of a reopened device, built from a port on the Door's one Vault.
//!
//! A running device has exactly one owner per Store: the Door's Vault. The actor
//! gets no Vault of its own; it works through [`AccountPort`] on that Vault, and the
//! member authority of that same Vault spends the actor's own one-use signing
//! channels while the port is in use.
use super::{
    account::{bind_account_actor, AccountParts},
    accounting::{AccountVault, CommunityAccount},
    custody::{AccountWiring, SystemClock},
    facades::VaultBoardOwner,
    passport::GlobalPassport,
    Door, Result,
};
use ckmg::{Authority, Clock, Entropy};
use cvlt::Records;

/// Bind the account actor of `origin` on the Door's Vault behind `owner`.
/// `global` is the member's restored global holder, `device` the member device key
/// and `prover` the native prover the embedder lends. The actor ends with the
/// session (the custody lifetime closes the port).
#[allow(clippy::too_many_arguments)]
pub async fn bind_member_account<B, A, R, GB, GC, GE, GA, GR>(
    door: &mut Door,
    origin: &str,
    owner: &VaultBoardOwner<B, SystemClock, ckmg::SystemEntropy, A, R, cvlt::WalletCustody>,
    wiring: AccountWiring,
    global: GlobalPassport<GB, GC, GE, GA, GR>,
    device: [u8; 32],
    prover: std::sync::Arc<dyn super::account::AccountProver>,
) -> Result<()>
where
    B: cwst::backend::Backend + 'static,
    A: Authority + 'static,
    R: Records + 'static,
    GB: cwst::backend::Backend + 'static,
    GC: Clock + 'static,
    GE: Entropy + 'static,
    GA: Authority + 'static,
    GR: Records + 'static,
{
    let membership = door.live_membership(origin)?;
    let policy = door.current_policy(origin)?;
    bind_member_account_with(
        door, origin, owner, wiring, membership, policy, global, device, prover,
    )
    .await
}

/// Like [`bind_member_account`], but the actor admits through its own community
/// session (`membership`, `policy`): a composed device lends it a companion session
/// because the Door's session is held by the Vault's recovery lease.
#[allow(clippy::too_many_arguments)]
pub async fn bind_member_account_with<B, A, R, GB, GC, GE, GA, GR>(
    door: &mut Door,
    origin: &str,
    owner: &VaultBoardOwner<B, SystemClock, ckmg::SystemEntropy, A, R, cvlt::WalletCustody>,
    wiring: AccountWiring,
    membership: cfyr::membership::LiveMembership<super::foyer::Transport>,
    policy: cfyr::policy::CurrentPolicy<super::foyer::Transport>,
    global: GlobalPassport<GB, GC, GE, GA, GR>,
    device: [u8; 32],
    prover: std::sync::Arc<dyn super::account::AccountProver>,
) -> Result<()>
where
    B: cwst::backend::Backend + 'static,
    A: Authority + 'static,
    R: Records + 'static,
    GB: cwst::backend::Backend + 'static,
    GC: Clock + 'static,
    GE: Entropy + 'static,
    GA: Authority + 'static,
    GR: Records + 'static,
{
    let account = CommunityAccount::recovered(
        origin.to_owned(),
        AccountVault::Port(owner.account_port(wiring.arm)),
    )
    .await?;
    let expires = wiring.intents.expires;
    bind_account_actor(
        door,
        origin,
        AccountParts {
            membership,
            policy,
            account,
            global,
            device,
            intents: wiring.intents,
            request_intent: wiring.request,
            rng: cwlt::passport::rand::rngs::OsRng,
            prover,
        },
        expires,
    )
}
