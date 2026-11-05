//! The wallet's concrete steps of the CLI delegation ceremony (A11, [`DelegatorSteps`]) over the
//! Door, exactly the existing pairing host's path with delegated custody: per community, Keys
//! enrols the CLI's `K_d` as a delegate and seals the material to the CLI under a single-use
//! `DelegateDevice` admission whose evidence is the live lineage digest (Q1); the member's ONE
//! wallet confirmation is the stamp covering each community's `device_pair` slot of `K_d` in
//! exactly that revision; the community registers `K_d` PENDING as `Delegated` with this
//! device's approval (option B); the revision evidence (the same stamp and approval, Q2) is
//! retained, the record value signed and published, the receipt acknowledged; then the
//! community activates `K_d`.
//!
//! Every step that took the person's time or must not run twice keeps its outcome, as in
//! [`super::pairing_host`]. A re-delegation (an offer that replaces a delegate) also revokes
//! the replaced key in the community registry, so it needs the registry revocation step; while
//! the wallet has none, such an offer is refused before anything is asked of the person.
use super::device_join::{DeviceSign, DeviceUse};
use super::device_pair::{self, DelegateApproval, PairingActions, PresentedStamp, StepChallenge};
use super::pairing_delegate::{DelegatorSteps, Grant, Target};
use super::pairing_host::PairingWallet;
use super::pairing_publish::prepare_revision_evidence;
use super::*;
use foyer::Transport;
use std::collections::BTreeMap;

/// Seconds a Keys signing admission of the pairing approval stays valid.
const SIGN_SECONDS: u64 = 60;

/// The member purposes a CLI delegation carries (D1: community sessions and member purposes).
pub fn delegated_purposes() -> Vec<ckmg::Purpose> {
    ["board", "inbox", "rooms"]
        .into_iter()
        .filter_map(|label| ckmg::Purpose::new(ckmg::Scope::Member, label, 1).ok())
        .collect()
}

/// The registry revocation of a replaced delegate (the community action of the registry
/// writer, gated like `device_add`). The wallet supplies it; without one, a re-delegation is
/// refused.
#[allow(async_fn_in_trait)]
pub trait RevokeDelegate {
    /// Whether this wallet can revoke a registry row at all.
    fn available(&self) -> bool;
    /// Revoke `key` (the member's delegate in `community`) in the community registry.
    async fn revoke(
        &mut self,
        community: &mut cfyr::Foyer<Transport>,
        actions: &PairingActions,
        key: &[u8; 32],
    ) -> Result<()>;
}

/// No registry revocation step: every re-delegation is refused.
pub struct NoRevocation;
impl RevokeDelegate for NoRevocation {
    fn available(&self) -> bool {
        false
    }
    async fn revoke(
        &mut self,
        _: &mut cfyr::Foyer<Transport>,
        _: &PairingActions,
        _: &[u8; 32],
    ) -> Result<()> {
        Err(ErrorCode::Unavailable)
    }
}

/// The approving device's key as the stamp salt source (it signs nothing).
struct VaultSalt<'a> {
    vault: &'a mut dyn facades::BoundVault,
    origin: &'a str,
}

impl DeviceSign for VaultSalt<'_> {
    async fn sign(&mut self, what: DeviceUse, payload: Vec<u8>) -> Result<Vec<u8>> {
        if what != DeviceUse::Salt {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(self
            .vault
            .device_salt(&payload, self.origin)
            .await?
            .to_vec())
    }
}

/// This device's approval of one delegated key: its device key and its typed PairingApproval
/// signature over the pairing digest, through the Vault's single-use admission.
async fn approval(
    vault: &mut dyn facades::BoundVault,
    origin: &str,
    actions: &PairingActions,
) -> Result<DelegateApproval> {
    let message = ckmg::PairingApproval::new(actions.community(), &actions.digest())
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?
        .message();
    let started = ckmg::Clock::now(&mut custody::SystemClock).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Clock",
            ErrorCode::Clock,
            &__cause,
        )
    })?;
    let (signature, device, _) = vault
        .sign_endorsement(
            &message,
            origin,
            started,
            started.saturating_add(SIGN_SECONDS),
        )
        .await?;
    let reconcile = |_| ErrorCode::Reconcile;
    Ok(DelegateApproval {
        host_key: device.try_into().map_err(reconcile)?,
        host_signature: signature.try_into().map_err(reconcile)?,
    })
}

/// What one community's ceremony settled and must not redo.
#[derive(Default)]
struct Progress {
    offer: Option<ckmg::DelegationOffer>,
    anchor: Option<ckmg::Lineage>,
    receipt: Option<ckmg::Receipt>,
    sealed: Option<ckmg::SealedDelegation>,
    actions: Option<PairingActions>,
    revoked: bool,
    stamp: Option<PresentedStamp>,
    added: bool,
    evidence: Option<cvlt::PreparedLineageEvidence>,
    retained: bool,
    value: Option<cdht::SignedValue>,
    published: bool,
    acknowledged: bool,
    challenge: Option<StepChallenge>,
}

/// The ceremony steps of ONE community over its Door.
pub struct DoorDelegator<'a, N: cdht::Network + Clone> {
    door: &'a mut Door,
    origin: String,
    network: N,
    community: cfyr::Foyer<Transport>,
    user: String,
    progress: Progress,
}

impl<'a, N: cdht::Network + Clone> DoorDelegator<'a, N> {
    /// Steps for the member portal `origin` of `door`; `network` takes the lineage record,
    /// `community` is a session-less Foyer of the community, `user` the member's user there
    /// (the account record), which the CLI opens its sessions as.
    pub fn new(
        door: &'a mut Door,
        origin: &str,
        network: N,
        community: cfyr::Foyer<Transport>,
        user: &str,
    ) -> Self {
        Self {
            door,
            origin: origin.to_owned(),
            network,
            community,
            user: user.to_owned(),
            progress: Progress::default(),
        }
    }

    /// Enrol `K_d` and derive the community's pairing action of exactly that revision (no
    /// ceremony yet). `None` when a repeat already holds it.
    async fn prepare(
        &mut self,
        wallet: &mut impl PairingWallet,
        offer: ckmg::DelegationOffer,
    ) -> Result<Option<PairingActions>> {
        if let Some(kept) = &self.progress.offer {
            return if *kept == offer {
                Ok(None)
            } else {
                Err(ErrorCode::Refused)
            };
        }
        offer.check().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unauthorized",
                ErrorCode::Unauthorized,
                &__cause,
            )
        })?;
        let vault = self
            .door
            .vaults
            .get_mut(&self.origin)
            .ok_or(ErrorCode::Unavailable)?;
        let anchor = vault.pairing_anchor().await?;
        // Keys enrols exactly this K_d FIRST: the one stamp commits to the revision.
        let (receipt, sealed) = vault
            .delegate_remote(&offer, &delegated_purposes(), &self.origin)
            .await?;
        let revision = receipt.passkey_challenge().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Reconcile",
                ErrorCode::Reconcile,
                &__cause,
            )
        })?;
        let name = self.door.config.community.clone();
        let member = wallet.pseudonym(&name).await?;
        let actions = {
            let vault = self
                .door
                .vaults
                .get_mut(&self.origin)
                .ok_or(ErrorCode::Unavailable)?;
            let mut salt = VaultSalt {
                vault: vault.as_mut(),
                origin: &self.origin,
            };
            PairingActions::derive(
                &mut self.community,
                &name,
                &member,
                &offer.device,
                revision,
                &mut salt,
            )
            .await?
        };
        self.progress = Progress {
            offer: Some(offer),
            anchor: Some(anchor),
            receipt: Some(receipt),
            sealed: Some(sealed),
            actions: Some(actions.clone()),
            ..Progress::default()
        };
        Ok(Some(actions))
    }

    async fn challenge(&mut self) -> Result<StepChallenge> {
        let challenge = device_pair::begin(&mut self.community).await?;
        self.progress.challenge = Some(challenge.clone());
        Ok(challenge)
    }

    async fn register(
        &mut self,
        wallet: &mut impl PairingWallet,
        revoke: &mut impl RevokeDelegate,
        signature: Vec<u8>,
    ) -> Result<Grant> {
        let actions = self
            .progress
            .actions
            .clone()
            .ok_or(ErrorCode::InvalidRequest)?;
        let anchor = self
            .progress
            .anchor
            .clone()
            .ok_or(ErrorCode::InvalidRequest)?;
        let receipt = self
            .progress
            .receipt
            .clone()
            .ok_or(ErrorCode::InvalidRequest)?;
        let host = {
            let vault = self
                .door
                .vaults
                .get_mut(&self.origin)
                .ok_or(ErrorCode::Unavailable)?;
            approval(vault.as_mut(), &self.origin, &actions).await?
        };
        // 0. The replaced delegate leaves the registry in the same ceremony (L2).
        if let Some(old) = self
            .progress
            .offer
            .as_ref()
            .and_then(|offer| offer.replaces)
        {
            if !self.progress.revoked {
                revoke
                    .revoke(&mut self.community, &actions, old.value())
                    .await?;
                self.progress.revoked = true;
            }
        }
        // 1. K_d PENDING as Delegated, approved by this device: it grants nothing yet.
        if !self.progress.added {
            let challenge = self
                .progress
                .challenge
                .as_ref()
                .ok_or(ErrorCode::InvalidRequest)?;
            let stamp = wallet
                .send_delegated(&mut self.community, &actions, challenge, signature, &host)
                .await?;
            self.progress.stamp = Some(stamp);
            self.progress.added = true;
        }
        // 2. Revision evidence: the same stamp and approval (Q2), verified before it is kept.
        if self.progress.evidence.is_none() {
            let stamp = self.progress.stamp.clone().ok_or(ErrorCode::Reconcile)?;
            let stamps = wallet.stamp_trust().await?;
            let mut policy = self.door.current_policy(&self.origin)?;
            let evidence = prepare_revision_evidence(
                &mut policy,
                &stamps,
                &anchor,
                &receipt,
                &actions,
                &stamp,
                host.host_signature,
                &mut custody::SystemClock,
            )?;
            self.progress.evidence = Some(evidence);
        }
        let vault = self
            .door
            .vaults
            .get_mut(&self.origin)
            .ok_or(ErrorCode::Unavailable)?;
        // 3. Durable before anything is published.
        if !self.progress.retained {
            let evidence = self
                .progress
                .evidence
                .as_ref()
                .ok_or(ErrorCode::Reconcile)?;
            vault.retain_pairing_evidence(evidence, &receipt).await?;
            self.progress.retained = true;
        }
        // 4. The signed next record value, made exactly once.
        if self.progress.value.is_none() {
            let packed = self
                .progress
                .evidence
                .as_ref()
                .ok_or(ErrorCode::Reconcile)?
                .packed()
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Reconcile",
                        ErrorCode::Reconcile,
                        &__cause,
                    )
                })?;
            let value = vault
                .revision_record(&receipt, &anchor, &packed, &self.origin)
                .await?;
            self.progress.value = Some(value);
        }
        // 5. Publication and forced read, then the receipt is acknowledged.
        if !self.progress.published {
            let value = self.progress.value.as_ref().ok_or(ErrorCode::Reconcile)?;
            cvlt::publish_lineage_revision(self.network.clone(), &anchor.root, value)
                .await
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?;
            self.progress.published = true;
        }
        if !self.progress.acknowledged {
            vault.acknowledge_pairing(&receipt).await?;
            self.progress.acknowledged = true;
        }
        Ok(Grant {
            user: self.user.clone(),
            sealed: self.progress.sealed.clone().ok_or(ErrorCode::Reconcile)?,
        })
    }

    async fn activate(
        &mut self,
        wallet: &mut impl PairingWallet,
        signature: Vec<u8>,
    ) -> Result<()> {
        // Only after the revision is published and acknowledged.
        if !self.progress.acknowledged {
            return Err(ErrorCode::InvalidRequest);
        }
        let actions = self
            .progress
            .actions
            .as_ref()
            .ok_or(ErrorCode::InvalidRequest)?;
        let challenge = self
            .progress
            .challenge
            .as_ref()
            .ok_or(ErrorCode::InvalidRequest)?;
        wallet
            .send(
                &mut self.community,
                actions,
                device_pair::Step::Activate,
                challenge,
                signature,
            )
            .await
            .map(|_| ())
    }
}

/// [`DelegatorSteps`] over the member's communities: one wallet, one [`DoorDelegator`] per
/// community, and the registry revocation step for re-delegations.
pub struct SessionDelegator<'a, N: cdht::Network + Clone, W: PairingWallet, V: RevokeDelegate> {
    wallet: W,
    revoke: V,
    communities: BTreeMap<String, DoorDelegator<'a, N>>,
}

impl<'a, N: cdht::Network + Clone, W: PairingWallet, V: RevokeDelegate>
    SessionDelegator<'a, N, W, V>
{
    /// The member's `wallet`, its revocation step and the communities (by name) it may
    /// delegate to the CLI.
    pub fn new(
        wallet: W,
        revoke: V,
        communities: impl IntoIterator<Item = (String, DoorDelegator<'a, N>)>,
    ) -> Self {
        Self {
            wallet,
            revoke,
            communities: communities.into_iter().collect(),
        }
    }

    fn community(&mut self, target: &Target) -> Result<&mut DoorDelegator<'a, N>> {
        self.communities
            .get_mut(&target.community)
            .ok_or(ErrorCode::Unavailable)
    }
}

impl<N: cdht::Network + Clone, W: PairingWallet, V: RevokeDelegate> DelegatorSteps
    for SessionDelegator<'_, N, W, V>
{
    async fn confirm_all(&mut self, offers: Vec<(Target, ckmg::DelegationOffer)>) -> Result<()> {
        // A re-delegation revokes the replaced key in the registry: without that step it is
        // refused before Keys or the person is asked anything (L2).
        if !self.revoke.available() && offers.iter().any(|(_, offer)| offer.replaces.is_some()) {
            return Err(ErrorCode::Unavailable);
        }
        // Every community first (Keys and the derived action; nothing is asked of the person
        // for an offer that cannot be delegated), then ONE confirmation over all of them.
        let mut open = Vec::new();
        for (target, offer) in offers {
            let host = self
                .communities
                .get_mut(&target.community)
                .ok_or(ErrorCode::Unavailable)?;
            if let Some(actions) = host.prepare(&mut self.wallet, offer).await? {
                open.push(actions);
            }
        }
        if !open.is_empty() {
            self.wallet.confirm_all(&open).await?;
        }
        Ok(())
    }

    async fn challenge(&mut self, target: &Target) -> Result<StepChallenge> {
        self.community(target)?.challenge().await
    }

    async fn register(&mut self, target: &Target, signature: Vec<u8>) -> Result<Grant> {
        let host = self
            .communities
            .get_mut(&target.community)
            .ok_or(ErrorCode::Unavailable)?;
        host.register(&mut self.wallet, &mut self.revoke, signature)
            .await
    }

    async fn activate(&mut self, target: &Target, signature: Vec<u8>) -> Result<()> {
        let host = self
            .communities
            .get_mut(&target.community)
            .ok_or(ErrorCode::Unavailable)?;
        host.activate(&mut self.wallet, signature).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A network with no reachable node.
    #[derive(Clone)]
    struct Dead;
    impl cdht::Network for Dead {
        fn now_ms(&self) -> u64 {
            0
        }
        async fn closest(
            &self,
            _: &cdht::RecordKey,
        ) -> std::result::Result<Vec<cdht::NodeId>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn descriptor(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
        ) -> std::result::Result<Option<cdht::Descriptor>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn get(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
            _: u32,
        ) -> std::result::Result<Option<cdht::SignedValue>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn set(
            &self,
            _: &cdht::NodeId,
            _: &cdht::Descriptor,
            _: u32,
            _: &cdht::SignedValue,
        ) -> std::result::Result<cdht::SetOutcome, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn watch(
            &self,
            _: &cdht::NodeId,
            _: &cdht::RecordKey,
        ) -> std::result::Result<cdht::WatchId, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn cancel_watch(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> std::result::Result<(), cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
        async fn changes(
            &self,
            _: &cdht::NodeId,
            _: cdht::WatchId,
        ) -> std::result::Result<Vec<cdht::Change>, cdht::Error> {
            Err(cdht::Error::Unavailable)
        }
    }

    /// A wallet that counts every use; none is expected below.
    struct Counting(Rc<Cell<u32>>);
    impl PairingWallet for Counting {
        async fn pseudonym(&mut self, _: &str) -> Result<String> {
            self.0.set(self.0.get() + 1);
            Err(ErrorCode::Unavailable)
        }
        async fn confirm_all(&mut self, _: &[PairingActions]) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Err(ErrorCode::Unavailable)
        }
        async fn send(
            &mut self,
            _: &mut cfyr::Foyer<Transport>,
            _: &PairingActions,
            _: device_pair::Step,
            _: &StepChallenge,
            _: Vec<u8>,
        ) -> Result<Option<PresentedStamp>> {
            self.0.set(self.0.get() + 1);
            Err(ErrorCode::Unavailable)
        }
        async fn stamp_trust(&mut self) -> Result<cvlt::StampTrust> {
            self.0.set(self.0.get() + 1);
            Err(ErrorCode::Unavailable)
        }
    }

    fn target(name: &str) -> Target {
        Target {
            community: name.into(),
            fingerprint: [1; 32],
        }
    }

    /// L2: a re-delegation revokes the replaced key, so without a registry revocation step it
    /// is refused before Keys or the person is asked anything; an unknown community is refused
    /// the same way.
    #[tokio::test]
    async fn a_re_delegation_without_registry_revocation_asks_nothing() {
        let uses = Rc::new(Cell::new(0));
        let mut steps: SessionDelegator<'_, Dead, _, _> =
            SessionDelegator::new(Counting(uses.clone()), NoRevocation, []);
        let old = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, None)
            .unwrap()
            .offer()
            .device;
        let again = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, Some(old)).unwrap();
        assert_eq!(
            steps
                .confirm_all(vec![(target("garden"), again.offer())])
                .await
                .err(),
            Some(ErrorCode::Unavailable)
        );
        let first = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, None).unwrap();
        assert_eq!(
            steps
                .confirm_all(vec![(target("garden"), first.offer())])
                .await
                .err(),
            Some(ErrorCode::Unavailable)
        );
        assert_eq!(uses.get(), 0);
        // D1: the delegation carries member purposes only.
        assert!(delegated_purposes()
            .iter()
            .all(|purpose| purpose.scope() == ckmg::Scope::Member));
        assert!(!delegated_purposes().is_empty());
    }
}
