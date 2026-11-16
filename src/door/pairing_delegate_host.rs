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
//! the wallet has none, such an offer is refused before anything is asked of the person. The
//! replaced key must be a current delegate of the member, never another of its registry keys.
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

/// What one community's ceremony settled and must not redo. The offer, anchor, receipt,
/// sealed material and actions are the PREPARED state (Keys enrolled the offer); `confirmed`
/// is set only once the person's confirmation over it succeeded, as in `pairing_host`.
#[derive(Default)]
struct Progress {
    offer: Option<ckmg::DelegationOffer>,
    confirmed: bool,
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
    /// ceremony yet). `None` when a repeat already holds its confirmation.
    async fn prepare(
        &mut self,
        wallet: &mut impl PairingWallet,
        offer: ckmg::DelegationOffer,
    ) -> Result<Option<PairingActions>> {
        if let Some(kept) = &self.progress.offer {
            // A repeat of the same offer is asked again until a confirmation succeeded, and
            // never after; another offer never reuses this prepared revision.
            if *kept != offer {
                return Err(ErrorCode::Refused);
            }
            if self.progress.confirmed {
                return Ok(None);
            }
            return self
                .progress
                .actions
                .clone()
                .map(Some)
                .ok_or(ErrorCode::Reconcile);
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
        // A re-delegation replaces a CURRENT delegate of the member only, never another key
        // of the member (the registry would revoke it): refused before Keys or the person is
        // asked. `register` revokes exactly this key against exactly this anchor.
        if offer
            .replaces
            .is_some_and(|old| !anchor.delegates.contains(&old))
        {
            return Err(ErrorCode::Unauthorized);
        }
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

    /// Keep that the person's confirmation over the prepared offer succeeded.
    fn confirmed(&mut self) {
        self.progress.confirmed = true;
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
        // Nothing registers without the person's confirmation.
        if !self.progress.confirmed {
            return Err(ErrorCode::InvalidRequest);
        }
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
        // for an offer that cannot be delegated), then ONE confirmation over all of them; only
        // a confirmation that succeeded counts.
        let mut open = Vec::new();
        let mut asked = Vec::new();
        for (target, offer) in offers {
            let host = self
                .communities
                .get_mut(&target.community)
                .ok_or(ErrorCode::Unavailable)?;
            if let Some(actions) = host.prepare(&mut self.wallet, offer).await? {
                open.push(actions);
                asked.push(target.community);
            }
        }
        if !open.is_empty() {
            self.wallet.confirm_all(&open).await?;
        }
        for community in asked {
            if let Some(host) = self.communities.get_mut(&community) {
                host.confirmed();
            }
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
        let old = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None)
            .unwrap()
            .offer()
            .device;
        let again =
            ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", Some(old)).unwrap();
        assert_eq!(
            steps
                .confirm_all(vec![(target("garden"), again.offer())])
                .await
                .err(),
            Some(ErrorCode::Unavailable)
        );
        let first = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None).unwrap();
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

    const ORIGIN: &str = "https://garden.example.test";
    /// The admission evidence of the test authority (production: the live lineage digest).
    const EVIDENCE: &[u8] = b"the live lineage digest";

    #[derive(Clone, Default)]
    struct Memory(Rc<std::cell::RefCell<std::collections::HashMap<ckmg::Locator, Vec<u8>>>>);
    impl ckmg::SecureStore for Memory {
        async fn load(
            &mut self,
            location: &ckmg::Locator,
        ) -> std::result::Result<Option<Vec<u8>>, ckmg::Error> {
            Ok(self.0.borrow().get(location).cloned())
        }
        async fn compare_exchange(
            &mut self,
            location: &ckmg::Locator,
            expected: Option<[u8; 32]>,
            next: &[u8],
        ) -> std::result::Result<ckmg::Commit, ckmg::Error> {
            let mut data = self.0.borrow_mut();
            if data.get(location).map(|v| *ckmg::hash(v).value()) != expected {
                return Ok(ckmg::Commit::Conflict);
            }
            data.insert(*location, next.to_vec());
            Ok(ckmg::Commit::Committed)
        }
    }

    #[derive(Clone)]
    struct Time;
    impl ckmg::Clock for Time {
        fn now(&mut self) -> std::result::Result<u64, ckmg::Error> {
            Ok(1_000)
        }
    }

    /// Synthetic test authority (not production membership): a delegation needs the evidence.
    struct Allow;
    impl ckmg::Authority for Allow {
        async fn check(
            &mut self,
            request: ckmg::Authorization<'_>,
        ) -> std::result::Result<(), ckmg::Error> {
            if request.action == ckmg::Action::DelegateDevice && request.evidence != EVIDENCE {
                return Err(ckmg::Error::Unauthorized);
            }
            Ok(())
        }
    }

    type Keys = ckmg::Keys<Memory, Time, ckmg::SystemEntropy, Allow>;

    /// The member's full custody of garden, with `delegates` delegated to (and acknowledged).
    async fn custody(delegates: usize) -> Keys {
        let mut keys = Keys::new(Memory::default(), Time, ckmg::SystemEntropy, Allow);
        let prf = ckmg::passkey::PrfOutput::from_bytes(&[0x5a; 32]).unwrap();
        let receipt = keys
            .create_scope(
                &prf,
                ckmg::Binding::new("garden", "member").unwrap(),
                ckmg::DeviceInfo::new("wallet", b"credential").unwrap(),
                b"registration",
            )
            .await
            .unwrap();
        keys.acknowledge(receipt.operation).await.unwrap();
        for _ in 0..delegates {
            let request =
                ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None).unwrap();
            let (receipt, _) = keys
                .delegate_remote_device(&request.offer(), &delegated_purposes(), EVIDENCE)
                .await
                .unwrap();
            keys.acknowledge(receipt.operation).await.unwrap();
        }
        keys
    }

    /// The approving device's Vault of garden: real Keys custody for the anchor and the
    /// enrolment, which it counts; everything else is unavailable.
    struct Custody {
        keys: Keys,
        enrolments: Rc<Cell<u32>>,
    }

    impl facades::BoundVault for Custody {
        fn current_identity(&mut self) -> facades::OwnedFuture<'_, facades::VaultIdentity> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn snapshot(
            &mut self,
            _: facades::Relation,
        ) -> facades::OwnedFuture<'_, cnbx::ConversationView> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn history(
            &mut self,
            _: facades::Conversation,
        ) -> facades::OwnedFuture<'_, Vec<cnbx::Message>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn thread(
            &mut self,
            _: facades::Conversation,
        ) -> facades::OwnedFuture<'_, Vec<facades::ThreadEntry>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn relation(&mut self, _: facades::Relation) -> facades::OwnedFuture<'_, cnbx::Relation> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn delivery(
            &mut self,
            _: facades::Delivery,
        ) -> facades::OwnedFuture<'_, Option<cnbx::DeliveryStatus>> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn sign_board<'a>(
            &'a mut self,
            _: &'a cbrd::Prepared,
            _: &'a str,
            _: u64,
            _: u64,
        ) -> facades::OwnedFuture<'a, facades::SignedBoard> {
            Box::pin(async { Err(ErrorCode::Unavailable) })
        }
        fn lock(
            self: Box<Self>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>> {
            Box::pin(async {})
        }
        fn pairing_anchor(&mut self) -> facades::OwnedFuture<'_, ckmg::Lineage> {
            Box::pin(async {
                self.keys
                    .lineage()
                    .await
                    .map_err(|_| ErrorCode::Unavailable)
            })
        }
        fn delegate_remote<'a>(
            &'a mut self,
            offer: &'a ckmg::DelegationOffer,
            purposes: &'a [ckmg::Purpose],
            _: &'a str,
        ) -> facades::OwnedFuture<'a, (ckmg::Receipt, ckmg::SealedDelegation)> {
            Box::pin(async move {
                self.enrolments.set(self.enrolments.get() + 1);
                self.keys
                    .delegate_remote_device(offer, purposes, EVIDENCE)
                    .await
                    .map_err(|_| ErrorCode::Unauthorized)
            })
        }
    }

    /// A Door of garden whose member Vault is `keys`; `enrolments` counts what Keys enrols.
    fn door(keys: Keys, enrolments: Rc<Cell<u32>>) -> Door {
        let mut door = Door::new(
            crate::door::Configuration::new(
                "garden".into(),
                BTreeMap::from([(
                    crate::door::Role::Member,
                    std::collections::BTreeSet::from([ORIGIN.to_owned()]),
                )]),
            )
            .unwrap(),
        );
        door.vaults
            .insert(ORIGIN.into(), Box::new(Custody { keys, enrolments }));
        door
    }

    /// A session-less Foyer of garden that is never reached here.
    #[cfg(not(feature = "ohttp"))]
    fn community() -> cfyr::Foyer<Transport> {
        cfyr::Foyer::new(crate::door::foyer::fixture_transport(
            "http://127.0.0.1:9",
            "garden.example.test",
        ))
    }

    /// A wallet whose person confirms; it counts the confirmations and the delegated adds.
    struct Confirms {
        asked: Rc<Cell<u32>>,
        added: Rc<Cell<u32>>,
    }
    impl PairingWallet for Confirms {
        async fn pseudonym(&mut self, _: &str) -> Result<String> {
            Ok("ab".repeat(16))
        }
        async fn confirm_all(&mut self, _: &[PairingActions]) -> Result<()> {
            self.asked.set(self.asked.get() + 1);
            Ok(())
        }
        async fn send(
            &mut self,
            _: &mut cfyr::Foyer<Transport>,
            _: &PairingActions,
            _: device_pair::Step,
            _: &StepChallenge,
            _: Vec<u8>,
        ) -> Result<Option<PresentedStamp>> {
            Err(ErrorCode::Unavailable)
        }
        async fn stamp_trust(&mut self) -> Result<cvlt::StampTrust> {
            Err(ErrorCode::Unavailable)
        }
        async fn send_delegated(
            &mut self,
            _: &mut cfyr::Foyer<Transport>,
            _: &PairingActions,
            _: &StepChallenge,
            _: Vec<u8>,
            _: &DelegateApproval,
        ) -> Result<PresentedStamp> {
            self.added.set(self.added.get() + 1);
            Err(ErrorCode::Unavailable)
        }
    }

    /// A registry revocation step that is available and counts its revocations.
    struct Revokes(Rc<Cell<u32>>);
    impl RevokeDelegate for Revokes {
        fn available(&self) -> bool {
            true
        }
        async fn revoke(
            &mut self,
            _: &mut cfyr::Foyer<Transport>,
            _: &PairingActions,
            _: &[u8; 32],
        ) -> Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    /// Review a11 F5: the offer is prepared before the person is asked, and only a
    /// confirmation that succeeded counts (as in `pairing_host`). After a declined or failed
    /// confirmation nothing registers, the same offer asks the person again, and once
    /// confirmed a repeat asks nothing; another offer never reuses the prepared revision.
    #[cfg(not(feature = "ohttp"))]
    #[tokio::test]
    async fn only_a_confirmation_that_succeeded_counts() {
        let mut keys = custody(0).await;
        let anchor = keys.lineage().await.unwrap();
        let request =
            ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None).unwrap();
        let offer = request.offer();
        let (receipt, sealed) = keys
            .delegate_remote_device(&offer, &delegated_purposes(), EVIDENCE)
            .await
            .unwrap();
        let scope = cwlt::passport::StampScope::of_community(
            cwlt::passport::CommunityId::new(b"garden").unwrap(),
            None,
        );
        let actions = PairingActions::new(
            scope,
            "garden",
            &"ab".repeat(16),
            *offer.device.value(),
            [2; 32],
            [3; 32],
            receipt.passkey_challenge().unwrap(),
        )
        .unwrap();
        let enrolments = Rc::new(Cell::new(0));
        let mut door = door(keys, enrolments.clone());
        let mut host = DoorDelegator::new(&mut door, ORIGIN, Dead, community(), "user");
        // What `prepare` keeps once Keys enrolled the offer, before the person answered (the
        // person then declined).
        host.progress = Progress {
            offer: Some(offer.clone()),
            anchor: Some(anchor),
            receipt: Some(receipt),
            sealed: Some(sealed),
            actions: Some(actions),
            ..Progress::default()
        };
        let (asked, added) = (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)));
        let wallet = Confirms {
            asked: asked.clone(),
            added: added.clone(),
        };
        let mut steps = SessionDelegator::new(wallet, NoRevocation, [("garden".into(), host)]);
        let garden = target("garden");
        // Not confirmed: nothing registers.
        assert_eq!(
            steps.register(&garden, vec![0; 64]).await.err(),
            Some(ErrorCode::InvalidRequest)
        );
        assert_eq!(added.get(), 0);
        // The same offer again asks the person again; Keys is not asked twice.
        steps
            .confirm_all(vec![(garden.clone(), offer.clone())])
            .await
            .unwrap();
        assert_eq!(asked.get(), 1);
        // Confirmed: a repeat asks nothing.
        steps
            .confirm_all(vec![(garden.clone(), offer.clone())])
            .await
            .unwrap();
        assert_eq!(asked.get(), 1);
        assert_eq!(enrolments.get(), 0);
        // Another offer never reuses this revision.
        let other = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None)
            .unwrap()
            .offer();
        assert_eq!(
            steps.confirm_all(vec![(garden, other)]).await.err(),
            Some(ErrorCode::Refused)
        );
        assert_eq!((asked.get(), enrolments.get()), (1, 0));
    }

    /// Review a11 F6: a re-delegation replaces a CURRENT delegate of the member only. An offer
    /// whose replaced key is not listed in the anchor's delegates (another registry key of the
    /// member, say) is refused before Keys, the person or the registry is asked anything; one
    /// that names a current delegate goes on to Keys.
    #[cfg(not(feature = "ohttp"))]
    #[tokio::test]
    async fn a_replaced_key_must_be_a_current_delegate() {
        let mut keys = custody(1).await;
        let anchor = keys.lineage().await.unwrap();
        let current = anchor.delegates[0];
        let enrolments = Rc::new(Cell::new(0));
        let mut door = door(keys, enrolments.clone());
        let host = DoorDelegator::new(&mut door, ORIGIN, Dead, community(), "user");
        let (asked, added, revoked) = (
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let wallet = Confirms {
            asked: asked.clone(),
            added: added.clone(),
        };
        let mut steps =
            SessionDelegator::new(wallet, Revokes(revoked.clone()), [("garden".into(), host)]);
        let device = anchor.devices[0];
        let foreign = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", None)
            .unwrap()
            .offer()
            .device;
        for replaced in [device, foreign] {
            let offer =
                ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", Some(replaced))
                    .unwrap()
                    .offer();
            assert_eq!(
                steps
                    .confirm_all(vec![(target("garden"), offer)])
                    .await
                    .err(),
                Some(ErrorCode::Unauthorized)
            );
        }
        assert_eq!((enrolments.get(), asked.get(), revoked.get()), (0, 0, 0));
        // A current delegate reaches Keys (the stamp scope then needs the community's
        // verified Charter, which this test has none of).
        let offer = ckmg::DelegationRequest::new(&mut ckmg::SystemEntropy, "garden", Some(current))
            .unwrap()
            .offer();
        assert_eq!(
            steps
                .confirm_all(vec![(target("garden"), offer)])
                .await
                .err(),
            Some(ErrorCode::Unavailable)
        );
        assert_eq!((enrolments.get(), asked.get()), (1, 0));
    }
}
