//! The existing device's concrete steps of a pairing ([`HostSteps`]) over the Door: the
//! member's ONE wallet confirmation (a stamp covering `device_add` and `device_activate` for
//! exactly the new device's key, which the pairing request names), the community's two
//! stamped pairing steps, Keys (`Pair`) and the lineage revision (certified evidence, record
//! value, publication through cvlt's narrow capability).
//!
//! Every step that took the person's time (the wallet confirmation, the evidence ceremony)
//! or that must not run twice (the Keys approval, the signed record value, the community
//! add) keeps its outcome in this value, so a failed round that the new device repeats
//! resumes after the last completed step. The order of the third round is the safety order:
//! the key is registered PENDING (it grants nothing), Keys approval, evidence over the
//! receipt, durable retention, record value, publication and forced read, Keys
//! acknowledgment, and only then, in the fourth round, the community activates the key. A
//! host that restarts loses the offer; the person starts a new link, nothing half-applied is
//! trusted.
use super::device_join::{DeviceSign, DeviceUse};
use super::device_pair::{self, PairingActions, PresentedStamp, Step, StepChallenge};
use super::pairing_publish::prepare_revision_evidence;
use super::pairing_roles::{HostSteps, Scope, Selection};
use super::passport::GlobalPassport;
use super::*;
use composer_core::DeviceKeys;
use foyer::Transport;
use std::collections::BTreeMap;

/// Seconds a Keys signing admission of the pairing approval stays valid.
const SIGN_SECONDS: u64 = 60;

fn secs() -> u64 {
    ckmg::Clock::now(&mut custody::SystemClock).unwrap_or(u64::MAX)
}

/// The member's wallet, as far as a pairing needs it.
#[allow(async_fn_in_trait)]
pub trait PairingWallet {
    /// The member's pseudonym in community `name` (hex), which the pairing stamp names.
    async fn pseudonym(&mut self, name: &str) -> Result<String>;
    /// The wallet confirmation over ALL scopes' actions: stamps of `STAMP_SLOTS` slots, one
    /// ceremony each (1 for up to 16 communities, 2 for 17).
    async fn confirm_all(&mut self, actions: &[PairingActions]) -> Result<()>;
    /// Send one pairing step to the community (only the add step presents the stamp).
    async fn send(
        &mut self,
        community: &mut cfyr::Foyer<Transport>,
        actions: &PairingActions,
        step: Step,
        challenge: &StepChallenge,
        signature: Vec<u8>,
    ) -> Result<Option<PresentedStamp>>;
    /// The wallet's stamp trust, to verify the revision evidence before it is kept.
    async fn stamp_trust(&mut self) -> Result<cvlt::StampTrust>;
}

/// [`PairingWallet`] over the wallet's authenticated Foyer, its passport and its passkeys.
pub struct WalletParts<'a, B, C, E, A, R, K>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
    K: cfyr::passkeys::Authenticator,
{
    /// The wallet's authenticated Foyer, for the stamp.
    pub api: &'a cfyr::Foyer<Transport>,
    /// The wallet's origin.
    pub origin: &'a str,
    /// The member's global passport.
    pub passport: &'a mut GlobalPassport<B, C, E, A, R>,
    /// The wallet passkeys; its `confirm` counts the one ceremony.
    pub keys: &'a mut DeviceKeys<K>,
}

impl<B, C, E, A, R, K> PairingWallet for WalletParts<'_, B, C, E, A, R, K>
where
    K: cfyr::passkeys::Authenticator,
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    async fn pseudonym(&mut self, name: &str) -> Result<String> {
        let id = cwlt::passport::CommunityId::new(name.as_bytes())
            .map_err(|_| ErrorCode::Unavailable)?;
        self.passport
            .with_global_passport(|holder| holder.pseudonym(&id).to_hex())
            .await
    }

    async fn confirm_all(&mut self, actions: &[PairingActions]) -> Result<()> {
        device_pair::confirm_all(actions, self.api, self.origin, self.passport, self.keys).await
    }

    async fn send(
        &mut self,
        community: &mut cfyr::Foyer<Transport>,
        actions: &PairingActions,
        step: Step,
        challenge: &StepChallenge,
        signature: Vec<u8>,
    ) -> Result<Option<PresentedStamp>> {
        device_pair::send(
            community,
            self.passport,
            actions,
            step,
            challenge,
            signature,
        )
        .await
    }

    async fn stamp_trust(&mut self) -> Result<cvlt::StampTrust> {
        composer_core::stamp_trust(self.api, self.origin)
            .await
            .map_err(|_| ErrorCode::Unavailable)
    }
}

/// The approving device's own key as the stamp salt source: its Vault's Keys derive the
/// device salt, which only this device can rebuild after a restart. It signs nothing.
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

/// The approving device's own key signing the typed pairing approval: the only purpose this
/// signer accepts is the digest of ONE pairing (`ckmg::PairingApproval`), signed through the
/// Vault's single-use admission over the exact transcript.
struct VaultApproval<'a> {
    vault: &'a mut dyn facades::BoundVault,
    origin: &'a str,
}

impl VaultApproval<'_> {
    async fn sign(&mut self, community: &str, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let message = ckmg::PairingApproval::new(community, digest)
            .map_err(|_| ErrorCode::InvalidRequest)?
            .message();
        let started = ckmg::Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)?;
        let (signature, _, _) = self
            .vault
            .sign_endorsement(
                &message,
                self.origin,
                started,
                started.saturating_add(SIGN_SECONDS),
            )
            .await?;
        signature.try_into().map_err(|_| ErrorCode::Reconcile)
    }
}

/// What round 2 settled: the request, its key's two stamp actions.
struct Confirmed {
    request: ckmg::PairingRequest,
    actions: PairingActions,
}

/// The progress of the third round that must survive a retried round.
#[derive(Default)]
struct Approval {
    added: bool,
    grant: Option<ckmg::PairingGrant>,
    receipt: Option<ckmg::Receipt>,
    stamp: Option<PresentedStamp>,
    evidence: Option<cvlt::PreparedLineageEvidence>,
    retained: bool,
    value: Option<cdht::SignedValue>,
    published: bool,
    acknowledged: bool,
}

/// The pairing steps of ONE community scope over its Door and one network for the record
/// publication. The member's wallet is lent per call ([`SessionHost`] owns it), because one
/// wallet serves every scope of a session.
pub struct DoorHost<'a, N: cdht::Network + Clone> {
    door: &'a mut Door,
    origin: String,
    network: N,
    /// A session-less Foyer of the community: the pairing challenges are public and a
    /// challenge issued to a session is refused for pairing.
    community: cfyr::Foyer<Transport>,
    anchor: Option<ckmg::Lineage>,
    confirmed: Option<Confirmed>,
    approval: Approval,
    /// The challenge fetched last (the add step's, then the activation's).
    challenge: Option<StepChallenge>,
}

impl<'a, N: cdht::Network + Clone> DoorHost<'a, N> {
    /// Steps for the member portal `origin` of `door`; `network` is the record network the
    /// lineage revision is published to, `community` a session-less Foyer of the community.
    pub fn new(
        door: &'a mut Door,
        origin: &str,
        network: N,
        community: cfyr::Foyer<Transport>,
    ) -> Self {
        Self {
            door,
            origin: origin.to_owned(),
            network,
            community,
            anchor: None,
            confirmed: None,
            approval: Approval::default(),
            challenge: None,
        }
    }

    async fn anchor(&mut self) -> Result<ckmg::Lineage> {
        if let Some(kept) = &self.anchor {
            return Ok(kept.clone());
        }
        let anchor = self
            .door
            .vaults
            .get_mut(&self.origin)
            .ok_or(ErrorCode::Unavailable)?
            .pairing_anchor()
            .await?;
        self.anchor = Some(anchor.clone());
        Ok(anchor)
    }

    /// Verify `request` and derive this community's pairing action (no ceremony). `None` when
    /// a repeat of round 2 for the same request already holds its confirmation.
    async fn prepare(
        &mut self,
        wallet: &mut impl PairingWallet,
        request: &ckmg::PairingRequest,
    ) -> Result<Option<PairingActions>> {
        if let Some(kept) = &self.confirmed {
            // A repeat of round 2 for the same request keeps the confirmation; another
            // request never reuses this pairing.
            return if kept.request == *request {
                Ok(None)
            } else {
                Err(ErrorCode::Refused)
            };
        }
        // Nothing is asked of the person for a request that cannot be approved anyway: it
        // must be proven and extend exactly the lineage this device showed.
        let anchor = self.anchor.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        request
            .verify(secs())
            .map_err(|_| ErrorCode::Unauthorized)?;
        if request.binding != anchor.binding
            || request.root != anchor.root
            || request.epoch != anchor.epoch
        {
            return Err(ErrorCode::Unauthorized);
        }
        let name = self.door.config.community.clone();
        let member = wallet.pseudonym(&name).await?;
        // Keys adds exactly the proven device FIRST: the one stamp commits to the revision
        // (the receipt's challenge), so it approves this key in exactly this revision. The
        // key grants nothing until the community activates it, which happens only after the
        // revision is published.
        if self.approval.receipt.is_none() {
            let approved = self.door.pair_approve(&self.origin, request).await?;
            self.approval.grant = Some(approved.grant);
            self.approval.receipt = Some(approved.receipt);
        }
        let revision = self
            .approval
            .receipt
            .as_ref()
            .ok_or(ErrorCode::Reconcile)?
            .passkey_challenge()
            .map_err(|_| ErrorCode::Unauthorized)?;
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
                &request.device,
                revision,
                &mut salt,
            )
            .await?
        };
        Ok(Some(actions))
    }

    /// Keep the outcome of the session's confirmation for `request`.
    fn confirmed(&mut self, request: ckmg::PairingRequest, actions: PairingActions) {
        self.confirmed = Some(Confirmed { request, actions });
    }

    /// A fresh one-use challenge (it lives 60 seconds, so it is fetched after the round's
    /// human steps).
    async fn challenge(&mut self) -> Result<StepChallenge> {
        let challenge = device_pair::begin(&mut self.community).await?;
        self.challenge = Some(challenge.clone());
        Ok(challenge)
    }

    async fn approve(
        &mut self,
        wallet: &mut impl PairingWallet,
        signature: Vec<u8>,
    ) -> Result<ckmg::PairingGrant> {
        let confirmed = self.confirmed.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        let anchor = self.anchor.clone().ok_or(ErrorCode::InvalidRequest)?;
        let actions = confirmed.actions.clone();
        // 0. The key is registered PENDING at the community with the ONE stamp: it grants
        // nothing yet. The stamp presentation is kept as the revision's public evidence.
        if !self.approval.added {
            let challenge = self.challenge.as_ref().ok_or(ErrorCode::InvalidRequest)?;
            let presented = wallet
                .send(
                    &mut self.community,
                    &actions,
                    Step::Add,
                    challenge,
                    signature,
                )
                .await?;
            self.approval.stamp = Some(presented.ok_or(ErrorCode::Reconcile)?);
            self.approval.added = true;
        }
        // 1. Keys already added exactly the proven device (round 2, before the stamp).
        let receipt = self.approval.receipt.clone().ok_or(ErrorCode::Reconcile)?;
        // 2. Revision evidence: the stamp and the host device key's signature over the same
        // digest, verified against the CURRENT devices before anything is kept.
        if self.approval.evidence.is_none() {
            let stamp = self.approval.stamp.clone().ok_or(ErrorCode::Reconcile)?;
            let stamps = wallet.stamp_trust().await?;
            let host_signature = {
                let vault = self
                    .door
                    .vaults
                    .get_mut(&self.origin)
                    .ok_or(ErrorCode::Unavailable)?;
                VaultApproval {
                    vault: vault.as_mut(),
                    origin: &self.origin,
                }
                .sign(actions.community(), &actions.digest())
                .await?
            };
            let mut policy = self.door.current_policy(&self.origin)?;
            let evidence = prepare_revision_evidence(
                &mut policy,
                &stamps,
                &anchor,
                &receipt,
                &actions,
                &stamp,
                host_signature,
                &mut custody::SystemClock,
            )?;
            self.approval.evidence = Some(evidence);
        }
        // 3. Durable before anything is published.
        let vault = self
            .door
            .vaults
            .get_mut(&self.origin)
            .ok_or(ErrorCode::Unavailable)?;
        if !self.approval.retained {
            let evidence = self
                .approval
                .evidence
                .as_ref()
                .ok_or(ErrorCode::Reconcile)?;
            vault.retain_pairing_evidence(evidence, &receipt).await?;
            self.approval.retained = true;
        }
        // 4. The signed next record value, made exactly once.
        if self.approval.value.is_none() {
            let packed = self
                .approval
                .evidence
                .as_ref()
                .ok_or(ErrorCode::Reconcile)?
                .packed()
                .map_err(|_| ErrorCode::Reconcile)?;
            let value = vault
                .revision_record(&receipt, &anchor, &packed, &self.origin)
                .await?;
            self.approval.value = Some(value);
        }
        // 5. Publication and forced read, then the receipt is acknowledged.
        if !self.approval.published {
            let value = self.approval.value.as_ref().ok_or(ErrorCode::Reconcile)?;
            cvlt::publish_lineage_revision(self.network.clone(), &anchor.root, value)
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
            self.approval.published = true;
        }
        if !self.approval.acknowledged {
            vault.acknowledge_pairing(&receipt).await?;
            self.approval.acknowledged = true;
        }
        self.approval.grant.clone().ok_or(ErrorCode::Reconcile)
    }

    async fn activate(
        &mut self,
        wallet: &mut impl PairingWallet,
        signature: Vec<u8>,
    ) -> Result<()> {
        let confirmed = self.confirmed.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        // Only after the revision is published and acknowledged.
        if !self.approval.acknowledged {
            return Err(ErrorCode::InvalidRequest);
        }
        let challenge = self.challenge.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        wallet
            .send(
                &mut self.community,
                &confirmed.actions,
                Step::Activate,
                challenge,
                signature,
            )
            .await
            .map(|_| ())
    }
}

/// [`HostSteps`] for one pairing session over the member's communities: one wallet, one
/// [`DoorHost`] per community scope. The wallet scope has no server pairing action yet, so a
/// session with [`Scope::Wallet`] is refused at its first step.
pub struct SessionHost<'a, N: cdht::Network + Clone, W: PairingWallet> {
    wallet: W,
    hosts: BTreeMap<Scope, DoorHost<'a, N>>,
}

impl<'a, N: cdht::Network + Clone, W: PairingWallet> SessionHost<'a, N, W> {
    /// The member's `wallet` and the community scopes (by community name) it can bring along.
    pub fn new(
        wallet: W,
        communities: impl IntoIterator<Item = (String, DoorHost<'a, N>)>,
    ) -> Self {
        Self {
            wallet,
            hosts: communities
                .into_iter()
                .map(|(name, host)| (Scope::Community(name), host))
                .collect(),
        }
    }

    /// Every scope the session can bring along, all selected: deselect before showing the link.
    pub fn selection(&self) -> Option<Selection> {
        Selection::all(self.hosts.keys().cloned())
    }

    fn host(&mut self, scope: &Scope) -> Result<&mut DoorHost<'a, N>> {
        self.hosts.get_mut(scope).ok_or(ErrorCode::Unavailable)
    }
}

impl<N: cdht::Network + Clone, W: PairingWallet> HostSteps for SessionHost<'_, N, W> {
    async fn anchor(&mut self, scope: &Scope) -> Result<ckmg::Lineage> {
        self.host(scope)?.anchor().await
    }

    async fn confirm_all(&mut self, requests: Vec<(Scope, ckmg::PairingRequest)>) -> Result<()> {
        // Verify and derive every scope first (nothing is asked of the person for a request
        // that cannot be approved), then ONE confirmation pass over all of them.
        let mut open = Vec::new();
        for (scope, request) in requests {
            let host = self.hosts.get_mut(&scope).ok_or(ErrorCode::Unavailable)?;
            if let Some(actions) = host.prepare(&mut self.wallet, &request).await? {
                open.push((scope, request, actions));
            }
        }
        let actions: Vec<_> = open.iter().map(|(_, _, a)| a.clone()).collect();
        if !actions.is_empty() {
            self.wallet.confirm_all(&actions).await?;
        }
        for (scope, request, actions) in open {
            if let Some(host) = self.hosts.get_mut(&scope) {
                host.confirmed(request, actions);
            }
        }
        Ok(())
    }

    async fn challenge(&mut self, scope: &Scope) -> Result<StepChallenge> {
        self.host(scope)?.challenge().await
    }

    async fn approve(&mut self, scope: &Scope, signature: Vec<u8>) -> Result<ckmg::PairingGrant> {
        let host = self.hosts.get_mut(scope).ok_or(ErrorCode::Unavailable)?;
        host.approve(&mut self.wallet, signature).await
    }

    async fn activate(&mut self, scope: &Scope, signature: Vec<u8>) -> Result<()> {
        let host = self.hosts.get_mut(scope).ok_or(ErrorCode::Unavailable)?;
        host.activate(&mut self.wallet, signature).await
    }
}
