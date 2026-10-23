//! The existing device's concrete steps of a pairing ([`HostSteps`]) over the Door: the
//! member's ONE wallet confirmation (a stamp covering `device_add` and `device_activate` for
//! exactly the new device's key), the community's two stamped pairing steps, Keys (`Pair`)
//! and the lineage revision (certified evidence, record value, publication through cvlt's
//! narrow capability).
//!
//! Every step that took the person's time (the wallet confirmation, the evidence ceremony)
//! or that must not run twice (the Keys approval, the signed record value, the community
//! add) keeps its outcome in this value, so a failed round that the new device repeats
//! resumes after the last completed step. The order of the second round is the safety order:
//! the key is registered PENDING (it grants nothing), Keys approval, evidence over the
//! receipt, durable retention, record value, publication and forced read, Keys
//! acknowledgment, and only then, in the third round, the community activates the key. A
//! host that restarts loses the offer; the person starts a new link, nothing half-applied is
//! trusted.
use super::device_join::DeviceSign;
use super::device_pair::{self, PairingActions, Step, StepChallenge};
use super::pairing_publish::prepare_pairing_evidence;
use super::pairing_roles::{Granted, HostSteps, Welcome};
use super::passport::GlobalPassport;
use super::*;
use composer_core::DeviceKeys;
use foyer::Transport;

/// Seconds the vault's signing admission stays valid for a salt signature.
const SIGN_SECONDS: u64 = 60;

/// The member's wallet, as far as a pairing needs it.
#[allow(async_fn_in_trait)]
pub trait PairingWallet {
    /// The ONE wallet confirmation: a stamp covering both steps for the pairing's key.
    async fn confirm(&mut self, actions: &PairingActions) -> Result<()>;
    /// Send one stamped pairing step to the community.
    async fn send(
        &mut self,
        community: &mut cfyr::Foyer<Transport>,
        actions: &PairingActions,
        step: Step,
        challenge: &StepChallenge,
        signature: Vec<u8>,
    ) -> Result<()>;
}

/// [`PairingWallet`] over the wallet's authenticated Foyer, its passport and its passkeys.
pub struct WalletParts<'a, B, C, E, A, R, K>
where
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
    async fn confirm(&mut self, actions: &PairingActions) -> Result<()> {
        device_pair::confirm(actions, self.api, self.origin, self.passport, self.keys).await
    }

    async fn send(
        &mut self,
        community: &mut cfyr::Foyer<Transport>,
        actions: &PairingActions,
        step: Step,
        challenge: &StepChallenge,
        signature: Vec<u8>,
    ) -> Result<()> {
        device_pair::send(community, self.passport, actions, step, challenge, signature).await
    }
}

/// The approving device's own key as the stamp salt source: its Vault's device key signs the
/// salt message, which only this device can rebuild after a restart.
struct VaultSalt<'a> {
    vault: &'a mut dyn facades::BoundVault,
    origin: &'a str,
}

impl DeviceSign for VaultSalt<'_> {
    async fn sign(&mut self, purpose: ckmg::DevicePurpose, payload: Vec<u8>) -> Result<Vec<u8>> {
        if !matches!(purpose, ckmg::DevicePurpose::SaltDerivation) {
            return Err(ErrorCode::Unauthorized);
        }
        let message = [purpose.tag(), &payload[..]].concat();
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
        Ok(signature)
    }
}

/// What round 1 settled: the key being paired, its two stamp actions and the answer.
struct Welcomed {
    device: ckmg::PublicKey,
    actions: PairingActions,
    welcome: Welcome,
}

/// The progress of the second round that must survive a retried round.
#[derive(Default)]
struct Approval {
    request: Option<ckmg::PairingRequest>,
    added: bool,
    grant: Option<ckmg::PairingGrant>,
    receipt: Option<ckmg::Receipt>,
    evidence: Option<cvlt::PreparedLineageEvidence>,
    retained: bool,
    value: Option<cdht::SignedValue>,
    published: bool,
    acknowledged: bool,
    granted: Option<Granted>,
}

/// [`HostSteps`] over one Door, one network for the record publication and the member's wallet.
pub struct DoorHost<'a, N: cdht::Network + Clone, W: PairingWallet> {
    door: &'a mut Door,
    origin: String,
    network: N,
    /// A session-less Foyer of the community: the pairing challenges are public and a
    /// challenge issued to a session is refused for pairing.
    community: cfyr::Foyer<Transport>,
    wallet: W,
    welcomed: Option<Welcomed>,
    approval: Approval,
    activation: Option<StepChallenge>,
}

impl<'a, N: cdht::Network + Clone, W: PairingWallet> DoorHost<'a, N, W> {
    /// Steps for the member portal `origin` of `door`; `network` is the record network the
    /// lineage revision is published to, `community` a session-less Foyer of the community.
    pub fn new(
        door: &'a mut Door,
        origin: &str,
        network: N,
        community: cfyr::Foyer<Transport>,
        wallet: W,
    ) -> Self {
        Self {
            door,
            origin: origin.to_owned(),
            network,
            community,
            wallet,
            welcomed: None,
            approval: Approval::default(),
            activation: None,
        }
    }
}

impl<N: cdht::Network + Clone, W: PairingWallet> HostSteps for DoorHost<'_, N, W> {
    async fn welcome(&mut self, device: ckmg::PublicKey) -> Result<Welcome> {
        if let Some(kept) = &self.welcomed {
            // A repeat of round 1 for the same key keeps the confirmed answer; another key
            // never reuses this pairing.
            return if kept.device == device {
                Ok(kept.welcome.clone())
            } else {
                Err(ErrorCode::Refused)
            };
        }
        let name = self.door.config.community.clone();
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
            PairingActions::derive(&mut self.community, &name, &device, &mut salt).await?
        };
        // The pairing's ONE wallet confirmation: nothing is prompted when a retained stamp
        // already covers both steps.
        self.wallet.confirm(&actions).await?;
        let anchor = self
            .door
            .vaults
            .get_mut(&self.origin)
            .ok_or(ErrorCode::Unavailable)?
            .pairing_anchor()
            .await?;
        let welcome = Welcome {
            anchor,
            challenge: device_pair::begin(&mut self.community).await?,
        };
        self.welcomed = Some(Welcomed {
            device,
            actions,
            welcome: welcome.clone(),
        });
        Ok(welcome)
    }

    async fn approve(
        &mut self,
        request: ckmg::PairingRequest,
        signature: Vec<u8>,
    ) -> Result<Granted> {
        let welcomed = self.welcomed.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        if request.device != welcomed.device {
            return Err(ErrorCode::Refused);
        }
        let anchor = welcomed.welcome.anchor.clone();
        match &self.approval.request {
            Some(kept) if kept != &request => return Err(ErrorCode::Refused),
            Some(_) => {}
            None => self.approval.request = Some(request.clone()),
        }
        if let Some(granted) = &self.approval.granted {
            return Ok(granted.clone());
        }
        // 0. The key is registered PENDING at the community: it grants nothing yet.
        if !self.approval.added {
            let welcomed = self.welcomed.as_ref().ok_or(ErrorCode::InvalidRequest)?;
            self.wallet
                .send(
                    &mut self.community,
                    &welcomed.actions,
                    Step::Add,
                    &welcomed.welcome.challenge,
                    signature,
                )
                .await?;
            self.approval.added = true;
        }
        // 1. Keys adds exactly the proven device.
        if self.approval.receipt.is_none() {
            let approved = self.door.pair_approve(&self.origin, &request).await?;
            self.approval.grant = Some(approved.grant);
            self.approval.receipt = Some(approved.receipt);
        }
        let receipt = self.approval.receipt.clone().ok_or(ErrorCode::Reconcile)?;
        // 2. The member's passkey signs the exact receipt (one ceremony).
        if self.approval.evidence.is_none() {
            let mut membership = self.door.live_membership(&self.origin)?;
            let mut policy = self.door.current_policy(&self.origin)?;
            let origin = self.origin.clone();
            let door = &mut *self.door;
            let evidence = prepare_pairing_evidence(
                &mut membership,
                &mut policy,
                async |options| door.passkey_assert(&origin, options).await,
                &receipt,
                &mut custody::SystemClock,
            )
            .await?;
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
        }        // 6. The revision is published: the next challenge is for the activation, fetched only
        // now so it is fresh when the new device signs it.
        let challenge = device_pair::begin(&mut self.community).await?;
        self.activation = Some(challenge.clone());
        let granted = Granted {
            grant: self.approval.grant.clone().ok_or(ErrorCode::Reconcile)?,
            challenge,
        };
        self.approval.granted = Some(granted.clone());
        Ok(granted)
    }

    async fn activate(&mut self, signature: Vec<u8>) -> Result<()> {
        let welcomed = self.welcomed.as_ref().ok_or(ErrorCode::InvalidRequest)?;
        let challenge = self.activation.clone().ok_or(ErrorCode::InvalidRequest)?;
        self.wallet
            .send(
                &mut self.community,
                &welcomed.actions,
                Step::Activate,
                &challenge,
                signature,
            )
            .await
    }
}
