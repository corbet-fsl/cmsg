//! The existing device's concrete steps of a pairing ([`HostSteps`]) over the Door: the
//! member's step-up ceremonies on the bound authenticator, the passkey registration at the
//! community server, Keys (`Pair`), the lineage revision (certified evidence, record value,
//! publication through cvlt's narrow capability) and the server's `device_approve`.
//!
//! Every step that took the person's time (each passkey ceremony) or that must not run
//! twice (the Keys approval, the signed record value) keeps its outcome in this value, so a
//! failed round that the new device repeats resumes after the last completed step. The
//! order of the third round is the safety order: Keys approval, evidence over the receipt,
//! durable retention, record value, publication and forced read, Keys acknowledgment, and
//! only then the server's approval of the pending key. A host that restarts loses the
//! offer; the person starts a new link, nothing half-applied is trusted.
use super::pairing_publish::prepare_pairing_evidence;
use super::pairing_roles::{HostSteps, Registered, Registration};
use super::*;
use cfyr::membership::{MembershipLease, StepUpAction, StepUpProof};
use foyer::Transport;

fn secs() -> u64 {
    ckmg::Clock::now(&mut custody::SystemClock).unwrap_or(u64::MAX)
}

/// The progress of the third round that must survive a retried round.
#[derive(Default)]
struct Approval {
    request: Option<ckmg::PairingRequest>,
    grant: Option<ckmg::PairingGrant>,
    receipt: Option<ckmg::Receipt>,
    evidence: Option<cvlt::PreparedLineageEvidence>,
    retained: bool,
    value: Option<cdht::SignedValue>,
    published: bool,
    acknowledged: bool,
}

/// [`HostSteps`] over one Door and one network for the record publication.
pub struct DoorHost<'a, N: cdht::Network + Clone> {
    door: &'a mut Door,
    origin: String,
    network: N,
    lease: Option<MembershipLease<Transport>>,
    registration: Option<Registration>,
    anchor: Option<ckmg::Lineage>,
    approval: Approval,
}

impl<'a, N: cdht::Network + Clone> DoorHost<'a, N> {
    /// Steps for the member portal `origin` of `door`; `network` is the record network
    /// the lineage revision is published to.
    pub fn new(door: &'a mut Door, origin: &str, network: N) -> Self {
        Self {
            door,
            origin: origin.to_owned(),
            network,
            lease: None,
            registration: None,
            anchor: None,
            approval: Approval::default(),
        }
    }

    async fn lease(&mut self) -> Result<&mut MembershipLease<Transport>> {
        if self.lease.is_none() {
            let mut membership = self.door.live_membership(&self.origin)?;
            self.lease = Some(
                membership
                    .observe_lease(secs)
                    .await
                    .map_err(|_| ErrorCode::Unavailable)?,
            );
        }
        self.lease.as_mut().ok_or(ErrorCode::Unavailable)
    }

    /// One user-verifying ceremony for exactly one account action.
    async fn step_up(&mut self, action: StepUpAction<'_>) -> Result<StepUpProof> {
        let begin = self
            .lease()
            .await?
            .step_up_begin(action, secs)
            .await
            .map_err(foyer::map_error)?;
        let ceremony = begin
            .get("ceremony")
            .and_then(Value::as_str)
            .ok_or(ErrorCode::Reconcile)?
            .to_owned();
        let options = begin.get("options").cloned().ok_or(ErrorCode::Reconcile)?;
        let credential = self.door.passkey_assert(&self.origin, options).await?;
        StepUpProof::new(ceremony, credential).map_err(foyer::map_error)
    }
}

impl<N: cdht::Network + Clone> HostSteps for DoorHost<'_, N> {
    async fn registration_options(&mut self) -> Result<Registration> {
        if let Some(kept) = &self.registration {
            return Ok(kept.clone());
        }
        let proof = self.step_up(StepUpAction::PasskeyAdd).await?;
        let answer = self
            .lease()
            .await?
            .passkey_add_begin(proof, secs)
            .await
            .map_err(foyer::map_error)?;
        let registration = Registration {
            ceremony: answer
                .get("ceremony")
                .and_then(Value::as_str)
                .ok_or(ErrorCode::Reconcile)?
                .to_owned(),
            options: answer.get("options").cloned().ok_or(ErrorCode::Reconcile)?,
        };
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    async fn register_credential(&mut self, registered: Registered) -> Result<ckmg::Lineage> {
        if let Some(anchor) = &self.anchor {
            return Ok(anchor.clone());
        }
        let expected = self
            .registration
            .as_ref()
            .ok_or(ErrorCode::InvalidRequest)?;
        if expected.ceremony != registered.ceremony {
            return Err(ErrorCode::InvalidRequest);
        }
        self.lease()
            .await?
            .passkey_add_finish(&registered.ceremony, registered.credential, secs)
            .await
            .map_err(foyer::map_error)?;
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

    async fn approve(&mut self, request: ckmg::PairingRequest) -> Result<ckmg::PairingGrant> {
        let anchor = self.anchor.clone().ok_or(ErrorCode::InvalidRequest)?;
        match &self.approval.request {
            Some(kept) if kept != &request => return Err(ErrorCode::Refused),
            Some(_) => {}
            None => self.approval.request = Some(request.clone()),
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
        }
        // 6. The server learns the revision exists: approve the pending key.
        let key = *request.device.value();
        let proof = self.step_up(StepUpAction::DeviceApprove { key }).await?;
        self.lease()
            .await?
            .device_approve(key, proof, secs)
            .await
            .map_err(foyer::map_error)?;
        self.approval.grant.clone().ok_or(ErrorCode::Reconcile)
    }
}
