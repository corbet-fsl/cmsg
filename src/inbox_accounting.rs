//! Derive accounting evidence from existing persisted cmsg decisions.
use super::*;
use crate::{
    AccountingAcknowledgment, AccountingContactContext, AccountingDelegation, AccountingKey,
    AccountingReceipt,
};

impl Inbox {
    pub fn prepare_accounting_contact(
        &self,
        peer: &str,
        member: &Member,
    ) -> Result<crate::AccountingIntroduction, Error> {
        let role = self
            .state
            .introductions
            .get(peer)
            .and_then(|i| i.strict.as_ref())
            .ok_or(Error::InvalidState)?
            .role;
        let (intro, contact) = self.accounting_context(member, peer, role)?;
        Ok(crate::AccountingIntroduction {
            community_id: self.state.community_id.clone(),
            responder_id: if role == FirstContactRole::Recipient {
                self.state.recipient_id.clone()
            } else {
                peer.to_owned()
            },
            introduction_id: intro.id,
            contact,
        })
    }

    fn accounting_context(
        &self,
        member: &Member,
        peer: &str,
        role: FirstContactRole,
    ) -> Result<(&Introduction, AccountingContactContext), Error> {
        self.validate_state(member)?;
        let intro = self
            .state
            .introductions
            .get(peer)
            .ok_or(Error::InvalidState)?;
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        if strict.role != role {
            return Err(Error::Admission);
        }
        let group = strict
            .accounting_group_id
            .clone()
            .ok_or(Error::InvalidState)?;
        if group != member.policy_group_id()? {
            return Err(Error::Admission);
        }
        self.check_selected_group(peer, member)?;
        let (local, remote) = self
            .state
            .directional
            .get(peer)
            .map(DirectionalContact::accounting_tips)
            .transpose()?
            .unwrap_or(([0; 32], [0; 32]));
        Ok((
            intro,
            AccountingContactContext {
                initiator_id: if role == FirstContactRole::Initiator {
                    self.state.recipient_id.clone()
                } else {
                    peer.to_owned()
                },
                group_id: group,
                policy: strict.policy,
                responder_history_tip: if role == FirstContactRole::Recipient {
                    local
                } else {
                    remote
                },
                peer_history_tip: if role == FirstContactRole::Recipient {
                    remote
                } else {
                    local
                },
            },
        ))
    }

    /// Issue a separate P-256 witness only for a durably recorded recipient
    /// answer/close. No new decision, transmission or accounting credit occurs.
    pub fn accounting_receipt(
        &self,
        peer: &str,
        member: &Member,
        key: &AccountingKey,
        delegation: &AccountingDelegation,
    ) -> Result<AccountingReceipt, Error> {
        let prepared = self.prepare_accounting_receipt(peer, member, delegation)?;
        key.issue(member, delegation, prepared.resolution, prepared.contact)
    }

    /// Derive the exact unsigned P-256 witness for an external delegated signer.
    /// Verification rejects its empty signature until that signer completes it.
    pub fn prepare_accounting_receipt(
        &self,
        peer: &str,
        member: &Member,
        delegation: &AccountingDelegation,
    ) -> Result<AccountingReceipt, Error> {
        let (intro, context) =
            self.accounting_context(member, peer, FirstContactRole::Recipient)?;
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        let resolution: ContactResolution =
            serde_json::from_slice(intro.outbound_receipt.as_ref().ok_or(Error::InvalidState)?)
                .map_err(|_| Error::InvalidStore)?;
        if resolution.introduction_id != intro.id
            || Some(resolution.kind) != intro.decision
            || resolution.responder_id != self.state.recipient_id
            || resolution.peer_id != peer
            || (resolution.kind == ContactResolutionKind::Answered
                && (!strict.sent || !strict.received))
        {
            return Err(Error::Admission);
        }
        AccountingReceipt::prepare(member, delegation, resolution, context)
    }

    /// The original sender acknowledges an authenticated answer it actually
    /// received. This is additional signed evidence, never a balance update.
    pub fn accounting_acknowledgment(
        &self,
        peer: &str,
        member: &Member,
        key: &AccountingKey,
        delegation: &AccountingDelegation,
        answer: &AccountingReceipt,
    ) -> Result<AccountingAcknowledgment, Error> {
        self.prepare_accounting_acknowledgment(peer, member, delegation, answer)?;
        key.acknowledge(member, delegation, answer)
    }

    pub fn prepare_accounting_acknowledgment(
        &self,
        peer: &str,
        member: &Member,
        delegation: &AccountingDelegation,
        answer: &AccountingReceipt,
    ) -> Result<AccountingAcknowledgment, Error> {
        let (intro, context) =
            self.accounting_context(member, peer, FirstContactRole::Initiator)?;
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        crate::verify_accounting_receipt(
            answer,
            member.trust.as_ref().ok_or(Error::Admission)?,
            member.authorization_time()?,
        )?;
        if intro.decision != Some(ContactResolutionKind::Answered)
            || !strict.sent
            || !strict.received
            || answer.resolution.kind != ContactResolutionKind::Answered
            || answer.resolution.introduction_id != intro.id
            || answer.resolution.responder_id != peer
            || answer.resolution.peer_id != self.state.recipient_id
            || answer.contact.group_binding()? != context.group_binding()?
            || answer.contact.policy_digest()? != context.policy_digest()?
            || answer.contact.initiator_id != self.state.recipient_id
        {
            return Err(Error::Admission);
        }
        AccountingAcknowledgment::prepare(member, delegation, answer)
    }
}
