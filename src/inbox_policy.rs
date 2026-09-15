//! Owner-controlled contact history. These private chains never reach cfrm.
use super::*;
use crate::{ContactDirective, ContactDirectiveKind as DirectiveKind};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DirectionalContact {
    local: Vec<ContactDirective>,
    peer: Vec<ContactDirective>,
    conflict: bool,
    peer_legacy_block: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    chain: Vec<ContactDirective>,
    receipt: Option<ContactResolution>,
}

fn tip(chain: &[ContactDirective]) -> Result<[u8; 32], Error> {
    chain.last().map(ContactDirective::digest).transpose().map(|v| v.unwrap_or([0; 32]))
}

fn expired_for(block: &ContactDirective, initiative: Option<&ContactDirective>) -> bool {
    initiative.is_some_and(|new| new.kind == DirectiveKind::FreshInitiative
        && new.peer_digest == block.digest().unwrap_or([0; 32])
        && block.until.is_some_and(|until| new.issued_at >= until))
}

impl DirectionalContact {
    pub(super) fn blocked(&self) -> bool {
        self.conflict || self.peer_legacy_block
            || self.local.last().is_some_and(|d| d.kind == DirectiveKind::Block && !expired_for(d, self.peer.last()))
            || self.peer.last().is_some_and(|d| d.kind == DirectiveKind::Block && !expired_for(d, self.local.last()))
    }

    fn selected(&self) -> Result<Option<&ContactDirective>, Error> {
        let local = self.local.last().filter(|d| d.kind == DirectiveKind::FreshInitiative);
        let peer = self.peer.last().filter(|d| d.kind == DirectiveKind::FreshInitiative);
        match (local, peer) {
            (Some(a), Some(b)) if a.introduction_id == b.introduction_id
                && a.policy == b.policy && a.group_id == b.group_id && a.initiator_id == b.initiator_id => Ok(Some(a)),
            (Some(a), Some(b)) if a.peer_digest == b.digest()? => Ok(Some(a)),
            (Some(a), Some(b)) if b.peer_digest == a.digest()? => Ok(Some(b)),
            (Some(_), Some(_)) => Err(Error::InvalidState),
            (Some(a), None) => Ok(Some(a)),
            (None, Some(b)) => Ok(Some(b)),
            (None, None) => Ok(None),
        }
    }

    pub(super) fn selected_nonce(&self) -> Result<Option<[u8; 32]>, Error> {
        self.selected().map(|d| d.map(|d| d.introduction_id))
    }

    fn validate_chain(chain: &[ContactDirective], owner: &str, peer: &str, member: &Member) -> Result<(), Error> {
        let mut previous = [0; 32];
        let mut issued = 0;
        for (index, directive) in chain.iter().enumerate() {
            if directive.owner_id != owner || directive.peer_id != peer
                || directive.revision != index as u64 + 1 || directive.previous_digest != previous
                || directive.issued_at < issued || directive.issued_at > member.authorization_time()? {
                return Err(Error::InvalidStore);
            }
            directive.verify_device_signature(member, directive.issued_at)?;
            previous = directive.digest()?;
            issued = directive.issued_at;
        }
        Ok(())
    }

    pub(super) fn validate(&self, owner: &str, peer: &str, member: &Member) -> Result<(), Error> {
        Self::validate_chain(&self.local, owner, peer, member)?;
        Self::validate_chain(&self.peer, peer, owner, member)?;
        if !self.conflict { self.selected()?; }
        Ok(())
    }

    fn merge_chain(local: &mut Vec<ContactDirective>, remote: &[ContactDirective]) -> Result<bool, Error> {
        for (a, b) in local.iter().zip(remote) {
            if a.digest()? != b.digest()? { return Ok(false); }
        }
        if remote.len() > local.len() { *local = remote.to_vec(); }
        Ok(true)
    }

    pub(super) fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.conflict |= other.conflict;
        self.conflict |= !Self::merge_chain(&mut self.local, &other.local)?;
        self.conflict |= !Self::merge_chain(&mut self.peer, &other.peer)?;
        self.peer_legacy_block |= other.peer_legacy_block;
        if self.peer.last().is_some_and(|d| d.kind == DirectiveKind::FreshInitiative) {
            self.peer_legacy_block = false;
        }
        self.conflict |= self.selected().is_err();
        Ok(())
    }
}

impl Inbox {
    pub(super) fn mark_contact_conflict(&mut self, peer: &str) {
        self.state.directional.entry(peer.to_owned()).or_default().conflict = true;
    }
    /// Block this peer until this member initiates again, or optionally until a
    /// configured deadline permits a fresh authenticated introduction. Expiry
    /// never releases queued old data. This saves local state without sending.
    pub fn block_member_until(
        &mut self, peer: &str, until: Option<u64>, member: &Member,
        key: &[u8; 32], context: &[u8], mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(member)?;
        member.member_id()?;
        let mut changed = self.duplicate();
        changed.append_local_block(peer, until, member)?;
        if changed.state.pending.as_ref().is_some_and(|p| p.inviter == peer) { changed.state.pending = None; }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    pub(super) fn append_local_block(&mut self, peer: &str, until: Option<u64>, member: &Member) -> Result<(), Error> {
        if !crate::admission::valid_member_id(peer) || peer == self.state.recipient_id { return Err(Error::Admission); }
        let intro = self.state.introductions.get(peer).map(|i| i.id).unwrap_or([0; 32]);
        let history = self.state.directional.entry(peer.to_owned()).or_default();
        if history.conflict { return Err(Error::InvalidState); }
        let directive = member.sign_contact_directive(peer, history.local.len() as u64 + 1,
            &tip(&history.local)?, &tip(&history.peer)?, DirectiveKind::Block, &intro, "",
            &member.policy_group_id().unwrap_or_default(), None, until)?;
        history.local.push(directive);
        self.state.closed.remove(peer);
        Ok(())
    }

    pub(super) fn record_local_close(&mut self, peer: &str, member: &Member) -> Result<(), Error> {
        if self.state.root_authorized && member.member_id().is_ok() {
            self.append_local_block(peer, None, member)
        } else {
            self.state.closed.insert(peer.to_owned());
            Ok(())
        }
    }

    pub(super) fn record_peer_close(&mut self, peer: &str) {
        self.state.directional.entry(peer.to_owned()).or_default().peer_legacy_block = true;
    }

    fn archive_current(&mut self, peer: &str) -> Result<(), Error> {
        if let Some(old) = self.state.introductions.remove(peer) {
            let archive = self.state.archived.entry(peer.to_owned()).or_default();
            if archive.iter().any(|i| i.id == old.id) { return Err(Error::InvalidState); }
            archive.push(old);
        }
        Ok(())
    }

    fn install_fresh(&mut self, peer: &str, directive: &ContactDirective, member: &Member) -> Result<(), Error> {
        if self.state.introductions.get(peer).is_some_and(|i| i.id == directive.introduction_id) {
            return Ok(());
        }
        if self.state.archived.get(peer).is_some_and(|items| items.iter().any(|i| i.id == directive.introduction_id)) {
            return Err(Error::Admission);
        }
        self.archive_current(peer)?;
        let role = if directive.initiator_id == self.state.recipient_id { FirstContactRole::Initiator } else { FirstContactRole::Recipient };
        self.state.introductions.insert(peer.to_owned(), Introduction {
            id: directive.introduction_id, decision: None, outbound_receipt: None, inbound_receipt: None,
            strict: Some(StrictIntroduction {
                role, policy: directive.policy.ok_or(Error::Admission)?,
                initial_writer_key: if role == FirstContactRole::Initiator { directive.device_public_key.clone() } else { member.chat_public_key() },
                sent: false, received: false, close_sent: false,
            }),
        });
        Ok(())
    }

    /// Only the blocker can initiate while its restriction remains active. A
    /// recipient may initiate after an explicitly configured peer-block expiry.
    /// This emits a signed fresh gate; send_contact then sends the one actual
    /// introduction. No data from the previous nonce becomes admissible.
    pub fn initiate_contact(
        &mut self, member: &mut Member, nonce: &[u8; 32], policy: FirstContactPolicy,
        key: &[u8; 32], context: &[u8], persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.fresh_control(member, Some((*nonce, policy)), key, context, persist)
    }

    /// Consent to the peer's currently selected fresh initiative when this
    /// member also owns a block. It clears only this member's restriction.
    pub fn consent_contact(
        &mut self, member: &mut Member, key: &[u8; 32], context: &[u8],
        persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.fresh_control(member, None, key, context, persist)
    }

    fn fresh_control(
        &mut self, member: &mut Member, fresh: Option<([u8; 32], FirstContactPolicy)>,
        key: &[u8; 32], context: &[u8], mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let peer = self.contact_peer(member)?;
        let now = member.authorization_time()?;
        let mut changed = self.duplicate();
        if changed.state.closed.contains(&peer) { changed.append_local_block(&peer, None, member)?; }
        let history = changed.state.directional.get(&peer).ok_or(Error::InvalidState)?;
        if history.conflict { return Err(Error::InvalidState); }
        let local_block = history.local.last().is_some_and(|d| d.kind == DirectiveKind::Block);
        let peer_expired = history.peer.last().is_some_and(|d| d.kind == DirectiveKind::Block && d.until.is_some_and(|until| until <= now));
        if !local_block && !(fresh.is_some() && peer_expired) { return Err(Error::Admission); }
        let (nonce, policy, initiator) = if let Some((nonce, policy)) = fresh {
            if changed.state.introductions.get(&peer).is_some_and(|i| i.id == nonce)
                || changed.state.archived.get(&peer).is_some_and(|items| items.iter().any(|i| i.id == nonce)) {
                return Err(Error::Admission);
            }
            (nonce, policy, changed.state.recipient_id.clone())
        } else {
            let selected = history.peer.last().filter(|d| d.kind == DirectiveKind::FreshInitiative
                && d.initiator_id == peer && d.peer_digest == tip(&history.local).unwrap_or([0; 32]))
                .ok_or(Error::Admission)?;
            (selected.introduction_id, selected.policy.ok_or(Error::Admission)?, peer.clone())
        };
        let directive = member.sign_contact_directive(&peer, history.local.len() as u64 + 1,
            &tip(&history.local)?, &tip(&history.peer)?, DirectiveKind::FreshInitiative,
            &nonce, &initiator, &member.policy_group_id()?, Some(policy), None)?;
        changed.state.directional.get_mut(&peer).ok_or(Error::InvalidState)?.local.push(directive.clone());
        changed.install_fresh(&peer, &directive, member)?;
        changed.state.closed.remove(&peer);
        let payload = changed.control_payload(&peer, None)?;
        let mut candidate = member.staged_copy(key, context)?;
        let wire = candidate.send_policy_record(&payload)?;
        changed.validate_state(&candidate)?;
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *self = changed;
        *member = candidate;
        Ok(wire)
    }

    fn control_payload(&self, peer: &str, receipt: Option<ContactResolution>) -> Result<Zeroizing<Vec<u8>>, Error> {
        let chain = self.state.directional.get(peer).ok_or(Error::InvalidState)?.local.clone();
        let mut payload = Zeroizing::new(CONTACT_DIRECTIVE_PREFIX.to_vec());
        payload.extend_from_slice(&serde_json::to_vec(&Control { chain, receipt }).map_err(|_| Error::InvalidMessage)?);
        Ok(payload)
    }

    /// Commit this member's directional block and transmit its authenticated
    /// control. None means until this member explicitly initiates again.
    pub fn close_contact_until(
        &mut self, member: &mut Member, until: Option<u64>, key: &[u8; 32], context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let peer = self.contact_peer(member)?;
        let intro = self.state.introductions.get(&peer).ok_or(Error::InvalidState)?;
        if intro.strict.as_ref().ok_or(Error::InvalidState)?.close_sent { return Err(Error::Admission); }
        let mut candidate = member.staged_copy(key, context)?;
        let receipt = match intro.outbound_receipt.as_ref().and_then(|b| serde_json::from_slice::<ContactResolution>(b).ok()) {
            Some(receipt) if receipt.kind == ContactResolutionKind::ClosedForever => {
                receipt.verify_device_signature(&candidate, candidate.authorization_time()?)?;
                receipt
            }
            _ => candidate.sign_contact_resolution(&peer, &intro.id, ContactResolutionKind::ClosedForever)?,
        };
        let encoded = serde_json::to_vec(&receipt).map_err(|_| Error::InvalidMessage)?;
        let mut changed = self.duplicate();
        changed.append_local_block(&peer, until, &candidate)?;
        let payload = changed.control_payload(&peer, Some(receipt))?;
        let wire = candidate.send_policy_record(&payload)?;
        let entry = changed.state.introductions.get_mut(&peer).ok_or(Error::InvalidState)?;
        let strict = entry.strict.as_mut().ok_or(Error::InvalidState)?;
        strict.close_sent = true;
        if strict.role == FirstContactRole::Recipient { entry.decision = Some(ContactResolutionKind::ClosedForever); }
        entry.outbound_receipt = Some(encoded);
        if changed.state.pending.as_ref().is_some_and(|p| p.inviter == peer) { changed.state.pending = None; }
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *self = changed;
        *member = candidate;
        Ok(wire)
    }

    pub(super) fn apply_control_record(&mut self, peer: &str, bytes: &[u8], member: &Member) -> Result<Received, Error> {
        let control: Control = serde_json::from_slice(bytes).map_err(|_| Error::InvalidMessage)?;
        let newest = control.chain.last().ok_or(Error::Admission)?;
        member.verify_contact_directive(newest, peer)?;
        DirectionalContact::validate_chain(&control.chain, peer, &self.state.recipient_id, member)?;
        if newest.kind == DirectiveKind::FreshInitiative && newest.group_id != member.policy_group_id()? { return Err(Error::Admission); }
        let history = self.state.directional.entry(peer.to_owned()).or_default();
        let was_len = history.peer.len();
        if !DirectionalContact::merge_chain(&mut history.peer, &control.chain)? {
            history.conflict = true;
            return Ok(Received::ContactPolicyChanged);
        }
        if control.chain.len() < was_len { return Err(Error::Admission); }
        if newest.kind == DirectiveKind::FreshInitiative {
            // Consent references the owner's exact current tip. This also stops
            // concurrent, independently chosen nonces from silently winning.
            if newest.peer_digest != tip(&history.local)? {
                if history.local.last().is_some_and(|d| d.kind == DirectiveKind::FreshInitiative) {
                    history.conflict = true;
                    return Ok(Received::ContactPolicyChanged);
                }
                return Err(Error::Admission);
            }
            if self.state.closed.contains(peer) { return Err(Error::Admission); }
            if let Some(block) = history.local.last().filter(|d| d.kind == DirectiveKind::Block) {
                let owner_initiates = newest.initiator_id == peer;
                let expired = block.until.is_some_and(|until| until <= member.authorization_time().unwrap_or(0));
                // An owner's initiative is retained while our separate block
                // still requires explicit consent; data remains inaccessible.
                if !owner_initiates && !expired { return Err(Error::Admission); }
            }
            history.peer_legacy_block = false;
            history.conflict |= history.selected().is_err();
            if !history.conflict { self.install_fresh(peer, newest, member)?; }
            return Ok(Received::ContactPolicyChanged);
        }
        if let Some(receipt) = &control.receipt {
            let entry = self.state.introductions.get_mut(peer).ok_or(Error::InvalidState)?;
            member.verify_contact_resolution(receipt, peer, &entry.id)?;
            if receipt.kind != ContactResolutionKind::ClosedForever { return Err(Error::Admission); }
            entry.decision = Some(ContactResolutionKind::ClosedForever);
            entry.inbound_receipt = Some(serde_json::to_vec(receipt).map_err(|_| Error::InvalidMessage)?);
            entry.outbound_receipt = None;
            return Ok(Received::ContactClosed);
        }
        Ok(Received::ContactPolicyChanged)
    }
}
