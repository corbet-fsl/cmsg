//! Protected first-payload release; accounting proofs stay on the peer channel.
use super::*;
use crate::{
    ReservationContext, ReservationContexts, ReservationExpectation, ReservationPolicy,
    ReservationVerifier, VerifiedReservation,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    policy: ReservationPolicy,
    contexts: ReservationContexts,
    consented: bool,
    outgoing: Option<VerifiedReservation>,
    incoming: Option<VerifiedReservation>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    gates: BTreeMap<String, Gate>,
}
fn key(peer: &str, nonce: &[u8; 32]) -> String {
    format!("{}:{}", peer, crate::live::id(nonce))
}
fn member_bytes(id: &str) -> Result<[u8; 32], Error> {
    data_encoding::BASE64URL_NOPAD
        .decode(id.as_bytes())
        .map_err(|_| Error::Admission)?
        .try_into()
        .map_err(|_| Error::Admission)
}
impl Journal {
    pub(super) fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, incoming) in &other.gates {
            if let Some(local) = self.gates.get_mut(id) {
                if local.policy != incoming.policy || local.contexts != incoming.contexts {
                    return Err(Error::InvalidStore);
                }
                local.consented |= incoming.consented;
                if local.outgoing.is_none() {
                    local.outgoing = incoming.outgoing.clone();
                }
                if local.incoming.is_none() {
                    local.incoming = incoming.incoming.clone();
                }
            } else {
                self.gates.insert(id.clone(), incoming.clone());
            }
        }
        Ok(())
    }

    pub(super) fn validate(&self, owner: &str, community: &str) -> Result<(), Error> {
        let own = member_bytes(owner)?;
        let scope: [u8; 32] = Sha256::digest(community.as_bytes()).into();
        for (id, gate) in &self.gates {
            let a = &gate.contexts.outgoing.expected;
            let b = &gate.contexts.incoming.expected;
            let peer = if a.owner == own {
                a.peer
            } else if a.peer == own {
                a.owner
            } else {
                return Err(Error::InvalidStore);
            };
            if *id != key(&crate::live::id(&peer), &a.nonce)
                || a.community != scope
                || a.owner == a.peer
                || a.role != 0
                || b.role != 1
                || a.phase != 2
                || b.phase != 2
                || a.owner != b.peer
                || a.peer != b.owner
                || a.nonce != b.nonce
                || a.group != b.group
                || a.contact_policy_digest != b.contact_policy_digest
                || a.history_digest != b.history_digest
                || a.opened_at != gate.policy.opened_at
                || b.opened_at != a.opened_at
                || Some(a.expires_at)
                    != gate.policy.opened_at.checked_add(gate.policy.abandon_after)
                || b.expires_at != a.expires_at
                || a.challenge == [0; 32]
                || b.challenge == [0; 32]
                || gate.policy.abandon_after == 0
                || gate
                    .policy
                    .opened_at
                    .checked_add(gate.policy.abandon_after)
                    .is_none_or(|end| end > 9_007_199_254_740_991)
                || gate.policy.state_policy_digest == [0; 32]
            {
                return Err(Error::InvalidStore);
            }
            for (value, expected) in [(&gate.outgoing, a), (&gate.incoming, b)] {
                if let Some(value) = value {
                    check(value, expected, &gate.policy)?;
                }
            }
        }
        Ok(())
    }
}
fn check(
    value: &VerifiedReservation,
    expected: &ReservationExpectation,
    policy: &ReservationPolicy,
) -> Result<(), Error> {
    if &value.expected != expected
        || value.state_policy_digest != policy.state_policy_digest
        || value.state_version == 0
        || value.state_version > 9_007_199_254_740_991
        || value.state_commitment == [0; 32]
        || value.presentation_binding == [0; 32]
        || value.owner_authority == [0; 32]
        || value.valid_until <= policy.opened_at
        || value.valid_until > expected.expires_at
        || value.valid_until > 9_007_199_254_740_991
    {
        return Err(Error::Admission);
    }
    Ok(())
}
impl Inbox {
    pub fn new_accounted(member: &Member) -> Result<Self, Error> {
        let mut inbox = Self::new_live(member)?;
        inbox.state.reservations = Some(Journal::default());
        Ok(inbox)
    }
    pub fn reservation_delivery_enabled(&self) -> bool {
        self.state.reservations.is_some()
    }
    pub fn require_active_reservations(
        &mut self,
        member: &Member,
        policy: ReservationPolicy,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<ReservationContexts, Error> {
        let peer = self.contact_peer(member)?;
        self.check_exclusions(member)?;
        let contact = self.prepare_accounting_contact(&peer, member)?;
        let now = member.authorization_time()?;
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?;
        let id = key(&peer, &intro.id);
        if let Some(old) = self
            .state
            .reservations
            .as_ref()
            .and_then(|j| j.gates.get(&id))
        {
            if old.policy != policy {
                return Err(Error::Admission);
            }
            return self.reservation_contexts(member);
        }
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        if intro.decision.is_some()
            || strict.sent
            || strict.received
            || policy.opened_at > now
            || policy.abandon_after == 0
            || policy
                .opened_at
                .checked_add(policy.abandon_after)
                .is_none_or(|end| end <= now || end > 9_007_199_254_740_991)
            || policy.state_policy_digest == [0; 32]
        {
            return Err(Error::Admission);
        }
        let participants = member.participants()?;
        if participants.len() != 2 {
            return Err(Error::Admission);
        }
        let initiator_device = participants
            .iter()
            .find(|p| p.member_id == contact.contact.initiator_id)
            .ok_or(Error::Admission)?
            .chat_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        let recipient_device = participants
            .iter()
            .find(|p| p.member_id == contact.responder_id)
            .ok_or(Error::Admission)?
            .chat_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        let outgoing = ReservationExpectation {
            community: Sha256::digest(self.state.community_id.as_bytes()).into(),
            owner: member_bytes(&contact.contact.initiator_id)?,
            peer: member_bytes(&contact.responder_id)?,
            role: 0,
            nonce: intro.id,
            group: contact.contact.group_binding()?,
            contact_policy_digest: contact.contact.policy_digest()?,
            history_digest: contact.contact.history_digest(),
            phase: 2,
            opened_at: policy.opened_at,
            expires_at: policy
                .opened_at
                .checked_add(policy.abandon_after)
                .ok_or(Error::Admission)?,
            challenge: crate::live::random()?,
        };
        let mut incoming = outgoing.clone();
        incoming.owner = outgoing.peer;
        incoming.peer = outgoing.owner;
        incoming.role = 1;
        incoming.challenge = crate::live::random()?;
        let contexts = ReservationContexts {
            outgoing: ReservationContext {
                now,
                device_public_key: initiator_device,
                expected: outgoing.clone(),
            },
            incoming: ReservationContext {
                now,
                device_public_key: recipient_device,
                expected: incoming,
            },
        };
        let mut changed = self.duplicate();
        changed
            .state
            .reservations
            .get_or_insert_with(Default::default)
            .gates
            .insert(
                id,
                Gate {
                    policy,
                    contexts: contexts.clone(),
                    consented: false,
                    outgoing: None,
                    incoming: None,
                },
            );
        changed.validate_state(member)?;
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(contexts)
    }
    /// Adopt the counterpart's fresh challenge for our own presentation. The
    /// embedding obtains it through the authenticated peer channel. Our challenge
    /// for the counterpart remains locally generated and cannot be overwritten.
    pub fn set_own_reservation_challenge(
        &mut self,
        member: &Member,
        challenge: &[u8; 32],
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if *challenge == [0; 32] {
            return Err(Error::Admission);
        }
        let peer = self.contact_peer(member)?;
        let contexts = self.reservation_contexts(member)?;
        let id = key(&peer, &contexts.outgoing.expected.nonce);
        let mut changed = self.duplicate();
        let gate = changed
            .state
            .reservations
            .as_mut()
            .unwrap()
            .gates
            .get_mut(&id)
            .unwrap();
        if gate.consented || gate.outgoing.is_some() || gate.incoming.is_some() {
            return Err(Error::Admission);
        }
        if gate.contexts.outgoing.expected.owner == member_bytes(&self.state.recipient_id)? {
            gate.contexts.outgoing.expected.challenge = *challenge;
        } else {
            gate.contexts.incoming.expected.challenge = *challenge;
        }
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn reservation_contexts(&self, member: &Member) -> Result<ReservationContexts, Error> {
        let peer = self.contact_peer(member)?;
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?;
        let gate = self
            .state
            .reservations
            .as_ref()
            .and_then(|j| j.gates.get(&key(&peer, &intro.id)))
            .ok_or(Error::Admission)?;
        self.check_reservation_context(member, &peer, gate)?;
        let mut contexts = gate.contexts.clone();
        contexts.outgoing.now = member.authorization_time()?;
        contexts.incoming.now = contexts.outgoing.now;
        Ok(contexts)
    }
    fn check_reservation_context(
        &self,
        member: &Member,
        peer: &str,
        gate: &Gate,
    ) -> Result<(), Error> {
        self.check_exclusions(member)?;
        let now = member.authorization_time()?;
        let own = member_bytes(&self.state.recipient_id)?;
        let designated = if gate.contexts.outgoing.expected.owner == own {
            &gate.contexts.outgoing
        } else {
            &gate.contexts.incoming
        };
        if designated.device_public_key.as_slice() != member.chat_public_key() {
            return Err(Error::Admission);
        }
        let c = self.prepare_accounting_contact(peer, member)?;
        let e = &gate.contexts.outgoing.expected;
        if c.introduction_id != e.nonce
            || c.contact.group_binding()? != e.group
            || c.contact.policy_digest()? != e.contact_policy_digest
            || c.contact.history_digest() != e.history_digest
            || now < gate.policy.opened_at
            || now >= e.expires_at
        {
            return Err(Error::Admission);
        }
        Ok(())
    }
    /// Explicit recipient consent, only after the sender's Active proof verifies.
    /// This records permission for incoming reservation; it does not debit a ledger.
    pub fn authorize_incoming_reservation(
        &mut self,
        member: &Member,
        outgoing: &[u8],
        verifier: &mut impl ReservationVerifier,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let peer = self.contact_peer(member)?;
        let contexts = self.reservation_contexts(member)?;
        if contexts.incoming.expected.owner != member_bytes(&self.state.recipient_id)?
            || outgoing.len() > MAX_WIRE_BYTES
        {
            return Err(Error::Admission);
        }
        let id = key(&peer, &contexts.outgoing.expected.nonce);
        let gate = self
            .state
            .reservations
            .as_ref()
            .unwrap()
            .gates
            .get(&id)
            .unwrap();
        let verified = verifier.verify_remote(outgoing, &contexts.outgoing)?;
        check(&verified, &contexts.outgoing.expected, &gate.policy)?;
        let refreshed = self.reservation_contexts(member)?;
        if refreshed.outgoing.expected != contexts.outgoing.expected
            || refreshed.outgoing.device_public_key != contexts.outgoing.device_public_key
            || refreshed.outgoing.now >= verified.valid_until
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        let gate = changed
            .state
            .reservations
            .as_mut()
            .unwrap()
            .gates
            .get_mut(&id)
            .unwrap();
        gate.consented = true;
        gate.outgoing = Some(verified);
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn bind_active_reservations(
        &mut self,
        member: &Member,
        outgoing: &[u8],
        incoming: &[u8],
        verifier: &mut impl ReservationVerifier,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if outgoing.len() > MAX_WIRE_BYTES || incoming.len() > MAX_WIRE_BYTES {
            return Err(Error::Admission);
        }
        let peer = self.contact_peer(member)?;
        let contexts = self.reservation_contexts(member)?;
        let id = key(&peer, &contexts.outgoing.expected.nonce);
        let gate = self
            .state
            .reservations
            .as_ref()
            .unwrap()
            .gates
            .get(&id)
            .unwrap();
        let own = member_bytes(&self.state.recipient_id)?;
        if own == contexts.incoming.expected.owner && !gate.consented {
            return Err(Error::Admission);
        }
        let local_outgoing = own == contexts.outgoing.expected.owner;
        let remote = if local_outgoing {
            verifier.verify_remote(incoming, &contexts.incoming)?
        } else {
            verifier.verify_remote(outgoing, &contexts.outgoing)?
        };
        let refreshed = self.reservation_contexts(member)?;
        let local = if local_outgoing {
            verifier.verify_current_local(outgoing, &refreshed.outgoing)?
        } else {
            verifier.verify_current_local(incoming, &refreshed.incoming)?
        };
        let (a, b) = if local_outgoing {
            (local, remote)
        } else {
            (remote, local)
        };
        let final_context = self.reservation_contexts(member)?;
        if final_context.outgoing.expected != contexts.outgoing.expected
            || final_context.incoming.expected != contexts.incoming.expected
            || final_context.outgoing.device_public_key != contexts.outgoing.device_public_key
            || final_context.incoming.device_public_key != contexts.incoming.device_public_key
            || final_context.outgoing.now >= a.valid_until
            || final_context.incoming.now >= b.valid_until
        {
            return Err(Error::Admission);
        }
        check(&a, &contexts.outgoing.expected, &gate.policy)?;
        check(&b, &contexts.incoming.expected, &gate.policy)?;
        let mut changed = self.duplicate();
        let gate = changed
            .state
            .reservations
            .as_mut()
            .unwrap()
            .gates
            .get_mut(&id)
            .unwrap();
        gate.outgoing = Some(a);
        gate.incoming = Some(b);
        changed.runtime.reservations.insert(id);
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }
    /// Call before publishing an accepted own accounting state that removes or
    /// changes the obligation. Rebinding requires trusted current-own verification.
    pub fn invalidate_reservation(
        &mut self,
        member: &Member,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut changed = self.duplicate();
        changed.runtime.reservations.clear();
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }
    pub(super) fn check_reservation_roster(&self, member: &Member) -> Result<(), Error> {
        let Some(journal) = &self.state.reservations else {
            return Ok(());
        };
        for (peer, intro) in &self.state.introductions {
            if intro.decision.is_some() {
                continue;
            }
            if let Some(gate) = journal.gates.get(&key(peer, &intro.id)) {
                let expected = [
                    gate.contexts.outgoing.device_public_key.to_vec(),
                    gate.contexts.incoming.device_public_key.to_vec(),
                ];
                let participants = member.participants()?;
                if participants.len() != 2
                    || participants
                        .iter()
                        .any(|p| !expected.contains(&p.chat_public_key))
                {
                    return Err(Error::Admission);
                }
            }
        }
        Ok(())
    }
    pub(super) fn check_reservation_release(&self, member: &Member) -> Result<(), Error> {
        let Some(journal) = &self.state.reservations else {
            return Ok(());
        };
        let peer = self.contact_peer(member)?;
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::Admission)?;
        // Established traffic needs the contact/session gate, not another debit.
        if intro.decision == Some(ContactResolutionKind::Answered) {
            return Ok(());
        }
        let now = member.authorization_time()?;
        if intro
            .strict
            .as_ref()
            .is_none_or(|s| now >= s.policy.response_deadline)
        {
            return Err(Error::Admission);
        }
        let id = key(&peer, &intro.id);
        let gate = journal.gates.get(&id).ok_or(Error::Admission)?;
        self.check_reservation_context(member, &peer, gate)?;
        self.check_reservation_roster(member)?;
        if !self.runtime.reservations.contains(&id)
            || gate.outgoing.as_ref().is_none_or(|v| now >= v.valid_until)
            || gate.incoming.as_ref().is_none_or(|v| now >= v.valid_until)
        {
            return Err(Error::Admission);
        }
        Ok(())
    }
}
