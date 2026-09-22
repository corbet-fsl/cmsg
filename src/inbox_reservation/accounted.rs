//! Accounted-only staged admission using the existing real reservation gates.
use super::*;

impl Inbox {
    /// Authenticate and durably stage an unknown two-member MLS invitation.
    /// This creates no account debit, known-contact mark or application release.
    /// The existing account proof gates must be completed separately.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_accounted_invitation(
        &mut self,
        member: &mut Member,
        welcome: &[u8],
        introduction_id: &[u8; 32],
        contact_policy: FirstContactPolicy,
        reservation_policy: ReservationPolicy,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<ReservationContexts, Error> {
        self.check_binding(member)?;
        if self.state.reservations.is_none()
            || self.state.pending.is_some()
            || *introduction_id == [0; 32]
            || welcome.is_empty()
            || welcome.len() > MAX_WIRE_BYTES
        {
            return Err(Error::Admission);
        }
        let welcome_hash: [u8; 32] = Sha256::digest(welcome).into();
        if member.policy_group_id().is_ok() {
            let peer = self.contact_peer(member)?;
            let id = key(&peer, introduction_id);
            let journal = self.state.reservations.as_ref().ok_or(Error::Admission)?;
            let admission = journal.admissions.get(&id).ok_or(Error::Admission)?;
            let gate = journal.gates.get(&id).ok_or(Error::Admission)?;
            let strict = self
                .state
                .introductions
                .get(&peer)
                .and_then(|intro| intro.strict.as_ref())
                .ok_or(Error::Admission)?;
            if admission.welcome_hash != welcome_hash
                || admission.completed
                || admission.cancelled
                || gate.policy != reservation_policy
                || strict.policy != contact_policy
                || strict.role != FirstContactRole::Recipient
            {
                return Err(Error::Admission);
            }
            return self.reservation_contexts(member);
        }
        let prepared = member.prepare_join(welcome)?;
        let peer = prepared.inviter.clone();
        if peer == self.state.recipient_id
            || self.state.known.contains(&peer)
            || self.state.introductions.contains_key(&peer)
            || prepared.contains_any(
                &self.excluded(),
                member.trust.as_ref().ok_or(Error::Admission)?,
                member.authorization_time()?,
            )?
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        let mut expected = None;
        member.commit_join(prepared, |joined| {
            changed.begin_first_contact(
                &peer,
                introduction_id,
                FirstContactRole::Recipient,
                contact_policy,
                joined,
                key_bytes,
                context,
                |_| Ok(()),
            )?;
            let contexts = changed.require_active_reservations(
                joined,
                reservation_policy,
                key_bytes,
                context,
                |_| Ok(()),
            )?;
            changed
                .state
                .reservations
                .as_mut()
                .ok_or(Error::Admission)?
                .admissions
                .insert(
                    key(&peer, introduction_id),
                    AccountedAdmission {
                        welcome_hash,
                        peer: peer.clone(),
                        nonce: *introduction_id,
                        completed: false,
                        cancelled: false,
                    },
                );
            changed.validate_state(joined)?;
            persist(&changed.seal(joined, key_bytes, context)?)?;
            expected = Some(contexts);
            Ok(())
        })?;
        *self = changed;
        expected.ok_or(Error::InvalidState)
    }

    /// Complete only after actual remote and current-own Active proofs verify.
    /// A failed final durable write leaves the staged invitation unaccepted.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_accounted_invitation(
        &mut self,
        member: &Member,
        outgoing: &[u8],
        incoming: &[u8],
        verifier: &mut impl ReservationVerifier,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let peer = self.contact_peer(member)?;
        let contexts = self.reservation_contexts(member)?;
        let id = key(&peer, &contexts.outgoing.expected.nonce);
        let admission = self
            .state
            .reservations
            .as_ref()
            .and_then(|journal| journal.admissions.get(&id))
            .ok_or(Error::Admission)?;
        if admission.cancelled {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        changed.bind_active_reservations(
            member,
            outgoing,
            incoming,
            verifier,
            key_bytes,
            context,
            |_| Ok(()),
        )?;
        changed
            .state
            .reservations
            .as_mut()
            .ok_or(Error::Admission)?
            .admissions
            .get_mut(&id)
            .ok_or(Error::Admission)?
            .completed = true;
        changed.state.known.insert(peer);
        changed.validate_state(member)?;
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }

    /// Cancel local admission without claiming a ledger refund. The staged group
    /// remains unusable; future invitations need a separately coordinated inbox.
    pub fn cancel_accounted_invitation(
        &mut self,
        member: &Member,
        key_bytes: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let peer = self.contact_peer(member)?;
        let nonce = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::Admission)?
            .id;
        let mut changed = self.duplicate();
        let admission = changed
            .state
            .reservations
            .as_mut()
            .and_then(|journal| journal.admissions.get_mut(&key(&peer, &nonce)))
            .ok_or(Error::Admission)?;
        if admission.completed {
            return Err(Error::Admission);
        }
        admission.cancelled = true;
        changed.runtime.reservations.remove(&key(&peer, &nonce));
        persist(&changed.seal(member, key_bytes, context)?)?;
        *self = changed;
        Ok(())
    }
}
