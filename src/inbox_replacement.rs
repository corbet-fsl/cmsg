//! A new admitted introduction after owner-controlled closure and group loss.
//! Ordinary reconnects and enrolled-device catchup do not use this path.
use super::*;

/// Private invitation bundle. Persist both exact frames with the replacement
/// checkpoint before delivery over an authenticated anonymous member channel.
pub struct ReopeningInvitation {
    pub welcome: Vec<u8>,
    pub control: Vec<u8>,
}
impl std::fmt::Debug for ReopeningInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReopeningInvitation([redacted])")
    }
}
impl Drop for ReopeningInvitation {
    fn drop(&mut self) {
        self.welcome.zeroize();
        self.control.zeroize();
    }
}

/// Authenticated private inputs for constructing the recipient's admission
/// claim. Obtain these from preview_replacement, never independent sender hints.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplacementPreview {
    pub inviter: String,
    pub introduction_id: [u8; 32],
    pub group_id: Vec<u8>,
    pub policy: FirstContactPolicy,
}
impl std::fmt::Debug for ReplacementPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplacementPreview([redacted])")
    }
}
impl Drop for ReplacementPreview {
    fn drop(&mut self) {
        self.inviter.zeroize();
        self.introduction_id.zeroize();
        self.group_id.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingReplacement {
    pub(super) control: Vec<u8>,
    /// Generated locally only after authenticating the complete bundle. This is
    /// used for sealed-state restore, never as network acceptance authority.
    pub(super) validated_at: u64,
}
impl Drop for PendingReplacement {
    fn drop(&mut self) {
        self.control.zeroize();
    }
}

struct PreparedReplacement {
    member: Member,
    inbox: Inbox,
    inviter: String,
}

impl Inbox {
    /// Authenticate the complete replacement at the live clock without joining,
    /// consuming a KeyPackage or changing the journal. The recipient's trusted
    /// admission adapter must bind its private claim to this exact context.
    pub fn preview_replacement(
        &self,
        replacement: &Member,
        welcome: &[u8],
        control: &[u8],
    ) -> Result<ReplacementPreview, Error> {
        self.check_binding(replacement)?;
        if welcome.is_empty()
            || welcome.len() > MAX_WIRE_BYTES
            || control.is_empty()
            || control.len() > MAX_WIRE_BYTES
        {
            return Err(Error::InvalidMessage);
        }
        let prepared = self.prepare_replacement(
            replacement,
            welcome,
            control,
            replacement.authorization_time()?,
        )?;
        if self.state.blocked.contains(&prepared.inviter) {
            return Err(Error::Admission);
        }
        let entry = prepared
            .inbox
            .state
            .introductions
            .get(&prepared.inviter)
            .ok_or(Error::InvalidState)?;
        Ok(ReplacementPreview {
            inviter: prepared.inviter,
            introduction_id: entry.id,
            group_id: prepared.member.policy_group_id()?,
            policy: entry.strict.as_ref().ok_or(Error::InvalidState)?.policy,
        })
    }

    /// Start a new group with a fresh admitted device of this same root/member.
    /// The existing contact journal is required. This is an owner-authorized new
    /// introduction, not restoration of old message ratchets or unpaid allowance.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_replacement(
        &mut self,
        replacement: &mut Member,
        peer_key_package: &[u8],
        nonce: &[u8; 32],
        policy: FirstContactPolicy,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &ReopeningInvitation) -> Result<(), Error>,
    ) -> Result<ReopeningInvitation, Error> {
        self.check_binding(replacement)?;
        if self.state.pending.is_some()
            || replacement.policy_group_id().is_ok()
            || replacement.device_authorization()?.is_none()
        {
            return Err(Error::InvalidState);
        }
        let mut candidate = replacement.staged_copy(key, context)?;
        candidate.create_group()?;
        let invitation = candidate.add(peer_key_package)?;
        let peer = candidate.replacement_peer()?;
        if !self
            .state
            .introductions
            .get(&peer)
            .is_some_and(|entry| entry.strict.is_some())
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        let control =
            changed.initiate_contact(&mut candidate, nonce, policy, key, context, |_, _| Ok(()))?;
        let bundle = ReopeningInvitation {
            welcome: invitation.welcome,
            control,
        };
        changed.validate_state(&candidate)?;
        persist(&changed.seal(&candidate, key, context)?, &bundle)?;
        *self = changed;
        *replacement = candidate;
        Ok(bundle)
    }

    /// Admit a replacement group only with a fresh recipient-prepared permit
    /// redemption. Known contacts do not bypass this new-introduction charge.
    /// Both owners' blocks remain effective until their exact signed consent;
    /// joining a pending-consent group exposes no application data.
    ///
    /// Persist the exact pending bundle and private claim before external spend,
    /// then persist the joined state before publishing it. Ambiguity, expiry or
    /// a failed final write retains that same pending claim, without a refund.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_replacement(
        &mut self,
        replacement: &mut Member,
        welcome: &[u8],
        control: &[u8],
        recipient_redemption: Option<&[u8]>,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
        mut redeem: impl FnMut(&[u8]) -> Redemption,
    ) -> Result<Acceptance, Error> {
        self.check_binding(replacement)?;
        if replacement.policy_group_id().is_ok() || replacement.device_authorization()?.is_none() {
            return Err(Error::InvalidState);
        }
        if welcome.is_empty()
            || welcome.len() > MAX_WIRE_BYTES
            || control.is_empty()
            || control.len() > MAX_WIRE_BYTES
        {
            return Err(Error::InvalidMessage);
        }
        let hash: [u8; 32] = Sha256::digest(welcome).into();
        if let Some(pending) = &self.state.pending {
            if pending.welcome_hash != hash
                || !pending
                    .replacement
                    .as_ref()
                    .is_some_and(|stored| stored.control == control)
                || recipient_redemption.is_some_and(|bytes| bytes != pending.recipient_redemption)
            {
                return Ok(Acceptance::Busy);
            }
        }
        let at = replacement.authorization_time()?;
        let prepared = match self.prepare_replacement(replacement, welcome, control, at) {
            Ok(prepared) => prepared,
            Err(error) => {
                return if self.state.pending.is_some() {
                    Ok(Acceptance::Pending)
                } else {
                    Err(error)
                }
            }
        };
        if self.state.blocked.contains(&prepared.inviter) {
            return Ok(Acceptance::Blocked);
        }
        if self.state.pending.is_none() {
            let Some(claim) = recipient_redemption else {
                return Ok(Acceptance::NeedsPermit);
            };
            if claim.is_empty() || claim.len() > 8192 {
                return Err(Error::InvalidMessage);
            }
            self.state.pending = Some(Pending {
                welcome: welcome.to_vec(),
                inviter: prepared.inviter.clone(),
                welcome_hash: hash,
                recipient_redemption: claim.to_vec(),
                replacement: Some(PendingReplacement {
                    control: control.to_vec(),
                    validated_at: at,
                }),
            });
        }
        drop(prepared);
        persist(&self.seal(replacement, key, context)?)?;
        match redeem(
            &self
                .state
                .pending
                .as_ref()
                .ok_or(Error::InvalidState)?
                .recipient_redemption,
        ) {
            Redemption::Indeterminate => return Ok(Acceptance::Pending),
            Redemption::Rejected => {
                let mut cleared = self.duplicate();
                cleared.state.pending = None;
                if persist(&cleared.seal(replacement, key, context)?).is_err() {
                    return Ok(Acceptance::Pending);
                }
                *self = cleared;
                return Ok(Acceptance::Rejected);
            }
            Redemption::Accepted => (),
        }
        // Rebuild from the unchanged pending journal after external spending.
        let mut prepared = match self.prepare_replacement(
            replacement,
            welcome,
            control,
            replacement.authorization_time()?,
        ) {
            Ok(prepared) => prepared,
            Err(_) => return Ok(Acceptance::Pending),
        };
        prepared.inbox.state.known.insert(prepared.inviter.clone());
        prepared.inbox.validate_state(&prepared.member)?;
        if persist(&prepared.inbox.seal(&prepared.member, key, context)?).is_err() {
            return Ok(Acceptance::Pending);
        }
        *self = prepared.inbox;
        *replacement = prepared.member;
        Ok(Acceptance::Joined)
    }

    /// Exact private retry control, paired with pending_welcome. Never disclose
    /// either frame or the identifying policy history to the admission operator.
    pub fn pending_replacement_control(&self) -> Option<&[u8]> {
        self.state
            .pending
            .as_ref()?
            .replacement
            .as_ref()
            .map(|pending| pending.control.as_slice())
    }

    fn prepare_replacement(
        &self,
        replacement: &Member,
        welcome: &[u8],
        control: &[u8],
        at: u64,
    ) -> Result<PreparedReplacement, Error> {
        if at == 0 || at > replacement.authorization_time()? {
            return Err(Error::InvalidStore);
        }
        let (candidate, (changed, inviter)) = replacement.inspect_at(at, |candidate| {
            let prepared = candidate.prepare_join(welcome)?;
            let inviter = prepared.inviter.clone();
            candidate.commit_join(prepared, |_| Ok(()))?;
            if candidate.replacement_peer()? != inviter {
                return Err(Error::Admission);
            }
            let mut changed = self.duplicate();
            changed.state.pending = None;
            if !changed
                .state
                .introductions
                .get(&inviter)
                .is_some_and(|entry| entry.strict.is_some())
            {
                return Err(Error::Admission);
            }
            let raw = candidate.receive_policy_excluding(control, &BTreeSet::new())?;
            match raw {
                Received::Bytes(message) if message.member_id == inviter => {
                    let body = message
                        .bytes
                        .strip_prefix(CONTACT_DIRECTIVE_PREFIX)
                        .ok_or(Error::InvalidMessage)?;
                    changed.apply_replacement_control(&inviter, body, candidate)?;
                }
                _ => return Err(Error::InvalidMessage),
            }
            // Other contacts may have newer journal entries than this saved
            // pending operation; their historical validation uses the live clock.
            changed.validate_state(replacement)?;
            Ok((changed, inviter))
        })?;
        Ok(PreparedReplacement {
            member: candidate,
            inbox: changed,
            inviter,
        })
    }

    pub(super) fn validate_pending_replacement(
        &self,
        member: &Member,
        pending: &Pending,
    ) -> Result<(), Error> {
        let replacement = pending.replacement.as_ref().ok_or(Error::InvalidStore)?;
        if replacement.control.is_empty() || replacement.control.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidStore);
        }
        let prepared = self.prepare_replacement(
            member,
            &pending.welcome,
            &replacement.control,
            replacement.validated_at,
        )?;
        if prepared.inviter != pending.inviter {
            return Err(Error::InvalidStore);
        }
        Ok(())
    }
}
