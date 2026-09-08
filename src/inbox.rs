//! Recipient-controlled first-contact acceptance, above the raw MLS primitive.
use crate::{Error, Member, MAX_WIRE_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, PartialEq, Eq)]
pub enum Acceptance {
    Joined,
    Rejected,
    Pending,
    NeedsPermit,
    Busy,
    Blocked,
}
/// Results from the trusted, anonymously connected cfrm redemption adapter.
#[derive(Debug, PartialEq, Eq)]
pub enum Redemption {
    Accepted,
    Rejected,
    Indeterminate,
}

pub struct Inbox {
    state: InboxState,
}
#[derive(Clone, Serialize, Deserialize)]
struct InboxState {
    community_id: String,
    recipient_id: String,
    known: BTreeSet<String>,
    #[serde(default)]
    blocked: BTreeSet<String>,
    pending: Option<Pending>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    welcome: Vec<u8>,
    inviter: String,
    welcome_hash: [u8; 32],
    recipient_redemption: Vec<u8>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.recipient_redemption.zeroize();
        self.welcome.zeroize();
        self.inviter.zeroize();
    }
}
impl Drop for InboxState {
    fn drop(&mut self) {
        self.community_id.zeroize();
        self.recipient_id.zeroize();
        for mut value in std::mem::take(&mut self.known) {
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.blocked) {
            value.zeroize();
        }
    }
}
impl Inbox {
    pub fn new(recipient: &Member) -> Result<Self, Error> {
        Ok(Self {
            state: InboxState {
                community_id: recipient
                    .trust
                    .as_ref()
                    .ok_or(Error::Admission)?
                    .community_id
                    .clone(),
                recipient_id: recipient.member_id()?,
                known: BTreeSet::new(),
                blocked: BTreeSet::new(),
                pending: None,
            },
        })
    }
    fn duplicate(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }

    pub fn is_known(&self, member_id: &str) -> bool {
        self.state.known.contains(member_id)
    }
    /// Private local recovery data; never include this in operator telemetry.
    pub fn pending_welcome(&self) -> Option<&[u8]> {
        self.state.pending.as_ref().map(|p| p.welcome.as_slice())
    }

    /// Accept an invitation only after the recipient enforces first-contact rules.
    ///
    /// `recipient_redemption` MUST come from the trusted recipient-side cfrm
    /// prepareRedemption adapter. Never take a retry claim supplied by the sender.
    /// Only the permit is sent by the inviter; the recipient adds fresh private
    /// randomness. The redemption callback receives those opaque bytes alone.
    ///
    /// `persist` must return Ok only after an atomic, durable local write of the
    /// supplied encrypted checkpoint. The first write precedes external spending;
    /// the last precedes exposing joined state. This callback contract cannot prove
    /// storage freshness or prevent an application from restoring an older file.
    ///
    /// Keep retries bounded in the application. Pending means retain/retry the
    /// exact checkpoint, not mint a new claim or treat a timeout as rejection.
    #[allow(clippy::too_many_arguments)]
    pub fn accept(
        &mut self,
        recipient: &mut Member,
        welcome: &[u8],
        recipient_redemption: Option<&[u8]>,
        wrapping_key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
        mut redeem: impl FnMut(&[u8]) -> Redemption,
    ) -> Result<Acceptance, Error> {
        self.check_binding(recipient)?;
        if welcome.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidMessage);
        }
        // Verify the entire invitation and the actual Welcome signer before any
        // persistence or debit. Merely possessing a public certificate is not enough.
        let prepared = recipient.prepare_join(welcome)?;
        let inviter = prepared.inviter.clone();
        if self.state.blocked.contains(&inviter) {
            return Ok(Acceptance::Blocked);
        }
        let hash: [u8; 32] = Sha256::digest(welcome).into();
        if let Some(pending) = &self.state.pending {
            if pending.welcome_hash != hash
                || recipient_redemption.is_some_and(|bytes| bytes != pending.recipient_redemption)
            {
                return Ok(Acceptance::Busy);
            }
        }
        let known = self.state.known.contains(&inviter);
        if !known && self.state.pending.is_none() {
            let Some(attempt) = recipient_redemption else {
                return Ok(Acceptance::NeedsPermit);
            };
            if attempt.is_empty() || attempt.len() > 8192 {
                return Err(Error::InvalidMessage);
            }
            self.state.pending = Some(Pending {
                welcome: welcome.to_vec(),
                inviter: inviter.clone(),
                welcome_hash: hash,
                recipient_redemption: attempt.to_vec(),
            });
        }
        if !known {
            // Re-persist on retry too: an interrupted previous local write must
            // never authorize a first external spend without durable intent.
            persist(&self.seal(recipient, wrapping_key, context)?)?;
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
                    match persist(&cleared.seal(recipient, wrapping_key, context)?) {
                        Ok(()) => {
                            *self = cleared;
                            return Ok(Acceptance::Rejected);
                        }
                        Err(_) => return Ok(Acceptance::Pending),
                    }
                }
                Redemption::Accepted => (),
            }
        }
        let mut committed = self.duplicate();
        committed.state.known.insert(inviter);
        committed.state.pending = None;
        // The candidate ratchet and contact book form one encrypted checkpoint.
        // commit_join rolls back in-memory MLS state if the final write fails.
        if recipient
            .commit_join(prepared, |joined| {
                persist(&committed.seal(joined, wrapping_key, context)?)
            })
            .is_err()
        {
            return if known {
                Err(Error::InvalidStore)
            } else {
                Ok(Acceptance::Pending)
            };
        }
        *self = committed;
        Ok(Acceptance::Joined)
    }
    /// Locally discard an unresolved invitation after durably clearing it. A spent
    /// permit is forfeited; cancellation never refunds allowance or calls cfrm.
    pub fn cancel_pending(
        &mut self,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(recipient)?;
        let mut cleared = self.duplicate();
        cleared.state.pending = None;
        persist(&cleared.seal(recipient, key, context)?)?;
        *self = cleared;
        Ok(())
    }
    /// Private stable-ID invitation blocking, including previously known contacts.
    /// Existing conversation output must separately honor the client's block state;
    /// this method does not modify raw Member::receive or report anything to cfrm.
    #[allow(clippy::too_many_arguments)]
    pub fn set_blocked(
        &mut self,
        member_id: &str,
        blocked: bool,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(recipient)?;
        if member_id.len() != 43
            || !data_encoding::BASE64URL_NOPAD
                .decode(member_id.as_bytes())
                .is_ok_and(|bytes| bytes.len() == 32)
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        if blocked {
            changed.state.blocked.insert(member_id.to_owned());
            if changed
                .state
                .pending
                .as_ref()
                .is_some_and(|p| p.inviter == member_id)
            {
                changed.state.pending = None;
            }
        } else {
            changed.state.blocked.remove(member_id);
        }
        persist(&changed.seal(recipient, key, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn is_blocked(&self, member_id: &str) -> bool {
        self.state.blocked.contains(member_id)
    }

    fn check_binding(&self, recipient: &Member) -> Result<(), Error> {
        if self.state.recipient_id != recipient.stored_member_id()?
            || self.state.community_id
                != recipient
                    .trust
                    .as_ref()
                    .ok_or(Error::Admission)?
                    .community_id
        {
            return Err(Error::Admission);
        }
        Ok(())
    }
    fn seal(&self, member: &Member, key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        #[derive(Serialize)]
        struct Bundle<'a> {
            inbox: &'a InboxState,
            member: Vec<u8>,
        }
        let bundle = Bundle {
            inbox: &self.state,
            member: member.snapshot(key, context)?,
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| Error::InvalidStore)?);
        crate::vault::seal(&plaintext, key, &inbox_context(context)?)
    }
    pub fn restore(sealed: &[u8], key: &[u8; 32], context: &[u8]) -> Result<(Self, Member), Error> {
        #[derive(Deserialize)]
        struct Bundle {
            inbox: InboxState,
            member: Vec<u8>,
        }
        let plaintext = crate::vault::open(sealed, key, &inbox_context(context)?)?;
        let bundle: Bundle = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        let member = Member::restore(&bundle.member, key, context)?;
        let inbox = Self {
            state: bundle.inbox,
        };
        inbox.check_binding(&member)?;
        Ok((inbox, member))
    }
}
fn inbox_context(context: &[u8]) -> Result<[u8; 32], Error> {
    if context.is_empty() || context.len() > 128 {
        return Err(Error::InvalidStore);
    }
    let mut hash = Sha256::new();
    hash.update(b"cmsg.inbox.v1\0");
    hash.update(context);
    Ok(hash.finalize().into())
}
