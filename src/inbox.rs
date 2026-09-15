//! Recipient-controlled first-contact acceptance, above the raw MLS primitive.
use crate::{
    Clock, ContactResolution, ContactResolutionKind, Error, Member, Received, MAX_WIRE_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[path = "inbox_policy.rs"]
mod owner_policy;
use owner_policy::DirectionalContact;
#[path = "inbox_accounting.rs"]
mod accounting_policy;
#[path = "inbox_live.rs"]
mod live_policy;
#[path = "inbox_replacement.rs"]
mod replacement_policy;
#[path = "inbox_reservation.rs"]
mod reservation_policy;
use replacement_policy::PendingReplacement;
pub use replacement_policy::{ReopeningInvitation, ReplacementPreview};

const CONTACT_DATA_PREFIX: &[u8] = b"cmsg.contact-data.v2\0";
const CONTACT_DIRECTIVE_PREFIX: &[u8] = b"cmsg.contact-directive.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactSync {
    community_id: String,
    owner_id: String,
    issued_at: u64,
    device_public_key: Vec<u8>,
    credential: Vec<u8>,
    known: BTreeSet<String>,
    closed: BTreeSet<String>,
    introductions: BTreeMap<String, Introduction>,
    directional: BTreeMap<String, DirectionalContact>,
    archived: BTreeMap<String, Vec<Introduction>>,
    #[serde(default)]
    live: Option<live_policy::Journal>,
    #[serde(default)]
    reservations: Option<reservation_policy::Journal>,
    signature: Vec<u8>,
}

impl ContactSync {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.reservations.is_some() {
            return serde_json::to_vec(&serde_json::json!([
                "cmsg.contact-sync.v3",
                self.community_id,
                self.owner_id,
                self.issued_at,
                self.device_public_key,
                self.credential,
                self.known,
                self.closed,
                self.introductions,
                self.directional,
                self.archived,
                self.live,
                self.reservations,
            ]))
            .map_err(|_| Error::InvalidMessage);
        }
        if self.live.is_some() {
            return serde_json::to_vec(&serde_json::json!([
                "cmsg.contact-sync.v2",
                self.community_id,
                self.owner_id,
                self.issued_at,
                self.device_public_key,
                self.credential,
                self.known,
                self.closed,
                self.introductions,
                self.directional,
                self.archived,
                self.live,
            ]))
            .map_err(|_| Error::InvalidMessage);
        }
        serde_json::to_vec(&serde_json::json!([
            "cmsg.contact-sync.v1",
            self.community_id,
            self.owner_id,
            self.issued_at,
            self.device_public_key,
            self.credential,
            self.known,
            self.closed,
            self.introductions,
            self.directional,
            self.archived,
        ]))
        .map_err(|_| Error::InvalidMessage)
    }
}

impl Drop for ContactSync {
    fn drop(&mut self) {
        self.community_id.zeroize();
        self.owner_id.zeroize();
        self.credential.zeroize();
        for mut value in std::mem::take(&mut self.known) {
            value.zeroize();
        }
        for mut value in std::mem::take(&mut self.closed) {
            value.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.introductions) {
            peer.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.directional) {
            peer.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.archived) {
            peer.zeroize();
        }
    }
}

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
    runtime: live_policy::Runtime,
}

/// Explicit first-contact bounds selected by the embedding community. The
/// deadline is an absolute timestamp from the same trusted Clock as Member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstContactPolicy {
    pub response_deadline: u64,
    pub max_intro_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirstContactRole {
    Initiator,
    Recipient,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictIntroduction {
    role: FirstContactRole,
    policy: FirstContactPolicy,
    initial_writer_key: Vec<u8>,
    sent: bool,
    received: bool,
    close_sent: bool,
    /// Old snapshots remain readable, but cannot issue accounting evidence for
    /// a group that was never retained with the original introduction.
    #[serde(default)]
    accounting_group_id: Option<Vec<u8>>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InboxState {
    #[serde(default)]
    publication_version: u64,
    community_id: String,
    recipient_id: String,
    root_authorized: bool,
    known: BTreeSet<String>,
    #[serde(default)]
    blocked: BTreeSet<String>,
    /// Unsigned local closures retained for legacy or expired-device recovery.
    closed: BTreeSet<String>,
    introductions: BTreeMap<String, Introduction>,
    directional: BTreeMap<String, DirectionalContact>,
    archived: BTreeMap<String, Vec<Introduction>>,
    pending: Option<Pending>,
    #[serde(default)]
    live: Option<live_policy::Journal>,
    #[serde(default)]
    reservations: Option<reservation_policy::Journal>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Introduction {
    id: [u8; 32],
    decision: Option<ContactResolutionKind>,
    outbound_receipt: Option<Vec<u8>>,
    inbound_receipt: Option<Vec<u8>>,
    strict: Option<StrictIntroduction>,
}

impl Drop for Introduction {
    fn drop(&mut self) {
        self.id.zeroize();
        if let Some(bytes) = &mut self.outbound_receipt {
            bytes.zeroize();
        }
        if let Some(bytes) = &mut self.inbound_receipt {
            bytes.zeroize();
        }
        if let Some(strict) = &mut self.strict {
            strict.initial_writer_key.zeroize();
            if let Some(group) = &mut strict.accounting_group_id {
                group.zeroize();
            }
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    welcome: Vec<u8>,
    inviter: String,
    welcome_hash: [u8; 32],
    recipient_redemption: Vec<u8>,
    #[serde(default)]
    replacement: Option<PendingReplacement>,
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
        for mut value in std::mem::take(&mut self.closed) {
            value.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.introductions) {
            peer.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.directional) {
            peer.zeroize();
        }
        for (mut peer, _) in std::mem::take(&mut self.archived) {
            peer.zeroize();
        }
    }
}
impl Inbox {
    pub fn new(recipient: &Member) -> Result<Self, Error> {
        Ok(Self {
            state: InboxState {
                publication_version: 0,
                community_id: recipient
                    .trust
                    .as_ref()
                    .ok_or(Error::Admission)?
                    .community_id
                    .clone(),
                recipient_id: recipient.member_id()?,
                root_authorized: recipient.device_authorization()?.is_some(),
                known: BTreeSet::new(),
                blocked: BTreeSet::new(),
                closed: BTreeSet::new(),
                introductions: BTreeMap::new(),
                directional: BTreeMap::new(),
                archived: BTreeMap::new(),
                pending: None,
                live: None,
                reservations: None,
            },
            runtime: live_policy::Runtime::default(),
        })
    }
    fn duplicate(&self) -> Self {
        Self {
            state: self.state.clone(),
            runtime: self.runtime.clone(),
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
        if self
            .state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.replacement.is_some())
        {
            return Ok(Acceptance::Busy);
        }
        if welcome.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidMessage);
        }
        // Verify the entire invitation and the actual Welcome signer before any
        // persistence or debit. Merely possessing a public certificate is not enough.
        let prepared = recipient.prepare_join(welcome)?;
        let inviter = prepared.inviter.clone();
        let excluded = self.excluded();
        if prepared.contains_any(
            &excluded,
            recipient.trust.as_ref().ok_or(Error::Admission)?,
            recipient.authorization_time()?,
        )? {
            return Ok(Acceptance::Blocked);
        }
        drop(prepared);
        let hash: [u8; 32] = Sha256::digest(welcome).into();
        if let Some(pending) = &self.state.pending {
            if pending.welcome_hash != hash
                || recipient_redemption.is_some_and(|bytes| bytes != pending.recipient_redemption)
            {
                return Ok(Acceptance::Busy);
            }
        }
        let known = inviter == self.state.recipient_id || self.state.known.contains(&inviter);
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
                replacement: None,
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
        // External redemption can outlive admission. A previously authenticated
        // candidate is not permission to join after expiry; keep the durable
        // spent attempt pending rather than minting a claim or refunding it.
        let prepared = match recipient.prepare_join(welcome) {
            Ok(prepared) => prepared,
            Err(error) => {
                return if known {
                    Err(error)
                } else {
                    Ok(Acceptance::Pending)
                }
            }
        };
        let mut committed = self.duplicate();
        if inviter != self.state.recipient_id {
            committed.state.known.insert(inviter);
        }
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
    /// Use Inbox::send/receive for existing conversations too. Raw Member methods
    /// intentionally remain low-level MLS primitives with no contact policy.
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
        if !crate::admission::valid_member_id(member_id) || member_id == self.state.recipient_id {
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
        self.state.blocked.contains(member_id) || self.is_closed(member_id)
    }

    /// Permanently refuse this community member across threads and device keys.
    /// Clearing a temporary block never clears this tombstone. The transaction
    /// does not send a notification or prove anything to an accounting service.
    /// Sync the tombstone with every other device before that device reconnects.
    pub fn close_forever(
        &mut self,
        member_id: &str,
        recipient: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.state.root_authorized {
            return self.block_member_until(member_id, None, recipient, key, context, persist);
        }
        self.check_binding(recipient)?;
        if !crate::admission::valid_member_id(member_id) || member_id == self.state.recipient_id {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        changed.state.closed.insert(member_id.to_owned());
        if changed
            .state
            .pending
            .as_ref()
            .is_some_and(|p| p.inviter == member_id)
        {
            changed.state.pending = None;
        }
        persist(&changed.seal(recipient, key, context)?)?;
        *self = changed;
        Ok(())
    }

    pub fn is_closed(&self, member_id: &str) -> bool {
        self.state.closed.contains(member_id)
            || self
                .state
                .directional
                .get(member_id)
                .is_some_and(DirectionalContact::blocked)
    }

    /// Register the shared, unpredictable first-introduction ID after peer
    /// authentication. A second thread cannot replace a member's unresolved
    /// introduction. The policy adapter controls when registration is authorized.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_introduction(
        &mut self,
        peer_id: &str,
        introduction_id: &[u8; 32],
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(member)?;
        if !crate::admission::valid_member_id(peer_id)
            || peer_id == self.state.recipient_id
            || self.is_blocked(peer_id)
        {
            return Err(Error::Admission);
        }
        if let Some(existing) = self.state.introductions.get(peer_id) {
            return if existing.id == *introduction_id {
                Ok(())
            } else {
                Err(Error::InvalidState)
            };
        }
        let mut changed = self.duplicate();
        changed.state.introductions.insert(
            peer_id.to_owned(),
            Introduction {
                id: *introduction_id,
                decision: None,
                outbound_receipt: None,
                inbound_receipt: None,
                strict: None,
            },
        );
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    pub fn needs_resolution(&self, peer_id: &str) -> bool {
        !self.is_closed(peer_id)
            && self
                .state
                .introductions
                .get(peer_id)
                .is_some_and(|intro| intro.decision.is_none())
    }

    /// Register the strict first-contact protocol. Each endpoint supplies the
    /// agreed nonce, its role and explicit bounds. Initial transmission belongs
    /// to this device; siblings must sync before use and cannot independently
    /// duplicate that transmission. Account-wide concurrent enrollment still
    /// requires the embedding application's coordination.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_first_contact(
        &mut self,
        peer_id: &str,
        introduction_id: &[u8; 32],
        role: FirstContactRole,
        policy: FirstContactPolicy,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(member)?;
        member.member_id()?;
        if !self.state.root_authorized
            || !crate::admission::valid_member_id(peer_id)
            || peer_id == self.state.recipient_id
            || self.is_blocked(peer_id)
            || policy.response_deadline <= member.authorization_time()?
            || policy.response_deadline > 9_007_199_254_740_991
            || policy.max_intro_bytes == 0
            || policy.max_intro_bytes > crate::MAX_DATA_BYTES
        {
            return Err(Error::Admission);
        }
        if let Some(existing) = self.state.introductions.get(peer_id) {
            if existing.id != *introduction_id {
                return Err(Error::InvalidState);
            }
            if let Some(strict) = &existing.strict {
                return if strict.role == role && strict.policy == policy {
                    Ok(())
                } else {
                    Err(Error::InvalidState)
                };
            }
            return Err(Error::InvalidState);
        }
        let mut changed = self.duplicate();
        changed.state.introductions.insert(
            peer_id.to_owned(),
            Introduction {
                id: *introduction_id,
                decision: None,
                outbound_receipt: None,
                inbound_receipt: None,
                strict: Some(StrictIntroduction {
                    role,
                    policy,
                    initial_writer_key: member.chat_public_key(),
                    sent: false,
                    received: false,
                    close_sent: false,
                    accounting_group_id: member.policy_group_id().ok(),
                }),
            },
        );
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    /// Apply caller-configured response deadlines as owner-controlled closures.
    /// This requires an awake client and a trusted Clock; no operator timer or
    /// delivery promise is implied. Exact signed close receipts are retained
    /// when the device is currently authorized, for later private delivery.
    pub fn apply_deadlines(
        &mut self,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        self.check_binding(member)?;
        let now = member.authorization_time()?;
        let expired: Vec<String> = self
            .state
            .introductions
            .iter()
            .filter_map(|(peer, intro)| {
                (intro.decision.is_none()
                    && !self.is_closed(peer)
                    && intro
                        .strict
                        .as_ref()
                        .is_some_and(|s| s.policy.response_deadline <= now))
                .then(|| peer.clone())
            })
            .collect();
        let mut changed = self.duplicate();
        let ended = changed.expire_live_sessions(now);
        if self.state.live.is_some() || self.state.reservations.is_some() {
            let mut expired_count = 0;
            for peer in &expired {
                let nonce = changed
                    .state
                    .introductions
                    .get(peer)
                    .ok_or(Error::InvalidState)?
                    .id;
                expired_count += usize::from(changed.expire_live_introduction(peer, &nonce));
            }
            if ended + expired_count > 0 {
                persist(&changed.seal(member, key, context)?)?;
                *self = changed;
            }
            return Ok(ended + expired_count);
        }
        if expired.is_empty() && ended == 0 {
            return Ok(0);
        }
        for peer in &expired {
            let intro = changed
                .state
                .introductions
                .get_mut(peer)
                .ok_or(Error::InvalidState)?;
            if let Ok(receipt) = member.sign_contact_resolution(
                peer,
                &intro.id,
                ContactResolutionKind::ClosedForever,
            ) {
                intro.outbound_receipt =
                    Some(serde_json::to_vec(&receipt).map_err(|_| Error::InvalidMessage)?);
            }
            if intro
                .strict
                .as_ref()
                .is_some_and(|s| s.role == FirstContactRole::Recipient)
            {
                intro.decision = Some(ContactResolutionKind::ClosedForever);
            }
            changed.record_local_close(peer, member)?;
        }
        if changed
            .state
            .pending
            .as_ref()
            .is_some_and(|p| changed.is_closed(&p.inviter))
        {
            changed.state.pending = None;
        }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(expired.len() + ended)
    }

    /// Send one introduction, an actual reply, or established conversation text.
    /// The callback atomically persists checkpoint and exact outbound ciphertext.
    /// Authorization and deadline checks apply when preparing this operation.
    /// Successful durable persistence commits it even if the callback takes time;
    /// callers must never roll back that committed ratchet to enforce a later time.
    pub fn send_contact(
        &mut self,
        member: &mut Member,
        text: &[u8],
        key: &[u8; 32],
        context: &[u8],
        persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        crate::validate_text(text)?;
        self.send_contact_payload(member, text, true, key, context, persist)
    }

    pub fn send_contact_bytes(
        &mut self,
        member: &mut Member,
        bytes: &[u8],
        key: &[u8; 32],
        context: &[u8],
        persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        if bytes.is_empty() || bytes.len() > crate::MAX_DATA_BYTES {
            return Err(Error::InvalidMessage);
        }
        self.send_contact_payload(member, bytes, false, key, context, persist)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_contact_payload(
        &mut self,
        member: &mut Member,
        bytes: &[u8],
        text: bool,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.apply_deadlines(member, key, context, |checkpoint| persist(checkpoint, &[]))?;
        self.check_reservation_release(member)?;
        if self.state.live.is_some() {
            return self.send_live_data(member, bytes, text, None, key, context, persist);
        }
        let peer = self.contact_peer(member)?;
        self.check_exclusions(member)?;
        self.check_selected_group(&peer, member)?;
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?;
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        if intro.decision.is_none()
            && (bytes.len() > strict.policy.max_intro_bytes
                || strict.initial_writer_key != member.chat_public_key()
                || match strict.role {
                    FirstContactRole::Initiator => strict.sent,
                    FirstContactRole::Recipient => !strict.received || strict.sent,
                })
        {
            return Err(Error::Admission);
        }
        let mut candidate = member.staged_copy(key, context)?;
        let mut record = Zeroizing::new(CONTACT_DATA_PREFIX.to_vec());
        record.extend_from_slice(&intro.id);
        record.push(u8::from(text));
        record.extend_from_slice(bytes);
        let wire = candidate.send_policy_record(&record)?;
        if text {
            candidate.remember_policy_text(&candidate.member_id()?, bytes)?;
        }
        let mut changed = self.duplicate();
        let entry = changed
            .state
            .introductions
            .get_mut(&peer)
            .ok_or(Error::InvalidState)?;
        let state = entry.strict.as_mut().ok_or(Error::InvalidState)?;
        state.sent = true;
        if entry.decision.is_none() && state.role == FirstContactRole::Recipient {
            entry.decision = Some(ContactResolutionKind::Answered);
            let receipt = candidate.sign_contact_resolution(
                &peer,
                &entry.id,
                ContactResolutionKind::Answered,
            )?;
            entry.outbound_receipt =
                Some(serde_json::to_vec(&receipt).map_err(|_| Error::InvalidMessage)?);
        }
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *member = candidate;
        *self = changed;
        Ok(wire)
    }

    /// Receive at most one introduction until an actual reply is durably sent.
    /// Authenticated replies establish the contact; signed close controls apply
    /// the peer's block. Rejected input exposes no plaintext/history.
    pub fn receive_contact(
        &mut self,
        member: &mut Member,
        wire: &[u8],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Received, Error> {
        self.apply_deadlines(member, key, context, &mut persist)?;
        let peer = self.contact_peer(member)?;
        let peer_excluded = self.is_blocked(&peer);
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?;
        intro.strict.as_ref().ok_or(Error::InvalidState)?;
        let mut candidate = member.staged_copy(key, context)?;
        let mut excluded = self.excluded();
        // A terminal signed close receipt may still settle the original peer
        // obligation after local cancellation. No application data is exposed.
        excluded.remove(&peer);
        let raw = candidate.receive_policy_excluding(wire, &excluded)?;
        let mut changed = self.duplicate();
        let received = match &raw {
            Received::Bytes(message)
                if message.member_id == peer && message.bytes.starts_with(crate::live::PREFIX) =>
            {
                changed.receive_live_record(
                    &mut candidate,
                    &message.bytes[crate::live::PREFIX.len()..],
                    &peer,
                )?
            }
            Received::Bytes(message)
                if message.member_id == peer
                    && message.bytes.starts_with(CONTACT_DIRECTIVE_PREFIX) =>
            {
                changed.apply_control_record(
                    &peer,
                    &message.bytes[CONTACT_DIRECTIVE_PREFIX.len()..],
                    &candidate,
                )?
            }
            Received::MembershipChanged => {
                changed.check_reservation_roster(&candidate)?;
                if peer_excluded {
                    let before: BTreeSet<_> = member
                        .participants()?
                        .iter()
                        .map(|p| (p.member_id.clone(), p.chat_public_key.clone()))
                        .collect();
                    let after: BTreeSet<_> = candidate
                        .participants()?
                        .iter()
                        .map(|p| (p.member_id.clone(), p.chat_public_key.clone()))
                        .collect();
                    // Renewing an existing device's credentials can make a
                    // delayed close receipt verifiable. It must not add/remove
                    // devices, reopen contact, or expose application data.
                    if before != after {
                        return Err(Error::Admission);
                    }
                }
                if self.contact_peer(&candidate)? != peer {
                    return Err(Error::Admission);
                }
                Received::MembershipChanged
            }
            Received::Bytes(message) if message.bytes.starts_with(CONTACT_DATA_PREFIX) => {
                if changed.state.live.is_some() {
                    return Err(Error::Admission);
                }
                changed.check_reservation_release(&candidate)?;
                changed.check_selected_group(&peer, &candidate)?;
                let record = &message.bytes[CONTACT_DATA_PREFIX.len()..];
                if peer_excluded
                    || message.member_id != peer
                    || record.len() <= 33
                    || record[..32] != intro.id
                    || record[32] > 1
                    || record.len() - 33 > crate::MAX_DATA_BYTES
                {
                    return Err(Error::Admission);
                }
                let bytes = &record[33..];
                let entry = changed
                    .state
                    .introductions
                    .get_mut(&peer)
                    .ok_or(Error::InvalidState)?;
                let state = entry.strict.as_mut().ok_or(Error::InvalidState)?;
                if entry.decision.is_none() {
                    if bytes.len() > state.policy.max_intro_bytes
                        || match state.role {
                            FirstContactRole::Recipient => state.received,
                            FirstContactRole::Initiator => !state.sent,
                        }
                    {
                        return Err(Error::Admission);
                    }
                    state.received = true;
                    if state.role == FirstContactRole::Initiator {
                        entry.decision = Some(ContactResolutionKind::Answered);
                    }
                }
                if record[32] == 1 {
                    let text = crate::validate_text(bytes)?.to_owned();
                    candidate.remember_policy_text(&peer, bytes)?;
                    Received::Text(crate::TextMessage {
                        member_id: peer.clone(),
                        text,
                    })
                } else {
                    Received::Bytes(crate::DataMessage {
                        member_id: peer.clone(),
                        bytes: bytes.to_vec(),
                    })
                }
            }
            _ => return Err(Error::InvalidMessage),
        };
        changed.validate_state(&candidate)?;
        persist(&changed.seal(&candidate, key, context)?)?;
        *member = candidate;
        *self = changed;
        Ok(received)
    }

    /// Send an encrypted owner-controlled closure after committing it locally.
    /// This is the only guarded outbound control permitted for a closed peer.
    pub fn close_contact(
        &mut self,
        member: &mut Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.close_contact_until(member, None, key, context, &mut persist)
    }

    fn contact_peer(&self, member: &Member) -> Result<String, Error> {
        self.check_binding(member)?;
        let peers: BTreeSet<String> = member
            .participants()?
            .iter()
            .filter(|p| p.member_id != self.state.recipient_id)
            .map(|p| p.member_id.clone())
            .collect();
        if peers.len() != 1 {
            return Err(Error::InvalidState);
        }
        peers.into_iter().next().ok_or(Error::InvalidState)
    }

    /// A local sender cancellation or local timeout never counts as a peer
    /// response and never earns a replacement introduction allowance.
    pub fn awaiting_peer_resolution(&self, peer_id: &str) -> bool {
        self.state
            .introductions
            .get(peer_id)
            .into_iter()
            .chain(self.state.archived.get(peer_id).into_iter().flatten())
            .any(|intro| {
                intro.decision.is_none()
                    && intro
                        .strict
                        .as_ref()
                        .is_some_and(|s| s.role == FirstContactRole::Initiator && s.sent)
            })
    }

    /// Commit a local decision and its exact signed outbound receipt atomically.
    /// Answered is a protocol declaration; the embedding application must pair
    /// it with the actual answer. No receipt establishes sincere participation.
    /// ClosedForever also commits this member's indefinite directional block.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_introduction(
        &mut self,
        peer_id: &str,
        kind: ContactResolutionKind,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.check_binding(member)?;
        let existing = self
            .state
            .introductions
            .get(peer_id)
            .ok_or(Error::InvalidState)?;
        if existing
            .strict
            .as_ref()
            .is_some_and(|s| s.role == FirstContactRole::Initiator)
        {
            return Err(Error::InvalidState);
        }
        if existing.strict.is_some()
            && kind == ContactResolutionKind::Answered
            && existing.decision.is_none()
        {
            return Err(Error::InvalidState);
        }
        if kind == ContactResolutionKind::Answered && self.is_closed(peer_id) {
            return Err(Error::Admission);
        }
        if let Some(decision) = existing.decision {
            return if decision == kind {
                existing.outbound_receipt.clone().ok_or(Error::InvalidState)
            } else {
                Err(Error::InvalidState)
            };
        }
        let receipt = member.sign_contact_resolution(peer_id, &existing.id, kind)?;
        let encoded = serde_json::to_vec(&receipt).map_err(|_| Error::InvalidMessage)?;
        let mut changed = self.duplicate();
        let entry = changed
            .state
            .introductions
            .get_mut(peer_id)
            .ok_or(Error::InvalidState)?;
        entry.decision = Some(kind);
        entry.outbound_receipt = Some(encoded.clone());
        if kind == ContactResolutionKind::ClosedForever {
            changed.record_local_close(peer_id, member)?;
            if changed
                .state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.inviter == peer_id)
            {
                changed.state.pending = None;
            }
        }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(encoded)
    }

    /// Apply the peer's signed decision for its registered or archived nonce. True
    /// means the first unresolved-to-resolved transition. False can still persist
    /// a later closure or newly supplied receipt evidence, but never a
    /// second first-contact resolution. An archived decision changes only that
    /// introduction's evidence, never the current contact gate. Authorization
    /// must still be current on delivery. This return value is not a credit proof.
    pub fn apply_resolution(
        &mut self,
        receipt: &ContactResolution,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        self.check_binding(member)?;
        let peer_id = &receipt.responder_id;
        let archive_index = if self
            .state
            .introductions
            .get(peer_id)
            .is_some_and(|entry| entry.id == receipt.introduction_id)
        {
            None
        } else {
            Some(
                self.state
                    .archived
                    .get(peer_id)
                    .and_then(|entries| {
                        entries
                            .iter()
                            .position(|entry| entry.id == receipt.introduction_id)
                    })
                    .ok_or(Error::InvalidState)?,
            )
        };
        let existing = match archive_index {
            Some(index) => &self
                .state
                .archived
                .get(peer_id)
                .ok_or(Error::InvalidState)?[index],
            None => self
                .state
                .introductions
                .get(peer_id)
                .ok_or(Error::InvalidState)?,
        };
        member.verify_contact_resolution(receipt, peer_id, &existing.id)?;
        if existing.strict.is_some()
            && receipt.kind == ContactResolutionKind::Answered
            && existing.decision.is_none()
        {
            return Err(Error::InvalidState);
        }
        let first_resolution = existing.decision.is_none();
        if let Some(decision) = existing.decision {
            if decision == receipt.kind {
                if let Some(stored) = &existing.inbound_receipt {
                    let previous: ContactResolution =
                        serde_json::from_slice(stored).map_err(|_| Error::InvalidStore)?;
                    if receipt.issued_at <= previous.issued_at {
                        return Ok(false);
                    }
                }
            }
            if decision != receipt.kind && receipt.kind != ContactResolutionKind::ClosedForever {
                return Err(Error::InvalidState);
            }
        }
        if archive_index.is_none()
            && receipt.kind == ContactResolutionKind::Answered
            && self.is_closed(peer_id)
        {
            return Err(Error::Admission);
        }
        let mut changed = self.duplicate();
        let entry = match archive_index {
            Some(index) => &mut changed
                .state
                .archived
                .get_mut(peer_id)
                .ok_or(Error::InvalidState)?[index],
            None => changed
                .state
                .introductions
                .get_mut(peer_id)
                .ok_or(Error::InvalidState)?,
        };
        entry.decision = Some(receipt.kind);
        entry.inbound_receipt =
            Some(serde_json::to_vec(receipt).map_err(|_| Error::InvalidMessage)?);
        if receipt.kind == ContactResolutionKind::ClosedForever
            && receipt_order(entry.outbound_receipt.as_deref())?.0 != 2
        {
            entry.outbound_receipt = None;
        }
        if archive_index.is_none() && receipt.kind == ContactResolutionKind::ClosedForever {
            changed.record_peer_close(peer_id);
            if changed
                .state
                .pending
                .as_ref()
                .is_some_and(|pending| &pending.inviter == peer_id)
            {
                changed.state.pending = None;
            }
        }
        changed.validate_state(member)?;
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(first_resolution)
    }

    /// Exact verified peer receipt retained locally for an eventual independent
    /// proof adapter. Never send these identifying bytes to a policy operator.
    pub fn inbound_resolution_receipt(&self, peer_id: &str) -> Option<&[u8]> {
        self.state
            .introductions
            .get(peer_id)?
            .inbound_receipt
            .as_deref()
    }

    /// Locally signed decision retained with its checkpoint for private delivery.
    pub fn outbound_resolution_receipt(&self, peer_id: &str) -> Option<&[u8]> {
        self.state
            .introductions
            .get(peer_id)?
            .outbound_receipt
            .as_deref()
    }

    /// Reissue an expired stored decision under this currently authorized
    /// device. The stable pair, nonce and decision cannot change. This creates
    /// no resolution or credit event; it only restores private delivery after
    /// certificate renewal. A fresh close can be transmitted once afterward.
    pub fn refresh_outbound_resolution(
        &mut self,
        peer_id: &str,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.check_binding(member)?;
        member.member_id()?;
        let entry = self
            .state
            .introductions
            .get(peer_id)
            .ok_or(Error::InvalidState)?;
        let stored = entry.outbound_receipt.as_ref().ok_or(Error::InvalidState)?;
        let previous: ContactResolution =
            serde_json::from_slice(stored).map_err(|_| Error::InvalidStore)?;
        if previous.responder_id != self.state.recipient_id
            || previous.peer_id != peer_id
            || previous.introduction_id != entry.id
            || previous.community_id != self.state.community_id
            || previous.issued_at == 0
            || previous.issued_at > member.authorization_time()?
        {
            return Err(Error::InvalidStore);
        }
        previous.verify_device_signature(member, previous.issued_at)?;
        if previous
            .verify_device_signature(member, member.authorization_time()?)
            .is_ok()
        {
            return Err(Error::InvalidState);
        }
        let refreshed = member.sign_contact_resolution(peer_id, &entry.id, previous.kind)?;
        let encoded = serde_json::to_vec(&refreshed).map_err(|_| Error::InvalidMessage)?;
        let mut changed = self.duplicate();
        let updated = changed
            .state
            .introductions
            .get_mut(peer_id)
            .ok_or(Error::InvalidState)?;
        updated.outbound_receipt = Some(encoded.clone());
        if previous.kind == ContactResolutionKind::ClosedForever {
            if let Some(strict) = &mut updated.strict {
                strict.close_sent = false;
            }
        }
        changed.validate_state(member)?;
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(encoded)
    }

    /// Private device-sync payload. It discloses contacts: carry it only inside
    /// an encrypted channel authenticated to another device of this same member.
    /// Member-controlled root authorization is required; an eligibility issuer's
    /// assertion alone cannot authorize a second device to modify this policy.
    pub fn export_contact_sync(&self, member: &Member) -> Result<Vec<u8>, Error> {
        use openmls_traits::signatures::Signer;
        self.check_binding(member)?;
        member.member_id()?;
        if member.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let mut sync = ContactSync {
            community_id: self.state.community_id.clone(),
            owner_id: self.state.recipient_id.clone(),
            issued_at: member.authorization_time()?,
            device_public_key: member.chat_public_key(),
            credential: member.private_identity_credential()?,
            known: self.state.known.clone(),
            closed: self.state.closed.clone(),
            introductions: self.state.introductions.clone(),
            directional: self.state.directional.clone(),
            archived: self.state.archived.clone(),
            live: self.state.live.clone(),
            reservations: self.state.reservations.clone(),
            signature: Vec::new(),
        };
        sync.signature = member
            .signer
            .sign(&Zeroizing::new(sync.signing_bytes()?))
            .map_err(|_| Error::Admission)?;
        let encoded = serde_json::to_vec(&sync).map_err(|_| Error::InvalidMessage)?;
        if encoded.len() > MAX_WIRE_BYTES {
            return Err(Error::InvalidMessage);
        }
        Ok(encoded)
    }

    /// Merge authenticated contacts and owner-controlled closure histories. A stale
    /// journal cannot erase a decision. Conflicting introduction nonces fail
    /// closed for explicit endpoint reconciliation. Replayed or stale device
    /// snapshots cannot remove a closure already known locally. This does
    /// not protect a device whose entire local store and all peers are rolled back.
    /// The host must persist before acknowledging synchronization to the peer.
    pub fn merge_contact_sync(
        &mut self,
        payload: &[u8],
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        use ed25519_dalek::{Signature, VerifyingKey};
        self.check_binding(member)?;
        if payload.len() > MAX_WIRE_BYTES || member.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let sync: ContactSync =
            serde_json::from_slice(payload).map_err(|_| Error::InvalidMessage)?;
        let now = member.authorization_time()?;
        if sync.community_id != self.state.community_id
            || sync.owner_id != self.state.recipient_id
            || sync.issued_at == 0
            || sync.issued_at > now
            || sync
                .closed
                .iter()
                .chain(&sync.known)
                .chain(sync.introductions.keys())
                .any(|id| !crate::admission::valid_member_id(id) || id == &sync.owner_id)
            || member.verify_private_identity_credential(
                &sync.credential,
                &sync.device_public_key,
                now,
            )? != sync.owner_id
        {
            return Err(Error::Admission);
        }
        let public: [u8; 32] = sync
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        VerifyingKey::from_bytes(&public)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &Zeroizing::new(sync.signing_bytes()?),
                &Signature::from_slice(&sync.signature).map_err(|_| Error::Admission)?,
            )
            .map_err(|_| Error::Admission)?;
        let incoming_state = Self {
            state: InboxState {
                publication_version: 0,
                community_id: sync.community_id.clone(),
                recipient_id: sync.owner_id.clone(),
                root_authorized: true,
                known: sync.known.clone(),
                blocked: BTreeSet::new(),
                closed: sync.closed.clone(),
                introductions: sync.introductions.clone(),
                pending: None,
                directional: sync.directional.clone(),
                archived: sync.archived.clone(),
                live: sync.live.clone(),
                reservations: sync.reservations.clone(),
            },
            runtime: live_policy::Runtime::default(),
        };
        incoming_state.validate_state(member)?;
        let mut changed = self.duplicate();
        changed.state.known.extend(sync.known.iter().cloned());
        if let Some(incoming) = &sync.reservations {
            changed
                .state
                .reservations
                .get_or_insert_with(Default::default)
                .merge(incoming)?;
        }
        if let Some(incoming) = &sync.live {
            changed
                .state
                .live
                .get_or_insert_with(Default::default)
                .merge(incoming)?;
        }
        changed.state.closed.extend(sync.closed.iter().cloned());
        for (peer, incoming) in &sync.directional {
            changed
                .state
                .directional
                .entry(peer.clone())
                .or_default()
                .merge(incoming)?;
        }
        for (peer, incoming) in &sync.archived {
            let archive = changed.state.archived.entry(peer.clone()).or_default();
            for record in incoming {
                if let Some(existing) = archive.iter_mut().find(|i| i.id == record.id) {
                    merge_archived_introduction(existing, record)?;
                } else {
                    archive.push(record.clone());
                }
            }
        }
        for (peer, incoming) in &sync.introductions {
            if changed
                .state
                .introductions
                .get(peer)
                .is_some_and(|i| i.id != incoming.id)
            {
                let selected = changed
                    .state
                    .directional
                    .get(peer)
                    .map(DirectionalContact::selected_nonce)
                    .transpose();
                match selected {
                    Ok(Some(Some(nonce))) if nonce == incoming.id => {
                        if let Some(old) = changed
                            .state
                            .introductions
                            .insert(peer.clone(), incoming.clone())
                        {
                            let archive = changed.state.archived.entry(peer.clone()).or_default();
                            if !archive.iter().any(|i| i.id == old.id) {
                                archive.push(old);
                            }
                        }
                    }
                    Ok(Some(Some(nonce)))
                        if changed
                            .state
                            .introductions
                            .get(peer)
                            .is_some_and(|i| i.id == nonce) =>
                    {
                        ()
                    }
                    _ => {
                        changed.mark_contact_conflict(peer);
                    }
                }
                continue;
            }
            if changed
                .state
                .introductions
                .get(peer)
                .is_some_and(|existing| match (&existing.strict, &incoming.strict) {
                    (Some(a), Some(b)) => {
                        a.role != b.role
                            || a.policy != b.policy
                            || a.initial_writer_key != b.initial_writer_key
                            || a.accounting_group_id != b.accounting_group_id
                    }
                    (None, None) => false,
                    _ => true,
                })
            {
                changed.mark_contact_conflict(peer);
                continue;
            }
            if let Some(existing) = changed.state.introductions.get_mut(peer) {
                if existing.id != incoming.id {
                    return Err(Error::InvalidState);
                }
                let local_receipt_time = receipt_order(existing.outbound_receipt.as_deref())?;
                let remote_receipt_time = receipt_order(incoming.outbound_receipt.as_deref())?;
                let previous_outbound = existing.outbound_receipt.clone();
                let strict = match (&existing.strict, &incoming.strict) {
                    (Some(local), Some(remote)) => {
                        if local.role != remote.role
                            || local.policy != remote.policy
                            || local.initial_writer_key != remote.initial_writer_key
                            || local.accounting_group_id != remote.accounting_group_id
                        {
                            return Err(Error::InvalidState);
                        }
                        let mut merged = local.clone();
                        merged.sent |= remote.sent;
                        merged.received |= remote.received;
                        merged.close_sent = if remote_receipt_time > local_receipt_time {
                            remote.close_sent
                        } else if local_receipt_time > remote_receipt_time {
                            local.close_sent
                        } else {
                            local.close_sent || remote.close_sent
                        };
                        Some(merged)
                    }
                    (None, None) => None,
                    _ => return Err(Error::InvalidState),
                };
                match (existing.decision, incoming.decision) {
                    (None, Some(_)) => *existing = incoming.clone(),
                    (
                        Some(ContactResolutionKind::Answered),
                        Some(ContactResolutionKind::ClosedForever),
                    ) => {
                        *existing = incoming.clone();
                    }
                    _ => (),
                }
                existing.strict = strict;
                if local_receipt_time.0 == 2 && local_receipt_time > remote_receipt_time {
                    existing.outbound_receipt = previous_outbound;
                }
                if existing.decision == incoming.decision {
                    if receipt_order(incoming.inbound_receipt.as_deref())?
                        > receipt_order(existing.inbound_receipt.as_deref())?
                    {
                        existing.inbound_receipt = incoming.inbound_receipt.clone();
                    }
                    if remote_receipt_time > local_receipt_time {
                        existing.outbound_receipt = incoming.outbound_receipt.clone();
                    }
                }
            } else {
                changed
                    .state
                    .introductions
                    .insert(peer.clone(), incoming.clone());
            }
        }
        for (peer, archive) in &mut changed.state.archived {
            if let Some(current) = changed.state.introductions.get(peer) {
                archive.retain(|old| old.id != current.id);
            }
        }
        if changed
            .state
            .pending
            .as_ref()
            .is_some_and(|p| changed.is_closed(&p.inviter))
        {
            changed.state.pending = None;
        }
        changed.validate_state(member)?;
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }

    fn excluded(&self) -> BTreeSet<String> {
        self.state
            .blocked
            .union(&self.state.closed)
            .cloned()
            .chain(
                self.state
                    .directional
                    .iter()
                    .filter(|(_, state)| state.blocked())
                    .map(|(peer, _)| peer.clone()),
            )
            .collect()
    }

    /// Enforce local contact exclusions before encrypting any new text. A group
    /// containing a closed member must remove that member before further sends.
    pub fn send(&self, member: &mut Member, text: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state.live.is_some() || self.state.reservations.is_some() {
            return Err(Error::Admission);
        }
        self.check_outbound(member)?;
        member.send(text)
    }

    pub fn send_bytes(&self, member: &mut Member, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if self.state.live.is_some() || self.state.reservations.is_some() {
            return Err(Error::Admission);
        }
        self.check_outbound(member)?;
        member.send_bytes(bytes)
    }

    fn check_exclusions(&self, member: &Member) -> Result<(), Error> {
        self.check_binding(member)?;
        if member
            .participants()?
            .iter()
            .any(|p| self.is_blocked(&p.member_id))
        {
            return Err(Error::Admission);
        }
        Ok(())
    }

    fn check_outbound(&self, member: &Member) -> Result<(), Error> {
        self.check_exclusions(member)?;
        self.check_unresolved(member)
    }

    fn check_unresolved(&self, member: &Member) -> Result<(), Error> {
        if member.participants()?.iter().any(|peer| {
            self.state
                .introductions
                .get(&peer.member_id)
                .is_some_and(|intro| intro.strict.is_some())
        }) {
            return Err(Error::Admission);
        }
        Ok(())
    }

    /// Validate a candidate conversation roster before publishing an invitation
    /// or a locally staged membership update. Hosts stage such mutations in an
    /// isolated checkpoint, check here, then durably commit before transmitting.
    pub fn check_group(&self, member: &Member) -> Result<(), Error> {
        self.check_reservation_roster(member)?;
        self.check_exclusions(member)
    }

    /// Reject excluded authenticated senders before publishing plaintext,
    /// changing receive ratchets, or appending history. A control message cannot
    /// silently reintroduce a closed identity under a different device key.
    pub fn receive(&self, member: &mut Member, wire: &[u8]) -> Result<Received, Error> {
        if self.state.live.is_some() || self.state.reservations.is_some() {
            return Err(Error::Admission);
        }
        self.check_binding(member)?;
        self.check_unresolved(member)?;
        member.receive_excluding(wire, &self.excluded())
    }

    fn check_binding(&self, recipient: &Member) -> Result<(), Error> {
        if self.state.recipient_id != recipient.stored_member_id()?
            || self.state.root_authorized != recipient.device_authorization()?.is_some()
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

    fn validate_state(&self, member: &Member) -> Result<(), Error> {
        self.check_binding(member)?;
        if self.state.publication_version > 9_007_199_254_740_991 {
            return Err(Error::InvalidStore);
        }
        if let Some(journal) = &self.state.live {
            journal.validate(member, &self.state.recipient_id)?;
        }
        if let Some(journal) = &self.state.reservations {
            journal.validate(&self.state.recipient_id, &self.state.community_id)?;
        }
        if self
            .state
            .known
            .iter()
            .chain(&self.state.blocked)
            .chain(&self.state.closed)
            .any(|id| !crate::admission::valid_member_id(id) || id == &self.state.recipient_id)
        {
            return Err(Error::InvalidStore);
        }
        for (peer, history) in &self.state.directional {
            if !crate::admission::valid_member_id(peer) || peer == &self.state.recipient_id {
                return Err(Error::InvalidStore);
            }
            history.validate(&self.state.recipient_id, peer, member)?;
            if !self.is_closed(peer) {
                if let Some(nonce) = history.selected_nonce()? {
                    if !self
                        .state
                        .introductions
                        .get(peer)
                        .is_some_and(|i| i.id == nonce && i.strict.is_some())
                    {
                        return Err(Error::InvalidStore);
                    }
                }
            }
        }
        for (peer, archive) in &self.state.archived {
            let mut nonces = BTreeSet::new();
            for introduction in archive {
                if !nonces.insert(introduction.id)
                    || self
                        .state
                        .introductions
                        .get(peer)
                        .is_some_and(|current| current.id == introduction.id)
                {
                    return Err(Error::InvalidStore);
                }
            }
        }
        for (peer, introduction, current) in self
            .state
            .introductions
            .iter()
            .map(|(p, i)| (p, i, true))
            .chain(
                self.state
                    .archived
                    .iter()
                    .flat_map(|(p, items)| items.iter().map(move |i| (p, i, false))),
            )
        {
            if !crate::admission::valid_member_id(peer)
                || peer == &self.state.recipient_id
                || (current
                    && introduction.decision == Some(ContactResolutionKind::ClosedForever)
                    && !self.is_closed(peer))
            {
                return Err(Error::InvalidStore);
            }
            if let Some(strict) = &introduction.strict {
                if !self.state.root_authorized
                    || strict.initial_writer_key.len() != 32
                    || strict.policy.response_deadline == 0
                    || strict.policy.response_deadline > 9_007_199_254_740_991
                    || strict.policy.max_intro_bytes == 0
                    || strict.policy.max_intro_bytes > crate::MAX_DATA_BYTES
                    || strict
                        .accounting_group_id
                        .as_ref()
                        .is_some_and(|id| id.is_empty() || id.len() > 256)
                    || (introduction.decision == Some(ContactResolutionKind::Answered)
                        && (!strict.sent || !strict.received))
                {
                    return Err(Error::InvalidStore);
                }
            }
            if let Some(bytes) = &introduction.outbound_receipt {
                if bytes.len() > 16 * 1024 {
                    return Err(Error::InvalidStore);
                }
                let receipt: ContactResolution =
                    serde_json::from_slice(bytes).map_err(|_| Error::InvalidStore)?;
                let sender_cancellation = introduction
                    .strict
                    .as_ref()
                    .is_some_and(|s| s.role == FirstContactRole::Initiator)
                    && (!current || self.is_closed(peer))
                    && receipt.kind == ContactResolutionKind::ClosedForever;
                if receipt.responder_id != self.state.recipient_id
                    || &receipt.peer_id != peer
                    || receipt.introduction_id != introduction.id
                    || (Some(receipt.kind) != introduction.decision && !sender_cancellation)
                    || receipt.community_id != self.state.community_id
                    || receipt.issued_at == 0
                    || receipt.issued_at > member.authorization_time()?
                {
                    return Err(Error::InvalidStore);
                }
                receipt
                    .verify_device_signature(member, receipt.issued_at)
                    .map_err(|_| Error::InvalidStore)?;
            }
            if let Some(bytes) = &introduction.inbound_receipt {
                if bytes.len() > 16 * 1024 {
                    return Err(Error::InvalidStore);
                }
                let receipt: ContactResolution =
                    serde_json::from_slice(bytes).map_err(|_| Error::InvalidStore)?;
                if &receipt.responder_id != peer
                    || receipt.peer_id != self.state.recipient_id
                    || receipt.community_id != self.state.community_id
                    || receipt.introduction_id != introduction.id
                    || introduction.decision.is_none()
                    || (Some(receipt.kind) != introduction.decision
                        && introduction.decision != Some(ContactResolutionKind::ClosedForever))
                    || receipt.issued_at == 0
                    || receipt.issued_at > member.authorization_time()?
                {
                    return Err(Error::InvalidStore);
                }
                receipt
                    .verify_device_signature(member, receipt.issued_at)
                    .map_err(|_| Error::InvalidStore)?;
            }
        }
        if let Some(pending) = &self.state.pending {
            if (pending.replacement.is_none()
                && (self.is_blocked(&pending.inviter) || self.is_known(&pending.inviter)))
                || self.state.blocked.contains(&pending.inviter)
                || !crate::admission::valid_member_id(&pending.inviter)
                || pending.recipient_redemption.is_empty()
                || pending.recipient_redemption.len() > 8192
                || pending.welcome.is_empty()
                || pending.welcome.len() > MAX_WIRE_BYTES
                || <[u8; 32]>::from(Sha256::digest(&pending.welcome)) != pending.welcome_hash
            {
                return Err(Error::InvalidStore);
            }
            if pending.replacement.is_some() {
                self.validate_pending_replacement(member, pending)
                    .map_err(|_| Error::InvalidStore)?;
                return Ok(());
            }
            // Authenticate pending bindings at restore without requiring old
            // admission to remain unexpired. accept rechecks current admission
            // before any spending, while expired pending data can be cancelled.
            let prepared = member
                .prepare_stored_join(&pending.welcome)
                .map_err(|_| Error::InvalidStore)?;
            if prepared.inviter != pending.inviter
                || prepared.contains_any(
                    &self.excluded(),
                    member.trust.as_ref().ok_or(Error::InvalidStore)?,
                    member.authorization_time()?,
                )?
            {
                return Err(Error::InvalidStore);
            }
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

    /// Export one encrypted checkpoint containing both policy and MLS state.
    pub fn publication_version(&self) -> u64 {
        self.state.publication_version
    }
    pub(crate) fn advance_publication(&mut self, expected: u64) -> Result<u64, Error> {
        if self.state.publication_version != expected || expected >= 9_007_199_254_740_991 {
            return Err(Error::InvalidStore);
        }
        self.state.publication_version = expected + 1;
        Ok(expected + 1)
    }
    pub fn snapshot(
        &self,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_state(member)?;
        self.seal(member, key, context)
    }

    pub fn restore(sealed: &[u8], key: &[u8; 32], context: &[u8]) -> Result<(Self, Member), Error> {
        Self::restore_with_clock(
            sealed,
            key,
            context,
            Arc::new(crate::lifecycle::SystemClock),
        )
    }

    pub fn restore_with_clock(
        sealed: &[u8],
        key: &[u8; 32],
        context: &[u8],
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, Member), Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bundle {
            inbox: InboxState,
            member: Vec<u8>,
        }
        let plaintext = crate::vault::open(sealed, key, &inbox_context(context)?)?;
        let bundle: Bundle = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        let member = Member::restore_with_clock(&bundle.member, key, context, clock)?;
        let mut inbox = Self {
            state: bundle.inbox,
            runtime: live_policy::Runtime::default(),
        };
        inbox.validate_state(&member)?;
        inbox.cancel_restored_live();
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

fn receipt_order(bytes: Option<&[u8]>) -> Result<(u8, u64), Error> {
    bytes
        .map(|bytes| {
            serde_json::from_slice::<ContactResolution>(bytes)
                .map(|receipt| {
                    (
                        match receipt.kind {
                            ContactResolutionKind::Answered => 1,
                            ContactResolutionKind::ClosedForever => 2,
                        },
                        receipt.issued_at,
                    )
                })
                .map_err(|_| Error::InvalidStore)
        })
        .transpose()
        .map(|order| order.unwrap_or((0, 0)))
}

fn merge_archived_introduction(
    existing: &mut Introduction,
    incoming: &Introduction,
) -> Result<(), Error> {
    if existing.id != incoming.id {
        return Err(Error::InvalidState);
    }
    let old_receipt = receipt_order(existing.outbound_receipt.as_deref())?;
    let new_receipt = receipt_order(incoming.outbound_receipt.as_deref())?;
    let previous_outbound = existing.outbound_receipt.clone();
    let strict = match (&existing.strict, &incoming.strict) {
        (Some(a), Some(b)) => {
            if a.role != b.role
                || a.policy != b.policy
                || a.initial_writer_key != b.initial_writer_key
                || a.accounting_group_id != b.accounting_group_id
            {
                return Err(Error::InvalidState);
            }
            let mut combined = a.clone();
            combined.sent |= b.sent;
            combined.received |= b.received;
            combined.close_sent = if new_receipt > old_receipt {
                b.close_sent
            } else if old_receipt > new_receipt {
                a.close_sent
            } else {
                a.close_sent || b.close_sent
            };
            Some(combined)
        }
        (None, None) => None,
        _ => return Err(Error::InvalidState),
    };
    if matches!(
        (existing.decision, incoming.decision),
        (None, Some(_))
            | (
                Some(ContactResolutionKind::Answered),
                Some(ContactResolutionKind::ClosedForever)
            )
    ) {
        existing.decision = incoming.decision;
        existing.outbound_receipt = incoming.outbound_receipt.clone();
    }
    if existing.decision == incoming.decision && new_receipt > old_receipt {
        existing.outbound_receipt = incoming.outbound_receipt.clone();
    }
    if old_receipt.0 == 2 && old_receipt > new_receipt {
        existing.outbound_receipt = previous_outbound;
    }
    if receipt_order(incoming.inbound_receipt.as_deref())?
        > receipt_order(existing.inbound_receipt.as_deref())?
    {
        existing.inbound_receipt = incoming.inbound_receipt.clone();
    }
    existing.strict = strict;
    Ok(())
}
