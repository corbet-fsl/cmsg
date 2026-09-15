//! Live-only application delivery integrated with the guarded contact journal.
use super::*;
use crate::live::{self, Body, Envelope};
use crate::{DeliveryStatus, LiveDelivery};

#[derive(Clone, Default)]
pub(super) struct Runtime {
    opening: BTreeMap<String, Envelope>,
    ready: BTreeSet<String>,
    pub(super) reservations: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    local: Envelope,
    peer: Envelope,
    ended: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    summary: LiveDelivery,
    digest: [u8; 32],
    wire_hash: [u8; 32],
    introduction: [u8; 32],
    issued_at: u64,
    resolution: Option<Vec<u8>>,
    data: Option<Envelope>,
    ack: Option<Envelope>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    session: [u8; 32],
    wire: Vec<u8>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    sessions: BTreeMap<String, Session>,
    deliveries: BTreeMap<String, Record>,
    controls: Vec<Control>,
    #[serde(default)]
    expired: BTreeSet<String>,
}
impl Journal {
    fn cancel(&mut self, session: &str) {
        if let Some(stored) = self.sessions.get_mut(session) {
            stored.ended = true;
        }
        for record in self.deliveries.values_mut() {
            if live::id(&record.summary.session_id) == session
                && record.summary.outgoing
                && record.summary.status == DeliveryStatus::Pending
            {
                record.summary.status = DeliveryStatus::CanceledUnconfirmed;
            }
        }
    }
    pub(super) fn validate(&self, member: &Member, owner: &str) -> Result<(), Error> {
        let now = member.authorization_time()?;
        for (id, stored) in &self.sessions {
            for envelope in [&stored.local, &stored.peer] {
                if envelope.issued_at > now {
                    return Err(Error::InvalidStore);
                }
                envelope.verify(member, envelope.issued_at)?;
            }
            if stored.local.owner != owner
                || live::id(&live::session(&stored.local, &stored.peer)?) != *id
            {
                return Err(Error::InvalidStore);
            }
        }
        for (id, record) in &self.deliveries {
            if *id != live::id(&record.summary.message_id)
                || record.summary.message_id == [0; 32]
                || record.digest == [0; 32]
                || record.summary.peer_id == owner
            {
                return Err(Error::InvalidStore);
            }
            let stored = self
                .sessions
                .get(&live::id(&record.summary.session_id))
                .ok_or(Error::InvalidStore)?;
            if stored.local.introduction != record.introduction
                || stored.peer.owner != record.summary.peer_id
                || record.issued_at == 0
                || record.issued_at > now
            {
                return Err(Error::InvalidStore);
            }
            if let Some(bytes) = &record.resolution {
                let receipt: ContactResolution =
                    serde_json::from_slice(bytes).map_err(|_| Error::InvalidStore)?;
                if !record.summary.outgoing
                    || receipt.responder_id != owner
                    || receipt.peer_id != record.summary.peer_id
                    || receipt.introduction_id != record.introduction
                    || receipt.kind != ContactResolutionKind::Answered
                    || receipt.issued_at < record.issued_at
                    || receipt.issued_at > now
                {
                    return Err(Error::InvalidStore);
                }
                receipt.verify_device_signature(member, receipt.issued_at)?;
            }
            if let Some(ack) = &record.ack {
                ack.verify(member, ack.issued_at)?;
                let expected = if record.summary.outgoing {
                    &stored.peer
                } else {
                    &stored.local
                };
                if ack.owner != expected.owner
                    || ack.peer != expected.peer
                    || ack.device != expected.device
                    || ack.credential != expected.credential
                    || ack.introduction != record.introduction
                    || ack.group != stored.local.group
                    || ack.issued_at > now
                    || ack.issued_at < record.issued_at
                    || !matches!(&ack.body,Body::Ack {session,message,digest} if *session==record.summary.session_id
                        && *message==record.summary.message_id && *digest==record.digest)
                {
                    return Err(Error::InvalidStore);
                }
            }
            if record.summary.status == DeliveryStatus::Accepted && record.ack.is_none() {
                return Err(Error::InvalidStore);
            }
            if !record.summary.outgoing {
                let data = record.data.as_ref().ok_or(Error::InvalidStore)?;
                data.verify(member, data.issued_at)?;
                if data.digest()? != record.digest
                    || data.owner != record.summary.peer_id
                    || data.peer != owner
                    || data.device != stored.peer.device
                    || data.credential != stored.peer.credential
                    || data.introduction != record.introduction
                    || data.group != stored.local.group
                    || data.issued_at > now
                    || data.issued_at != record.issued_at
                    || !matches!(&data.body,Body::Data {session,message,..} if *session==record.summary.session_id && *message==record.summary.message_id)
                    || record.summary.status != DeliveryStatus::Accepted
                {
                    return Err(Error::InvalidStore);
                }
            } else if record.data.is_some() {
                return Err(Error::InvalidStore);
            }
        }
        if self.controls.iter().any(|c| {
            c.wire.is_empty()
                || c.wire.len() > MAX_WIRE_BYTES
                || !self.sessions.contains_key(&live::id(&c.session))
        }) {
            return Err(Error::InvalidStore);
        }
        Ok(())
    }
    pub(super) fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.expired.extend(other.expired.iter().cloned());
        for (id, incoming) in &other.sessions {
            if let Some(local) = self.sessions.get_mut(id) {
                if local.local.digest()? != incoming.local.digest()?
                    || local.peer.digest()? != incoming.peer.digest()?
                {
                    return Err(Error::InvalidStore);
                }
                local.ended |= incoming.ended;
            } else {
                self.sessions.insert(id.clone(), incoming.clone());
            }
        }
        for (id, incoming) in &other.deliveries {
            if let Some(local) = self.deliveries.get_mut(id) {
                if local.digest != incoming.digest
                    || local.summary.session_id != incoming.summary.session_id
                    || local.summary.outgoing != incoming.summary.outgoing
                {
                    return Err(Error::InvalidStore);
                }
                if incoming.summary.status == DeliveryStatus::Accepted
                    || (local.summary.status == DeliveryStatus::Pending
                        && incoming.summary.status == DeliveryStatus::CanceledUnconfirmed)
                {
                    *local = incoming.clone();
                }
            } else {
                self.deliveries.insert(id.clone(), incoming.clone());
            }
        }
        Ok(())
    }
}

impl Inbox {
    pub fn new_live(member: &Member) -> Result<Self, Error> {
        let mut inbox = Self::new(member)?;
        inbox.state.live = Some(Journal::default());
        Ok(inbox)
    }
    pub fn live_delivery_enabled(&self) -> bool {
        self.state.live.is_some()
    }
    pub(crate) fn require_live_delivery(&mut self) {
        self.state.live.get_or_insert_with(Default::default);
    }
    /// Private outbox metadata for an atomic host transaction. Application
    /// records carry a session/message identity and must be purged on cancellation.
    pub fn live_outbox_metadata(&self, wires: &[Vec<u8>]) -> serde_json::Value {
        let entries:Vec<_>=wires.iter().map(|wire|{
            let record=self.state.live.as_ref().and_then(|j|j.deliveries.values().find(|r|r.summary.outgoing && r.wire_hash==live::hash(wire)));
            match record {Some(r)=>serde_json::json!({"kind":"application","messageId":r.summary.message_id,"sessionId":r.summary.session_id}),
                None=>serde_json::json!({"kind":"control"})}
        }).collect();
        let canceled: Vec<_> = self
            .live_deliveries()
            .into_iter()
            .filter(|r| r.outgoing && r.status == DeliveryStatus::CanceledUnconfirmed)
            .map(|r| r.message_id)
            .collect();
        serde_json::json!({"version":1,"liveOnly":self.live_delivery_enabled(),"entries":entries,"cancelApplicationIds":canceled})
    }
    pub fn live_deliveries(&self) -> Vec<LiveDelivery> {
        self.state
            .live
            .as_ref()
            .map(|j| {
                j.deliveries
                    .values()
                    .map(|r| {
                        let mut summary = r.summary.clone();
                        if summary.outgoing
                            && summary.status == DeliveryStatus::Pending
                            && (!self.runtime.ready.contains(&live::id(&summary.session_id))
                                || j.sessions
                                    .get(&live::id(&summary.session_id))
                                    .is_none_or(|s| {
                                        s.ended
                                            || self.is_blocked(&s.peer.owner)
                                            || self
                                                .state
                                                .introductions
                                                .get(&s.peer.owner)
                                                .map(|i| i.id)
                                                != Some(s.local.introduction)
                                    }))
                        {
                            summary.status = DeliveryStatus::CanceledUnconfirmed;
                        }
                        summary
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn pending_live_controls(&self) -> Vec<Vec<u8>> {
        self.state
            .live
            .as_ref()
            .map(|j| j.controls.iter().map(|c| c.wire.clone()).collect())
            .unwrap_or_default()
    }
    fn opening_sessions(&self, nonce: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        self.state
            .live
            .as_ref()
            .map(|j| {
                j.sessions
                    .values()
                    .filter(|s| matches!(&s.local.body,Body::Hello {nonce:n,..} if n==nonce))
                    .filter_map(|s| live::session(&s.local, &s.peer).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn pending_live_controls_for(&self, nonce: &[u8; 32]) -> Vec<Vec<u8>> {
        let sessions = self.opening_sessions(nonce);
        self.state
            .live
            .as_ref()
            .map(|j| {
                j.controls
                    .iter()
                    .filter(|c| sessions.contains(&c.session))
                    .map(|c| c.wire.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn clear_live_controls_for(
        &mut self,
        member: &Member,
        nonce: &[u8; 32],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let sessions = self.opening_sessions(nonce);
        let mut changed = self.duplicate();
        changed
            .state
            .live
            .as_mut()
            .ok_or(Error::InvalidState)?
            .controls
            .retain(|c| !sessions.contains(&c.session));
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn live_sessions(&self) -> Vec<[u8; 32]> {
        self.runtime
            .ready
            .iter()
            .filter(|id| {
                self.state
                    .live
                    .as_ref()
                    .and_then(|j| j.sessions.get(*id))
                    .is_some_and(|s| !s.ended)
            })
            .filter_map(|id| {
                data_encoding::BASE64URL_NOPAD
                    .decode(id.as_bytes())
                    .ok()?
                    .try_into()
                    .ok()
            })
            .collect()
    }
    pub fn live_opening_nonce(&self, peer_device: &[u8]) -> Option<[u8; 32]> {
        let envelope = self
            .runtime
            .opening
            .get(&data_encoding::BASE64URL_NOPAD.encode(peer_device))?;
        if let Body::Hello { nonce, .. } = &envelope.body {
            Some(*nonce)
        } else {
            None
        }
    }
    pub fn cancel_live_opening(
        &mut self,
        member: &Member,
        nonce: &[u8; 32],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut changed = self.duplicate();
        changed
            .runtime
            .opening
            .retain(|_, e| !matches!(&e.body,Body::Hello {nonce:n,..} if n==nonce));
        let ids: Vec<_> = changed
            .state
            .live
            .as_ref()
            .ok_or(Error::InvalidState)?
            .sessions
            .iter()
            .filter(|(_, s)| matches!(&s.local.body,Body::Hello {nonce:n,..} if n==nonce))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            changed.retire_live(&id);
        }
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }
    /// Copy transient connection permissions only while staging this same running
    /// client. Deserializing a checkpoint never calls this method.
    pub(crate) fn copy_live_runtime(&mut self, original: &Inbox) {
        self.runtime = original.runtime.clone();
        self.state.live = original.state.live.clone();
    }
    pub(super) fn cancel_restored_live(&mut self) {
        if let Some(journal) = &mut self.state.live {
            let ids: Vec<_> = journal.sessions.keys().cloned().collect();
            for id in ids {
                journal.cancel(&id);
            }
            journal.controls.clear();
        }
    }
    pub fn accepted_live_history(&self) -> Vec<crate::DataMessage> {
        self.state
            .live
            .as_ref()
            .map(|j| {
                j.deliveries
                    .values()
                    .filter_map(|r| {
                        if r.summary.outgoing || r.summary.status != DeliveryStatus::Accepted {
                            return None;
                        }
                        let data = r.data.as_ref()?;
                        let Body::Data { payload, .. } = &data.body else {
                            return None;
                        };
                        Some(crate::DataMessage {
                            member_id: data.owner.clone(),
                            bytes: payload.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn retransmit_live_ack(
        &mut self,
        member: &mut Member,
        message: &[u8; 32],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let record = self
            .state
            .live
            .as_ref()
            .and_then(|j| j.deliveries.get(&live::id(message)))
            .ok_or(Error::InvalidState)?;
        if record.summary.outgoing {
            return Err(Error::Admission);
        }
        let ack = record.ack.as_ref().ok_or(Error::InvalidState)?;
        let mut candidate = member.staged_copy(key, context)?;
        let wire = candidate.send_live(ack)?;
        let mut changed = self.duplicate();
        changed.state.live.as_mut().unwrap().controls.push(Control {
            session: record.summary.session_id,
            wire: wire.clone(),
        });
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *member = candidate;
        *self = changed;
        Ok(wire)
    }
    pub fn end_live_session(
        &mut self,
        member: &mut Member,
        session: &[u8; 32],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let stored = self
            .state
            .live
            .as_ref()
            .and_then(|j| j.sessions.get(&live::id(session)))
            .ok_or(Error::InvalidState)?;
        let end = member.sign_live(
            &stored.peer.owner,
            &stored.local.introduction,
            Body::End { session: *session },
        )?;
        let mut candidate = member.staged_copy(key, context)?;
        let wire = candidate.send_live(&end)?;
        let mut changed = self.duplicate();
        changed.retire_live(&live::id(session));
        changed.state.live.as_mut().unwrap().controls.push(Control {
            session: *session,
            wire: wire.clone(),
        });
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *member = candidate;
        *self = changed;
        Ok(wire)
    }
    pub fn clear_live_controls(
        &mut self,
        member: &Member,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut changed = self.duplicate();
        changed
            .state
            .live
            .as_mut()
            .ok_or(Error::InvalidState)?
            .controls
            .clear();
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn begin_live_session(
        &mut self,
        member: &mut Member,
        peer_device: &[u8],
        until: u64,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        let peer = self.contact_peer(member)?;
        self.check_exclusions(member)?;
        self.check_selected_group(&peer, member)?;
        if self.state.live.is_none()
            || !member
                .participants()?
                .iter()
                .any(|p| p.member_id == peer && p.chat_public_key == peer_device)
            || until <= member.authorization_time()?
        {
            return Err(Error::Admission);
        }
        let introduction = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?
            .id;
        let hello = member.sign_live(
            &peer,
            &introduction,
            Body::Hello {
                nonce: live::random()?,
                until,
            },
        )?;
        let mut candidate = member.staged_copy(key, context)?;
        let wire = candidate.send_live(&hello)?;
        let mut changed = self.duplicate();
        changed
            .runtime
            .opening
            .insert(data_encoding::BASE64URL_NOPAD.encode(peer_device), hello);
        let old: Vec<_> = changed
            .state
            .live
            .as_ref()
            .unwrap()
            .sessions
            .iter()
            .filter(|(_, s)| s.peer.device == peer_device)
            .map(|(id, _)| id.clone())
            .collect();
        for id in old {
            changed.retire_live(&id);
        }
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *member = candidate;
        *self = changed;
        Ok(wire)
    }
    pub(super) fn expire_live_introduction(&mut self, peer: &str, nonce: &[u8; 32]) -> bool {
        let Some(journal) = &mut self.state.live else {
            return false;
        };
        let inserted = journal.expired.insert(live::id(nonce));
        let ids: Vec<_> = journal
            .sessions
            .iter()
            .filter(|(_, s)| s.peer.owner == peer && s.local.introduction == *nonce)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.retire_live(&id);
        }
        inserted
    }
    pub(super) fn expire_live_sessions(&mut self, now: u64) -> usize {
        let ids:Vec<_>=self.state.live.as_ref().map(|j|j.sessions.iter().filter(|(_,s)|!s.ended &&
            matches!((&s.local.body,&s.peer.body),(Body::Hello {until:a,..},Body::Hello {until:b,..}) if now>=*a || now>=*b))
            .map(|(id,_)|id.clone()).collect()).unwrap_or_default();
        for id in &ids {
            self.retire_live(id);
        }
        ids.len()
    }
    fn retire_live(&mut self, id: &str) {
        self.runtime.ready.remove(id);
        if let Some(journal) = &mut self.state.live {
            journal.cancel(id);
        }
    }
    /// Loss is evidence of local unavailability, never non-delivery or a refund.
    pub fn lose_live_session(
        &mut self,
        member: &Member,
        session: &[u8; 32],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check_binding(member)?;
        let mut changed = self.duplicate();
        changed.retire_live(&live::id(session));
        persist(&changed.seal(member, key, context)?)?;
        *self = changed;
        Ok(())
    }
    pub fn can_transmit_live_wire(&self, wire: &[u8], member: &Member) -> Result<bool, Error> {
        let Some(journal) = &self.state.live else {
            return Ok(true);
        };
        if let Some(record) = journal
            .deliveries
            .values()
            .find(|r| r.summary.outgoing && r.wire_hash == live::hash(wire))
        {
            return Ok(record.summary.status == DeliveryStatus::Pending
                && self
                    .session_ready(&record.summary.session_id, member)
                    .is_ok());
        }
        // Unknown bytes are never authorized as restored live application outbox.
        Ok(journal.controls.iter().any(|control| control.wire == wire))
    }
    fn session_ready(&self, id: &[u8; 32], member: &Member) -> Result<&Session, Error> {
        let id = live::id(id);
        let s = self
            .state
            .live
            .as_ref()
            .and_then(|j| j.sessions.get(&id))
            .ok_or(Error::Admission)?;
        let now = member.authorization_time()?;
        let active = matches!((&s.local.body,&s.peer.body),(Body::Hello {until:a,..},Body::Hello {until:b,..}) if now<*a && now<*b);
        if s.ended
            || !self.runtime.ready.contains(&id)
            || !active
            || s.local.device != member.chat_public_key()
            || s.local.group != member.policy_group_id()?
            || self.is_blocked(&s.peer.owner)
            || self.state.introductions.get(&s.peer.owner).map(|i| i.id)
                != Some(s.local.introduction)
        {
            return Err(Error::Admission);
        }
        Ok(s)
    }
    /// Send through one authenticated device session; never select another stream.
    pub fn send_live_bytes(
        &mut self,
        member: &mut Member,
        session: &[u8; 32],
        bytes: &[u8],
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        if bytes.is_empty() || bytes.len() > crate::MAX_DATA_BYTES {
            return Err(Error::InvalidMessage);
        }
        self.apply_deadlines(member, key, context, |checkpoint| persist(checkpoint, &[]))?;
        self.send_live_data(member, bytes, false, Some(session), key, context, persist)
    }
    pub fn live_session_for_opening(&self, nonce: &[u8; 32]) -> Option<[u8; 32]> {
        self.live_sessions().into_iter().find(|sid| {
            self.state
                .live
                .as_ref()
                .and_then(|j| j.sessions.get(&live::id(sid)))
                .is_some_and(|s| matches!(&s.local.body,Body::Hello {nonce:n,..} if n==nonce))
        })
    }
    pub(super) fn send_live_data(
        &mut self,
        member: &mut Member,
        bytes: &[u8],
        text: bool,
        selected: Option<&[u8; 32]>,
        key: &[u8; 32],
        context: &[u8],
        mut persist: impl FnMut(&[u8], &[u8]) -> Result<(), Error>,
    ) -> Result<Vec<u8>, Error> {
        self.check_reservation_release(member)?;
        let peer = self.contact_peer(member)?;
        self.check_exclusions(member)?;
        self.check_selected_group(&peer, member)?;
        let sid = match selected {
            Some(id) => {
                self.session_ready(id, member)?;
                *id
            }
            None => self
                .live_sessions()
                .into_iter()
                .find(|id| self.session_ready(id, member).is_ok())
                .ok_or(Error::Admission)?,
        };
        let intro = self
            .state
            .introductions
            .get(&peer)
            .ok_or(Error::InvalidState)?;
        let strict = intro.strict.as_ref().ok_or(Error::InvalidState)?;
        if intro.decision.is_none()
            && (member.authorization_time()? >= strict.policy.response_deadline
                || self
                    .state
                    .live
                    .as_ref()
                    .unwrap()
                    .expired
                    .contains(&live::id(&intro.id)))
        {
            return Err(Error::Admission);
        }
        if intro.decision.is_none()
            && (bytes.len() > strict.policy.max_intro_bytes
                || match strict.role {
                    FirstContactRole::Initiator => {
                        strict.sent || strict.initial_writer_key != member.chat_public_key()
                    }
                    FirstContactRole::Recipient => {
                        !strict.received
                            || self
                                .state
                                .live
                                .as_ref()
                                .unwrap()
                                .deliveries
                                .values()
                                .any(|r| {
                                    r.summary.outgoing
                                        && r.introduction == intro.id
                                        && r.resolution.is_some()
                                        && r.summary.status == DeliveryStatus::Pending
                                        && self.session_ready(&r.summary.session_id, member).is_ok()
                                })
                    }
                })
        {
            return Err(Error::Admission);
        }
        let message = live::random()?;
        let envelope = member.sign_live(
            &peer,
            &intro.id,
            Body::Data {
                session: sid,
                message,
                text,
                payload: bytes.to_vec(),
            },
        )?;
        let resolution = if intro.decision.is_none() && strict.role == FirstContactRole::Recipient {
            Some(
                serde_json::to_vec(&member.sign_contact_resolution(
                    &peer,
                    &intro.id,
                    ContactResolutionKind::Answered,
                )?)
                .map_err(|_| Error::InvalidMessage)?,
            )
        } else {
            None
        };
        let mut candidate = member.staged_copy(key, context)?;
        let wire = candidate.send_live(&envelope)?;
        let mut changed = self.duplicate();
        changed
            .state
            .introductions
            .get_mut(&peer)
            .unwrap()
            .strict
            .as_mut()
            .unwrap()
            .sent = true;
        changed.state.live.as_mut().unwrap().deliveries.insert(
            live::id(&message),
            Record {
                summary: LiveDelivery {
                    message_id: message,
                    session_id: sid,
                    peer_id: peer,
                    outgoing: true,
                    status: DeliveryStatus::Pending,
                },
                digest: envelope.digest()?,
                wire_hash: live::hash(&wire),
                introduction: intro.id,
                issued_at: envelope.issued_at,
                resolution,
                data: None,
                ack: None,
            },
        );
        changed.validate_state(&candidate)?;
        persist(&changed.seal(&candidate, key, context)?, &wire)?;
        *member = candidate;
        *self = changed;
        Ok(wire)
    }
    pub(super) fn receive_live_record(
        &mut self,
        member: &mut Member,
        bytes: &[u8],
        peer: &str,
    ) -> Result<Received, Error> {
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidMessage)?;
        if envelope.owner != peer || envelope.peer != self.state.recipient_id {
            return Err(Error::Admission);
        }
        let now = member.authorization_time()?;
        let historical = matches!(&envelope.body, Body::Ack { .. });
        envelope.verify(member, if historical { envelope.issued_at } else { now })?;
        if envelope.issued_at > now {
            return Err(Error::Admission);
        }
        if !historical
            && (envelope.group != member.policy_group_id()?
                || self.state.introductions.get(peer).map(|i| i.id) != Some(envelope.introduction))
        {
            return Err(Error::Admission);
        }
        if self.state.live.is_none() {
            return Err(Error::Admission);
        }
        match &envelope.body {
            Body::Hello { nonce, until } => {
                if self.is_blocked(peer) || now >= *until {
                    return Err(Error::Admission);
                }
                let local = self
                    .runtime
                    .opening
                    .get(&data_encoding::BASE64URL_NOPAD.encode(&envelope.device))
                    .ok_or(Error::Admission)?
                    .clone();
                let Body::Hello {
                    nonce: ours,
                    until: our_until,
                } = &local.body
                else {
                    return Err(Error::InvalidState);
                };
                if now >= *our_until {
                    return Err(Error::Admission);
                }
                let sid = live::session(&local, &envelope)?;
                let old: Vec<_> = self
                    .state
                    .live
                    .as_ref()
                    .unwrap()
                    .sessions
                    .iter()
                    .filter(|(id, s)| s.peer.device == envelope.device && **id != live::id(&sid))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in old {
                    self.retire_live(&id);
                }
                let ready = member.sign_live(
                    peer,
                    &envelope.introduction,
                    Body::Ready {
                        nonce: *ours,
                        peer_nonce: *nonce,
                    },
                )?;
                let wire = member.send_live(&ready)?;
                let journal = self.state.live.as_mut().unwrap();
                let session_id = sid;
                let sid = live::id(&sid);
                if journal.sessions.get(&sid).is_some_and(|s| s.ended) {
                    return Err(Error::Admission);
                }
                journal.sessions.entry(sid).or_insert(Session {
                    local,
                    peer: envelope.clone(),
                    ended: false,
                });
                journal.controls.push(Control {
                    session: session_id,
                    wire,
                });
                Ok(Received::LiveControl)
            }
            Body::Ready { nonce, peer_nonce } => {
                let (id,stored)=self.state.live.as_ref().unwrap().sessions.iter().find(|(_,s)|s.peer.device==envelope.device &&
                    matches!((&s.local.body,&s.peer.body),(Body::Hello {nonce:a,..},Body::Hello {nonce:b,..}) if a==peer_nonce && b==nonce)).ok_or(Error::Admission)?;
                if stored.ended
                    || stored.local.group != envelope.group
                    || stored.local.introduction != envelope.introduction
                    || self
                        .runtime
                        .opening
                        .get(&data_encoding::BASE64URL_NOPAD.encode(&envelope.device))
                        .map(|e| e.digest())
                        .transpose()?
                        != Some(stored.local.digest()?)
                {
                    return Err(Error::Admission);
                }
                self.runtime.ready.insert(id.clone());
                Ok(Received::LiveControl)
            }
            Body::Data {
                session,
                message,
                text,
                payload,
            } => {
                self.check_reservation_release(member)?;
                let stored = self.session_ready(session, member)?;
                if stored.peer.device != envelope.device
                    || stored.peer.credential != envelope.credential
                {
                    return Err(Error::Admission);
                }
                let digest = envelope.digest()?;
                let id = live::id(message);
                if self
                    .state
                    .live
                    .as_ref()
                    .unwrap()
                    .deliveries
                    .contains_key(&id)
                {
                    return Err(Error::Admission);
                }
                let entry = self
                    .state
                    .introductions
                    .get_mut(peer)
                    .ok_or(Error::InvalidState)?;
                let strict = entry.strict.as_mut().ok_or(Error::InvalidState)?;
                if entry.decision.is_none() {
                    if now >= strict.policy.response_deadline
                        || self
                            .state
                            .live
                            .as_ref()
                            .unwrap()
                            .expired
                            .contains(&live::id(&entry.id))
                    {
                        return Err(Error::Admission);
                    }
                    if payload.len() > strict.policy.max_intro_bytes
                        || match strict.role {
                            FirstContactRole::Recipient => strict.received,
                            FirstContactRole::Initiator => !strict.sent,
                        }
                    {
                        return Err(Error::Admission);
                    }
                    strict.received = true;
                    if strict.role == FirstContactRole::Initiator {
                        entry.decision = Some(ContactResolutionKind::Answered);
                    }
                }
                let ack = member.sign_live(
                    peer,
                    &envelope.introduction,
                    Body::Ack {
                        session: *session,
                        message: *message,
                        digest,
                    },
                )?;
                let wire = member.send_live(&ack)?;
                if *text {
                    member.remember_policy_text(peer, payload)?;
                }
                let journal = self.state.live.as_mut().unwrap();
                journal.controls.push(Control {
                    session: *session,
                    wire,
                });
                journal.deliveries.insert(
                    id,
                    Record {
                        summary: LiveDelivery {
                            message_id: *message,
                            session_id: *session,
                            peer_id: peer.to_owned(),
                            outgoing: false,
                            status: DeliveryStatus::Accepted,
                        },
                        digest,
                        wire_hash: [0; 32],
                        introduction: envelope.introduction,
                        issued_at: envelope.issued_at,
                        resolution: None,
                        data: Some(envelope.clone()),
                        ack: Some(ack),
                    },
                );
                Ok(if *text {
                    Received::Text(crate::TextMessage {
                        member_id: peer.to_owned(),
                        text: crate::validate_text(payload)?.to_owned(),
                    })
                } else {
                    Received::Bytes(crate::DataMessage {
                        member_id: peer.to_owned(),
                        bytes: payload.clone(),
                    })
                })
            }
            Body::Ack {
                session,
                message,
                digest,
            } => {
                let journal = self.state.live.as_mut().unwrap();
                let stored = journal
                    .sessions
                    .get(&live::id(session))
                    .ok_or(Error::Admission)?;
                if stored.peer.device != envelope.device
                    || stored.peer.credential != envelope.credential
                {
                    return Err(Error::Admission);
                }
                let record = journal
                    .deliveries
                    .get_mut(&live::id(message))
                    .ok_or(Error::Admission)?;
                if !record.summary.outgoing
                    || record.summary.session_id != *session
                    || record.digest != *digest
                    || record.introduction != envelope.introduction
                    || stored.local.group != envelope.group
                    || envelope.issued_at < record.issued_at
                {
                    return Err(Error::Admission);
                }
                record.summary.status = DeliveryStatus::Accepted;
                record.ack = Some(envelope.clone());
                if let Some(entry) = self.state.introductions.get_mut(peer) {
                    if entry.id == record.introduction
                        && entry.decision.is_none()
                        && entry
                            .strict
                            .as_ref()
                            .is_some_and(|s| now < s.policy.response_deadline)
                        && !journal.expired.contains(&live::id(&entry.id))
                    {
                        if let Some(resolution) = &record.resolution {
                            entry.decision = Some(ContactResolutionKind::Answered);
                            entry.outbound_receipt = Some(resolution.clone());
                        }
                    }
                }
                Ok(Received::LiveControl)
            }
            Body::End { session } => {
                let stored = self
                    .state
                    .live
                    .as_ref()
                    .unwrap()
                    .sessions
                    .get(&live::id(session))
                    .ok_or(Error::Admission)?;
                if stored.peer.device != envelope.device {
                    return Err(Error::Admission);
                }
                self.retire_live(&live::id(session));
                Ok(Received::LiveControl)
            }
        }
    }
}
