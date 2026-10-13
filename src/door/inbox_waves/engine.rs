//! The wave transitions on one device. Every function takes the already
//! locked Store and the member's purpose keys; it writes only through the
//! owners (Waves, Contacts, Threads) and through the desk, and a member's
//! action is durable before any proof exists.
//!
//! Crash order: an owner commit may be followed by the desk commit. Every
//! owner step is idempotent for a repeated message (`Replay` is a step already
//! done), so a crash between the two is repaired by running the step again.
use super::super::*;
use super::desk::{Desk, Session, KEY, OWNER};
use super::ports::{Policy, WavePorts};
use super::types::*;
use ckmg::{Authority, Binding, Clock, Entropy, KeyHandle, Keys, Lineage, SecureStore};
use cwlt::wave::{WaveOutcome, WaveOutcomeStatement, WaveStatement};
use cwst::{backend::Backend, Change, Store};

/// Everything one transition needs, borrowed for its duration.
pub(crate) struct Env<'a, S, C, R, A, B: Backend> {
    pub inbox: &'a cnbx::Inbox,
    pub binding: &'a Binding,
    pub keys: &'a mut Keys<S, C, R, A>,
    pub store: &'a mut Store<B>,
    pub ports: &'a dyn WavePorts,
    pub contacts: &'a KeyHandle,
    pub threads: &'a KeyHandle,
    pub delivery: &'a KeyHandle,
}

/// Map an owner refusal to the Door's stable codes. A conflicting or unknown
/// write is reconciled by the caller, never retried as a new operation.
pub(crate) fn inbox_error(error: cnbx::Error) -> ErrorCode {
    match error {
        cnbx::Error::Contacts(cnbx::ContactError::Unavailable)
        | cnbx::Error::Threads(cthr::Error::Unavailable) => ErrorCode::Unavailable,
        cnbx::Error::Contacts(cnbx::ContactError::Storage | cnbx::ContactError::Conflict)
        | cnbx::Error::Threads(cthr::Error::Storage | cthr::Error::Conflict)
        | cnbx::Error::Waves(cnbx::WaveError::Storage | cnbx::WaveError::Conflict) => {
            ErrorCode::Reconcile
        }
        cnbx::Error::Contacts(cnbx::ContactError::Limit)
        | cnbx::Error::Waves(cnbx::WaveError::Limit) => ErrorCode::Capacity,
        cnbx::Error::Waves(cnbx::WaveError::Clock) => ErrorCode::Clock,
        cnbx::Error::Contacts(cnbx::ContactError::Authority)
        | cnbx::Error::Threads(cthr::Error::Authority) => ErrorCode::Unauthorized,
        _ => ErrorCode::Refused,
    }
}

fn replayed(error: &cnbx::Error) -> bool {
    matches!(error, cnbx::Error::Waves(cnbx::WaveError::Replay))
}

fn now() -> Result<u64> {
    Clock::now(&mut custody::SystemClock).map_err(|_| ErrorCode::Clock)
}

fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    Entropy::fill(&mut ckmg::SystemEntropy, &mut bytes).map_err(|_| ErrorCode::Unavailable)?;
    Ok(bytes)
}

fn operation(nonce: &[u8; 32], step: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"cmsg.wave-step.v1");
    hash.update(nonce);
    hash.update(step.as_bytes());
    hash.finalize().into()
}

fn blob_statement<T: serde::de::DeserializeOwned>(blob: &Blob) -> Result<T> {
    serde_json::from_slice(&blob.statement).map_err(|_| ErrorCode::InvalidRequest)
}

/// The community-wide ordered contexts of one wave, derived from the exchanged
/// public terms. Both devices derive the same pair.
fn contexts(
    binding: &Binding,
    session: &Session,
    me: [u8; 32],
) -> Result<(cnbx::WaveContext, cnbx::WaveContext)> {
    let terms = session.terms.as_ref().ok_or(ErrorCode::Refused)?;
    let peer = cnbx::member_digest_of(&session.peer).map_err(inbox_error)?;
    let (sender, recipient) = if session.role == 0 {
        (me, peer)
    } else {
        (peer, me)
    };
    let h = &session.hello;
    let community: [u8; 32] = Sha256::digest(binding.community().as_bytes()).into();
    let sender_context = cnbx::WaveContext {
        community,
        owner: sender,
        peer: recipient,
        role: 0,
        nonce: session.nonce,
        group: h.group,
        contact_policy: h.contact_policy,
        history: h.history,
        challenge: h.sender_challenge,
        opened_at: h.opened_at,
        expires_at: h.expires_at,
        owner_authority: h.sender_authority,
        peer_authority: terms.recipient_authority,
    };
    let recipient_context = cnbx::WaveContext {
        owner: recipient,
        peer: sender,
        role: 1,
        challenge: terms.recipient_challenge,
        owner_authority: terms.recipient_authority,
        peer_authority: h.sender_authority,
        ..sender_context.clone()
    };
    Ok((sender_context, recipient_context))
}

/// Lineage of the member itself plus the ports' current view of peers.
pub(crate) struct Devices<'a> {
    pub own: Lineage,
    pub ports: &'a dyn WavePorts,
}
impl cnbx::DeviceAuthority for Devices<'_> {
    async fn current(
        &mut self,
        binding: &Binding,
    ) -> std::result::Result<Lineage, cnbx::ContactError> {
        if binding.member() == self.own.binding.member() {
            return if *binding == self.own.binding {
                Ok(self.own.clone())
            } else {
                Err(cnbx::ContactError::Authority)
            };
        }
        self.ports
            .peer_lineage(binding)
            .await
            .map_err(|code| match code {
                ErrorCode::Unauthorized | ErrorCode::Refused => cnbx::ContactError::Authority,
                _ => cnbx::ContactError::Unavailable,
            })
    }
}

struct Own<'a>(&'a dyn WavePorts);
impl cnbx::OwnRecord for Own<'_> {
    async fn matches_newest_epoch(&mut self, binding: &Binding) -> std::result::Result<(), ()> {
        self.0.own_record(binding).await.map_err(|_| ())
    }
}

impl<'a, S, C, R, A, B> Env<'a, S, C, R, A, B>
where
    S: SecureStore,
    C: Clock,
    R: Entropy,
    A: Authority,
    B: Backend,
{
    fn me(&self) -> Result<[u8; 32]> {
        self.inbox.member_digest().map_err(inbox_error)
    }

    async fn devices(&mut self) -> Result<Devices<'a>> {
        let own = self.keys.lineage().await.map_err(facades::keys_error)?;
        Ok(Devices {
            own,
            ports: self.ports,
        })
    }

    async fn write_desk(&mut self, desk: &Desk, op: [u8; 32]) -> Result<()> {
        let bytes = desk.encode()?;
        let expected = self.store.version().map_err(|_| ErrorCode::Unavailable)?;
        self.store
            .commit(
                expected,
                op,
                &[Change::Put {
                    owner: OWNER,
                    key: KEY,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .map(|_| ())
            .map_err(|_| ErrorCode::Reconcile)
    }

    /// The device refuses every wave exchange with a peer this member blocked,
    /// before anything is countersigned or sent. Blocks live in Contacts.
    pub(crate) fn refuse_blocked(&self, peer: &str) -> Result<()> {
        let relation = self
            .inbox
            .contacts(self.store)
            .and_then(|contacts| contacts.relation(peer))
            .map_err(inbox_error)?;
        if relation.state == cnbx::ContactState::Blocked {
            return Err(ErrorCode::Refused);
        }
        Ok(())
    }

    async fn check_peer(&mut self, peer: &str) -> Result<()> {
        let peer_binding =
            Binding::new(self.binding.community(), peer).map_err(|_| ErrorCode::InvalidRequest)?;
        if peer == self.binding.member() {
            return Err(ErrorCode::InvalidRequest);
        }
        cnbx::member_digest_of(peer).map_err(inbox_error)?;
        self.refuse_blocked(peer)?;
        self.ports.peer_lineage(&peer_binding).await.map(|_| ())
    }

    // ---- member actions ---------------------------------------------------

    /// Start a wave to `peer`. Returns at once; the reservation proof follows
    /// in the background.
    pub async fn send(&mut self, peer: &str) -> Result<WaveStatus> {
        self.check_peer(peer).await?;
        let now = now()?;
        let policy: Policy = self.ports.policy(now)?;
        let mut desk = Desk::load(self.store)?;
        let nonce = random()?;
        let hello = Hello {
            conversation: random()?,
            group: policy.group,
            contact_policy: policy.contact_policy,
            history: policy.history,
            opened_at: now,
            expires_at: now
                .checked_add(policy.lifetime)
                .ok_or(ErrorCode::InvalidRequest)?,
            sender_authority: policy.authority,
            sender_challenge: random()?,
        };
        desk.add(Session {
            nonce,
            peer: peer.into(),
            role: 0,
            stage: Stage::Hello,
            hello: hello.clone(),
            terms: None,
            own: None,
            theirs: None,
            receipt_digest: None,
            key_package: None,
            welcome: None,
            opened: false,
            outbox: vec![WaveMessage::Hello { nonce, hello }],
        })?;
        self.write_desk(&desk, operation(&nonce, "hello")).await?;
        Ok(desk.status(desk.wave(&nonce).ok_or(ErrorCode::Refused)?))
    }

    /// Answer or close a wave addressed to this member.
    pub async fn decide(&mut self, nonce: &[u8; 32], decision: Decision) -> Result<WaveStatus> {
        let mut desk = Desk::load(self.store)?;
        let session = desk.wave(nonce).ok_or(ErrorCode::Refused)?.clone();
        if session.role != 1 {
            return Err(ErrorCode::Refused);
        }
        self.refuse_blocked(&session.peer)?;
        match decision {
            Decision::Close => {
                if !matches!(
                    session.stage,
                    Stage::Reserving | Stage::Reserved | Stage::Ready
                ) {
                    return Err(ErrorCode::Refused);
                }
                desk.record(*nonce, Work::Close)?;
                desk.wave_mut(nonce)?.stage = Stage::Closed;
                self.write_desk(&desk, operation(nonce, "close")).await?;
            }
            Decision::Answer => {
                if session.stage != Stage::Ready {
                    return Err(ErrorCode::Refused);
                }
                self.answer(&mut desk, session).await?;
            }
        }
        Ok(desk.status(desk.wave(nonce).ok_or(ErrorCode::Refused)?))
    }

    /// The Answer: ONE checkpoint opens the member's conversation (Waves claim,
    /// Contacts Begin, Threads join) and records the Answer as work. The proof
    /// never blocks it.
    async fn answer(&mut self, desk: &mut Desk, session: Session) -> Result<()> {
        let nonce = session.nonce;
        let receipt = session.receipt_digest.ok_or(ErrorCode::Refused)?;
        let welcome = session.welcome.clone().ok_or(ErrorCode::Refused)?;
        let conversation = session.hello.conversation;
        let me = self.me()?;
        let mut clock = custody::SystemClock;
        let waves = self.inbox.waves(me, self.store).map_err(inbox_error)?;
        let claimed = waves
            .claim_answer(&nonce, receipt, &mut clock)
            .map_err(inbox_error)?;
        // The desk after this action, carried inside the same checkpoint.
        let mut next = desk.clone();
        next.record(nonce, Work::Answer)?;
        {
            let s = next.wave_mut(&nonce)?;
            s.stage = Stage::Claimed;
            s.opened = true;
        }
        let carried = cnbx::WalletChange::new(OWNER.into(), KEY.to_vec(), next.encode()?);
        let mut devices = self.devices().await?;
        let release = self
            .inbox
            .prepare_release(
                &mut Own(self.ports),
                self.keys,
                self.contacts,
                self.threads,
                &mut devices,
                self.store,
                &session.peer,
                conversation,
                claimed,
                cnbx::ReleaseEntry::Join { welcome: &welcome },
                vec![carried],
            )
            .await
            .map_err(inbox_error)?;
        let released = release
            .commit(
                &mut Own(self.ports),
                self.keys,
                self.threads,
                &mut devices,
                self.store,
                operation(&nonce, "answer"),
                &mut clock,
            )
            .await
            .map_err(inbox_error)?;
        drop(released);
        *desk = next;
        Ok(())
    }

    /// Punish: block the peer on this device at once (own, signed action) and
    /// record the punishment as work for the wallet. Blocking never waits.
    pub async fn punish(&mut self, peer: &str, nonce: Option<[u8; 32]>) -> Result<cnbx::Relation> {
        cnbx::member_digest_of(peer).map_err(inbox_error)?;
        let mut desk = Desk::load(self.store)?;
        let target = match nonce {
            Some(n) => {
                let s = desk.wave(&n).ok_or(ErrorCode::Refused)?;
                if s.peer != peer {
                    return Err(ErrorCode::Refused);
                }
                Some(n)
            }
            None => desk
                .waves
                .iter()
                .rev()
                .find(|s| s.peer == peer)
                .map(|s| s.nonce),
        };
        if let Some(n) = target {
            desk.record(n, Work::Punish)?;
            desk.wave_mut(&n)?.stage = Stage::Punished;
            self.write_desk(&desk, operation(&n, "punish")).await?;
        }
        let contacts = self.inbox.contacts(self.store).map_err(inbox_error)?;
        let next = contacts
            .apply(
                peer,
                cnbx::OwnAction::Block,
                self.keys,
                self.contacts,
                self.store,
            )
            .await
            .map_err(inbox_error)?;
        next.relation(peer).map_err(inbox_error)
    }

    pub fn list(&self) -> Result<WaveList> {
        let desk = Desk::load(self.store)?;
        Ok(WaveList {
            waves: desk.waves.iter().map(|s| desk.status(s)).collect(),
            stalled: desk.stalled(),
        })
    }

    pub fn outbox(&self) -> Result<Outbox> {
        let desk = Desk::load(self.store)?;
        Ok(Outbox {
            messages: desk
                .waves
                .iter()
                .flat_map(|s| {
                    s.outbox.iter().map(|message| Queued {
                        peer: s.peer.clone(),
                        message: message.clone(),
                    })
                })
                .collect(),
        })
    }

    /// The host confirms that a queued message reached the other device.
    pub async fn delivered(&mut self, delivered: &Delivered) -> Result<()> {
        let mut desk = Desk::load(self.store)?;
        let session = desk.wave_mut(&delivered.nonce)?;
        let before = session.outbox.len();
        let kind = delivered.kind.clone();
        session.outbox.retain(|m| kind_of(m) != kind);
        if session.outbox.len() == before {
            return Err(ErrorCode::Refused);
        }
        self.write_desk(
            &desk,
            operation(&delivered.nonce, &format!("delivered.{kind}")),
        )
        .await
    }

    // ---- messages from the other device -------------------------------------

    pub async fn receive(&mut self, peer: &str, message: WaveMessage) -> Result<WaveStatus> {
        self.check_peer(peer).await?;
        let nonce = *message.nonce();
        let mut desk = Desk::load(self.store)?;
        if let WaveMessage::Hello { hello, .. } = &message {
            self.on_hello(&mut desk, peer, nonce, hello.clone()).await?;
        } else {
            let session = desk.wave(&nonce).ok_or(ErrorCode::Refused)?.clone();
            if session.peer != peer {
                return Err(ErrorCode::Refused);
            }
            match message {
                WaveMessage::Hello { .. } => unreachable!("handled above"),
                WaveMessage::Terms { terms, .. } => {
                    self.on_terms(&mut desk, session, terms).await?
                }
                WaveMessage::Offer {
                    reservation,
                    receipt_digest,
                    ..
                } => {
                    self.on_offer(&mut desk, session, reservation, receipt_digest)
                        .await?
                }
                WaveMessage::Reservation {
                    reservation,
                    key_package,
                    ..
                } => {
                    self.on_reservation(&mut desk, session, reservation, key_package)
                        .await?
                }
                WaveMessage::Welcome { welcome, .. } => {
                    self.on_welcome(&mut desk, session, welcome).await?
                }
                WaveMessage::Outcome {
                    decision, outcome, ..
                } => {
                    self.on_outcome(&mut desk, session, decision, outcome)
                        .await?
                }
            }
        }
        Ok(desk.status(desk.wave(&nonce).ok_or(ErrorCode::Refused)?))
    }

    async fn on_hello(
        &mut self,
        desk: &mut Desk,
        peer: &str,
        nonce: [u8; 32],
        hello: Hello,
    ) -> Result<()> {
        let now = now()?;
        if desk.wave(&nonce).is_some()
            || nonce == [0; 32]
            || hello.conversation == [0; 32]
            || hello.sender_challenge == [0; 32]
            || hello.opened_at == 0
            || hello.expires_at <= hello.opened_at
            || now < hello.opened_at
            || now >= hello.expires_at
        {
            return Err(ErrorCode::Refused);
        }
        let terms = self.ports.terms(&nonce, now)?;
        desk.add(Session {
            nonce,
            peer: peer.into(),
            role: 1,
            stage: Stage::Hello,
            hello,
            terms: Some(terms.clone()),
            own: None,
            theirs: None,
            receipt_digest: None,
            key_package: None,
            welcome: None,
            opened: false,
            outbox: vec![WaveMessage::Terms { nonce, terms }],
        })?;
        self.write_desk(desk, operation(&nonce, "hello-in")).await
    }

    async fn on_terms(&mut self, desk: &mut Desk, session: Session, terms: Terms) -> Result<()> {
        if session.role != 0 || session.stage != Stage::Hello || session.terms.is_some() {
            return Err(ErrorCode::Refused);
        }
        let nonce = session.nonce;
        let mut next = session;
        next.terms = Some(terms);
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &next, me)?;
        let mut clock = custody::SystemClock;
        let offer = self
            .inbox
            .waves(me, self.store)
            .and_then(|waves| waves.prepare_offer(sender, recipient, &mut clock))
            .map_err(inbox_error)?;
        match offer
            .commit(self.store, operation(&nonce, "offer"), &mut clock)
            .await
        {
            Ok(_) => {}
            Err(error) if replayed(&error) => {}
            Err(error) => return Err(inbox_error(error)),
        }
        next.stage = Stage::Reserving;
        desk.record(nonce, Work::ReserveSender)?;
        *desk.wave_mut(&nonce)? = next;
        self.write_desk(desk, operation(&nonce, "terms")).await
    }

    async fn on_offer(
        &mut self,
        desk: &mut Desk,
        session: Session,
        reservation: Blob,
        receipt_digest: [u8; 32],
    ) -> Result<()> {
        if session.role != 1 || session.stage != Stage::Hello || receipt_digest == [0; 32] {
            return Err(ErrorCode::Refused);
        }
        let nonce = session.nonce;
        let now = now()?;
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &session, me)?;
        // The recipient never countersigns an unverified sender reservation.
        let statement: WaveStatement = blob_statement(&reservation)?;
        self.ports
            .verify_reservation(&statement, &reservation.proof, &sender, now)
            .await?;
        // The conversation's key package is made under the sender's chosen id.
        let package = self.key_package(session.hello.conversation, &nonce).await?;
        let mut clock = custody::SystemClock;
        let offer = self
            .inbox
            .waves(me, self.store)
            .and_then(|waves| waves.prepare_offer(sender, recipient, &mut clock))
            .map_err(inbox_error)?;
        match offer
            .commit(self.store, operation(&nonce, "offer-in"), &mut clock)
            .await
        {
            Ok(_) => {}
            Err(error) if replayed(&error) => {}
            Err(error) => return Err(inbox_error(error)),
        }
        desk.record(nonce, Work::ReserveRecipient)?;
        let next = desk.wave_mut(&nonce)?;
        next.theirs = Some(reservation);
        next.receipt_digest = Some(receipt_digest);
        next.key_package = Some(package);
        next.stage = Stage::Reserving;
        self.write_desk(desk, operation(&nonce, "offer-recorded"))
            .await
    }

    async fn key_package(&mut self, conversation: [u8; 32], nonce: &[u8; 32]) -> Result<Vec<u8>> {
        let view = self
            .inbox
            .view(conversation, self.store)
            .map_err(inbox_error)?;
        let mut devices = self.devices().await?;
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut devices,
        };
        let opened = view
            .key_package(&mut port)
            .await
            .map_err(inbox_error)?
            .commit(
                &mut port,
                &mut cthr::Unavailable,
                self.store,
                operation(nonce, "key-package"),
            )
            .await
            .map_err(inbox_error)?;
        match opened.events().first() {
            Some(cnbx::ConversationEvent::KeyPackage { bytes }) => Ok(bytes.clone()),
            _ => Err(ErrorCode::Refused),
        }
    }

    async fn on_reservation(
        &mut self,
        desk: &mut Desk,
        session: Session,
        reservation: Blob,
        key_package: Vec<u8>,
    ) -> Result<()> {
        if session.role != 0 || session.stage != Stage::Offered {
            return Err(ErrorCode::Refused);
        }
        let nonce = session.nonce;
        let own = session.own.clone().ok_or(ErrorCode::Refused)?;
        let now = now()?;
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &session, me)?;
        let sender_statement: WaveStatement = blob_statement(&own)?;
        let recipient_statement: WaveStatement = blob_statement(&reservation)?;
        let verified_sender = self
            .ports
            .verify_reservation(&sender_statement, &own.proof, &sender, now)
            .await?;
        let verified_recipient = self
            .ports
            .verify_reservation(&recipient_statement, &reservation.proof, &recipient, now)
            .await?;
        let mut clock = custody::SystemClock;
        let waves = self.inbox.waves(me, self.store).map_err(inbox_error)?;
        let accepted = waves
            .accept_reservations(verified_sender, verified_recipient, &mut clock)
            .map_err(inbox_error)?;
        let mut next = desk.clone();
        {
            let s = next.wave_mut(&nonce)?;
            s.theirs = Some(reservation);
            s.stage = Stage::Released;
            s.opened = true;
        }
        let carried = cnbx::WalletChange::new(OWNER.into(), KEY.to_vec(), next.encode()?);
        let mut devices = self.devices().await?;
        let release = self
            .inbox
            .prepare_release(
                &mut Own(self.ports),
                self.keys,
                self.contacts,
                self.threads,
                &mut devices,
                self.store,
                &session.peer,
                session.hello.conversation,
                accepted,
                cnbx::ReleaseEntry::Create {
                    package: &key_package,
                },
                vec![carried],
            )
            .await
            .map_err(inbox_error)?;
        let released = release
            .commit(
                &mut Own(self.ports),
                self.keys,
                self.threads,
                &mut devices,
                self.store,
                operation(&nonce, "release"),
                &mut clock,
            )
            .await
            .map_err(inbox_error)?;
        let welcome = match released.opened.events().first() {
            Some(cnbx::ConversationEvent::Invitation { welcome, .. }) => welcome.clone(),
            _ => return Err(ErrorCode::Reconcile),
        };
        next.wave_mut(&nonce)?.welcome = Some(welcome.clone());
        next.wave_mut(&nonce)?
            .outbox
            .push(WaveMessage::Welcome { nonce, welcome });
        *desk = next;
        self.write_desk(desk, operation(&nonce, "welcome-queued"))
            .await
    }

    async fn on_welcome(
        &mut self,
        desk: &mut Desk,
        session: Session,
        welcome: Vec<u8>,
    ) -> Result<()> {
        if session.role != 1 || session.stage != Stage::Reserved || welcome.is_empty() {
            return Err(ErrorCode::Refused);
        }
        let nonce = session.nonce;
        let own = session.own.clone().ok_or(ErrorCode::Refused)?;
        let theirs = session.theirs.clone().ok_or(ErrorCode::Refused)?;
        let now = now()?;
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &session, me)?;
        let sender_statement: WaveStatement = blob_statement(&theirs)?;
        let recipient_statement: WaveStatement = blob_statement(&own)?;
        let verified_sender = self
            .ports
            .verify_reservation(&sender_statement, &theirs.proof, &sender, now)
            .await?;
        let verified_recipient = self
            .ports
            .verify_reservation(&recipient_statement, &own.proof, &recipient, now)
            .await?;
        let mut clock = custody::SystemClock;
        let accepted = self
            .inbox
            .waves(me, self.store)
            .and_then(|waves| {
                waves.accept_reservations(verified_sender, verified_recipient, &mut clock)
            })
            .map_err(inbox_error)?;
        match accepted
            .commit(self.store, operation(&nonce, "accepted-in"), &mut clock)
            .await
        {
            Ok(_) => {}
            Err(error) if replayed(&error) => {}
            Err(error) => return Err(inbox_error(error)),
        }
        let next = desk.wave_mut(&nonce)?;
        next.welcome = Some(welcome);
        next.stage = Stage::Ready;
        self.write_desk(desk, operation(&nonce, "welcome-in")).await
    }

    async fn on_outcome(
        &mut self,
        desk: &mut Desk,
        session: Session,
        decision: Decision,
        outcome: Blob,
    ) -> Result<()> {
        // Only the sender learns the recipient's decision.
        if session.role != 0 || !matches!(session.stage, Stage::Released | Stage::Offered) {
            return Err(ErrorCode::Refused);
        }
        let nonce = session.nonce;
        let receipt = session.receipt_digest.ok_or(ErrorCode::Refused)?;
        let now = now()?;
        let me = self.me()?;
        let (_, recipient) = contexts(self.binding, &session, me)?;
        let statement: WaveOutcomeStatement = blob_statement(&outcome)?;
        let (kind, stage) = match decision {
            Decision::Answer => (WaveOutcome::Answer, Stage::Answered),
            Decision::Close => (WaveOutcome::Close, Stage::Closed),
        };
        let verified = self
            .ports
            .verify_outcome(&statement, &outcome.proof, &recipient, kind, &receipt, now)
            .await?;
        let mut clock = custody::SystemClock;
        let waves = self.inbox.waves(me, self.store).map_err(inbox_error)?;
        let recorded = match decision {
            Decision::Answer => waves.record_peer_answer(verified, &mut clock),
            Decision::Close => waves.record_outcome(verified, &mut clock),
        }
        .map_err(inbox_error)?;
        match recorded
            .commit(self.store, operation(&nonce, "outcome-in"), &mut clock)
            .await
        {
            Ok(_) => {}
            Err(error) if replayed(&error) => {}
            Err(error) => return Err(inbox_error(error)),
        }
        desk.wave_mut(&nonce)?.stage = stage;
        self.write_desk(desk, operation(&nonce, "outcome-recorded"))
            .await?;
        if decision == Decision::Answer {
            self.mark_answered(&session.peer, session.hello.conversation, receipt)
                .await?;
        }
        Ok(())
    }

    /// Contacts `Answered`, a later checkpoint backed by the committed link.
    async fn mark_answered(
        &mut self,
        peer: &str,
        conversation: [u8; 32],
        receipt: [u8; 32],
    ) -> Result<()> {
        let me = self.me()?;
        let waves = self.inbox.waves(me, self.store).map_err(inbox_error)?;
        self.inbox
            .mark_answered(
                &waves,
                peer,
                conversation,
                receipt,
                self.keys,
                self.contacts,
                self.store,
            )
            .await
            .map(|_| ())
            .map_err(inbox_error)
    }

    // ---- the host worker's short calls ---------------------------------------

    /// Give a stalled job a fresh set of attempts.
    pub async fn retry_job(&mut self, id: &[u8; 32]) -> Result<()> {
        let mut desk = Desk::load(self.store)?;
        desk.retry(id)?;
        self.write_desk(&desk, operation(id, "retry")).await
    }

    /// A restart found the worker gone: proving jobs go back to the queue.
    pub async fn recover_jobs(&mut self) -> Result<()> {
        let mut desk = Desk::load(self.store)?;
        desk.recover();
        let nonce = [0; 32];
        self.write_desk(
            &desk,
            operation(
                &nonce,
                &format!(
                    "recover.{}",
                    self.store.version().map_err(|_| ErrorCode::Unavailable)?
                ),
            ),
        )
        .await
    }

    /// Hand the next recorded job to the host worker. Short: nothing is proved
    /// here and no lock is held while the worker proves.
    pub async fn next_job(&mut self) -> Result<JobOffer> {
        let mut desk = Desk::load(self.store)?;
        let Some(job) = desk.take() else {
            return Ok(JobOffer { job: None });
        };
        let session = desk.wave(&job.nonce).ok_or(ErrorCode::Refused)?.clone();
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &session, me)?;
        let receipt_digest = match job.work {
            Work::Answer | Work::Close => session.receipt_digest,
            _ => None,
        };
        let offer = ProveJob {
            id: job.id,
            nonce: job.nonce,
            work: job.work,
            sender,
            recipient,
            receipt_digest,
        };
        let id = job.id;
        self.write_desk(&desk, operation(&id, &format!("take.{}", job.attempts)))
            .await?;
        Ok(JobOffer { job: Some(offer) })
    }

    /// The worker returns a proved job. The proof is verified here (fast) before
    /// anything is recorded; a failed or uncertain proof keeps the member's
    /// action and reverts only the claim.
    pub async fn job_done(&mut self, done: JobDone) -> Result<WaveStatus> {
        let mut desk = Desk::load(self.store)?;
        let job = desk.job(&done.id).ok_or(ErrorCode::Refused)?.clone();
        let session = desk.wave(&job.nonce).ok_or(ErrorCode::Refused)?.clone();
        let nonce = job.nonce;
        let proved = match done.result {
            JobResult::Proved { proved } => proved,
            JobResult::Failed => {
                self.job_failed(&mut desk, &job, &session).await?;
                return Ok(desk.status(desk.wave(&nonce).ok_or(ErrorCode::Refused)?));
            }
        };
        let applied = self.apply(&mut desk, &job, session.clone(), proved).await;
        if let Err(error) = applied {
            // A refused or unavailable result never loses the action. The failure
            // is recorded on a fresh desk: nothing the failed step half-applied
            // in memory is ever written.
            if matches!(
                error,
                ErrorCode::Refused
                    | ErrorCode::Unavailable
                    | ErrorCode::Unauthorized
                    | ErrorCode::InvalidRequest
            ) {
                let mut fresh = Desk::load(self.store)?;
                self.job_failed(&mut fresh, &job, &session).await?;
            }
            return Err(error);
        }
        Ok(desk.status(desk.wave(&nonce).ok_or(ErrorCode::Refused)?))
    }

    async fn job_failed(
        &mut self,
        desk: &mut Desk,
        job: &super::desk::Job,
        session: &Session,
    ) -> Result<()> {
        if job.work == Work::Answer && session.stage == Stage::Claimed {
            let me = self.me()?;
            let mut clock = custody::SystemClock;
            let reverted = self
                .inbox
                .waves(me, self.store)
                .and_then(|waves| waves.revert_claim(&job.nonce, &mut clock))
                .map_err(inbox_error)?;
            match reverted
                .commit(self.store, operation(&job.id, "revert"), &mut clock)
                .await
            {
                Ok(_) => {}
                Err(cnbx::Error::Waves(cnbx::WaveError::State)) => {}
                Err(error) => return Err(inbox_error(error)),
            }
            // The member's conversation stays open; only the claim is pending again.
            desk.wave_mut(&job.nonce)?.stage = Stage::Ready;
        }
        desk.fail(&job.id)?;
        self.write_desk(
            desk,
            operation(&job.id, &format!("failed.{}", job.attempts)),
        )
        .await
    }

    async fn apply(
        &mut self,
        desk: &mut Desk,
        job: &super::desk::Job,
        session: Session,
        proved: Proved,
    ) -> Result<()> {
        let nonce = job.nonce;
        let now = now()?;
        let me = self.me()?;
        let (sender, recipient) = contexts(self.binding, &session, me)?;
        let mut clock = custody::SystemClock;
        match job.work {
            Work::ReserveSender => {
                let receipt = proved
                    .receipt_digest
                    .filter(|digest| *digest != [0; 32])
                    .ok_or(ErrorCode::Refused)?;
                // Our own proof is checked before it is queued: garbage from the
                // prover is a failed attempt, never an offer the peer must reject.
                let statement: WaveStatement = blob_statement(&proved.blob)?;
                self.ports
                    .verify_reservation(&statement, &proved.blob.proof, &sender, now)
                    .await?;
                let s = desk.wave_mut(&nonce)?;
                s.own = Some(proved.blob.clone());
                s.receipt_digest = Some(receipt);
                if s.stage == Stage::Reserving {
                    s.stage = Stage::Offered;
                    s.outbox.push(WaveMessage::Offer {
                        nonce,
                        reservation: proved.blob.clone(),
                        receipt_digest: receipt,
                    });
                }
            }
            Work::ReserveRecipient => {
                let package = session.key_package.clone().ok_or(ErrorCode::Refused)?;
                let statement: WaveStatement = blob_statement(&proved.blob)?;
                self.ports
                    .verify_reservation(&statement, &proved.blob.proof, &recipient, now)
                    .await?;
                let s = desk.wave_mut(&nonce)?;
                s.own = Some(proved.blob.clone());
                // A member who closed meanwhile sends no reservation: the Close
                // outcome that follows settles the slot.
                if s.stage == Stage::Reserving {
                    s.stage = Stage::Reserved;
                    s.outbox.push(WaveMessage::Reservation {
                        nonce,
                        reservation: proved.blob.clone(),
                        key_package: package,
                    });
                }
            }
            Work::Answer | Work::Close => {
                let receipt = session.receipt_digest.ok_or(ErrorCode::Refused)?;
                let (kind, decision) = if job.work == Work::Answer {
                    (WaveOutcome::Answer, Decision::Answer)
                } else {
                    (WaveOutcome::Close, Decision::Close)
                };
                let statement: WaveOutcomeStatement = blob_statement(&proved.blob)?;
                let verified = self
                    .ports
                    .verify_outcome(
                        &statement,
                        &proved.blob.proof,
                        &recipient,
                        kind,
                        &receipt,
                        now,
                    )
                    .await?;
                let recorded = self
                    .inbox
                    .waves(me, self.store)
                    .and_then(|waves| waves.record_outcome(verified, &mut clock))
                    .map_err(inbox_error)?;
                match recorded
                    .commit(self.store, operation(&job.id, "settled"), &mut clock)
                    .await
                {
                    Ok(_) => {}
                    Err(error) if replayed(&error) => {}
                    Err(error) => return Err(inbox_error(error)),
                }
                let s = desk.wave_mut(&nonce)?;
                if job.work == Work::Answer {
                    s.stage = Stage::Answered;
                }
                s.outbox.push(WaveMessage::Outcome {
                    nonce,
                    decision,
                    outcome: proved.blob.clone(),
                });
                if job.work == Work::Answer {
                    self.mark_answered(&session.peer, session.hello.conversation, receipt)
                        .await?;
                }
            }
            Work::Punish => {
                // Punishment is private to the punisher: nothing is sent.
            }
        }
        desk.finish(&job.id)?;
        self.write_wallet(desk, &proved.wallet, operation(&job.id, "applied"))
            .await
    }

    /// The desk and the wallet's own new records adopted in one checkpoint.
    async fn write_wallet(
        &mut self,
        desk: &Desk,
        wallet: &[WalletRecord],
        op: [u8; 32],
    ) -> Result<()> {
        let bytes = desk.encode()?;
        let expected = self.store.version().map_err(|_| ErrorCode::Unavailable)?;
        let mut changes = vec![Change::Put {
            owner: OWNER,
            key: KEY,
            value: &bytes,
        }];
        for record in wallet {
            // The wallet writes only inside its own namespace; the desk, Contacts,
            // Threads, Delivery and Waves records are never the worker's to touch.
            if !record.owner.starts_with("cwlt.") {
                return Err(ErrorCode::Refused);
            }
            changes.push(Change::Put {
                owner: &record.owner,
                key: &record.key,
                value: &record.value,
            });
        }
        self.store
            .commit(expected, op, &changes, &[])
            .await
            .map(|_| ())
            .map_err(|_| ErrorCode::Reconcile)
    }
}

pub(crate) fn kind_of(message: &WaveMessage) -> String {
    match message {
        WaveMessage::Hello { .. } => "hello",
        WaveMessage::Terms { .. } => "terms",
        WaveMessage::Offer { .. } => "offer",
        WaveMessage::Reservation { .. } => "reservation",
        WaveMessage::Welcome { .. } => "welcome",
        WaveMessage::Outcome { .. } => "outcome",
    }
    .into()
}
