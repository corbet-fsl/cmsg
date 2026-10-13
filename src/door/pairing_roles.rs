//! The two roles of one device pairing over the three-round channel of [`super::pairing`]:
//! the existing device ([`Host`], serves rounds) and the new device ([`Guest`], drives
//! them). Both are generic over the steps they delegate, so this module owns the protocol
//! (order, payload shapes, retries, restarts) and nothing about authority: every step is
//! a capability the embedding supplies (passkey ceremonies, Keys, the community server).
//!
//! Human time is never redone. The [`Guest`] keeps a serializable [`GuestRecord`] that
//! holds, per round, the reply-key seed and the exact sealed message; a restart resends
//! those bytes and calls a step again only for a round it never completed. The [`Host`]
//! answers an exact repeat of a message with its stored reply, so a lost answer costs the
//! person nothing either. A [`Host`] that restarts loses its offer: the existing device
//! shows a new link.
use super::pairing::{Link, Offer, Received, ROUNDS};
use super::*;

/// The round 1 reply: the registration challenge for the new device's own passkey.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    /// Server ceremony the credential answers.
    pub ceremony: String,
    /// WebAuthn creation options for the new device's authenticator.
    pub options: Value,
}

/// The round 2 request: the new device's registration credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registered {
    /// The ceremony of round 1.
    pub ceremony: String,
    /// The public registration credential.
    pub credential: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    hello: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorMessage {
    anchor: ckmg::Lineage,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestMessage {
    request: ckmg::PairingRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantMessage {
    grant: ckmg::PairingGrant,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| ErrorCode::InvalidRequest)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)
}

/// What the existing device does for each round. Each method is one authority-bearing or
/// human-facing step; a failure leaves the round unanswered so the new device may retry.
#[allow(async_fn_in_trait)]
pub trait HostSteps {
    /// Round 1: after the member's explicit approval (step-up), the registration options
    /// for the new device's passkey.
    async fn registration_options(&mut self) -> Result<Registration>;
    /// Round 2: finish the passkey registration; answer with the current lineage anchor.
    async fn register_credential(&mut self, registered: Registered) -> Result<ckmg::Lineage>;
    /// Round 3: verify the request, approve it (Keys), publish the lineage revision, have
    /// the new key approved at the server; answer with the grant.
    async fn approve(&mut self, request: ckmg::PairingRequest) -> Result<ckmg::PairingGrant>;
}

/// The existing device's side of one open offer.
pub struct Host<S: HostSteps> {
    offer: Offer,
    steps: S,
}

impl<S: HostSteps> Host<S> {
    /// Serve `offer` with `steps`.
    pub fn new(offer: Offer, steps: S) -> Self {
        Self { offer, steps }
    }

    /// Unix seconds this offer stays open.
    pub fn expires(&self) -> u64 {
        self.offer.expires()
    }

    /// All three rounds are answered.
    pub fn finished(&self) -> bool {
        self.offer.finished()
    }

    /// Rounds answered so far.
    pub fn rounds_done(&self) -> u8 {
        self.offer.rounds_done()
    }

    /// Take the steps back, for example to close the offer.
    pub fn into_steps(self) -> S {
        self.steps
    }

    /// Answer one message from the new device: the sealed reply to send back.
    pub async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        let (round, payload, reply_to) = match self.offer.open_round(message, now)? {
            Received::Repeat(reply) => return Ok(reply),
            Received::Round {
                round,
                payload,
                reply_to,
            } => (round, payload, reply_to),
        };
        let reply = match round {
            1 => {
                let Hello { hello } = decode(&payload)?;
                if hello != 1 {
                    return Err(ErrorCode::InvalidRequest);
                }
                encode(&self.steps.registration_options().await?)?
            }
            2 => {
                let anchor = self.steps.register_credential(decode(&payload)?).await?;
                encode(&AnchorMessage { anchor })?
            }
            3 => {
                let RequestMessage { request } = decode(&payload)?;
                let grant = self.steps.approve(request).await?;
                encode(&GrantMessage { grant })?
            }
            _ => return Err(ErrorCode::Refused),
        };
        self.offer.answer(message, &reply_to, &reply)
    }
}

/// What the new device does for each round.
#[allow(async_fn_in_trait)]
pub trait GuestSteps {
    /// Round 1 answered: register the new passkey from the options (a human ceremony).
    async fn register(&mut self, registration: Registration) -> Result<Registered>;
    /// Round 2 answered: sign in with the new passkey, authorize this device's key as
    /// pending at the server and make the pairing request over the confirmed anchor.
    async fn request(&mut self, anchor: ckmg::Lineage) -> Result<ckmg::PairingRequest>;
    /// Round 3 answered: accept the grant (the root arrives sealed) and confirm the key.
    async fn accept(&mut self, grant: ckmg::PairingGrant) -> Result<()>;
}

/// How the new device reaches the existing one: one sealed message, one sealed reply.
#[allow(async_fn_in_trait)]
pub trait Channel {
    /// Deliver `message` to `address` and return the sealed reply.
    async fn call(&mut self, address: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>>;
}

/// One round the new device has begun: the reply-key seed and the exact sealed message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SentRound {
    seed: [u8; 32],
    message: Vec<u8>,
}

/// Everything the new device must keep to continue after a restart (keep it in the
/// device's own durable storage, never in logs; it holds no key, only the link and sealed
/// messages, but the link is the pairing secret).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GuestRecord {
    link: String,
    sent: Vec<SentRound>,
    /// The completed outcome of each step, as the payload of the next round: the human
    /// work (registration credential, request) that must not be redone.
    results: Vec<Vec<u8>>,
    accepted: bool,
}

impl GuestRecord {
    /// A record for a fresh link.
    pub fn new(link: &str) -> Self {
        Self {
            link: link.to_owned(),
            ..Self::default()
        }
    }

    /// Rounds begun.
    pub fn rounds_sent(&self) -> usize {
        self.sent.len()
    }

    /// The pairing is complete on this side.
    pub fn done(&self) -> bool {
        self.accepted
    }
}

/// The new device's side. `save` is called with the record after every durable change.
pub struct Guest<S: GuestSteps, C: Channel, P: FnMut(&GuestRecord) -> Result<()>> {
    steps: S,
    channel: C,
    save: P,
    record: GuestRecord,
}

impl<S: GuestSteps, C: Channel, P: FnMut(&GuestRecord) -> Result<()>> Guest<S, C, P> {
    /// Start or continue from `record`.
    pub fn new(steps: S, channel: C, save: P, record: GuestRecord) -> Self {
        Self {
            steps,
            channel,
            save,
            record,
        }
    }

    /// The current record.
    pub fn record(&self) -> &GuestRecord {
        &self.record
    }

    /// Take the steps back.
    pub fn into_steps(self) -> S {
        self.steps
    }

    /// Send round `n`: reuse the exact stored message when the round was begun before,
    /// otherwise seal and store `payload` first. Returns the opened reply.
    async fn exchange(
        &mut self,
        link: &Link,
        round: u8,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let index = usize::from(round) - 1;
        if self.record.sent.len() == index {
            let payload = payload.ok_or(ErrorCode::InvalidRequest)?;
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| ErrorCode::Unavailable)?;
            let (message, _) = link.seal_round_with(&seed, round, &payload)?;
            self.record.sent.push(SentRound { seed, message });
            (self.save)(&self.record)?;
        }
        let sent = self
            .record
            .sent
            .get(index)
            .ok_or(ErrorCode::InvalidRequest)?;
        let awaiting = link.awaiting(&sent.seed, round)?;
        let message = sent.message.clone();
        let reply = self.channel.call(link.address(), &message).await?;
        Ok(awaiting.open_reply(&reply)?.to_vec())
    }

    /// Run the pairing to its end, resuming wherever the record stands.
    pub async fn run(&mut self) -> Result<()> {
        if self.record.accepted {
            return Ok(());
        }
        let link = Link::parse(&self.record.link)?;
        // Round 1.
        let hello = if self.record.sent.is_empty() {
            Some(encode(&Hello { hello: 1 })?)
        } else {
            None
        };
        let registration: Registration = decode(&self.exchange(&link, 1, hello).await?)?;
        // Round 2: the registration is the human ceremony; its outcome is kept first and a
        // restart uses the kept outcome instead of asking the person again.
        let registered = if self.record.sent.len() >= 2 {
            None
        } else if let Some(kept) = self.record.results.first() {
            Some(kept.clone())
        } else {
            let registered = encode(&self.steps.register(registration).await?)?;
            self.record.results.push(registered.clone());
            (self.save)(&self.record)?;
            Some(registered)
        };
        let anchor: AnchorMessage = decode(&self.exchange(&link, 2, registered).await?)?;
        // Round 3.
        let request = if self.record.sent.len() >= 3 {
            None
        } else if let Some(kept) = self.record.results.get(1) {
            Some(kept.clone())
        } else {
            let request = encode(&RequestMessage {
                request: self.steps.request(anchor.anchor).await?,
            })?;
            self.record.results.push(request.clone());
            (self.save)(&self.record)?;
            Some(request)
        };
        let grant: GrantMessage = decode(&self.exchange(&link, ROUNDS, request).await?)?;
        self.steps.accept(grant.grant).await?;
        self.record.accepted = true;
        (self.save)(&self.record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    fn key(n: u8) -> ckmg::PublicKey {
        ckmg::PublicKey::new(ckmg::VLD0, [n; 32])
    }

    fn signature() -> ckmg::Signature {
        ckmg::Signature::new(ckmg::VLD0, [9; 64])
    }

    fn lineage(revision: u64) -> ckmg::Lineage {
        ckmg::Lineage {
            version: 2,
            binding: ckmg::Binding::new("omega", "member").unwrap(),
            epoch: 1,
            revision,
            root: key(1),
            identity: None,
            devices: vec![key(2)],
            signature: signature(),
        }
    }

    fn request() -> ckmg::PairingRequest {
        ckmg::PairingRequest {
            version: 1,
            binding: ckmg::Binding::new("omega", "member").unwrap(),
            root: key(1),
            epoch: 1,
            device: key(3),
            nonce: [4; 32],
            issued_at: 10,
            expires_at: 20,
            proof: signature(),
        }
    }

    /// What the existing device did, to prove no human step ran twice.
    #[derive(Default)]
    struct Counts {
        options: usize,
        registered: usize,
        approved: usize,
        registers: usize,
        requests: usize,
        accepts: usize,
    }

    type Shared = Rc<RefCell<Counts>>;

    struct FakeHost(Shared);
    impl HostSteps for FakeHost {
        async fn registration_options(&mut self) -> Result<Registration> {
            self.0.borrow_mut().options += 1;
            Ok(Registration {
                ceremony: "c1".into(),
                options: serde_json::json!({"challenge": "x"}),
            })
        }
        async fn register_credential(&mut self, registered: Registered) -> Result<ckmg::Lineage> {
            assert_eq!(registered.ceremony, "c1");
            self.0.borrow_mut().registered += 1;
            Ok(lineage(1))
        }
        async fn approve(&mut self, request: ckmg::PairingRequest) -> Result<ckmg::PairingGrant> {
            self.0.borrow_mut().approved += 1;
            Ok(ckmg::PairingGrant {
                version: 3,
                request,
                lineage: lineage(2),
                sealed_root: vec![1, 2, 3],
                signature: signature(),
            })
        }
    }

    struct FakeGuest(Shared);
    impl GuestSteps for FakeGuest {
        async fn register(&mut self, registration: Registration) -> Result<Registered> {
            self.0.borrow_mut().registers += 1;
            Ok(Registered {
                ceremony: registration.ceremony,
                credential: serde_json::json!({"id": "new passkey"}),
            })
        }
        async fn request(&mut self, anchor: ckmg::Lineage) -> Result<ckmg::PairingRequest> {
            assert!(anchor == lineage(1));
            self.0.borrow_mut().requests += 1;
            Ok(request())
        }
        async fn accept(&mut self, grant: ckmg::PairingGrant) -> Result<()> {
            assert!(grant.lineage == lineage(2));
            self.0.borrow_mut().accepts += 1;
            Ok(())
        }
    }

    /// Delivers to the host in process; can lose the n-th reply (the host has acted).
    struct Wire {
        host: Rc<RefCell<Host<FakeHost>>>,
        calls: Rc<RefCell<usize>>,
        lose_reply_at: Option<usize>,
        drop_request_at: Option<usize>,
    }
    impl Channel for Wire {
        async fn call(&mut self, _: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>> {
            let n = {
                let mut calls = self.calls.borrow_mut();
                *calls += 1;
                *calls
            };
            if self.drop_request_at == Some(n) {
                return Err(ErrorCode::Unavailable);
            }
            let reply = self.host.borrow_mut().serve(message, 1_050).await?;
            if self.lose_reply_at == Some(n) {
                return Err(ErrorCode::Unavailable);
            }
            Ok(reply)
        }
    }

    fn setup() -> (Rc<RefCell<Host<FakeHost>>>, String, Shared) {
        let address = cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap();
        let (offer, link) = Offer::new(&address, 1_000).unwrap();
        let counts = Shared::default();
        (
            Rc::new(RefCell::new(Host::new(offer, FakeHost(counts.clone())))),
            link,
            counts,
        )
    }

    fn wire(host: &Rc<RefCell<Host<FakeHost>>>, calls: &Rc<RefCell<usize>>) -> Wire {
        Wire {
            host: host.clone(),
            calls: calls.clone(),
            lose_reply_at: None,
            drop_request_at: None,
        }
    }

    #[test]
    fn three_rounds_pair_the_devices() {
        let (host, link, counts) = setup();
        let saved = RefCell::new(GuestRecord::new(&link));
        let mut guest = Guest::new(
            FakeGuest(counts.clone()),
            wire(&host, &Rc::default()),
            |record: &GuestRecord| {
                *saved.borrow_mut() = record.clone();
                Ok(())
            },
            GuestRecord::new(&link),
        );
        futures_executor::block_on(guest.run()).unwrap();
        let counts = counts.borrow();
        assert_eq!(
            (counts.options, counts.registered, counts.approved),
            (1, 1, 1)
        );
        assert_eq!(
            (counts.registers, counts.requests, counts.accepts),
            (1, 1, 1)
        );
        assert!(host.borrow().finished() && saved.borrow().done());
        // A finished record is a no-op.
        futures_executor::block_on(guest.run()).unwrap();
        assert_eq!(counts.accepts, 1);
    }

    #[test]
    fn a_lost_connection_or_restart_at_any_step_redoes_no_human_work() {
        // Break the exchange at every call, once as a lost request and once as a lost
        // reply (the host has already acted), and restart from the saved record each time.
        for lose_reply in [false, true] {
            for at in 1..=3usize {
                let (host, link, counts) = setup();
                let saved = RefCell::new(GuestRecord::new(&link));
                let calls: Rc<RefCell<usize>> = Rc::default();
                for attempt in 0..2 {
                    let mut channel = wire(&host, &calls);
                    if attempt == 0 {
                        if lose_reply {
                            channel.lose_reply_at = Some(at);
                        } else {
                            channel.drop_request_at = Some(at);
                        }
                    }
                    let start = saved.borrow().clone();
                    let mut guest = Guest::new(
                        FakeGuest(counts.clone()),
                        channel,
                        |record: &GuestRecord| {
                            *saved.borrow_mut() = record.clone();
                            Ok(())
                        },
                        start,
                    );
                    let outcome = futures_executor::block_on(guest.run());
                    assert_eq!(outcome.is_ok(), attempt == 1, "{lose_reply} {at}");
                }
                let counts = counts.borrow();
                assert_eq!(
                    (counts.options, counts.registered, counts.approved),
                    (1, 1, 1),
                    "{lose_reply} {at}"
                );
                assert_eq!(
                    (counts.registers, counts.requests, counts.accepts),
                    (1, 1, 1),
                    "{lose_reply} {at}"
                );
            }
        }
    }

    #[test]
    fn a_guest_cannot_skip_a_round_or_use_another_offers_link() {
        let (host, link, counts) = setup();
        let (_, other_link, _) = setup();
        let mut guest = Guest::new(
            FakeGuest(counts.clone()),
            wire(&host, &Rc::default()),
            |_: &GuestRecord| Ok(()),
            GuestRecord::new(&other_link),
        );
        assert!(futures_executor::block_on(guest.run()).is_err());
        assert_eq!(host.borrow().rounds_done(), 0);
        // The host serves round 3 only after rounds 1 and 2.
        let link = Link::parse(&link).unwrap();
        let (message, _) = link.seal_round(3, b"{}").unwrap();
        assert_eq!(
            futures_executor::block_on(host.borrow_mut().serve(&message, 1_050)).err(),
            Some(ErrorCode::Refused)
        );
        assert_eq!(counts.borrow().approved, 0);
    }
}
