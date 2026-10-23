//! The two roles of one device pairing over the three-round channel of [`super::pairing`]:
//! the existing device ([`Host`], serves rounds) and the new device ([`Guest`], drives
//! them). Both are generic over the steps they delegate, so this module owns the protocol
//! (order, payload shapes, retries, restarts) and nothing about authority: every step is
//! a capability the embedding supplies (the wallet confirmation, Keys, the community server).
//!
//! The pairing runs on stamps, not on a second passkey: the new device only has its own
//! device key. Round 1 carries that key to the existing device, whose member approves it with
//! ONE wallet confirmation (a stamp covering `device_add` and `device_activate` for exactly
//! this key, see [`super::device_pair`]); round 2 carries the pairing request and the new
//! key's possession signature, the existing device registers the key PENDING, adds it to the
//! lineage, publishes the revision and returns the grant; round 3 carries the possession
//! signature of the activation, which makes the key ACTIVE. Each community challenge lives
//! only 60 seconds, so every one is fetched right before the new device signs it.
//!
//! Human time is never redone. The [`Guest`] keeps a serializable [`GuestRecord`] that
//! holds, per round, the reply-key seed and the exact sealed message; a restart resends
//! those bytes and calls a step again only for a round it never completed. The [`Host`]
//! answers an exact repeat of a message with its stored reply, so a lost answer costs the
//! person nothing either. A [`Host`] that restarts loses its offer: the existing device
//! shows a new link.
use super::device_pair::StepChallenge;
use super::pairing::{Link, Offer, Received, ROUNDS};
use super::*;

/// The round 1 request: this device's community key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    hello: u8,
    device: ckmg::PublicKey,
}

/// The round 1 reply: the lineage anchor the request is made over, and the fresh challenge
/// of `device_add` for the new device to sign.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    /// The member's current lineage.
    pub anchor: ckmg::Lineage,
    /// The community's one-use challenge of the add step.
    pub challenge: StepChallenge,
}

/// The round 2 request: the pairing request and the new key's possession signature over the
/// add challenge.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestMessage {
    request: ckmg::PairingRequest,
    signature: Vec<u8>,
}

/// The round 2 reply: the grant, and the fresh challenge of `device_activate`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Granted {
    /// The grant (the root arrives sealed).
    pub grant: ckmg::PairingGrant,
    /// The community's one-use challenge of the activation step.
    pub challenge: StepChallenge,
}

/// The round 3 request: the new key's possession signature over the activation challenge.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationMessage {
    signature: Vec<u8>,
}

/// The round 3 reply: the key is ACTIVE.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    done: u8,
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
    /// Round 1: the member's explicit approval of pairing exactly `device`, which is the ONE
    /// wallet confirmation (a stamp covering both community steps for this key); answer with
    /// the lineage anchor and a fresh challenge for the add step.
    async fn welcome(&mut self, device: ckmg::PublicKey) -> Result<Welcome>;
    /// Round 2: verify the request, register the key PENDING at the community (`signature`
    /// proves the new key signed the add challenge), approve it (Keys), publish the lineage
    /// revision; answer with the grant and a fresh challenge for the activation.
    async fn approve(
        &mut self,
        request: ckmg::PairingRequest,
        signature: Vec<u8>,
    ) -> Result<Granted>;
    /// Round 3: make the pending key ACTIVE at the community (`signature` proves the new key
    /// signed the activation challenge).
    async fn activate(&mut self, signature: Vec<u8>) -> Result<()>;
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
                let Hello { hello, device } = decode(&payload)?;
                if hello != 1 {
                    return Err(ErrorCode::InvalidRequest);
                }
                encode(&self.steps.welcome(device).await?)?
            }
            2 => {
                let RequestMessage { request, signature } = decode(&payload)?;
                encode(&self.steps.approve(request, signature).await?)?
            }
            3 => {
                let ActivationMessage { signature } = decode(&payload)?;
                self.steps.activate(signature).await?;
                encode(&Done { done: 1 })?
            }
            _ => return Err(ErrorCode::Refused),
        };
        self.offer.answer(message, &reply_to, &reply)
    }
}

/// What the new device does for each round.
#[allow(async_fn_in_trait)]
pub trait GuestSteps {
    /// Before round 1: this device's community key, which the pairing adds.
    async fn device(&mut self) -> Result<ckmg::PublicKey>;
    /// Round 1 answered: make the pairing request over the confirmed anchor and sign, with
    /// this device's key, possession of the add `challenge`.
    async fn request(
        &mut self,
        anchor: ckmg::Lineage,
        challenge: StepChallenge,
    ) -> Result<(ckmg::PairingRequest, Vec<u8>)>;
    /// Round 2 answered: accept the grant (the root arrives sealed) and sign, with this
    /// device's key, possession of the activation `challenge`.
    async fn accept(
        &mut self,
        grant: ckmg::PairingGrant,
        challenge: StepChallenge,
    ) -> Result<Vec<u8>>;
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
        // Round 1: this device's key. The key is only asked for on a fresh record.
        let hello = if self.record.sent.is_empty() {
            Some(encode(&Hello {
                hello: 1,
                device: self.steps.device().await?,
            })?)
        } else {
            None
        };
        let welcome: Welcome = decode(&self.exchange(&link, 1, hello).await?)?;
        // Round 2: the request and the add signature are made once and kept before they are
        // sent; a restart uses the kept bytes.
        let request = if self.record.sent.len() >= 2 {
            None
        } else if let Some(kept) = self.record.results.first() {
            Some(kept.clone())
        } else {
            let (request, signature) = self
                .steps
                .request(welcome.anchor, welcome.challenge)
                .await?;
            let request = encode(&RequestMessage { request, signature })?;
            self.record.results.push(request.clone());
            (self.save)(&self.record)?;
            Some(request)
        };
        let granted: Granted = decode(&self.exchange(&link, 2, request).await?)?;
        // Round 3: accepting the grant and signing the activation happen once; the signature
        // is kept before it is sent.
        let activation = if self.record.sent.len() >= 3 {
            None
        } else if let Some(kept) = self.record.results.get(1) {
            Some(kept.clone())
        } else {
            let signature = self.steps.accept(granted.grant, granted.challenge).await?;
            let activation = encode(&ActivationMessage { signature })?;
            self.record.results.push(activation.clone());
            (self.save)(&self.record)?;
            Some(activation)
        };
        let _: Done = decode(&self.exchange(&link, ROUNDS, activation).await?)?;
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

    fn challenge(id: &str) -> StepChallenge {
        StepChallenge {
            id: id.into(),
            request: vec![1, 2, 3],
        }
    }

    /// What the existing device and the new device did, to prove no human step ran twice.
    #[derive(Default)]
    struct Counts {
        /// The wallet confirmation: exactly one per pairing.
        welcomes: usize,
        approved: usize,
        activated: usize,
        devices: usize,
        requests: usize,
        accepts: usize,
    }

    type Shared = Rc<RefCell<Counts>>;

    struct FakeHost(Shared);
    impl HostSteps for FakeHost {
        async fn welcome(&mut self, device: ckmg::PublicKey) -> Result<Welcome> {
            assert!(device == key(3));
            self.0.borrow_mut().welcomes += 1;
            Ok(Welcome {
                anchor: lineage(1),
                challenge: challenge("add"),
            })
        }
        async fn approve(
            &mut self,
            request: ckmg::PairingRequest,
            signature: Vec<u8>,
        ) -> Result<Granted> {
            assert_eq!(signature, b"signed add".to_vec());
            self.0.borrow_mut().approved += 1;
            Ok(Granted {
                grant: ckmg::PairingGrant {
                    version: 3,
                    request,
                    lineage: lineage(2),
                    sealed_root: vec![1, 2, 3],
                    signature: self::signature(),
                },
                challenge: challenge("activate"),
            })
        }
        async fn activate(&mut self, signature: Vec<u8>) -> Result<()> {
            assert_eq!(signature, b"signed activate".to_vec());
            self.0.borrow_mut().activated += 1;
            Ok(())
        }
    }

    struct FakeGuest(Shared);
    impl GuestSteps for FakeGuest {
        async fn device(&mut self) -> Result<ckmg::PublicKey> {
            self.0.borrow_mut().devices += 1;
            Ok(key(3))
        }
        async fn request(
            &mut self,
            anchor: ckmg::Lineage,
            challenge: StepChallenge,
        ) -> Result<(ckmg::PairingRequest, Vec<u8>)> {
            assert!(anchor == lineage(1));
            assert_eq!(challenge.id, "add");
            self.0.borrow_mut().requests += 1;
            Ok((request(), b"signed add".to_vec()))
        }
        async fn accept(
            &mut self,
            grant: ckmg::PairingGrant,
            challenge: StepChallenge,
        ) -> Result<Vec<u8>> {
            assert!(grant.lineage == lineage(2));
            assert_eq!(challenge.id, "activate");
            self.0.borrow_mut().accepts += 1;
            Ok(b"signed activate".to_vec())
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
    fn three_rounds_pair_the_devices_with_one_confirmation() {
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
        // ONE wallet confirmation (welcome) for the whole pairing, then add and activate.
        assert_eq!(
            (counts.welcomes, counts.approved, counts.activated),
            (1, 1, 1)
        );
        assert_eq!(
            (counts.devices, counts.requests, counts.accepts),
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
                    (counts.welcomes, counts.approved, counts.activated),
                    (1, 1, 1),
                    "{lose_reply} {at}"
                );
                assert_eq!(
                    (counts.devices, counts.requests, counts.accepts),
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
        assert_eq!(counts.borrow().activated, 0);
    }
}
