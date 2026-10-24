//! The two roles of one device pairing over the four-round channel of [`super::pairing`]:
//! the existing device ([`Host`], serves rounds) and the new device ([`Guest`], drives
//! them). Both are generic over the steps they delegate, so this module owns the protocol
//! (order, payload shapes, retries, restarts) and nothing about authority: every step is
//! a capability the embedding supplies (the wallet confirmation, Keys, the community server).
//!
//! One pairing session is ONE link and ONE channel for every scope it brings along: the
//! wallet and each community membership, all by default and deselectable on the existing
//! device ([`Selection`]). Each round carries one entry per scope, and every scope runs its
//! own steps with its own credential and server; the entries share no identifier, so no
//! server can link the memberships. Wallet first, then the communities in name order.
//!
//! The pairing runs on stamps, not on a second passkey: the new device only has its own
//! device key per scope. Round 1 gives it each lineage anchor; round 2 carries its pairing
//! requests, which name its keys, and the existing device's member approves exactly those
//! keys, ONE wallet confirmation per scope (a stamp covering `device_add` and
//! `device_activate`, see [`super::device_pair`]); the answer is each community's fresh
//! challenge for the add step. Round 3 carries the new keys' possession signatures over
//! them: the existing device registers each key PENDING, adds it to its lineage, publishes
//! the revision and answers with the grants and the fresh activation challenges. Round 4
//! carries the possession signatures of the activations, which make the keys ACTIVE. A
//! community challenge lives only 60 seconds, so every challenge is fetched after all human
//! steps of its round, right before the new device signs it.
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
use std::collections::BTreeSet;

/// One scope of a pairing session. The wallet sorts before every community.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// The member's wallet (global passport and its lineage).
    Wallet,
    /// One community membership, by community name.
    Community(String),
}

/// The scopes one pairing session brings along: every scope by default, the member may
/// deselect any before the link is shown. Never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection(BTreeSet<Scope>);

impl Selection {
    /// Every scope selected. `None` without any scope: there is nothing to pair.
    pub fn all(scopes: impl IntoIterator<Item = Scope>) -> Option<Self> {
        let all: BTreeSet<Scope> = scopes.into_iter().collect();
        (!all.is_empty()).then_some(Self(all))
    }

    /// Leave `scope` out. Refused (`false`) when it is not selected or is the last one.
    pub fn deselect(&mut self, scope: &Scope) -> bool {
        self.0.len() > 1 && self.0.remove(scope)
    }

    /// The selected scopes in session order (wallet first).
    pub fn scopes(&self) -> Vec<Scope> {
        self.0.iter().cloned().collect()
    }
}

/// One scope's value inside a round.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry<T> {
    scope: Scope,
    value: T,
}

/// A round's payload: exactly one entry per scope of the session, in session order.
type Entries<T> = Vec<Entry<T>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    hello: u8,
}

/// Round 1 reply.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorsMessage {
    anchors: Entries<ckmg::Lineage>,
}

/// Round 2 request: one pairing request per scope, naming the new device's key there.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestsMessage {
    requests: Entries<ckmg::PairingRequest>,
}

/// Round 2 reply: the one-use challenge of the add step of every community scope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengesMessage {
    challenges: Entries<StepChallenge>,
}

/// Round 3 request and round 4 request: the new keys' possession signatures per scope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturesMessage {
    signatures: Entries<Vec<u8>>,
}

/// Round 3 reply: the grants (the roots arrive sealed) and the fresh challenges of the
/// activation step.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantsMessage {
    grants: Entries<ckmg::PairingGrant>,
    challenges: Entries<StepChallenge>,
}

/// Round 4 reply: every key is ACTIVE.
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

/// The entries' values, once their scopes are exactly `scopes` in order.
fn values<T>(scopes: &[Scope], entries: Entries<T>) -> Result<Vec<T>> {
    if entries.len() != scopes.len()
        || entries
            .iter()
            .zip(scopes)
            .any(|(entry, scope)| &entry.scope != scope)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(entries.into_iter().map(|entry| entry.value).collect())
}

/// What the existing device does for each round and scope. Each method is one
/// authority-bearing or human-facing step; a failure leaves the round unanswered so the new
/// device may retry.
#[allow(async_fn_in_trait)]
pub trait HostSteps {
    /// Round 1: the member's current lineage in `scope`, which the pairing request is made over.
    async fn anchor(&mut self, scope: &Scope) -> Result<ckmg::Lineage>;
    /// Round 2: the member's explicit approval of pairing exactly the key `request` names in
    /// `scope`, which is that scope's ONE wallet confirmation (a stamp covering both
    /// community steps for this key).
    async fn confirm(&mut self, scope: &Scope, request: ckmg::PairingRequest) -> Result<()>;
    /// A fresh one-use community challenge of `scope`, asked for after the round's human
    /// steps (rounds 2 and 3) so it is fresh when the new device signs it.
    async fn challenge(&mut self, scope: &Scope) -> Result<StepChallenge>;
    /// Round 3: register the key PENDING at the community (`signature` proves the new key
    /// signed the add challenge), approve it (Keys), publish the lineage revision; answer
    /// with the grant.
    async fn approve(&mut self, scope: &Scope, signature: Vec<u8>) -> Result<ckmg::PairingGrant>;
    /// Round 4: make the pending key ACTIVE at the community (`signature` proves the new key
    /// signed the activation challenge).
    async fn activate(&mut self, scope: &Scope, signature: Vec<u8>) -> Result<()>;
}

/// The existing device's side of one open offer.
pub struct Host<S: HostSteps> {
    offer: Offer,
    scopes: Vec<Scope>,
    steps: S,
}

impl<S: HostSteps> Host<S> {
    /// Serve `offer` for the `selection`'s scopes with `steps`.
    pub fn new(offer: Offer, selection: &Selection, steps: S) -> Self {
        Self {
            offer,
            scopes: selection.scopes(),
            steps,
        }
    }

    /// Unix seconds this offer stays open.
    pub fn expires(&self) -> u64 {
        self.offer.expires()
    }

    /// All rounds are answered.
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

    /// Fresh challenges for every scope, in session order.
    async fn challenges(&mut self) -> Result<Entries<StepChallenge>> {
        let mut challenges = Vec::new();
        for scope in self.scopes.clone() {
            let value = self.steps.challenge(&scope).await?;
            challenges.push(Entry { scope, value });
        }
        Ok(challenges)
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
        let scopes = self.scopes.clone();
        let reply = match round {
            1 => {
                let Hello { hello } = decode(&payload)?;
                if hello != 1 {
                    return Err(ErrorCode::InvalidRequest);
                }
                let mut anchors = Vec::new();
                for scope in scopes {
                    let value = self.steps.anchor(&scope).await?;
                    anchors.push(Entry { scope, value });
                }
                encode(&AnchorsMessage { anchors })?
            }
            2 => {
                let RequestsMessage { requests } = decode(&payload)?;
                // Every scope's confirmation first (they take the person's time), then the
                // challenges, so none of them expires while the person confirms.
                for (scope, request) in scopes.iter().zip(values(&scopes, requests)?) {
                    self.steps.confirm(scope, request).await?;
                }
                encode(&ChallengesMessage {
                    challenges: self.challenges().await?,
                })?
            }
            3 => {
                let SignaturesMessage { signatures } = decode(&payload)?;
                let mut grants = Vec::new();
                for (scope, signature) in scopes.iter().zip(values(&scopes, signatures)?) {
                    let value = self.steps.approve(scope, signature).await?;
                    grants.push(Entry {
                        scope: scope.clone(),
                        value,
                    });
                }
                encode(&GrantsMessage {
                    grants,
                    challenges: self.challenges().await?,
                })?
            }
            4 => {
                let SignaturesMessage { signatures } = decode(&payload)?;
                for (scope, signature) in scopes.iter().zip(values(&scopes, signatures)?) {
                    self.steps.activate(scope, signature).await?;
                }
                encode(&Done { done: 1 })?
            }
            _ => return Err(ErrorCode::Refused),
        };
        self.offer.answer(message, &reply_to, &reply)
    }
}

/// What the new device does for each round and scope.
#[allow(async_fn_in_trait)]
pub trait GuestSteps {
    /// Round 1 answered: make the pairing request over the confirmed anchor of `scope` (it
    /// names this device's key there).
    async fn request(
        &mut self,
        scope: &Scope,
        anchor: ckmg::Lineage,
    ) -> Result<ckmg::PairingRequest>;
    /// Round 2 answered: sign, with this device's key of `scope`, possession of the add
    /// `challenge`.
    async fn possess(&mut self, scope: &Scope, challenge: StepChallenge) -> Result<Vec<u8>>;
    /// Round 3 answered: accept the grant of `scope` (the root arrives sealed) and sign, with
    /// this device's key there, possession of the activation `challenge`.
    async fn accept(
        &mut self,
        scope: &Scope,
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
        // Round 1: the host names the session's scopes with their anchors.
        let hello = if self.record.sent.is_empty() {
            Some(encode(&Hello { hello: 1 })?)
        } else {
            None
        };
        let AnchorsMessage { anchors } = decode(&self.exchange(&link, 1, hello).await?)?;
        let scopes: Vec<Scope> = anchors.iter().map(|entry| entry.scope.clone()).collect();
        if scopes.is_empty() || scopes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ErrorCode::InvalidRequest);
        }
        // Round 2: the requests are made once and kept before they are sent; a restart uses
        // the kept bytes.
        let requests = if self.record.sent.len() >= 2 {
            None
        } else if let Some(kept) = self.record.results.first() {
            Some(kept.clone())
        } else {
            let mut requests = Vec::new();
            for Entry { scope, value } in anchors {
                let request = self.steps.request(&scope, value).await?;
                requests.push(Entry {
                    scope,
                    value: request,
                });
            }
            let requests = encode(&RequestsMessage { requests })?;
            self.record.results.push(requests.clone());
            (self.save)(&self.record)?;
            Some(requests)
        };
        let ChallengesMessage { challenges } = decode(&self.exchange(&link, 2, requests).await?)?;
        // Round 3: the add signatures are made once and kept before they are sent.
        let possessions = if self.record.sent.len() >= 3 {
            None
        } else if let Some(kept) = self.record.results.get(1) {
            Some(kept.clone())
        } else {
            let mut signatures = Vec::new();
            for (scope, challenge) in scopes.iter().zip(values(&scopes, challenges)?) {
                let value = self.steps.possess(scope, challenge).await?;
                signatures.push(Entry {
                    scope: scope.clone(),
                    value,
                });
            }
            let possessions = encode(&SignaturesMessage { signatures })?;
            self.record.results.push(possessions.clone());
            (self.save)(&self.record)?;
            Some(possessions)
        };
        let granted: GrantsMessage = decode(&self.exchange(&link, 3, possessions).await?)?;
        // Round 4: accepting the grants and signing the activations happen once; the
        // signatures are kept before they are sent.
        let activations = if self.record.sent.len() >= 4 {
            None
        } else if let Some(kept) = self.record.results.get(2) {
            Some(kept.clone())
        } else {
            let grants = values(&scopes, granted.grants)?;
            let challenges = values(&scopes, granted.challenges)?;
            let mut signatures = Vec::new();
            for ((scope, grant), challenge) in scopes.iter().zip(grants).zip(challenges) {
                let value = self.steps.accept(scope, grant, challenge).await?;
                signatures.push(Entry {
                    scope: scope.clone(),
                    value,
                });
            }
            let activations = encode(&SignaturesMessage { signatures })?;
            self.record.results.push(activations.clone());
            (self.save)(&self.record)?;
            Some(activations)
        };
        let _: Done = decode(&self.exchange(&link, ROUNDS, activations).await?)?;
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
            delegates: Vec::new(),
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

    fn community(name: &str) -> Scope {
        Scope::Community(name.into())
    }

    /// What the existing device and the new device did, to prove no human step ran twice.
    #[derive(Default)]
    struct Counts {
        anchors: usize,
        /// The wallet confirmations: exactly one per scope.
        confirmations: usize,
        approved: usize,
        activated: usize,
        requests: usize,
        possessions: usize,
        accepts: usize,
        touched: Vec<Scope>,
    }

    type Shared = Rc<RefCell<Counts>>;

    struct FakeHost(Shared);
    impl HostSteps for FakeHost {
        async fn anchor(&mut self, _: &Scope) -> Result<ckmg::Lineage> {
            self.0.borrow_mut().anchors += 1;
            Ok(lineage(1))
        }
        async fn confirm(&mut self, scope: &Scope, request: ckmg::PairingRequest) -> Result<()> {
            assert!(request.device == key(3));
            let mut counts = self.0.borrow_mut();
            counts.confirmations += 1;
            counts.touched.push(scope.clone());
            Ok(())
        }
        async fn challenge(&mut self, scope: &Scope) -> Result<StepChallenge> {
            Ok(challenge(&format!("{scope:?}")))
        }
        async fn approve(&mut self, _: &Scope, signature: Vec<u8>) -> Result<ckmg::PairingGrant> {
            assert_eq!(signature, b"signed add".to_vec());
            self.0.borrow_mut().approved += 1;
            Ok(ckmg::PairingGrant {
                version: 3,
                request: request(),
                lineage: lineage(2),
                sealed_root: vec![1, 2, 3],
                signature: self::signature(),
            })
        }
        async fn activate(&mut self, _: &Scope, signature: Vec<u8>) -> Result<()> {
            assert_eq!(signature, b"signed activate".to_vec());
            self.0.borrow_mut().activated += 1;
            Ok(())
        }
    }

    struct FakeGuest(Shared);
    impl GuestSteps for FakeGuest {
        async fn request(
            &mut self,
            _: &Scope,
            anchor: ckmg::Lineage,
        ) -> Result<ckmg::PairingRequest> {
            assert!(anchor == lineage(1));
            self.0.borrow_mut().requests += 1;
            Ok(request())
        }
        async fn possess(&mut self, scope: &Scope, challenge: StepChallenge) -> Result<Vec<u8>> {
            assert_eq!(challenge.id, format!("{scope:?}"));
            self.0.borrow_mut().possessions += 1;
            Ok(b"signed add".to_vec())
        }
        async fn accept(
            &mut self,
            scope: &Scope,
            grant: ckmg::PairingGrant,
            challenge: StepChallenge,
        ) -> Result<Vec<u8>> {
            assert!(grant.lineage == lineage(2));
            assert_eq!(challenge.id, format!("{scope:?}"));
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

    fn selection() -> Selection {
        Selection::all([community("beta"), Scope::Wallet, community("alpha")]).unwrap()
    }

    fn setup_with(selection: &Selection) -> (Rc<RefCell<Host<FakeHost>>>, String, Shared) {
        let address = cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap();
        let (offer, link) = Offer::new(&address, 1_000).unwrap();
        let counts = Shared::default();
        (
            Rc::new(RefCell::new(Host::new(
                offer,
                selection,
                FakeHost(counts.clone()),
            ))),
            link,
            counts,
        )
    }

    fn setup() -> (Rc<RefCell<Host<FakeHost>>>, String, Shared) {
        setup_with(&selection())
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
    fn the_selection_is_all_by_default_wallet_first_and_never_empty() {
        let mut selected = selection();
        assert_eq!(
            selected.scopes(),
            vec![Scope::Wallet, community("alpha"), community("beta")]
        );
        assert!(selected.deselect(&community("alpha")));
        assert!(!selected.deselect(&community("alpha")), "already left out");
        assert!(selected.deselect(&Scope::Wallet));
        assert!(
            !selected.deselect(&community("beta")),
            "the last scope stays"
        );
        assert_eq!(selected.scopes(), vec![community("beta")]);
        assert!(Selection::all([]).is_none());
    }

    #[test]
    fn four_rounds_on_one_link_pair_every_scope_with_one_confirmation_each() {
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
        // Three scopes, ONE link: one wallet confirmation per scope, then add and activate.
        assert_eq!(
            (
                counts.anchors,
                counts.confirmations,
                counts.approved,
                counts.activated
            ),
            (3, 3, 3, 3)
        );
        assert_eq!(
            (counts.requests, counts.possessions, counts.accepts),
            (3, 3, 3)
        );
        assert_eq!(
            counts.touched,
            vec![Scope::Wallet, community("alpha"), community("beta")],
            "wallet first, then the communities in order"
        );
        assert!(host.borrow().finished() && saved.borrow().done());
        // A finished record is a no-op.
        futures_executor::block_on(guest.run()).unwrap();
        assert_eq!(counts.accepts, 3);
    }

    #[test]
    fn a_deselected_scope_is_never_touched() {
        let mut chosen = selection();
        assert!(chosen.deselect(&community("beta")));
        let (host, link, counts) = setup_with(&chosen);
        let mut guest = Guest::new(
            FakeGuest(counts.clone()),
            wire(&host, &Rc::default()),
            |_: &GuestRecord| Ok(()),
            GuestRecord::new(&link),
        );
        futures_executor::block_on(guest.run()).unwrap();
        let counts = counts.borrow();
        assert_eq!(counts.touched, vec![Scope::Wallet, community("alpha")]);
        assert_eq!((counts.confirmations, counts.activated), (2, 2));
    }

    #[test]
    fn a_lost_connection_or_restart_at_any_step_redoes_no_human_work() {
        // Break the exchange at every call, once as a lost request and once as a lost
        // reply (the host has already acted), and restart from the saved record each time.
        for lose_reply in [false, true] {
            for at in 1..=usize::from(ROUNDS) {
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
                    (
                        counts.anchors,
                        counts.confirmations,
                        counts.approved,
                        counts.activated
                    ),
                    (3, 3, 3, 3),
                    "{lose_reply} {at}"
                );
                assert_eq!(
                    (counts.requests, counts.possessions, counts.accepts),
                    (3, 3, 3),
                    "{lose_reply} {at}"
                );
            }
        }
    }

    #[test]
    fn entries_must_be_exactly_the_sessions_scopes_in_order() {
        let scopes = [Scope::Wallet, community("alpha")];
        let entry = |scope: Scope| Entry { scope, value: 1u8 };
        assert!(values(
            &scopes,
            vec![entry(Scope::Wallet), entry(community("alpha"))]
        )
        .is_ok());
        assert!(
            values(&scopes, vec![entry(Scope::Wallet)]).is_err(),
            "a scope missing"
        );
        assert!(
            values(
                &scopes,
                vec![entry(community("alpha")), entry(Scope::Wallet)]
            )
            .is_err(),
            "out of order"
        );
        assert!(
            values(
                &scopes,
                vec![entry(Scope::Wallet), entry(community("beta"))]
            )
            .is_err(),
            "a scope the session does not have"
        );
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
        // The host serves the last round only after the rounds before it.
        let link = Link::parse(&link).unwrap();
        let (message, _) = link.seal_round(ROUNDS, b"{}").unwrap();
        assert_eq!(
            futures_executor::block_on(host.borrow_mut().serve(&message, 1_050)).err(),
            Some(ErrorCode::Refused)
        );
        assert_eq!(counts.borrow().activated, 0);
    }
}
