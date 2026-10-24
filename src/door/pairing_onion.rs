//! The real carrier of a device pairing: an EPHEMERAL onion service of the existing device and
//! calls of the new device through Tor.
//!
//! The existing device calls [`OnionOffer::open`]: the backend publishes a fresh onion service
//! (with [`ephemeral_tor`], a fresh key per offer, never a member key), whose address goes into
//! the `cvpr1.` link together with the one-time secret ([`Offer`]). [`OnionOffer::serve`] then
//! answers the sealed rounds until the pairing is finished, the offer window
//! ([`super::pairing::OFFER_SECONDS`]) has passed, or too many messages arrived; in each case the onion service
//! is withdrawn (the listener is dropped). The new device uses [`OnionChannel`] as its
//! [`Channel`]: one Tor call per round.
//!
//! Nothing here seals or opens anything: every message is already HPKE PSK mode under the
//! link's one-time secret ([`super::pairing`]), so a party without the secret can neither read
//! nor inject, and a message that fails to open gets NO reply at all (the stream just ends).
//! This module adds only bounds: a hard maximum message size in both directions
//! ([`MAX_MESSAGE_BYTES`], checked before any decoding), a bounded number of calls per offer
//! ([`MAX_CALLS`]), and the offer deadline. Framing is that of the Tor message layer
//! (length-prefixed frames with a size limit, set to the same maximum).
use super::pairing::{MAX_MESSAGE_BYTES, Offer};
use super::pairing_roles::{Channel, Host, HostSteps};
use super::*;
use std::sync::Arc;
use std::time::Duration;

/// Most calls (valid or not) one offer handles before it closes: the four rounds with
/// generous room for retries, and a hard stop for a flood of guesses.
pub const MAX_CALLS: usize = 64;

/// What the serve loop needs from the existing device's side of an offer.
#[allow(async_fn_in_trait)]
pub trait Serve {
    /// Answer one message, or refuse it.
    async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>>;
    /// The pairing is complete.
    fn finished(&self) -> bool;
    /// Unix second at which the offer ends.
    fn expires(&self) -> u64;
}

impl<S: HostSteps> Serve for Host<S> {
    async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        Host::serve(self, message, now).await
    }
    fn finished(&self) -> bool {
        Host::finished(self)
    }
    fn expires(&self) -> u64 {
        Host::expires(self)
    }
}

/// The new device's [`Channel`]: one call over Tor per round, size-bounded both ways.
pub struct OnionChannel<B: cmsh::Backend> {
    backend: Arc<B>,
}

impl<B: cmsh::Backend> OnionChannel<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }
}

impl<B: cmsh::Backend> Channel for OnionChannel<B> {
    async fn call(&mut self, address: &cmsh::Address, message: &[u8]) -> Result<Vec<u8>> {
        if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
            return Err(ErrorCode::InvalidRequest);
        }
        let reply = self
            .backend
            .app_call(address, message)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        if reply.is_empty() || reply.len() > MAX_MESSAGE_BYTES {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(reply)
    }
}

/// The published ephemeral service of one offer. Dropping it withdraws the service.
pub struct OnionOffer {
    listener: Box<dyn cmsh::Listener>,
}

impl OnionOffer {
    /// Publish a fresh service on `backend` (which must hold a key used for this offer only)
    /// and open the [`Offer`] for its address: returns the service, the offer and the
    /// `cvpr1.` link text to show locally.
    pub async fn open<B: cmsh::Backend + ?Sized>(
        backend: &B,
        now: u64,
    ) -> Result<(Self, Offer, String)> {
        let listener = backend.listen().await.map_err(|_| ErrorCode::Unavailable)?;
        let (offer, link) = Offer::new(listener.address(), now)?;
        Ok((Self { listener }, offer, link))
    }

    /// Answer calls until the pairing is finished (`Ok`), the offer expires or the call
    /// budget is spent (`Refused`), or the service is lost (`Unavailable`). The service is
    /// withdrawn on return in every case. A message that is oversized, empty, out of order,
    /// under another secret, or too late gets no reply.
    pub async fn serve<H: Serve>(mut self, host: &mut H, clock: impl Fn() -> u64) -> Result<()> {
        let mut calls = 0usize;
        loop {
            if host.finished() {
                return Ok(());
            }
            let now = clock();
            let expires = host.expires();
            if now >= expires || calls >= MAX_CALLS {
                return Err(ErrorCode::Refused);
            }
            let wait = Duration::from_secs(expires - now);
            let event = match tokio::time::timeout(wait, self.listener.next()).await {
                Err(_) => return Err(ErrorCode::Refused),
                Ok(Err(_)) => return Err(ErrorCode::Unavailable),
                Ok(Ok(event)) => event,
            };
            calls += 1;
            let cmsh::Event::Call { payload, reply } = event else {
                continue;
            };
            if payload.is_empty() || payload.len() > MAX_MESSAGE_BYTES {
                continue;
            }
            if let Ok(sealed) = host.serve(&payload, clock()).await {
                if sealed.len() <= MAX_MESSAGE_BYTES {
                    let _ = reply.send(&sealed).await;
                }
            }
        }
    }
}

/// A Tor backend for ONE offer: a fresh random onion key and scope, so no offer is linkable
/// to the member's community onion or to another offer. Needs a started tokio runtime.
#[cfg(feature = "native-tor")]
pub mod ephemeral {
    use super::*;
    use ctrn::arti::{ArtiNetwork, Directories, Identity, TokioClock};
    use tor_hscrypto::pk::HsIdKeypair;
    use tor_llcrypto::pk::ed25519;

    struct OneKey {
        scope: ctrn::Scope,
        seed: zeroize::Zeroizing<[u8; 32]>,
    }
    impl Identity for OneKey {
        fn onion_key(&self, scope: &ctrn::Scope) -> std::result::Result<HsIdKeypair, ctrn::Error> {
            if scope != &self.scope {
                return Err(ctrn::Error::new(ctrn::ErrorKind::Protocol, "wrong scope"));
            }
            let pair = ed25519::Keypair::from_bytes(&self.seed);
            Ok(HsIdKeypair::from(ed25519::ExpandedKeypair::from(&pair)))
        }
    }

    /// The started backend of one offer; `stop` it (or drop it with the offer) when done.
    pub struct EphemeralTor {
        node: Arc<ctrn::Node>,
        /// The mesh-facing backend.
        pub backend: Arc<cmsh::Tor>,
    }
    impl EphemeralTor {
        /// Tear the whole Tor runtime of this offer down.
        pub fn stop(&self) {
            self.node.stop();
        }
    }
    impl Drop for EphemeralTor {
        fn drop(&mut self) {
            self.node.stop();
        }
    }

    fn random<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0u8; N];
        getrandom::fill(&mut bytes).map_err(|_| ErrorCode::Unavailable)?;
        Ok(bytes)
    }

    /// Build and start an ephemeral Tor backend. `tor` is the default network configuration
    /// (or the private fixture's), `directories` holds this device's guard/cache state.
    pub async fn ephemeral_tor(
        runtime: tor_rtcompat::tokio::TokioRustlsRuntime,
        tor: arti_client::config::TorClientConfigBuilder,
        directories: Directories,
        limits: ctrn::Limits,
    ) -> Result<EphemeralTor> {
        let scope = ctrn::Scope(random::<32>()?);
        let identity = Arc::new(OneKey {
            scope: scope.clone(),
            seed: zeroize::Zeroizing::new(random::<32>()?),
        });
        let network = ArtiNetwork::new(runtime, tor, directories, identity)
            .map_err(|_| ErrorCode::Unavailable)?;
        let clock = Arc::new(TokioClock::default());
        let node = Arc::new(
            ctrn::Node::new(Arc::new(network), clock.clone(), scope, limits)
                .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        let messages = ctrn::messages::Messages::new(
            node.clone(),
            Arc::new(|future: ctrn::BoxFuture<'static, ()>| {
                tokio::spawn(future);
            }),
            clock,
            ctrn::MessageLimits {
                max_payload: MAX_MESSAGE_BYTES,
                timeout_ms: 60_000,
            },
        )
        .map_err(|_| ErrorCode::InvalidRequest)?;
        node.start().await.map_err(|_| ErrorCode::Unavailable)?;
        Ok(EphemeralTor {
            node,
            backend: Arc::new(cmsh::Tor(messages)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::pairing::{Link, OFFER_SECONDS, Received};
    use super::*;
    use std::cell::Cell;
    use std::sync::Mutex;
    use tokio::sync::{mpsc, oneshot};

    type Call = (Vec<u8>, oneshot::Sender<Vec<u8>>);

    /// In-memory carrier with the semantics of the Tor message backend: one listener, one
    /// call = one request and at most one reply; a dropped listener or reply fails the call.
    struct Net {
        tx: Mutex<Option<mpsc::UnboundedSender<Call>>>,
        address: cmsh::Address,
    }
    struct Port(oneshot::Sender<Vec<u8>>);
    #[cmsh::async_trait]
    impl cmsh::ReplyPort for Port {
        async fn send(self: Box<Self>, payload: &[u8]) -> std::result::Result<(), cmsh::Error> {
            self.0
                .send(payload.to_vec())
                .map_err(|_| cmsh::Error::new(cmsh::ErrorKind::Closed, "gone"))
        }
    }
    struct Live {
        rx: mpsc::UnboundedReceiver<Call>,
        address: cmsh::Address,
    }
    #[cmsh::async_trait]
    impl cmsh::Listener for Live {
        fn address(&self) -> &cmsh::Address {
            &self.address
        }
        async fn next(&mut self) -> std::result::Result<cmsh::Event, cmsh::Error> {
            match self.rx.recv().await {
                Some((payload, tx)) => Ok(cmsh::Event::Call {
                    payload,
                    reply: cmsh::Reply::new(Box::new(Port(tx)), MAX_MESSAGE_BYTES),
                }),
                None => Err(cmsh::Error::new(cmsh::ErrorKind::Closed, "gone")),
            }
        }
    }
    #[cmsh::async_trait]
    impl cmsh::Backend for Net {
        fn scheme(&self) -> cmsh::Scheme {
            self.address.scheme().clone()
        }
        fn capabilities(&self) -> cmsh::Capabilities {
            cmsh::Capabilities {
                anonymous: true,
                datagrams: false,
                offline_delivery: false,
                dht: false,
                latency: cmsh::LatencyClass::Interactive,
            }
        }
        fn max_payload(&self) -> usize {
            MAX_MESSAGE_BYTES
        }
        async fn listen(&self) -> std::result::Result<Box<dyn cmsh::Listener>, cmsh::Error> {
            let (tx, rx) = mpsc::unbounded_channel();
            *self.tx.lock().unwrap() = Some(tx);
            Ok(Box::new(Live {
                rx,
                address: self.address.clone(),
            }))
        }
        async fn app_message(
            &self,
            _: &cmsh::Address,
            _: &[u8],
        ) -> std::result::Result<(), cmsh::Error> {
            Err(cmsh::Error::new(cmsh::ErrorKind::Unsupported, "no"))
        }
        async fn app_call(
            &self,
            _: &cmsh::Address,
            payload: &[u8],
        ) -> std::result::Result<Vec<u8>, cmsh::Error> {
            let closed = || cmsh::Error::new(cmsh::ErrorKind::Closed, "gone");
            let (reply_tx, reply_rx) = oneshot::channel();
            let tx = self.tx.lock().unwrap().clone().ok_or_else(closed)?;
            tx.send((payload.to_vec(), reply_tx))
                .map_err(|_| closed())?;
            reply_rx.await.map_err(|_| closed())
        }
    }
    fn net() -> Arc<Net> {
        Arc::new(Net {
            tx: Mutex::new(None),
            address: cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap(),
        })
    }

    /// Host side with the real offer (all sealing and ordering rules), echoing payloads.
    struct Echo {
        offer: Offer,
        handled: usize,
    }
    impl Serve for Echo {
        async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
            match self.offer.open_round(message, now)? {
                Received::Repeat(reply) => Ok(reply),
                Received::Round {
                    payload, reply_to, ..
                } => {
                    self.handled += 1;
                    self.offer.answer(message, &reply_to, &payload)
                }
            }
        }
        fn finished(&self) -> bool {
            self.offer.finished()
        }
        fn expires(&self) -> u64 {
            self.offer.expires()
        }
    }

    const NOW: u64 = 1_000;

    async fn setup() -> (Arc<Net>, OnionOffer, Echo, Link) {
        let net = net();
        let (service, offer, text) = OnionOffer::open(&*net, NOW).await.unwrap();
        (
            net,
            service,
            Echo { offer, handled: 0 },
            Link::parse(&text).unwrap(),
        )
    }

    /// One honest round: seal, call, open the reply.
    async fn round(
        channel: &mut OnionChannel<Net>,
        link: &Link,
        n: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let (message, awaiting) = link.seal_round(n, payload)?;
        let reply = channel.call(link.address(), &message).await?;
        Ok(awaiting.open_reply(&reply)?.to_vec())
    }

    #[tokio::test(start_paused = true)]
    async fn full_round_trip_finishes_and_withdraws_the_service() {
        let (net, service, mut host, link) = setup().await;
        let mut channel = OnionChannel::new(net.clone());
        let guest = async {
            for n in 1..=4u8 {
                let payload = vec![n; 10 * n as usize];
                assert_eq!(
                    round(&mut channel, &link, n, &payload).await.unwrap(),
                    payload
                );
            }
        };
        let (served, ()) = tokio::join!(service.serve(&mut host, || NOW + 1), guest);
        served.unwrap();
        assert_eq!(host.handled, 4);
        // The service is gone: nothing answers any more.
        assert!(round(&mut channel, &link, 1, b"late").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_secret_is_refused_without_a_reply() {
        let (net, service, mut host, link) = setup().await;
        // Same service address, another offer's secret.
        let (_, text) = Offer::new(link.address(), NOW).unwrap();
        let wrong = Link::parse(&text).unwrap();
        let mut channel = OnionChannel::new(net.clone());
        let guest = async {
            assert!(round(&mut channel, &wrong, 1, b"x").await.is_err());
            assert_eq!(round(&mut channel, &link, 1, b"y").await.unwrap(), b"y");
        };
        let (_, ()) = tokio::join!(service.serve(&mut host, || NOW + 1), guest);
        assert_eq!(host.handled, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn reordered_tampered_and_replayed_frames_are_refused() {
        let (net, service, mut host, link) = setup().await;
        let mut channel = OnionChannel::new(net.clone());
        let guest = async {
            // Round 3 first: out of order.
            assert!(round(&mut channel, &link, 3, b"c").await.is_err());
            // A flipped bit in a valid frame.
            let (mut message, _) = link.seal_round(1, b"a").unwrap();
            let last = message.len() - 1;
            message[last] ^= 1;
            assert!(channel.call(link.address(), &message).await.is_err());
            // Honest round 1, then its exact replay: the identical reply, no new effect.
            let (message, awaiting) = link.seal_round(1, b"a").unwrap();
            let first = channel.call(link.address(), &message).await.unwrap();
            let again = channel.call(link.address(), &message).await.unwrap();
            assert_eq!(first, again);
            assert_eq!(awaiting.open_reply(&first).unwrap().to_vec(), b"a");
            // A reply fed back as a request, and round 1 resealed after round 1 is done
            // out of order again: both refused.
            assert!(channel.call(link.address(), &first).await.is_err());
            assert!(round(&mut channel, &link, 4, b"d").await.is_err());
        };
        let (_, ()) = tokio::join!(service.serve(&mut host, || NOW + 1), guest);
        assert_eq!(host.handled, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_offer_is_refused_and_withdrawn() {
        let (net, service, mut host, link) = setup().await;
        let mut channel = OnionChannel::new(net.clone());
        let clock = Cell::new(NOW + 1);
        let guest = async {
            clock.set(NOW + OFFER_SECONDS);
            assert!(round(&mut channel, &link, 1, b"late").await.is_err());
        };
        let (served, ()) = tokio::join!(service.serve(&mut host, || clock.get()), guest);
        assert_eq!(served, Err(ErrorCode::Refused));
        assert_eq!(host.handled, 0);
        assert!(round(&mut channel, &link, 1, b"late").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_offer_expires_by_itself() {
        let (net, service, mut host, link) = setup().await;
        let clock = Cell::new(NOW);
        let served = service.serve(&mut host, || {
            // Virtual time runs while waiting; the wall clock follows it.
            clock.set(clock.get() + 100);
            clock.get()
        });
        assert_eq!(served.await, Err(ErrorCode::Refused));
        let mut channel = OnionChannel::new(net);
        assert!(round(&mut channel, &link, 1, b"x").await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_frames_are_refused_both_ways() {
        let (net, service, mut host, link) = setup().await;
        let mut channel = OnionChannel::new(net.clone());
        let huge = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let guest = async {
            // The channel refuses before sending.
            assert_eq!(
                channel.call(link.address(), &huge).await,
                Err(ErrorCode::InvalidRequest)
            );
            // The host refuses what a hostile caller sends past the channel.
            use cmsh::Backend;
            assert!(net.app_call(link.address(), &huge).await.is_err());
            assert!(net.app_call(link.address(), &[]).await.is_err());
            assert_eq!(round(&mut channel, &link, 1, b"ok").await.unwrap(), b"ok");
        };
        let (_, ()) = tokio::join!(service.serve(&mut host, || NOW + 1), guest);
        assert_eq!(host.handled, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_call_budget_is_bounded() {
        let (net, service, mut host, link) = setup().await;
        let mut channel = OnionChannel::new(net.clone());
        let guest = async {
            for _ in 0..MAX_CALLS {
                let _ = round(&mut channel, &link, 2, b"x").await;
            }
        };
        let (served, ()) = tokio::join!(service.serve(&mut host, || NOW + 1), guest);
        assert_eq!(served, Err(ErrorCode::Refused));
    }
}
