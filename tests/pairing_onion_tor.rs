//! One full pairing round trip over a real ephemeral onion service on the private Tor test
//! network (ctrn fixture). Needs `TOR_FIXTURE_JSON`; run inside the fixture network.
#![cfg(feature = "private-tor-fixture")]
use cmsg::door::pairing::{Link, Offer, Received};
use cmsg::door::pairing_onion::{ephemeral::ephemeral_tor, OnionChannel, OnionOffer, Serve};
use cmsg::door::pairing_roles::Channel;
use cmsg::door::{ErrorCode, Result};
use std::sync::Arc;

struct Echo(Offer);
impl Serve for Echo {
    async fn serve(&mut self, message: &[u8], now: u64) -> Result<Vec<u8>> {
        match self.0.open_round(message, now)? {
            Received::Repeat(r) => Ok(r),
            Received::Round {
                payload, reply_to, ..
            } => self.0.answer(message, &reply_to, &payload),
        }
    }
    fn finished(&self) -> bool {
        self.0.finished()
    }
    fn expires(&self) -> u64 {
        self.0.expires()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn tor(
    dir: &std::path::Path,
    name: &str,
) -> cmsg::door::pairing_onion::ephemeral::EphemeralTor {
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("TOR_FIXTURE_JSON").unwrap()).unwrap())
            .unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    ephemeral_tor(
        tor_rtcompat::tokio::TokioRustlsRuntime::current().unwrap(),
        serde_json::from_value(fixture).unwrap(),
        ctrn::arti::Directories {
            state: dir.join(format!("state-{name}")),
            cache: dir.join(format!("cache-{name}")),
        },
        ctrn::Limits {
            streams: 64,
            bootstrap_ms: 240_000,
            operation_ms: 60_000,
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn pairing_rounds_over_an_ephemeral_onion_service() {
    let dir = tempfile::tempdir().unwrap();
    let (host_tor, guest_tor) = tokio::join!(tor(dir.path(), "h"), tor(dir.path(), "g"));
    let (service, offer, text) = OnionOffer::open(&*host_tor.backend, now()).await.unwrap();
    let mut host = Echo(offer);
    let link = Link::parse(&text).unwrap();
    let mut channel = OnionChannel::new(guest_tor.backend.clone());
    let guest = async {
        // A wrong secret over the real network gets no reply.
        let (_, other) = Offer::new(link.address(), now()).unwrap();
        let wrong = Link::parse(&other).unwrap();
        let (m, _) = wrong.seal_round(1, b"x").unwrap();
        assert!(channel.call(link.address(), &m).await.is_err());
        for n in 1..=4u8 {
            let payload = vec![n; 1000 * n as usize];
            let (m, awaiting) = link.seal_round(n, &payload).unwrap();
            let reply = channel.call(link.address(), &m).await.unwrap();
            assert_eq!(awaiting.open_reply(&reply).unwrap().to_vec(), payload);
        }
    };
    let (served, ()) = tokio::join!(service.serve(&mut host, now), guest);
    assert_eq!(served, Ok(()));
    let _ = (ErrorCode::Refused, Arc::new(()));
}
