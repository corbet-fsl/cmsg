use super::*;

fn address(byte: u8) -> Address {
    Address::new(Scheme::new("tor").unwrap(), vec![byte; 8]).unwrap()
}

#[test]
fn reachability_round_trips_and_drops_garbage() {
    let own = vec![address(1), address(2)];
    assert_eq!(decode_reachability(&encode_reachability(&own)), own);
    assert!(decode_reachability(b"not json").is_empty());
    assert!(decode_reachability(br#"[{"scheme":"BAD!","address":"AA"}]"#).is_empty());
    let many: Vec<Address> = (0..20).map(address).collect();
    assert_eq!(decode_reachability(&encode_reachability(&many)).len(), MAX_ADDRESSES);
}

#[test]
fn the_book_keeps_the_latest_and_ignores_empty_updates() {
    let mut book = Book::default();
    book.learn("bob", &encode_reachability(&[address(1)]));
    book.learn("bob", &encode_reachability(&[address(2)]));
    assert_eq!(book.get("bob"), Some(&vec![address(2)]));
    book.learn("bob", b"junk");
    assert_eq!(book.get("bob"), Some(&vec![address(2)]));
}

#[test]
fn frames_are_versioned_and_strict() {
    let frame = Frame {
        version: FRAME_VERSION,
        reach: vec![1],
        body: Body::WaveAck { nonce: [7; 32], kind: "hello".into() },
    };
    let bytes = serde_json::to_vec(&frame).unwrap();
    assert_eq!(serde_json::from_slice::<Frame>(&bytes).unwrap(), frame);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["extra"] = json!(1);
    assert!(serde_json::from_value::<Frame>(value).is_err());
    let chat = Frame {
        version: 2,
        reach: vec![],
        body: Body::Chat { conversation: [1; 32], wire: vec![9] },
    };
    // A future version still parses; the receiver drops it by version.
    let parsed: Frame = serde_json::from_slice(&serde_json::to_vec(&chat).unwrap()).unwrap();
    assert_ne!(parsed.version, FRAME_VERSION);
}

#[test]
fn only_the_own_sends_waiting_for_a_receipt_are_scanned_and_newest_first() {
    let entry = |id: u8, status: Value| {
        json!({
            "message": {"id": vec![id; 32], "sender": "x", "epoch": 1, "bytes": [], "accepted_at": 0},
            "status": status,
        })
    };
    let thread = json!([
        entry(1, json!("Accepted")),
        entry(2, json!("Pending")),
        entry(3, json!(null)),
        entry(4, json!("CanceledUnconfirmed")),
        entry(5, json!("Pending")),
    ]);
    assert_eq!(pending_ids(&thread), vec![[5; 32], [2; 32]]);
    // Anything that is not a thread, or an entry without an id, yields nothing.
    assert!(pending_ids(&json!({"history": []})).is_empty());
    assert!(pending_ids(&json!([{"status": "Pending"}, {"message": {"id": "x"}, "status": "Pending"}])).is_empty());
    // The scan is bounded to the newest sends.
    let many: Vec<Value> = (0..=u8::MAX).map(|id| entry(id, json!("Pending"))).collect();
    let found = pending_ids(&Value::Array(many));
    assert_eq!(found.len(), MAX_SCAN_MESSAGES);
    assert_eq!(found[0], [u8::MAX; 32]);
}

#[test]
fn defaults_keep_presence_inside_a_short_lease() {
    let config = Config::default();
    assert!(config.heartbeat <= 30 && config.resend > config.tick);
}

mod isolation {
    use super::*;
    use crate::door::{Configuration, Role};
    use cmsh::{async_trait, Backend, Capabilities, Event, LatencyClass, Listener};
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };

    /// Hands out a fresh address for every listener, as a Tor onion would.
    struct Fresh(Arc<AtomicU8>, bool);
    struct Silent(Address);
    #[async_trait]
    impl Listener for Silent {
        fn address(&self) -> &Address {
            &self.0
        }
        async fn next(&mut self) -> std::result::Result<Event, cmsh::Error> {
            std::future::pending().await
        }
    }
    #[async_trait]
    impl Backend for Fresh {
        fn scheme(&self) -> Scheme {
            Scheme::new("tor").unwrap()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                anonymous: true,
                datagrams: false,
                offline_delivery: false,
                dht: false,
                latency: LatencyClass::Interactive,
            }
        }
        fn max_payload(&self) -> usize {
            1024
        }
        async fn listen(&self) -> std::result::Result<Box<dyn Listener>, cmsh::Error> {
            let n = if self.1 { self.0.fetch_add(1, Ordering::SeqCst) + 1 } else { 1 };
            Ok(Box::new(Silent(address(n))))
        }
        async fn app_message(&self, _: &Address, _: &[u8]) -> std::result::Result<(), cmsh::Error> {
            Ok(())
        }
        async fn app_call(&self, _: &Address, _: &[u8]) -> std::result::Result<Vec<u8>, cmsh::Error> {
            Ok(vec![])
        }
    }
    struct Tokio;
    impl cmsh::Spawn for Tokio {
        fn spawn(&self, future: cmsh::BoxFuture<'static, ()>) {
            tokio::spawn(future);
        }
    }

    // One counter for the whole device: every listener gets a distinct onion.
    fn mesh(counter: &Arc<AtomicU8>) -> cmsh::Mesh {
        backend(counter, true)
    }
    fn backend(counter: &Arc<AtomicU8>, fresh: bool) -> cmsh::Mesh {
        cmsh::Mesh::builder(Arc::new(Tokio))
            .backend(Arc::new(Fresh(counter.clone(), fresh)))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn each_origin_exposes_only_its_own_addresses_and_no_grant_leaks() {
        let (a, b) = ("http://127.0.0.1:1".to_owned(), "http://127.0.0.1:2".to_owned());
        let config = Configuration::new(
            "community".into(),
            [(Role::Member, [a.clone(), b.clone()].into())].into(),
        )
        .unwrap();
        let mut door = Door::new(config);
        // Two memberships on one device: two Meshes, two listeners.
        let counter = Arc::new(AtomicU8::new(0));
        door.bind_mesh(&a, mesh(&counter)).await.unwrap();
        door.bind_mesh(&b, mesh(&counter)).await.unwrap();
        let (ra, rb) = (door.reachability(&a), door.reachability(&b));
        assert!(!decode_reachability(&ra).is_empty());
        assert!(!decode_reachability(&rb).is_empty());
        for address in decode_reachability(&ra) {
            assert!(!decode_reachability(&rb).contains(&address));
        }
        // A frame carries the sending origin's own descriptor only.
        let shared_a = door.courier_shared(&a).unwrap();
        let shared_b = door.courier_shared(&b).unwrap();
        assert_eq!(shared_a.reachability(), ra);
        assert_eq!(shared_b.reachability(), rb);
        assert!(door.reachability("http://127.0.0.1:3").is_empty());
        // The internal grant exists only while a lease is open and is removed on close.
        let before = door.grants.len();
        let lease = Lease::open(&mut door, &a, now(), 60).unwrap();
        assert_eq!(door.grants.len(), before + 1);
        lease.close(&mut door);
        assert_eq!(door.grants.len(), before);
    }

    /// The invariant is enforced by the Door, not assumed of the backend: a
    /// second origin that would publish an address already published for
    /// another origin is refused. (That production origins get distinct onion
    /// keys is the ckmg derivation `device_seed(prf, community)`; its live
    /// check belongs to the Tor fixture.)
    #[tokio::test]
    async fn a_backend_that_repeats_an_address_across_origins_is_refused() {
        let (a, b) = ("http://127.0.0.1:1".to_owned(), "http://127.0.0.1:2".to_owned());
        let config = Configuration::new(
            "community".into(),
            [(Role::Member, [a.clone(), b.clone()].into())].into(),
        )
        .unwrap();
        let mut door = Door::new(config);
        let counter = Arc::new(AtomicU8::new(10));
        door.bind_mesh(&a, backend(&counter, false)).await.unwrap();
        assert!(door.bind_mesh(&b, backend(&counter, false)).await.is_err());
        assert!(door.reachability(&b).is_empty());
        door.bind_mesh(&b, backend(&counter, true)).await.unwrap();
        assert_ne!(door.reachability(&a), door.reachability(&b));
    }

    #[tokio::test]
    async fn an_external_token_cannot_reach_the_internal_grant() {
        let a = "http://127.0.0.1:1".to_owned();
        let config = Configuration::new(
            "community".into(),
            [(Role::Member, [a.clone()].into())].into(),
        )
        .unwrap();
        let mut door = Door::new(config);
        let lease = Lease::open(&mut door, &a, now(), 60).unwrap();
        // Grants are keyed by a hash of a bearer token; the lease key is random
        // and never encoded as a token, so no presented token authenticates it.
        let out = door.dispatch(&a, &"A".repeat(43), br#"{"action":"inbox.waves","version":1,"body":{}}"#, now()).await;
        assert!(matches!(out, crate::door::Output::Error { error: ErrorCode::Unauthorized }));
        lease.close(&mut door);
    }
}
