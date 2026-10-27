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
    assert_eq!(
        decode_reachability(&encode_reachability(&many)).len(),
        MAX_ADDRESSES
    );
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
        body: Body::WaveAck {
            nonce: [7; 32],
            kind: "hello".into(),
        },
    };
    let bytes = serde_json::to_vec(&frame).unwrap();
    assert_eq!(serde_json::from_slice::<Frame>(&bytes).unwrap(), frame);
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["extra"] = json!(1);
    assert!(serde_json::from_value::<Frame>(value).is_err());
    let chat = Frame {
        version: 2,
        reach: vec![],
        body: Body::Chat {
            conversation: [1; 32],
            wire: vec![9],
        },
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
    assert!(pending_ids(
        &json!([{"status": "Pending"}, {"message": {"id": "x"}, "status": "Pending"}])
    )
    .is_empty());
    // The scan is bounded to the newest sends.
    let many: Vec<Value> = (0..=u8::MAX)
        .map(|id| entry(id, json!("Pending")))
        .collect();
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
            let n = if self.1 {
                self.0.fetch_add(1, Ordering::SeqCst) + 1
            } else {
                1
            };
            Ok(Box::new(Silent(address(n))))
        }
        async fn app_message(&self, _: &Address, _: &[u8]) -> std::result::Result<(), cmsh::Error> {
            Ok(())
        }
        async fn app_call(
            &self,
            _: &Address,
            _: &[u8],
        ) -> std::result::Result<Vec<u8>, cmsh::Error> {
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
        let (a, b) = (
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
        );
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
        let (a, b) = (
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
        );
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

    /// 11.4: a peer without a route gets chat wires and receipts through the
    /// mailbox the embedder bound; a wave never waits there.
    #[tokio::test]
    async fn a_frame_for_an_unreachable_peer_waits_in_the_bound_mailbox() {
        let a = "http://127.0.0.1:1".to_owned();
        let config = Configuration::new(
            "community".into(),
            [(Role::Member, [a.clone()].into())].into(),
        )
        .unwrap();
        let mut door = Door::new(config);
        let mailbox = Rc::new(offline::Stub::default());
        assert_eq!(
            door.bind_mailbox(&a, mailbox.clone()),
            Err(ErrorCode::Unavailable)
        );
        let counter = Arc::new(AtomicU8::new(20));
        door.bind_mesh(&a, mesh(&counter)).await.unwrap();
        let shared = door.courier_shared(&a).unwrap();
        let mut left = BTreeSet::new();
        // Nothing bound yet: no route and no mailbox is a failure to retry.
        assert_eq!(
            deliver(&shared, &offline::chat("bob"), &mut left).await,
            None
        );
        door.bind_mailbox(&a, mailbox.clone()).unwrap();
        assert_eq!(
            deliver(&shared, &offline::chat("bob"), &mut left).await,
            Some(false)
        );
        {
            let held = mailbox.left.borrow();
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].0, "bob");
            // What waits is the versioned frame, with this device's descriptor.
            let frame: Frame = serde_json::from_slice(&held[0].1).unwrap();
            assert_eq!(frame.version, FRAME_VERSION);
            assert_eq!(frame.reach, shared.reachability());
            assert!(accept_left(&held[0].1));
        }
        // The frames of one session leave once; a wave never waits.
        assert_eq!(
            deliver(&shared, &offline::chat("bob"), &mut left).await,
            Some(false)
        );
        assert_eq!(mailbox.left.borrow().len(), 1);
        let wave = Outgoing {
            peer: "bob".into(),
            body: Body::WaveAck {
                nonce: [7; 32],
                kind: "hello".into(),
            },
        };
        assert_eq!(deliver(&shared, &wave, &mut left).await, None);
        assert_eq!(mailbox.left.borrow().len(), 1);
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
        let out = door
            .dispatch(
                &a,
                &"A".repeat(43),
                br#"{"action":"inbox.waves","version":1,"body":{}}"#,
                now(),
            )
            .await;
        assert!(matches!(
            out,
            crate::door::Output::Error {
                error: ErrorCode::Unauthorized
            }
        ));
        lease.close(&mut door);
    }
}

mod offline {
    use super::*;
    use std::cell::RefCell;

    /// Keeps what is left; `full` makes every leave fail.
    #[derive(Default)]
    pub(super) struct Stub {
        pub left: RefCell<Vec<(String, Vec<u8>)>>,
        pub full: Cell<bool>,
        pub waiting: RefCell<Vec<Vec<u8>>>,
    }
    impl Mailbox for Stub {
        fn leave<'a>(&'a self, peer: &'a str, frame: &'a [u8]) -> LocalBoxFuture<'a, bool> {
            Box::pin(async move {
                if self.full.get() {
                    return false;
                }
                self.left
                    .borrow_mut()
                    .push((peer.to_owned(), frame.to_vec()));
                true
            })
        }
        fn collect(&self) -> LocalBoxFuture<'_, Vec<Vec<u8>>> {
            Box::pin(async move { self.waiting.borrow_mut().drain(..).collect() })
        }
    }

    pub(super) fn chat(peer: &str) -> Outgoing {
        Outgoing {
            peer: peer.into(),
            body: Body::Chat {
                conversation: [1; 32],
                wire: vec![9],
            },
        }
    }

    #[test]
    fn only_chat_wires_and_receipts_may_wait() {
        assert!(offline_body(&chat("p").body));
        assert!(offline_body(&Body::Receipt {
            conversation: [1; 32],
            wire: vec![]
        }));
        assert!(!offline_body(&Body::WaveAck {
            nonce: [0; 32],
            kind: "x".into()
        }));
    }

    #[test]
    fn only_current_chat_and_receipt_frames_are_taken_from_the_mailbox() {
        let frame = |version: u8, body: Body| {
            serde_json::to_vec(&Frame {
                version,
                reach: vec![],
                body,
            })
            .unwrap()
        };
        let chat_body = || Body::Chat {
            conversation: [1; 32],
            wire: vec![1],
        };
        assert!(accept_left(&frame(FRAME_VERSION, chat_body())));
        assert!(accept_left(&frame(
            FRAME_VERSION,
            Body::Receipt {
                conversation: [1; 32],
                wire: vec![1]
            }
        )));
        // A wave is first contact: a mailbox cannot carry one into the Door.
        assert!(!accept_left(&frame(
            FRAME_VERSION,
            Body::WaveAck {
                nonce: [0; 32],
                kind: "x".into()
            }
        )));
        assert!(!accept_left(&frame(FRAME_VERSION + 1, chat_body())));
        assert!(!accept_left(b"not a frame"));
    }

    #[tokio::test]
    async fn a_mailbox_that_cannot_store_is_a_failure_that_is_tried_again() {
        let stub = Rc::new(Stub::default());
        stub.full.set(true);
        let mut left = BTreeSet::new();
        let item = chat("bob");
        let mailbox: Rc<dyn Mailbox> = stub.clone();
        assert!(!leave_offline(Some(mailbox.clone()), &mut left, &item, b"f").await);
        assert!(left.is_empty());
        stub.full.set(false);
        assert!(leave_offline(Some(mailbox.clone()), &mut left, &item, b"f").await);
        // The same frame for the same peer is not left twice; another peer's is.
        assert!(leave_offline(Some(mailbox.clone()), &mut left, &item, b"f").await);
        assert_eq!(stub.left.borrow().len(), 1);
        assert!(leave_offline(Some(mailbox), &mut left, &chat("carol"), b"f").await);
        assert_eq!(stub.left.borrow().len(), 2);
        assert!(!leave_offline(None, &mut left, &item, b"f").await);
    }

    #[tokio::test]
    async fn the_set_of_left_frames_is_bounded() {
        let stub = Rc::new(Stub::default());
        let mailbox: Rc<dyn Mailbox> = stub.clone();
        let mut left: BTreeSet<Vec<u8>> = (0..4096u32).map(|n| n.to_be_bytes().to_vec()).collect();
        assert!(leave_offline(Some(mailbox), &mut left, &chat("bob"), b"f").await);
        assert_eq!(left.len(), 1);
    }

    #[tokio::test]
    async fn the_mailbox_hands_over_each_waiting_frame_once() {
        let stub = Stub::default();
        stub.waiting.borrow_mut().push(vec![1]);
        stub.waiting.borrow_mut().push(vec![2]);
        assert_eq!(stub.collect().await, vec![vec![1], vec![2]]);
        assert!(stub.collect().await.is_empty());
    }
}

/// Every action the courier calls through its own lease is one the lease grants: a
/// missing one is refused in a release build and panics the owner thread in a debug
/// build (journey row 19: `inbox.thread` of the re-send scan, 2026-10-27).
#[test]
fn the_lease_grants_every_action_the_courier_calls() {
    let source = include_str!("../../src/door/courier.rs");
    let mut called = Vec::new();
    for (at, _) in source.match_indices(".call(") {
        let rest = source[at + ".call(".len()..].trim_start();
        let Some(rest) = rest.strip_prefix("door,") else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('"') else {
            continue;
        };
        let name = &rest[..rest.find('"').unwrap()];
        called.push(name);
    }
    assert!(called.len() >= 10, "found {called:?}");
    for name in called {
        assert!(ACTIONS.contains(&name), "the lease does not grant {name}");
    }
}
