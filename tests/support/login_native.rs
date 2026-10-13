//! Actual owner-accepted session writes with transport faults. No session is synthesized.
use super::*;
use serde_json::{json, Value};
const ORIGIN: &str = "https://alpha.example.test";

fn pending_door(now: u64) -> (Door, [u8; 32]) {
    let mut door = Door::new(
        crate::door::Configuration::new(
            "alpha".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
        )
        .unwrap(),
    );
    // This transport is never called. Only the real local lifecycle is under test.
    let client = foyer::Foyer::new(foyer::fixture_transport(
        "https://alpha.example.test",
        "alpha.example.test",
    ));
    door.bind_foyer(
        ORIGIN,
        Role::Member,
        foyer::Sessions::new(foyer::Scope::Community, client),
    )
    .unwrap();
    let token = door
        .pair_client(
            ORIGIN,
            Role::Member,
            BTreeSet::from(["login.start".into(), "login.poll".into()]),
            now,
            now + 60,
        )
        .unwrap();
    let key = crate::door::token_hash(token.expose_for_transport());
    door.foyers.get_mut(ORIGIN).unwrap().uncertain = true;
    (door, key)
}

struct Dropped(std::rc::Rc<std::cell::Cell<bool>>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn unsent_login_expires_at_its_deadline_without_polling_a_queued_callback() {
    use std::{cell::Cell, rc::Rc, task::Poll};
    for ready in [false, true] {
        let (mut door, key) = pending_door(100);
        let polled = Rc::new(Cell::new(0));
        let dropped = Rc::new(Cell::new(false));
        let count = polled.clone();
        let guard = Dropped(dropped.clone());
        let future = futures_util::future::poll_fn(move |_| {
            let _ = &guard;
            count.set(count.get() + 1);
            if ready {
                Poll::Ready(Err(cfyr::passkeys::Error::Cancelled))
            } else {
                Poll::Pending
            }
        })
        .boxed_local();
        door.logins.insert(
            key,
            State::Waiting {
                future,
                ceremony: "unsent-ceremony".into(),
                expires: 110,
            },
        );
        if !ready {
            door.observe(109).unwrap();
            assert_eq!(
                poll(&mut door, &key),
                Ok(Status::Pending { expires_at: 110 })
            );
            assert_eq!(polled.get(), 1);
            assert!(!dropped.get());
            assert!(door.foyers[ORIGIN].uncertain);
        }
        let before = polled.get();
        door.observe(110).unwrap();
        assert_eq!(poll(&mut door, &key), Ok(Status::Expired));
        assert_eq!(polled.get(), before);
        assert!(dropped.get());
        assert!(!door.foyers[ORIGIN].uncertain);
        assert!(matches!(door.logins[&key], State::Expired));
        assert_eq!(poll(&mut door, &key), Ok(Status::Expired));
        assert_eq!(cancel(&mut door, &key), Ok(Status::Expired));
        assert_eq!(door.observe(109), Err(ErrorCode::Clock));
        assert_eq!(poll(&mut door, &key), Ok(Status::Expired));
    }
}

#[test]
fn ceremony_expiry_keeps_a_started_server_write_fenced_until_reconciliation() {
    let (mut door, key) = pending_door(100);
    let client = door
        .foyers
        .get_mut(ORIGIN)
        .unwrap()
        .sessions
        .clients
        .remove(&foyer::Scope::Community)
        .unwrap();
    let dropped = std::rc::Rc::new(std::cell::Cell::new(false));
    let guard = Dropped(dropped.clone());
    let future = async move {
        let _guard = guard;
        futures_util::future::pending::<()>().await;
        (client, Err(cfyr::Error::Unavailable))
    }
    .boxed_local();
    door.logins.insert(
        key,
        State::Finishing {
            future,
            scope: foyer::Scope::Community,
            expires: 110,
            custody: VaultOutcome::Locked(cfyr::passkeys::Error::PrfUnavailable),
        },
    );
    door.observe(110).unwrap();
    assert_eq!(
        poll(&mut door, &key),
        Ok(Status::Pending { expires_at: 110 })
    );
    assert!(!dropped.get());
    assert!(door.foyers[ORIGIN].uncertain);
    assert!(door.foyers[ORIGIN].sessions.clients.is_empty());
    assert_eq!(cancel(&mut door, &key), Err(ErrorCode::Reconcile));
    assert!(dropped.get());
    assert!(door.foyers[ORIGIN].uncertain);
    assert!(door.foyers[ORIGIN].sessions.clients.is_empty());
    assert_eq!(poll(&mut door, &key), Err(ErrorCode::Reconcile));
}

#[tokio::test]
async fn unknown_session_result_and_cancelled_reply_fence_original_foyer() {
    let path = std::env::var("CMSG_FOYER_FIXTURE").expect("use the original owner fixture");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let now = fixture["now"].as_u64().unwrap();
    let fault = &fixture["login_faults"];
    let base = fault["base"].as_str().unwrap();
    for index in 0..2 {
        let mut door = Door::new(
            crate::door::Configuration::new(
                "alpha".into(),
                BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.into()]))]),
            )
            .unwrap(),
        );
        let client = foyer::Foyer::new(foyer::fixture_transport(
            base,
            fault["host"].as_str().unwrap(),
        ));
        door.bind_foyer(
            ORIGIN,
            Role::Member,
            foyer::Sessions::new(foyer::Scope::Global, client),
        )
        .unwrap();
        let token = door
            .pair_client(
                ORIGIN,
                Role::Member,
                catalog().into_iter().map(|action| action.action).collect(),
                now,
                now + 60,
            )
            .unwrap();
        let key = crate::door::token_hash(token.expose_for_transport());
        let binding = door.foyers.get_mut(ORIGIN).unwrap();
        binding.uncertain = true;
        let mut client = binding
            .sessions
            .clients
            .remove(&foyer::Scope::Global)
            .unwrap();
        let body = fault["requests"][index].clone();
        // The public assertion came from the original server's real authenticator
        // fixture. The proxy breaks/withholds only its already accepted reply.
        let future = async move {
            let error = match client.authenticate(body).await {
                Err(error) => error,
                Ok(_) => panic!("the accepted reply must be corrupted or withheld"),
            };
            (client, Err(error))
        }
        .boxed_local();
        door.logins.insert(
            key,
            State::Finishing {
                future,
                scope: foyer::Scope::Global,
                expires: now + 60,
                // The original legacy SoftToken fixture has no PRF support.
                custody: VaultOutcome::Locked(cfyr::passkeys::Error::PrfUnavailable),
            },
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let status = poll(&mut door, &key);
                if index == 0 && matches!(status, Err(ErrorCode::Reconcile)) {
                    break;
                }
                let bytes = reqwest::get(format!("{base}/__stats"))
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap();
                let counts: Vec<usize> = serde_json::from_slice(&bytes).unwrap();
                if index == 1 && counts[index] == 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(cancel(&mut door, &key), Err(ErrorCode::Reconcile));
        assert_eq!(start(&mut door, &key).await, Err(ErrorCode::Refused));
        assert!(door.foyers[ORIGIN].uncertain);
        assert!(door.foyers[ORIGIN].sessions.clients.is_empty());
        let output = crate::door::surface::invoke(
            &mut door,
            ORIGIN,
            token.expose_for_transport(),
            "foyer.global_public",
            1,
            json!({}),
            now,
        )
        .await;
        assert!(matches!(
            output,
            Output::Error {
                error: ErrorCode::Reconcile
            }
        ));
        door.revoke(&token);
        assert!(!door.logins.contains_key(&key));
        assert!(door.foyers[ORIGIN].uncertain);
    }
    reqwest::Client::new()
        .post(format!("{base}/__release"))
        .send()
        .await
        .unwrap();
    let bytes = reqwest::get(format!("{base}/__stats"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Vec<usize>>(&bytes).unwrap(),
        vec![1, 1]
    );
}
