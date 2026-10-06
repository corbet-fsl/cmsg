//! Actual owner-accepted session writes with transport faults. No session is synthesized.
use super::*;
use serde_json::{json, Value};
const ORIGIN: &str = "https://alpha.example.test";

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
        let client = foyer::Foyer::new(
            foyer::Transport::new(base.into(), fault["host"].as_str().unwrap().into(), None)
                .unwrap(),
        );
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
