//! Real server challenges/sessions and original maintained PRF authenticator.
//! The shared Rust owner runs on both targets. This does not substitute for the
//! separate real browser popup/HPKE fixture or claim an accepted Vault/Wallet.
use super::*;
use cfyr::Transport as _;
use cpky::software::{SoftwareAuthenticator, TestConfiguration};
use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const MEMBER: &str = "https://alpha.example.test";
const VAULT: &str = "https://vault.alpha.example.test";
const RP: &str = "alpha.example.test";
type Passkeys = cpky::Client<SoftwareAuthenticator>;

#[cfg(not(target_arch = "wasm32"))]
async fn fixture() -> Value {
    let path = std::env::var("CMSG_FOYER_FIXTURE").expect("original live owner fixture required");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
#[cfg(target_arch = "wasm32")]
async fn fixture() -> Value {
    gloo_net::http::Request::get("/__fixture")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
fn client(fixture: &Value) -> foyer::Foyer<foyer::Transport> {
    let row = &fixture["vault"];
    foyer::Foyer::new(foyer::fixture_transport(
        row["base"].as_str().unwrap(),
        row["host"].as_str().unwrap(),
    ))
}
fn door(fixture: &Value, role: Role, scope: foyer::Scope, now: u64) -> (Door, ClientToken) {
    let mut door = Door::new(
        crate::door::Configuration::new(
            "alpha".into(),
            BTreeMap::from([(role, BTreeSet::from([MEMBER.into()]))]),
        )
        .unwrap(),
    );
    door.bind_foyer(MEMBER, role, foyer::Sessions::new(scope, client(fixture)))
        .unwrap();
    let token = door
        .pair_client(
            MEMBER,
            role,
            catalog().into_iter().map(|action| action.action).collect(),
            now,
            now + 60,
        )
        .unwrap();
    (door, token)
}
async fn wait() {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(10).await;
}
async fn login(door: &mut Door, token: &ClientToken, passkeys: &mut Passkeys, now: u64) {
    let binding = door.foyers.get_mut(MEMBER).unwrap();
    let client = binding
        .sessions
        .clients
        .get_mut(&binding.sessions.primary)
        .unwrap();
    let challenge = client.begin_browser_login().await.unwrap();
    let authentication = passkeys.sign_in(challenge.options).await.unwrap();
    binding.uncertain = true;
    let key = token_hash(token.expose_for_transport());
    door.logins.insert(
        key,
        State::Waiting {
            // Only the platform future is already complete. The result is an actual
            // original Passkeys capability; poll must perform real login_finish.
            future: futures_util::future::ready(Ok(CeremonyResult::Authentication(authentication)))
                .boxed_local(),
            ceremony: challenge.ceremony,
            expires: now + 60,
        },
    );
    for _ in 0..1000 {
        match poll(door, &key).unwrap() {
            Status::Pending { .. } => wait().await,
            Status::AuthenticatedPendingCustody => return,
            _ => panic!("unexpected original login result"),
        }
    }
    panic!("original session acceptance deadline exceeded");
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
async fn actual_login_custody_is_consumed_once_with_local_and_original_session_refusals() {
    #[cfg(target_arch = "wasm32")]
    if web_sys::window().unwrap().location().origin().unwrap() != VAULT {
        return; // The existing original HTTPS portal matrix includes this vault.
    }
    let fixture = fixture().await;
    let now = fixture["now"].as_u64().unwrap();
    // Native mints its registration now (the owner's ceremonies live 300 s from
    // register_begin); the browser matrix keeps the fixture's pre-minted one.
    #[cfg(not(target_arch = "wasm32"))]
    let registration: &Value = &{
        let minted = reqwest::Client::new()
            .post(fixture["custody_registration_mint"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        serde_json::from_slice::<Value>(&minted).unwrap()
    };
    #[cfg(target_arch = "wasm32")]
    let registration = &fixture["custody_registrations"]["browser"];
    let platform = SoftwareAuthenticator::new(
        VAULT,
        TestConfiguration {
            user_verified: true,
            prf: true,
            evaluate_at_create: false,
        },
    )
    .unwrap();
    let mut passkeys = cpky::Client::new(cpky::Context::new(VAULT, RP).unwrap(), platform);
    let (credential, registration_unlock) = passkeys
        .register_member(registration["options"].clone())
        .await
        .unwrap()
        .into_parts();
    drop(registration_unlock);
    let row = &fixture["vault"];
    let mut registration_transport =
        foyer::fixture_transport(row["base"].as_str().unwrap(), row["host"].as_str().unwrap());
    registration_transport
        .send(
            "/v1/register_finish",
            json!({
                "ceremony": registration["ceremony"], "credential": credential.into_json(),
            }),
        )
        .await
        .unwrap();
    drop(registration_transport);

    for case in [
        "once",
        "foreign_origin",
        "admin",
        "root",
        "global",
        "grant_expired",
        "session_expired",
        "clock",
        "uncertain",
        "cancelled",
        "replacement",
        "logout",
        "initializer_refused",
        "locked",
    ] {
        let role = match case {
            "admin" => Role::Admin,
            "root" => Role::Root,
            _ => Role::Member,
        };
        let scope = if case == "global" {
            foyer::Scope::Global
        } else {
            foyer::Scope::Community
        };
        let (mut door, token) = door(&fixture, role, scope, now);
        assert!(matches!(
            door.prepare_login_custody(MEMBER, &token, now),
            Err(ErrorCode::Refused | ErrorCode::Unauthorized)
        ));
        login(&mut door, &token, &mut passkeys, now).await;
        let key = token_hash(token.expose_for_transport());
        match case {
            "foreign_origin" => {
                assert!(matches!(
                    door.prepare_login_custody(VAULT, &token, now),
                    Err(ErrorCode::Unauthorized)
                ));
                drop(door.prepare_login_custody(MEMBER, &token, now).unwrap());
            }
            "admin" | "root" | "global" => {
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Unauthorized)
                ));
            }
            "grant_expired" => {
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now + 60),
                    Err(ErrorCode::Unauthorized)
                ));
                assert!(!door.logins.contains_key(&key));
            }
            "session_expired" => {
                let State::Authenticated { session, .. } = &door.logins[&key] else {
                    panic!()
                };
                let expires = session.expires;
                // Extend only the local test grant to isolate the *actual*
                // server deadline. No server session or custody is fabricated.
                door.grants.get_mut(&key).unwrap().expires = expires + 1;
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, expires),
                    Err(ErrorCode::Unauthorized)
                ));
                assert!(matches!(
                    door.logins[&key],
                    State::Refused(ErrorCode::Unauthorized)
                ));
            }
            "clock" => {
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now - 1),
                    Err(ErrorCode::Clock)
                ));
                drop(door.prepare_login_custody(MEMBER, &token, now).unwrap());
            }
            "uncertain" => {
                door.foyers.get_mut(MEMBER).unwrap().uncertain = true;
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Reconcile)
                ));
            }
            "cancelled" => {
                assert_eq!(cancel(&mut door, &key), Ok(Status::Cancelled));
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Refused)
                ));
            }
            "replacement" => {
                let mut replacement = client(&fixture);
                let challenge = replacement.begin_browser_login().await.unwrap();
                let (credential, custody) = passkeys
                    .sign_in(challenge.options)
                    .await
                    .unwrap()
                    .into_parts();
                drop(custody);
                replacement
                    .finish_browser_login(challenge.ceremony, credential)
                    .await
                    .unwrap();
                door.foyers
                    .get_mut(MEMBER)
                    .unwrap()
                    .sessions
                    .clients
                    .insert(scope, replacement);
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Unauthorized)
                ));
            }
            "initializer_refused" => {
                // This is accepted by the local Configuration constructor but
                // rejected by the original Keys scope validation after consume.
                door.config.community = "invalid\nscope".into();
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Refused)
                ));
                assert!(matches!(
                    door.logins[&key],
                    State::Authenticated { custody: None, .. }
                ));
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Refused)
                ));
                assert_eq!(
                    poll(&mut door, &key),
                    Ok(Status::AuthenticatedPendingCustody)
                );
            }
            "locked" => {
                // Negative outcome injection drops the actual original PRF;
                // it never constructs an accepted secret, session or Authority.
                let State::Authenticated { custody, .. } = door.logins.get_mut(&key).unwrap()
                else {
                    panic!()
                };
                *custody = Some(VaultOutcome::Locked(cpky::Error::PrfUnavailable));
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Unavailable)
                ));
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Refused)
                ));
            }
            "logout" => {
                door.foyers
                    .get_mut(MEMBER)
                    .unwrap()
                    .sessions
                    .clients
                    .get_mut(&scope)
                    .unwrap()
                    .call("logout", json!({}))
                    .await
                    .unwrap();
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Unauthorized)
                ));
            }
            "once" => {
                let prepared = door.prepare_login_custody(MEMBER, &token, now).unwrap();
                assert_eq!(format!("{prepared:?}"), "PreparedOpen([redacted])");
                assert!(prepared.inspector().is_ok());
                assert!(matches!(
                    door.prepare_login_custody(MEMBER, &token, now),
                    Err(ErrorCode::Refused)
                ));
                assert_eq!(
                    poll(&mut door, &key),
                    Ok(Status::AuthenticatedPendingCustody)
                );
                assert_eq!(
                    cancel(&mut door, &key),
                    Ok(Status::AuthenticatedPendingCustody)
                );
                drop(prepared);
            }
            _ => unreachable!(),
        }
        door.revoke(&token);
        let current = now.max(door.clock_floor);
        assert!(matches!(
            door.prepare_login_custody(MEMBER, &token, current),
            Err(ErrorCode::Unauthorized)
        ));
    }
}
