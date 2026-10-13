//! Same original HTTPS community source; synchronous borrowing creates no grant.
use super::super::wallet::*;
use serde_json::{Value, json};

pub(super) async fn exercise(
    world: &Value,
    keys: &mut cpky::Client<cpky::software::SoftwareAuthenticator>,
) {
    for mode in 0..6 {
        // Isolate each follower's sticky wall floor and real authentication.
        let mut api = foyer(world, false).await;
        if mode == 5 {
            let challenge = api.begin_browser_login().await.unwrap();
            let (credential, unlock) = keys.sign_in(challenge.options).await.unwrap().into_parts();
            drop(unlock);
            // The original generic authentication succeeds on real UV, but
            // intentionally supplies no typed-login credential pin.
            api.authenticate(json!({"ceremony":challenge.ceremony,
                "credential":credential.into_json()}))
                .await
                .unwrap();
        } else {
            login(&mut api, keys).await;
        }
        let mut policy = api.current_policy();
        let mut membership = api.live_membership();
        let mut lease = membership.observe_lease(now).await.unwrap();
        let sample = std::cell::Cell::new(now());
        let called = std::cell::Cell::new(false);
        match mode {
            0 => {
                let (started, completed) = lease
                    .with_community_policy(
                        &mut policy,
                        || sample.get(),
                        |charter, member, credential, origin, checked| {
                            assert_eq!(charter.community(), "omega");
                            assert!(!member.member.is_empty());
                            assert!(!credential.is_empty());
                            assert_eq!(origin, world["base"].as_str().unwrap());
                            sample.set(checked + 1);
                            checked
                        },
                    )
                    .unwrap();
                assert_eq!(completed, started + 1);
                assert!(
                    lease
                        .with_community_policy(&mut policy, || started, |_, _, _, _, _| ())
                        .is_err()
                );
            }
            1 => {
                let mut owner = Some(api);
                assert!(
                    lease
                        .with_community_policy(&mut policy, now, |_, _, _, _, _| {
                            called.set(true);
                            drop(owner.take());
                        })
                        .is_err()
                );
                assert!(called.get());
            }
            2 => {
                assert!(
                    lease
                        .with_community_policy(
                            &mut policy,
                            || sample.get(),
                            |_, observed, _, _, _| {
                                called.set(true);
                                sample.set(observed.expires);
                            },
                        )
                        .is_err()
                );
                assert!(called.get());
            }
            3 => {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        lease.with_community_policy(&mut policy, now, |_, _, _, _, _| {
                            called.set(true);
                            panic!("current community callback interrupted");
                        })
                    }))
                    .is_err()
                );
                assert!(called.get());
            }
            4 => {
                let foreign = foyer(world, false).await;
                let mut foreign_policy = foreign.current_policy();
                assert!(
                    lease
                        .with_community_policy(&mut foreign_policy, now, |_, _, _, _, _| called
                            .set(true),)
                        .is_err()
                );
                assert!(!called.get());
            }
            5 => {
                assert!(
                    lease
                        .with_community_policy(&mut policy, now, |_, _, _, _, _| called.set(true),)
                        .is_err()
                );
                assert!(!called.get());
            }
            _ => unreachable!(),
        }
        assert!(
            lease
                .with_community_policy(&mut policy, now, |_, _, _, _, _| ())
                .is_err()
        );
    }
}
