//! Actual same-holder community ACK and recipient-owner cuts. The host has no
//! configured record Epoch: no downloaded packet or initialized account is accepted.
use super::{initial_network, wallet::*};
use cmsg::door::{custody, foyer::Scope, record, Role};
use serde_json::{json, Value};

async fn initial<'p>(
    door: &cmsg::door::Door,
    origin: &str,
    policy: &'p mut cfyr::policy::CurrentPolicy<cmsg::door::foyer::Transport>,
) -> cfyr::membership::InitialCreationLease<'p, cmsg::door::foyer::Transport> {
    door.live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .passkey_certificate(policy, now)
        .await
        .unwrap()
        .initial_creation(now)
        .await
        .unwrap()
}

pub(super) async fn exercise(
    world: &Value,
    mut api: cfyr::Foyer<cfyr::HttpClient>,
    passport: Value,
    member: &str,
) {
    let origin = world["passkey_origin"].as_str().unwrap();
    let mut clock = custody::SystemClock;
    let mut entropy = ckmg::SystemEntropy;
    let seed =
        ckmg::EnrollmentSeed::new(ckmg::Binding::new("omega", member).unwrap(), &mut entropy)
            .unwrap();
    let commitment = seed.commitment().unwrap();
    let pending = api
        .begin_initial_registration(passport, commitment, now)
        .await
        .unwrap();
    let mut keys = passkeys(world);
    let registration = keys
        .register_member(pending.options().clone())
        .await
        .unwrap();
    let backend = cwst::backend::Memory::new();
    let candidate = custody::retain_initial_enrollment(
        &api,
        pending,
        registration,
        seed,
        backend.clone(),
        "same-holder-community",
        &mut clock,
        &mut entropy,
    )
    .await
    .unwrap();
    let device = candidate.device();
    candidate.resume_finish(&mut api, now).await.unwrap();
    login(&mut api, &mut keys).await;
    api.call("device_authorize", json!({"key":device.value()}))
        .await
        .unwrap();
    let door = bound("omega", origin, Role::Member, Scope::Community, api);
    let mut policy = door.current_policy(origin).unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    assert_eq!(lease.observation().unwrap().member, member);
    assert_eq!(lease.seed().unwrap(), commitment);
    let creation = custody::activate_initial(candidate, lease, &mut clock, &mut entropy)
        .await
        .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let (creation, lease) =
        custody::prepare_initial_publication(creation, lease, &mut keys, &mut clock, &mut entropy)
            .await
            .unwrap();
    let creation = custody::retain_initial_publication(creation, lease, &mut clock)
        .await
        .unwrap();
    let network = initial_network::Nodes::new();
    let publication = creation
        .stage(cdht::NetworkBackend::new(
            network.clone(),
            initial_network::Verifier,
        ))
        .await
        .unwrap();
    let (creation, report) = publication.flush().await.unwrap();
    assert_eq!(report.written, 1);
    let read = creation
        .read_first_lineage(network.clone(), &mut clock)
        .await
        .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let creation = custody::acknowledge_initial_publication(
        read,
        lease,
        network.clone(),
        &mut clock,
        &mut entropy,
    )
    .await
    .unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let retired = custody::complete_initial_recovery(
        creation,
        lease,
        network.clone(),
        &mut clock,
        &mut entropy,
    )
    .await
    .unwrap();
    drop(retired);

    let mut companion = foyer(world, false).await;
    let challenge = companion.begin_browser_login().await.unwrap();
    let (credential, outcome) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    let cpky::VaultOutcome::Ready(unlock) = outcome else {
        panic!("original PRF required")
    };
    companion
        .finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
    let opening = cvlt::PreparedOpen::new(unlock, "omega").unwrap();
    let mut records = opening.tor_records(network.clone()).await.unwrap();
    let checkpoint = records.checkpoint(&opening.locator()).await.unwrap();
    drop(records);
    let recovered = opening.prepare_initial_recovery(&checkpoint).unwrap();
    let lease = initial(&door, origin, &mut policy).await;
    let owners = custody::prepare_initial_recovery(&recovered, lease, network.clone())
        .await
        .unwrap();
    let mut vault = owners
        .open_root(network, backend.clone())
        .await
        .unwrap()
        .restore_community_account()
        .await
        .unwrap();
    assert_eq!(
        vault.keys().lineage().await.unwrap().binding.member(),
        member
    );
    let recipient = vault
        .keys()
        .with_record_recipient(|recipient| recipient.public_key())
        .await
        .unwrap();
    assert_ne!(recipient, [0; 32]);
    let projection = vault.account_projection().await.unwrap();

    // Independent original same-key source, never Keys' already held session.
    let source_door = bound("omega", origin, Role::Member, Scope::Community, companion);
    let mut source_policy = source_door.current_policy(origin).unwrap();
    let mut source = source_door
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .common_record(&mut source_policy, now)
        .unwrap();
    source
        .with_current(now, |charter, observed, credential, _, _| {
            assert_eq!(observed.member, member);
            assert!(observed.device_keys.contains(device.value()));
            assert!(!credential.is_empty());
            assert!(charter.balance().is_none());
        })
        .unwrap();
    let before = cwst::backend::Backend::read(&backend).await.unwrap();
    assert!(matches!(
        record::receive_common_record(
            source,
            &mut vault,
            &record::RecordConfiguration::new("account.record_period".into()).unwrap()
        )
        .await,
        Err(cmsg::door::ErrorCode::Unavailable)
    ));
    assert_eq!(
        cwst::backend::Backend::read(&backend).await.unwrap(),
        before
    );
    assert_eq!(vault.account_projection().await.unwrap(), projection);

    // A genuine callback unwind consumes the local source attempt permanently.
    let mut source = source_door
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .common_record(&mut source_policy, now)
        .unwrap();
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        source.with_current(now, |_, _, _, _, _| panic!("consumer cut"))
    }));
    assert!(refused.is_err());
    assert!(source.with_current(now, |_, _, _, _, _| ()).is_err());
    drop(source);
    // Policy observations belong the exact original source Foyer instance.
    let foreign = foyer(world, false).await;
    let mut foreign_policy = foreign.current_policy();
    assert!(source_door
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .common_record(&mut foreign_policy, now)
        .is_err());

    // Each synthetic-clock scenario has a separately authenticated original
    // Foyer/Trust owner: a successful +1 sample must not poison a later real
    // SystemClock request on a shared follower.
    for mode in 0..4 {
        let mut timed = foyer(world, false).await;
        login(&mut timed, &mut keys).await;
        let timed = bound("omega", origin, Role::Member, Scope::Community, timed);
        let mut timed_policy = timed.current_policy(origin).unwrap();
        let mut source = timed
            .live_membership(origin)
            .unwrap()
            .observe_lease(now)
            .await
            .unwrap()
            .common_record(&mut timed_policy, now)
            .unwrap();
        let sample = std::cell::Cell::new(now());
        match mode {
            0 => {
                let (started, completed) = source
                    .with_current_checked(
                        || sample.get(),
                        |_, _, _, _, checked| {
                            sample.set(checked + 1);
                            checked
                        },
                    )
                    .unwrap();
                assert_eq!(completed, started + 1);
                assert!(source.with_current(|| started, |_, _, _, _, _| ()).is_err());
            }
            1 => {
                assert!(source
                    .with_current_checked(
                        || sample.get(),
                        |_, observed, _, _, _| sample.set(observed.expires)
                    )
                    .is_err());
            }
            2 => {
                let checked = source
                    .with_current(now, |_, _, _, _, checked| checked)
                    .unwrap();
                assert!(source
                    .with_current(|| checked - 1, |_, _, _, _, _| ())
                    .is_err());
            }
            3 => {
                let expires = source
                    .with_current(now, |_, observed, _, _, _| observed.expires)
                    .unwrap();
                assert!(source.with_current(|| expires, |_, _, _, _, _| ()).is_err());
            }
            _ => unreachable!(),
        }
        assert!(source.with_current(now, |_, _, _, _, _| ()).is_err());
        // Drop source before its actual policy/Foyer; no follower is reused.
    }
    let mut source = source_door
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .common_record(&mut source_policy, now)
        .unwrap();
    {
        let download = source.download(1, now);
        futures_util::pin_mut!(download);
        assert!(matches!(
            futures_util::poll!(download.as_mut()),
            std::task::Poll::Pending
        ));
    }
    assert!(source.with_current(now, |_, _, _, _, _| ()).is_err());
    drop(source);

    let mut closing = foyer(world, false).await;
    login(&mut closing, &mut keys).await;
    let closing = bound("omega", origin, Role::Member, Scope::Community, closing);
    let mut closing_policy = closing.current_policy(origin).unwrap();
    let mut source = closing
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await
        .unwrap()
        .common_record(&mut closing_policy, now)
        .unwrap();
    drop(closing);
    assert!(source.with_current(now, |_, _, _, _, _| ()).is_err());
    drop(source);

    // A second genuine passkey becomes current, then revokes A through the actual
    // owner. This removes A's signing device from Membership's current projection.
    let mut administrator = foyer(world, false).await;
    login(&mut administrator, &mut keys).await;
    let old_id: Vec<u8> = administrator.call("passkey_list", json!({})).await.unwrap()["passkeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["current"] == true)
        .map(|key| serde_json::from_value(key["credential"].clone()).unwrap())
        .unwrap();
    let begin = administrator
        .call("passkey_add", json!({"step":"begin"}))
        .await
        .unwrap();
    let mut added = passkeys(world);
    let (credential, unlock) = added
        .register_member(begin["options"].clone())
        .await
        .unwrap()
        .into_parts();
    let added_id = credential.credential_id().unwrap();
    assert_ne!(added_id, old_id);
    let opening = cvlt::PreparedOpen::new(unlock, "omega").unwrap();
    let added_device = opening.device().unwrap();
    drop(opening);
    administrator
        .call(
            "passkey_add",
            json!({"step":"finish", "ceremony":begin["ceremony"],
        "credential":credential.into_json()}),
        )
        .await
        .unwrap();
    login(&mut administrator, &mut added).await;
    administrator
        .call("device_authorize", json!({"key":added_device.value()}))
        .await
        .unwrap();
    administrator
        .call("passkey_revoke", json!({"credential":old_id}))
        .await
        .unwrap();
    let observed = administrator
        .live_membership()
        .observe_lease(now)
        .await
        .unwrap();
    assert!(!observed.observation().device_keys.contains(device.value()));
    assert!(observed
        .observation()
        .device_keys
        .contains(added_device.value()));
    drop(observed);
    let called = std::cell::Cell::new(false);
    assert!(vault
        .keys()
        .with_record_recipient(|_| called.set(true))
        .await
        .is_err());
    assert!(!called.get());
    // This tests actual selected-device withdrawal and the original final owner
    // refusal; the missing Epoch still prevents a packet-acceptance claim.
    let source = source_door
        .live_membership(origin)
        .unwrap()
        .observe_lease(now)
        .await;
    assert!(source.is_err());
}
