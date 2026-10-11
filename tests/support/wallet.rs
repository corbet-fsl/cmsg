//! Original current HTTPS/Passkeys fixture composition shared by owner journeys.
use cmsg::door::{
    custody::SystemClock,
    foyer::{Scope, Sessions},
    Configuration, Door, Role,
};
use cpky::{
    software::{SoftwareAuthenticator, TestConfiguration},
    Context,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn now() -> u64 {
    ckmg::Clock::now(&mut SystemClock).unwrap()
}
pub(super) fn passkeys(world: &Value) -> cpky::Client<SoftwareAuthenticator> {
    let origin = world["passkey_origin"].as_str().unwrap();
    cpky::Client::new(
        Context::new(origin, world["rp_id"].as_str().unwrap()).unwrap(),
        SoftwareAuthenticator::new(
            origin,
            TestConfiguration {
                user_verified: true,
                prf: true,
                evaluate_at_create: false,
            },
        )
        .unwrap(),
    )
}
pub(super) async fn foyer(world: &Value, wallet: bool) -> cfyr::Foyer<cfyr::HttpClient> {
    let roots = [include_bytes!("current-tls/ca.der").to_vec()];
    let origin = world["base"].as_str().unwrap().to_owned();
    let configuration = cfyr::trust::Configuration {
        origin: origin.clone(),
        community: world["scope"].as_str().unwrap().into(),
        key_ring: serde_json::from_value(world["trust_key_ring"].clone()).unwrap(),
        minimum_revision: 1,
        ring_revision: 0,
    };
    let following = cfyr::trust::Config {
        retry_entropy: 27,
        refresh_seconds: 30,
        poll_seconds: 1,
        request_seconds: 30,
        initial_backoff_seconds: 1,
        maximum_backoff_seconds: 10,
        maximum_staleness_seconds: 900,
    };
    let mut trust = if wallet {
        cfyr::trust::Trust::wallet_native(configuration, following, &roots)
    } else {
        cfyr::trust::Trust::native(configuration, following, &roots)
    }
    .unwrap();
    trust.start(now).await.unwrap();
    cfyr::Foyer::with_trust(
        cfyr::HttpClient::with_roots(origin, "127.0.0.1".into(), None, &roots).unwrap(),
        trust,
    )
}
pub(super) async fn login(
    api: &mut cfyr::Foyer<cfyr::HttpClient>,
    keys: &mut cpky::Client<SoftwareAuthenticator>,
) {
    let challenge = api.begin_browser_login().await.unwrap();
    let (credential, unlock) = keys.sign_in(challenge.options).await.unwrap().into_parts();
    drop(unlock);
    api.finish_browser_login(challenge.ceremony, credential)
        .await
        .unwrap();
}
pub(super) async fn initial<'p>(
    door: &Door,
    origin: &str,
    policy: &'p mut cfyr::policy::CurrentPolicy<cfyr::HttpClient>,
) -> cfyr::membership::InitialCreationLease<'p, cfyr::HttpClient> {
    door.live_wallet_membership(origin)
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
pub(super) fn bound(
    community: &str,
    origin: &str,
    role: Role,
    scope: Scope,
    api: cfyr::Foyer<cfyr::HttpClient>,
) -> Door {
    let mut door = Door::new(
        Configuration::new(
            community.into(),
            BTreeMap::from([(role, BTreeSet::from([origin.to_owned()]))]),
        )
        .unwrap(),
    );
    door.bind_foyer(origin, role, Sessions::new(scope, api))
        .unwrap();
    door
}
