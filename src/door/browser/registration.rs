//! Browser registration of a fresh device on the wallet model (DESIGN-one-confirmation): the
//! portable composer core (`composer_core::compose_device`, steps 1-7 and the community vault)
//! inside the deployment's ONE wallet custody frame at `wallet.<base>`. The wallet passkey is
//! the device's only passkey; its PRF unlocks the wallet vault and derives every community
//! vault; the community joins by device key (`device_join`) and its sessions open by the device
//! key's signature. No community frame ever runs a WebAuthn ceremony.
//!
//! The account actor (step 8) needs a prover. A deployment that ships the browser prover names it
//! (`prover`); the wallet frame then lends the `BrowserProver` (`prover::lend`) and the composed
//! Door binds its account actor, so the account genesis proves in a Web Worker of this origin. A
//! deployment without one lends nothing: the Door stops after `bind_vault_with_board_owner`.
//!
//! The records network both lineages publish to before the vault exists is lent by the
//! deployment (`network`), one isolated circuit per scope.
pub mod network;

use super::{Service, TrustConfiguration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Public deployment data of the wallet frame's registration. No credential, PRF, session or
/// record identity is accepted here; every value is pinned by the deployment.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    /// The wallet (global) service and its publishing trust.
    pub wallet: Service,
    pub wallet_trust: TrustConfiguration,
    /// The community service; its trust is anchored to the founding fingerprint.
    pub community: Service,
    /// Trust scope the community feed is signed for.
    pub community_scope: String,
    /// Founding-key fingerprint of the community (64 hex digits).
    pub fingerprint: String,
    pub community_following: cfyr::trust::Config,
    /// Origin and relying party of the wallet passkey (`https://wallet.<base>`, `<base>`).
    pub passkey_origin: String,
    pub rp_id: String,
    /// IndexedDB namespace of this deployment's device vaults (not a URL).
    pub storage: String,
    /// The records network the deployment lends the registration (production: the bootstrap
    /// Tor client; toy: the stack's records helper).
    pub records: network::Lent,
    /// The browser prover this deployment ships, or none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover: Option<ProverDeployment>,
}

/// Where the wallet origin serves the browser prover's circuit group (the published circuits).
pub const PROVER_CIRCUIT_PATH: &str = "/prover/circuit.json";
/// Where the wallet origin serves the browser prover's verification-key group.
pub const PROVER_KEYS_PATH: &str = "/prover/keys.json";
/// Where the wallet origin serves the dummy input of the calibration proof (public test data).
pub const PROVER_CALIBRATION_PATH: &str = "/prover/calibration.json";

/// Public data of the browser prover this deployment ships. The files sit at fixed paths of the
/// wallet origin; the deployment pins their digests, so a file the origin serves differently is
/// refused before any proof. The setup (`/prover/srs/g1-<points>.dat`, `g2.dat`) is pinned by the
/// engine itself, never by this configuration.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProverDeployment {
    /// SHA-256 (64 lowercase hex digits) of `/prover/circuit.json`.
    pub circuit_sha256: String,
    /// SHA-256 of `/prover/keys.json`.
    pub keys_sha256: String,
    /// SHA-256 of `/prover/calibration.json`.
    pub calibration_sha256: String,
    /// The dyadic number of setup points the circuit needs (the engine pins 2^19 and 2^20).
    pub points: u32,
}

impl Configuration {
    /// IndexedDB names: a fixed wallet namespace, and the community vault and progress marker
    /// by the community's founding fingerprint, so a reused community name never sees an old
    /// vault.
    pub fn databases(&self) -> [String; 3] {
        databases(&self.storage, &self.fingerprint)
    }

    /// The registration's records networks: the wallet's and this community's, each on its
    /// own circuit, as the deployment lends them (a bootstrap client runs on the deployment's
    /// browser Tor budgets, `tor`). Refused before any ceremony when the lent network cannot
    /// be opened.
    pub async fn networks(
        &self,
        tor: Option<&super::deployment::Configuration>,
    ) -> Result<
        crate::door::composer_core::Networks<network::Network>,
        crate::door::composer_core::ComposeError,
    > {
        let fingerprint = crate::door::identity::Fingerprint::from_hex(&self.fingerprint)
            .ok_or_else(|| {
                crate::door::composer_core::ComposeError::Config("fingerprint".into())
            })?;
        network::Circuits::new(network::Deployment(&self.records, tor))
            .registration(fingerprint.0)
            .await
    }
}

fn databases(storage: &str, fingerprint: &str) -> [String; 3] {
    [
        format!("{storage}.wallet"),
        format!("{storage}.community.{fingerprint}"),
        format!("{storage}.progress.{fingerprint}"),
    ]
}

#[cfg(target_arch = "wasm32")]
mod runtime {
    use super::Configuration;
    use crate::door::{
        browser::open_transport,
        composer_core::{
            compose_device, now, step, BackendProgress, ComposeError, DeviceKeys, Names, Networks,
            ProgressFile, Service as Endpoint, Services,
        },
        foyer::{Foyer, Transport},
        identity, Door,
    };

    /// Foyer clients of the two configured services, one fresh client per call, exactly as
    /// `Configuration::construct_inner` builds them for a browser Door.
    pub struct BrowserServices<'a>(pub &'a Configuration);

    fn feed_origin(base: &str) -> Result<String, ComposeError> {
        Ok(url::Url::parse(base)
            .map_err(|_| ComposeError::Config("service base".into()))?
            .origin()
            .ascii_serialization())
    }

    fn fresh(mut following: cfyr::trust::Config) -> Result<cfyr::trust::Config, ComposeError> {
        // Retry jitter is fresh runtime entropy, never a deployment value.
        let mut entropy = [0; 8];
        getrandom::fill(&mut entropy).map_err(step("entropy"))?;
        following.retry_entropy = u64::from_le_bytes(entropy);
        Ok(following)
    }

    impl Services for BrowserServices<'_> {
        async fn foyer(&mut self, service: Endpoint) -> Result<Foyer<Transport>, ComposeError> {
            let configuration = self.0;
            let mut trust = match service {
                Endpoint::Global => {
                    let trust = configuration.wallet_trust.clone();
                    if trust.publishing.community != "wallet"
                        || trust.publishing.origin != feed_origin(&configuration.wallet.base)?
                    {
                        return Err(ComposeError::Config("wallet trust".into()));
                    }
                    cfyr::trust::Trust::wallet_browser(trust.publishing, fresh(trust.following)?)
                }
                Endpoint::Community => {
                    let fingerprint = identity::Fingerprint::from_hex(&configuration.fingerprint)
                        .ok_or_else(|| ComposeError::Config("fingerprint".into()))?;
                    cfyr::trust::Trust::anchored_browser(
                        &cfyr::trust::Anchor {
                            origin: &feed_origin(&configuration.community.base)?,
                            community: &configuration.community_scope,
                            fingerprint: fingerprint.0,
                            minimum_revision: 1,
                            pin: None,
                        },
                        fresh(configuration.community_following.clone())?,
                    )
                }
            }
            .map_err(step("trust"))?;
            trust.start(now).await.map_err(step("trust"))?;
            let transport =
                open_transport(self.service(service), &[]).map_err(step("transport"))?;
            Ok(Foyer::with_trust(transport, trust))
        }

        async fn public(&mut self, service: Endpoint) -> Result<Foyer<Transport>, ComposeError> {
            let transport =
                open_transport(self.service(service), &[]).map_err(step("transport"))?;
            Ok(Foyer::new(transport))
        }
    }

    impl BrowserServices<'_> {
        fn service(&self, service: Endpoint) -> &crate::door::browser::Service {
            match service {
                Endpoint::Global => &self.0.wallet,
                Endpoint::Community => &self.0.community,
            }
        }
    }

    /// Register (or resume) this browser device and return its community Door, keyed by the
    /// wallet frame's origin `door_origin`, with the community vault bound. Resumable at every
    /// step from the two IndexedDB vault checkpoints and the progress marker beside them; a
    /// half-registered device never registers twice. `keys` is the wallet passkey client of
    /// this frame (`cpky::Context::new(passkey_origin, rp_id)`), `networks` the records
    /// networks the wallet and community lineages publish to and recover from, one isolated
    /// circuit per scope (`network::Circuits::registration`).
    pub async fn compose_browser_device<A, N>(
        configuration: &Configuration,
        door_origin: &str,
        community_name: &str,
        keys: &mut DeviceKeys<A>,
        networks: Networks<N>,
        prover: Option<std::sync::Arc<dyn crate::door::account::AccountProver>>,
    ) -> Result<(Door, super::Retained), ComposeError>
    where
        A: cfyr::passkeys::Authenticator,
        N: cdht::Network + Clone + 'static,
    {
        if community_name.is_empty() || community_name == "wallet" {
            return Err(ComposeError::Config("community name".into()));
        }
        let global_origin = feed_origin(&configuration.wallet.base)?;
        if global_origin == feed_origin(&configuration.community.base)? {
            return Err(ComposeError::Config("service scopes".into()));
        }
        let [wallet, community, progress] = configuration.databases();
        let open = |name: String| async move {
            cwst::browser::IndexedDb::open(&name)
                .await
                .map_err(step("vault"))
        };
        let wallet = open(wallet).await?;
        let community = open(community).await?;
        let mut progress = ProgressFile::load(BackendProgress::new(open(progress).await?)).await?;
        let mut services = BrowserServices(configuration);
        let composed = compose_device(
            Names {
                global_origin: &global_origin,
                community_origin: door_origin,
                community_name,
            },
            &mut services,
            keys,
            wallet,
            community,
            &mut progress,
            networks,
        )
        .await?;
        // The wallet Door's session is held by the global passport's recovery lease; the
        // frame keeps the wallet Door and the companion for its life (`Retained`), as native
        // keeps them in the account actor. The board owner ends here exactly as in
        // compose_native_device.
        let mut door = composed.door;
        match prover {
            // 8. The account actor with its three single-use intents, proving in the Web
            //    Worker. It holds the global passport, as natively.
            #[cfg(feature = "browser-prover")]
            Some(prover) => {
                crate::door::account_open::bind_member_account_with(
                    &mut door,
                    door_origin,
                    &composed.owner,
                    composed.account,
                    composed.actor_membership,
                    composed.actor_policy,
                    composed.global,
                    *composed.device.value(),
                    prover,
                )
                .await
                .map_err(step("bind account"))?;
                drop(composed.owner);
                Ok((
                    door,
                    super::Retained(Box::new((composed.wallet_door, composed.global_companion))),
                ))
            }
            // No prover lent: the actor's parts end unused, the passport stays in `Retained`
            // and the next start reserves the intents again.
            _ => {
                let _ = prover;
                drop(composed.owner);
                drop((
                    composed.account,
                    composed.actor_membership,
                    composed.actor_policy,
                    composed.device,
                ));
                Ok((
                    door,
                    super::Retained(Box::new((
                        composed.global,
                        composed.wallet_door,
                        composed.global_companion,
                    ))),
                ))
            }
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use runtime::{compose_browser_device, BrowserServices};

/// What a browser registration keeps beside the community Door for the wallet frame's life:
/// the wallet Door (the passport's recovery lease holds its session), the wallet companion and,
/// when no prover is lent, the global passport. The frame's `VaultHost` owns it and drops it
/// with itself; nothing is leaked. With a prover the account actor holds the passport
/// (`bind_member_account_with`), exactly as natively.
pub struct Retained(#[allow(dead_code)] Box<dyn std::any::Any>);

#[cfg(test)]
mod tests {
    use super::Configuration;

    fn configuration() -> serde_json::Value {
        let service = |scope: &str, base: &str| serde_json::json!({"scope": scope, "base": base, "host": base.trim_start_matches("https://")});
        let following = serde_json::json!({"retry_entropy":0,"refresh_seconds":30,"poll_seconds":1,
            "request_seconds":30,"initial_backoff_seconds":1,"maximum_backoff_seconds":10,
            "maximum_staleness_seconds":900});
        serde_json::json!({
            "wallet": service("global", "https://api.wallet.toy.test"),
            "wallet_trust": {"publishing": {"origin": "https://api.wallet.toy.test", "community": "wallet",
                "key_ring": [], "minimum_revision": 1, "ring_revision": 0}, "following": following},
            "community": service("community", "https://api.omega.toy.test"),
            "community_scope": "omega",
            "fingerprint": "ab".repeat(32),
            "community_following": following,
            "passkey_origin": "https://wallet.toy.test",
            "rp_id": "toy.test",
            "storage": "cmeet",
            "records": {"kind": "relay", "endpoint": "http://127.0.0.1:7000/"},
        })
    }

    #[test]
    fn vault_databases_are_named_by_the_fixed_wallet_namespace_and_the_community_fingerprint() {
        let fingerprint = "ab".repeat(32);
        assert_eq!(
            super::databases("cmeet", &fingerprint),
            [
                "cmeet.wallet".to_owned(),
                format!("cmeet.community.{fingerprint}"),
                format!("cmeet.progress.{fingerprint}"),
            ]
        );
        // Another community never shares a vault or a progress marker; the wallet is one.
        let other = super::databases("cmeet", &"cd".repeat(32));
        assert_eq!(other[0], "cmeet.wallet");
        assert_ne!(other[1], format!("cmeet.community.{fingerprint}"));
    }

    #[test]
    fn a_registration_names_its_records_network() {
        let parsed: Configuration = serde_json::from_value(configuration()).expect("configuration");
        assert!(matches!(parsed.records, super::network::Lent::Relay { .. }));
        let mut value = configuration();
        value.as_object_mut().expect("object").remove("records");
        assert!(serde_json::from_value::<Configuration>(value).is_err());
    }

    #[test]
    fn unknown_registration_fields_are_refused() {
        let mut value = configuration();
        value["session"] = serde_json::json!("x");
        let refused = serde_json::from_value::<Configuration>(value)
            .err()
            .map(|e| e.to_string());
        assert!(
            refused
                .as_ref()
                .is_some_and(|e| e.contains("unknown field `session`")),
            "{refused:?}"
        );
    }
}
