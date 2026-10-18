//! Browser registration of a fresh device on the wallet model (DESIGN-one-confirmation): the
//! portable composer core (`composer_core::compose_device`, steps 1-7 and the community vault)
//! inside the deployment's ONE wallet custody frame at `wallet.<base>`. The wallet passkey is
//! the device's only passkey; its PRF unlocks the wallet vault and derives every community
//! vault; the community joins by device key (`device_join`) and its sessions open by the device
//! key's signature. No community frame ever runs a WebAuthn ceremony.
//!
//! The account actor (step 8) needs a prover the browser does not have yet; the composed Door
//! stops after `bind_vault_with_board_owner`.
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
}

impl Configuration {
    /// IndexedDB names: a fixed wallet namespace, and the community vault and progress marker
    /// by the community's founding fingerprint, so a reused community name never sees an old
    /// vault.
    pub fn databases(&self) -> [String; 3] {
        databases(&self.storage, &self.fingerprint)
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
            compose_device, now, step, BackendProgress, ComposeError, DeviceKeys, Names,
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
            let transport = open_transport(self.service(service), &[]).map_err(step("transport"))?;
            Ok(Foyer::with_trust(transport, trust))
        }

        async fn public(&mut self, service: Endpoint) -> Result<Foyer<Transport>, ComposeError> {
            let transport = open_transport(self.service(service), &[]).map_err(step("transport"))?;
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
    /// this frame (`cpky::Context::new(passkey_origin, rp_id)`), `network` the records network
    /// the lineages publish to and recover from.
    pub async fn compose_browser_device<A, N>(
        configuration: &Configuration,
        door_origin: &str,
        community_name: &str,
        keys: &mut DeviceKeys<A>,
        network: N,
    ) -> Result<Door, ComposeError>
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
            network,
        )
        .await?;
        // The wallet Door's session is held by the global passport's recovery lease for the
        // frame's life; the companion and the passport stay with it.
        Box::leak(Box::new((composed.wallet_door, composed.global_companion)));
        Box::leak(Box::new(composed.global));
        drop(composed.owner);
        Ok(composed.door)
    }
}
#[cfg(target_arch = "wasm32")]
pub use runtime::{compose_browser_device, BrowserServices};

/// The records network of a fresh browser registration. OPEN (W2b-SPEC decision 1a/1b): both
/// lineages publish to and recover from the records network before any vault-derived browser
/// Tor identity exists (`prepare_browser_transport` needs an opened vault and a session), and
/// no substituted transport may stand in. Until the manager decides, no network can be built
/// and the wallet frame refuses before its first ceremony, so nothing is half registered.
pub enum NoRecordsNetwork {}

#[cfg(target_arch = "wasm32")]
pub(crate) fn network(
    _configuration: &Configuration,
) -> Result<NoRecordsNetwork, crate::door::composer_core::ComposeError> {
    Err(crate::door::composer_core::ComposeError::Step(
        "records network",
        "no records identity exists before the wallet vault (W2b decision 1a/1b)".into(),
    ))
}

impl Clone for NoRecordsNetwork {
    fn clone(&self) -> Self {
        match *self {}
    }
}

impl cdht::Network for NoRecordsNetwork {
    fn now_ms(&self) -> u64 {
        match *self {}
    }
    async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        match *self {}
    }
    async fn descriptor(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        match *self {}
    }
    async fn get(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
        _: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        match *self {}
    }
    async fn set(
        &self,
        _: &cdht::NodeId,
        _: &cdht::Descriptor,
        _: u32,
        _: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        match *self {}
    }
    async fn watch(&self, _: &cdht::NodeId, _: &cdht::RecordKey) -> Result<cdht::WatchId, cdht::Error> {
        match *self {}
    }
    async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
        match *self {}
    }
    async fn changes(
        &self,
        _: &cdht::NodeId,
        _: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::Configuration;

    fn configuration() -> serde_json::Value {
        let service = |scope: &str, base: &str| {
            serde_json::json!({"scope": scope, "base": base, "host": base.trim_start_matches("https://")})
        };
        let following = serde_json::json!({"retry_entropy":0,"refresh_seconds":30,"poll_seconds":1,
            "request_seconds":30,"initial_backoff_seconds":1,"maximum_backoff_seconds":10,
            "maximum_staleness_seconds":900});
        serde_json::json!({
            "wallet": service("global", "https://api.wallet.toy.test"),
            "wallet_trust": {"publishing": {"origin": "https://api.wallet.toy.test", "community": "wallet",
                "key_ring": null, "minimum_revision": 1, "ring_revision": 0}, "following": following},
            "community": service("community", "https://api.omega.toy.test"),
            "community_scope": "omega",
            "fingerprint": "ab".repeat(32),
            "community_following": following,
            "passkey_origin": "https://wallet.toy.test",
            "rp_id": "toy.test",
            "storage": "cmeet",
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
    fn unknown_registration_fields_are_refused() {
        let mut value = configuration();
        value["session"] = serde_json::json!("x");
        let refused = serde_json::from_value::<Configuration>(value).err().map(|e| e.to_string());
        assert!(refused.is_some_and(|e| e.contains("unknown field `session`")));
    }
}
