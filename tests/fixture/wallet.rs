//! Original current-time Wallet and same-issuer community over fixed TLS ingress.
//! The client must derive its holder from actual certified Keys and issue its
//! own passport. This fixture supplies no holder, presentation or admission.
use super::{https, owner};
use cvld::{
    api::{GlobalPublic, TrustFeed},
    service::{Clock, Door, SystemClock},
};
use serde_json::{Value, json};
use std::{io, path::Path, sync::Arc, time::Duration};

const COMMUNITY: &str = "omega";
const COMMUNITY_HOST: &str = "api.omega.example.test";
const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);

pub(super) struct Fixture {
    wallet: https::HttpsFixture,
    wallet_alternate: https::HttpsFixture,
    community: https::HttpsFixture,
    wallet_owner: Door,
    community_owner: Door,
    _wallet_directory: Arc<tempfile::TempDir>,
    _community_directory: Arc<tempfile::TempDir>,
    pub(super) data: Value,
}
impl Fixture {
    pub(super) async fn start(chain: &Path, key: &Path) -> io::Result<Self> {
        let wallet_dir = Arc::new(tempfile::tempdir()?);
        let mut config = owner::wallet_config_at(wallet_dir.path(), 1000, SystemClock.now()).await;
        config.root_bootstrap_file = None;
        let wallet_owner = Door::global(config, Arc::new(SystemClock))
            .await
            .map_err(refused)?;
        let wallet_router = cvld::api::router(wallet_owner.clone());
        let wallet = https::HttpsFixture::start(
            fixed_host(wallet_router, owner::WALLET),
            wallet_dir.clone(),
            chain,
            key,
        )
        .await?;
        // A second actual HTTPS origin for the SAME original Wallet Door/SDK,
        // not a copied database, accepting transport or alternate signer.
        let wallet_alternate = https::HttpsFixture::start(
            fixed_host(cvld::api::router(wallet_owner.clone()), owner::WALLET),
            wallet_dir.clone(),
            chain,
            key,
        )
        .await?;
        let roots = std::fs::read(chain)?;
        let root = reqwest::Certificate::from_pem(&roots).map_err(refused)?;
        // The fixture's original provisioned TLS identity authenticates these
        // owner reads. No request selects a host, URL, issuer or trust ring.
        let transport = reqwest::Client::builder()
            .add_root_certificate(root)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(refused)?;
        let public: GlobalPublic =
            serde_json::from_value(call(&transport, wallet.base_url(), "global_public").await?)
                .map_err(refused)?;
        let wallet_feed: TrustFeed =
            serde_json::from_value(call(&transport, wallet.base_url(), "wallet_trust_feed").await?)
                .map_err(refused)?;

        let community_dir = Arc::new(tempfile::tempdir()?);
        let mut config = owner::community_config(community_dir.path(), COMMUNITY, &public, 1000);
        config.root.bootstrap_file = None;
        config.admin.bootstrap_file = None;
        let community_owner = Door::community(config, Arc::new(SystemClock))
            .await
            .map_err(refused)?;
        let community = https::HttpsFixture::start(
            fixed_host(cvld::api::router(community_owner.clone()), COMMUNITY_HOST),
            community_dir.clone(),
            chain,
            key,
        )
        .await?;
        let community_feed: TrustFeed =
            serde_json::from_value(call(&transport, community.base_url(), "trust_feed").await?)
                .map_err(refused)?;
        let data = json!({
            "clock":"SystemClock",
            "now":SystemClock.now(),
            "passport_gate":"original development fixture",
            "wallet":{"base":wallet.base_url(),"host":"127.0.0.1",
                "scope":"wallet","passkey_origin":"https://wallet.example.test",
                "rp_id":owner::WALLET,"trust_key_ring":wallet_feed.key_ring},
            "wallet_alternate":{"base":wallet_alternate.base_url(),"host":"127.0.0.1",
                "scope":"wallet","passkey_origin":"https://wallet.example.test",
                "rp_id":owner::WALLET,"trust_key_ring":wallet_feed.key_ring},
            "community":{"base":community.base_url(),"host":"127.0.0.1",
                "scope":COMMUNITY,"passkey_origin":"https://vault.omega.example.test",
                "rp_id":"omega.example.test","trust_key_ring":community_feed.key_ring},
            "global_public":public,
            "accounting":"unconfigured; no accepted account or proof claim",
        });
        Ok(Self {
            wallet,
            wallet_alternate,
            community,
            wallet_owner,
            community_owner,
            _wallet_directory: wallet_dir,
            _community_directory: community_dir,
            data,
        })
    }

    pub(super) async fn shutdown(self) -> io::Result<()> {
        // Fence BOTH real owners before any worker join and retain the original
        // total deadline across SDK/native work and the TLS connection drains.
        self.wallet_owner
            .begin_shutdown_accounts()
            .map_err(refused)?;
        self.community_owner
            .begin_shutdown_accounts()
            .map_err(refused)?;
        tokio::time::timeout(SHUTDOWN_LIMIT, async {
            self.wallet.shutdown().await?;
            self.wallet_alternate.shutdown().await?;
            self.community.shutdown().await?;
            self.wallet_owner
                .shutdown_accounts()
                .await
                .map_err(refused)?;
            self.community_owner
                .shutdown_accounts()
                .await
                .map_err(refused)
        })
        .await
        .map_err(|_| io::Error::other("wallet fixture shutdown timed out"))?
    }
}

fn fixed_host(router: axum::Router, host: &'static str) -> axum::Router {
    router.layer(axum::middleware::from_fn(
        move |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
            request.headers_mut().insert(
                axum::http::header::HOST,
                axum::http::HeaderValue::from_static(host),
            );
            next.run(request).await
        },
    ))
}
async fn call(client: &reqwest::Client, origin: &str, action: &str) -> io::Result<Value> {
    client
        .post(format!("{origin}/v1/{action}"))
        .json(&json!({}))
        .send()
        .await
        .map_err(refused)?
        .error_for_status()
        .map_err(refused)?
        .json()
        .await
        .map_err(refused)
}
fn refused(_: impl std::fmt::Debug) -> io::Error {
    io::Error::other("original wallet fixture owner refused")
}
