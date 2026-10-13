//! Original current-time Wallet and same-issuer community over fixed TLS ingress.
//! The client must derive its holder from actual certified Keys and issue its
//! own passport. This fixture supplies no holder, presentation or admission.
use super::{https, owner};
use cvld::{
    api::{GlobalPublic, TrustFeed},
    service::{Clock, Door, SystemClock},
};
use serde_json::{json, Value};
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
        eprintln!("original wallet fixture entering Wallet construction");
        let wallet_owner = Door::global(config, Arc::new(SystemClock))
            .await
            .map_err(|_| refused_stage("Wallet construction"))?;
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
        let root = reqwest::Certificate::from_der(include_bytes!("../support/current-tls/ca.der"))
            .map_err(refused)?;
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
                .map_err(|_| refused_stage("GlobalPublic decoding"))?;
        let wallet_feed: TrustFeed =
            serde_json::from_value(call(&transport, wallet.base_url(), "wallet_trust_feed").await?)
                .map_err(|_| refused_stage("Wallet trust feed decoding"))?;

        let community_dir = Arc::new(tempfile::tempdir()?);
        let mut config = owner::community_config(community_dir.path(), COMMUNITY, &public, 1000);
        config.root.bootstrap_file = None;
        config.admin.bootstrap_file = None;
        // The native accounting operator exists only in a fixture instance started with the
        // assembled G5 configuration (`.ci/g5-account-config.sh`); every other instance keeps
        // `accounting: None`, so no existing journey changes.
        let accounting = match std::env::var_os("CMSG_G5_ACCOUNT_CONFIG") {
            None => None,
            Some(path) => {
                let account: cvld::accounting::AccountConfig =
                    serde_json::from_slice(&std::fs::read(path)?)
                        .map_err(|_| refused_stage("G5 account configuration"))?;
                // The authenticated Rulebook carries the period and the daily quota the operator reads.
                let mut rules: cmty::cplc::crbk::Rulebook =
                    serde_json::from_slice(&std::fs::read(&config.rulebook_file)?)
                        .map_err(|_| refused_stage("community Rulebook"))?;
                cmty::cplc::crbk::RecordEpochSettings::define(&mut rules, &account.period_key)
                    .map_err(|_| refused_stage("Rulebook period key"))?;
                cmty::cplc::crbk::OutcomeQuotaSettings::define(
                    &mut rules,
                    &account.settlement.quota_key,
                )
                .map_err(|_| refused_stage("Rulebook quota key"))?;
                rules
                    .set_community(&account.period_key, Some(json!(86_400)))
                    .map_err(|_| refused_stage("Rulebook period"))?;
                rules
                    .set_community(&account.settlement.quota_key, Some(json!(4)))
                    .map_err(|_| refused_stage("Rulebook quota"))?;
                std::fs::write(
                    &config.rulebook_file,
                    serde_json::to_vec(&rules).map_err(|_| refused_stage("Rulebook encoding"))?,
                )?;
                Some(account)
            }
        };
        let accounting_state = if accounting.is_some() {
            "configured; native operator from the assembled G5 account configuration"
        } else {
            "unconfigured; no accepted account or proof claim"
        };
        config.accounting = accounting;
        eprintln!("original wallet fixture entering community construction");
        let community_owner = Door::community(config, Arc::new(SystemClock))
            .await
            .map_err(|_| refused_stage("community construction"))?;
        let community = https::HttpsFixture::start(
            lose_first_account_response(fixed_host(
                cvld::api::router(community_owner.clone()),
                COMMUNITY_HOST,
            )),
            community_dir.clone(),
            chain,
            key,
        )
        .await?;
        let community_feed: TrustFeed =
            serde_json::from_value(call(&transport, community.base_url(), "trust_feed").await?)
                .map_err(|_| refused_stage("community trust feed decoding"))?;
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
            "accounting":accounting_state,
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

/// With `CMSG_G5_LOSE_FIRST_ACCOUNT_RESPONSE` set, the operator ACCEPTS the first account request but the
/// client never sees the answer (a crash between send and state B). The retry must carry the identical
/// bytes; any other body is refused, so only a faithful re-send can complete the lifecycle.
fn lose_first_account_response(router: axum::Router) -> axum::Router {
    if std::env::var_os("CMSG_G5_LOSE_FIRST_ACCOUNT_RESPONSE").is_none() {
        return router;
    }
    let first: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Arc::default();
    router.layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let first = first.clone();
            async move {
                use axum::response::IntoResponse;
                if request.uri().path() != "/v1/account" {
                    return next.run(request).await;
                }
                let (parts, body) = request.into_parts();
                let Ok(bytes) = axum::body::to_bytes(body, 8 * 1024 * 1024).await else {
                    return axum::http::StatusCode::PAYLOAD_TOO_LARGE.into_response();
                };
                let lose = {
                    let mut seen = first.lock().unwrap();
                    match seen.as_ref() {
                        None => {
                            *seen = Some(bytes.to_vec());
                            true
                        }
                        Some(previous) if previous.as_slice() == bytes.as_ref() => false,
                        Some(_) => return axum::http::StatusCode::CONFLICT.into_response(),
                    }
                };
                let response = next
                    .run(axum::extract::Request::from_parts(
                        parts,
                        axum::body::Body::from(bytes),
                    ))
                    .await;
                if lose {
                    return axum::http::StatusCode::BAD_GATEWAY.into_response();
                }
                response
            }
        },
    ))
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
    let stage = match action {
        "global_public" => "GlobalPublic read",
        "wallet_trust_feed" => "Wallet trust feed read",
        "trust_feed" => "community trust feed read",
        _ => return Err(refused_stage("unsupported fixture read")),
    };
    eprintln!("original wallet fixture entering {stage}");
    client
        .post(format!("{origin}/v1/{action}"))
        .json(&json!({}))
        .send()
        .await
        .map_err(|_| refused_stage(stage))?
        .error_for_status()
        .map_err(|_| refused_stage(stage))?
        .json()
        .await
        .map_err(|_| refused_stage(stage))
}
fn refused_stage(stage: &'static str) -> io::Error {
    io::Error::other(format!("original wallet fixture owner refused at {stage}"))
}
fn refused(_: impl std::fmt::Debug) -> io::Error {
    io::Error::other("original wallet fixture owner refused")
}
