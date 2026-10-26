//! Oblivious HTTP wire for the member's server connections (feature `ohttp`).
//! The trusted embedding supplies the relay URL and the gateway key entries it
//! took from the signature-verified community trust feed; request JSON cannot
//! choose either. Streams stay on their direct transports.
use super::*;
#[cfg(not(target_arch = "wasm32"))]
use cblv::client::{Post, RawReply};
use cblv::{
    client::OhttpWire,
    keys::{Directory, FeedKeys, KeySource, Preferred, PublishedKey, Snapshot},
};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OhttpKey {
    pub service: String,
    pub key_id: u8,
    pub config: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OhttpEndpoint {
    /// Base URL of the proxied gateway host that forwards ciphertext.
    pub relay: String,
    /// Key entries taken from the verified trust feed manifest.
    pub keys: Vec<OhttpKey>,
    /// Keys of the verified community feed. Until a verified publication is
    /// installed the configured `keys` serve; afterwards the feed alone does.
    #[serde(skip)]
    feed: Arc<FeedKeys>,
}

/// Key source of one endpoint: the verified feed replaces the configured
/// snapshot as soon as it has been installed; the two are never merged.
#[derive(Clone)]
pub struct Keys {
    feed: Arc<FeedKeys>,
    configured: Arc<Snapshot>,
}

impl KeySource for Keys {
    fn current(&self, service: &str, now: u64) -> Option<(String, PublishedKey)> {
        Preferred {
            feed: &self.feed,
            configured: self.configured.clone(),
        }
        .current(service, now)
    }
}

#[cfg(target_arch = "wasm32")]
pub type Outer = cblv::browser::FetchPost;
#[cfg(not(target_arch = "wasm32"))]
pub type Outer = ReqwestPost;
pub type Wire = OhttpWire<Outer, Keys>;

impl OhttpEndpoint {
    /// The feed that follows the verified community trust publications.
    pub fn feed(&self) -> Arc<FeedKeys> {
        self.feed.clone()
    }

    /// The key source: the verified feed once installed, else the configured keys.
    pub fn keys(&self) -> Result<Keys> {
        let entries = self
            .keys
            .iter()
            .map(|key| PublishedKey {
                service: key.service.clone(),
                key_id: key.key_id,
                config: key.config.clone(),
                not_before: key.not_before,
                not_after: key.not_after,
            })
            .collect();
        let keys = Directory {
            relay: self.relay.clone(),
            keys: entries,
        }
        .verify()
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        Ok(Keys {
            feed: self.feed.clone(),
            configured: Arc::new(keys),
        })
    }

    /// The wire for the gateway whose inner authority is `service`.
    pub(super) fn wire(&self, service: &str) -> Result<Wire> {
        let url = url::Url::parse(&self.relay).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        if url.scheme() != "https" {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(OhttpWire::new(outer()?, service, self.keys()?, now))
    }
}

#[cfg(target_arch = "wasm32")]
fn outer() -> Result<Outer> {
    Ok(cblv::browser::FetchPost)
}

#[cfg(target_arch = "wasm32")]
fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Native outer POST: no proxy, redirects, cookies or identifying headers.
#[cfg(not(target_arch = "wasm32"))]
pub struct ReqwestPost(reqwest::Client);

#[cfg(not(target_arch = "wasm32"))]
fn outer() -> Result<Outer> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map(ReqwestPost)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Unavailable",
                ErrorCode::Unavailable,
                &__cause,
            )
        })
}

#[cfg(not(target_arch = "wasm32"))]
impl Post for ReqwestPost {
    async fn post(
        &self,
        url: &str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> cblv::Result<RawReply> {
        let response = self
            .0
            .post(url)
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "cblv::Error::Transport",
                    cblv::Error::Transport,
                    &__cause,
                )
            })?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "cblv::Error::Transport",
                cblv::Error::Transport,
                &__cause,
            )
        })?;
        if bytes.len() > 1 << 20 {
            return Err(cblv::Error::Transport);
        }
        Ok(RawReply {
            status,
            body: bytes.to_vec(),
        })
    }
}

/// Endpoint with one placeholder key for fixtures whose transport is never used.
#[cfg(test)]
pub(crate) fn fixture_endpoint() -> OhttpEndpoint {
    let mut config = vec![1, 0x00, 0x20];
    config.extend([2; 32]);
    config.extend([0x00, 0x04, 0x00, 0x01, 0x00, 0x03]);
    OhttpEndpoint {
        relay: "https://relay.example.test".into(),
        keys: vec![OhttpKey {
            service: "fixture.example.test".into(),
            key_id: 1,
            config,
            not_before: 0,
            not_after: u64::MAX,
        }],
        feed: Arc::default(),
    }
}
