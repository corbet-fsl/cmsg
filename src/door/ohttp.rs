//! Oblivious HTTP wire for the member's server connections (feature `ohttp`).
//! The trusted embedding supplies the relay URL and the gateway key entries it
//! took from the signature-verified community trust feed; request JSON cannot
//! choose either. Streams stay on their direct transports.
use super::*;
#[cfg(not(target_arch = "wasm32"))]
use cblv::client::{Post, RawReply};
use cblv::{
    client::OhttpWire,
    keys::{PublishedKey, VerifiedKeys},
};

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
}

#[cfg(target_arch = "wasm32")]
pub type Outer = cblv::browser::FetchPost;
#[cfg(not(target_arch = "wasm32"))]
pub type Outer = ReqwestPost;
pub type Wire = OhttpWire<Outer>;

impl OhttpEndpoint {
    /// The wire for the gateway whose inner authority is `service`.
    pub(super) fn wire(&self, service: &str) -> Result<Wire> {
        let url = url::Url::parse(&self.relay).map_err(|_| ErrorCode::InvalidRequest)?;
        if url.scheme() != "https" {
            return Err(ErrorCode::InvalidRequest);
        }
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
        let keys =
            VerifiedKeys::from_verified_feed(entries).map_err(|_| ErrorCode::InvalidRequest)?;
        Ok(OhttpWire::new(outer()?, &self.relay, service, keys, now))
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
        .map_err(|_| ErrorCode::Unavailable)
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
            .map_err(|_| cblv::Error::Transport)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|_| cblv::Error::Transport)?;
        if bytes.len() > 1 << 20 {
            return Err(cblv::Error::Transport);
        }
        Ok(RawReply { status, body: bytes.to_vec() })
    }
}
