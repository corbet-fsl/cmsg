//! The records network of a fresh browser registration (decision 2026-10-22, option 1a).
//!
//! Both lineages publish to and recover from the records network before the wallet vault, and
//! so any vault-derived browser Tor identity, exists. The deployment lends the registration
//! that network; nothing in it holds a secret, and custody is unchanged: lineages, checkpoints
//! and recovery are complete at `Done`, signed by the lineage keys. Later starts use the
//! vault-derived identity (`prepare_browser_transport`).
//!
//! Every scope (the wallet, each community) gets its OWN network with its own isolation, and a
//! registration lends a scope once (`Circuits`), so no two scopes ever share a circuit: shared
//! circuits are the one way the bootstrap transport could link a wallet to its communities.
use crate::door::composer_core::{ComposeError, Networks};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What the deployment lends as the registration's records network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum Lent {
    /// Production: a bootstrap browser Tor client (Snowflake) with a fresh EPHEMERAL client
    /// identity and one isolated circuit per scope. (A struct variant, so an unknown field
    /// is refused.)
    Bootstrap {},
    /// Toy stack only: the stack's records helper (`e2e_records`), the network the CLI's
    /// embedder lends, reached over loopback HTTP. Any non-loopback endpoint is refused.
    Relay { endpoint: String },
}

/// The scopes of one registration. A community is named by its founding fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Wallet,
    Community([u8; 32]),
}

/// The isolation of one scope's circuit, unique inside a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Isolation(u32);

impl Isolation {
    pub fn value(self) -> u32 {
        self.0
    }
}

/// Opens the records network of one scope on its own isolation.
pub trait Open {
    type Network: cdht::Network + Clone + 'static;
    fn open(&mut self, scope: Scope, isolation: Isolation)
        -> Result<Self::Network, ComposeError>;
}

/// One registration's circuits: each scope is lent once, on a fresh isolation.
pub struct Circuits<O> {
    open: O,
    lent: Vec<Scope>,
}

fn refused(reason: &str) -> ComposeError {
    ComposeError::Step("records network", reason.into())
}

impl<O: Open> Circuits<O> {
    pub fn new(open: O) -> Self {
        Self {
            open,
            lent: Vec::new(),
        }
    }

    /// The network of `scope`. A scope lent before is refused instead of sharing its circuit.
    pub fn lend(&mut self, scope: Scope) -> Result<O::Network, ComposeError> {
        if self.lent.contains(&scope) {
            return Err(refused("a scope is lent once per registration"));
        }
        let isolation = Isolation(
            u32::try_from(self.lent.len()).map_err(|_| refused("too many scopes"))?,
        );
        let network = self.open.open(scope, isolation)?;
        self.lent.push(scope);
        Ok(network)
    }

    /// The wallet's and one community's networks, for `compose_device`.
    pub fn registration(
        &mut self,
        fingerprint: [u8; 32],
    ) -> Result<Networks<O::Network>, ComposeError> {
        Ok(Networks {
            wallet: self.lend(Scope::Wallet)?,
            community: self.lend(Scope::Community(fingerprint))?,
        })
    }
}

/// A relay endpoint is accepted only on loopback (the toy stack's helper), over http(s).
pub fn relay_endpoint(endpoint: &str) -> Result<url::Url, ComposeError> {
    let url = url::Url::parse(endpoint).map_err(|_| refused("relay endpoint"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost" || name.ends_with(".localhost"),
        None => false,
    };
    if !matches!(url.scheme(), "http" | "https")
        || !loopback
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(refused("relay endpoint is not a loopback toy helper"));
    }
    Ok(url)
}

/// The deployment's lent network as an `Open`.
pub struct Deployment<'a>(pub &'a Lent);

impl Open for Deployment<'_> {
    type Network = Network;
    fn open(&mut self, scope: Scope, isolation: Isolation) -> Result<Network, ComposeError> {
        match self.0 {
            // The bootstrap client needs a transport identity that no vault derives: a fresh
            // ephemeral node key for the browser Tor engine (ckmg/ctrn). Until that exists the
            // registration refuses here, before any ceremony; nothing substitutes for Tor.
            Lent::Bootstrap {} => Err(refused(
                "bootstrap Tor client: no ephemeral transport identity yet",
            )),
            Lent::Relay { endpoint } => Ok(Network::Relay(Relay {
                endpoint: relay_endpoint(endpoint)?.to_string(),
                scope,
                isolation,
            })),
        }
    }
}

/// The records network of one scope.
#[derive(Clone)]
pub enum Network {
    Relay(Relay),
}

/// The toy stack's records helper: five validating nodes in one process, one JSON request per
/// HTTP POST (the `e2e_records` wire). The nodes verify every signature themselves.
#[derive(Clone)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub struct Relay {
    endpoint: String,
    scope: Scope,
    isolation: Isolation,
}

impl Relay {
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }
}

const NODES: u8 = 5;

fn index(node: &cdht::NodeId) -> Result<u8, cdht::Error> {
    if *node != [node[0]; 32] || node[0] >= NODES {
        return Err(cdht::Error::Unavailable);
    }
    Ok(node[0])
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn error_from(name: &str) -> cdht::Error {
    match name {
        "Encoding" => cdht::Error::Encoding,
        "InvalidSchema" => cdht::Error::InvalidSchema,
        "BadSignature" => cdht::Error::BadSignature,
        "WrongWriter" => cdht::Error::WrongWriter,
        "SubkeyOutOfRange" => cdht::Error::SubkeyOutOfRange,
        "ValueTooLarge" => cdht::Error::ValueTooLarge,
        "SeqExhausted" => cdht::Error::SeqExhausted,
        _ => cdht::Error::Unavailable,
    }
}

/// The answer body of the helper: `{"ok": value}` or `{"err": name}`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn answer(text: &str) -> Result<serde_json::Value, cdht::Error> {
    let mut answer: serde_json::Value =
        serde_json::from_str(text).map_err(|_| cdht::Error::Encoding)?;
    match answer.get("err").and_then(serde_json::Value::as_str) {
        Some(name) => Err(error_from(name)),
        None => Ok(answer["ok"].take()),
    }
}

fn request(op: &str, node: &cdht::NodeId) -> Result<serde_json::Value, cdht::Error> {
    Ok(serde_json::json!({ "op": op, "node": index(node)? }))
}

#[cfg(target_arch = "wasm32")]
impl Relay {
    async fn call(&self, request: serde_json::Value) -> Result<serde_json::Value, cdht::Error> {
        use wasm_bindgen::JsCast;
        let unavailable = |_| cdht::Error::Unavailable;
        let init = web_sys::RequestInit::new();
        init.set_method("POST");
        // A text/plain POST is a simple CORS request: no preflight, no credentials.
        init.set_mode(web_sys::RequestMode::Cors);
        init.set_credentials(web_sys::RequestCredentials::Omit);
        init.set_body(&wasm_bindgen::JsValue::from_str(&request.to_string()));
        let request = web_sys::Request::new_with_str_and_init(&self.endpoint, &init)
            .map_err(unavailable)?;
        let window = web_sys::window().ok_or(cdht::Error::Unavailable)?;
        let response: web_sys::Response =
            wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
                .await
                .map_err(unavailable)?
                .dyn_into()
                .map_err(unavailable)?;
        if !response.ok() {
            return Err(cdht::Error::Unavailable);
        }
        let text = wasm_bindgen_futures::JsFuture::from(response.text().map_err(unavailable)?)
            .await
            .map_err(unavailable)?
            .as_string()
            .ok_or(cdht::Error::Encoding)?;
        answer(&text)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Relay {
    async fn call(&self, _: serde_json::Value) -> Result<serde_json::Value, cdht::Error> {
        // Browser registration only; native embedders lend their own network.
        Err(cdht::Error::Unavailable)
    }
}

impl cdht::Network for Network {
    fn now_ms(&self) -> u64 {
        match self {
            Network::Relay(_) => 1,
        }
    }
    async fn closest(&self, _: &cdht::RecordKey) -> Result<Vec<cdht::NodeId>, cdht::Error> {
        match self {
            Network::Relay(_) => Ok((0..NODES).map(|index| [index; 32]).collect()),
        }
    }
    async fn descriptor(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
    ) -> Result<Option<cdht::Descriptor>, cdht::Error> {
        let Network::Relay(relay) = self;
        let mut call = request("descriptor", node)?;
        call["key"] = serde_json::json!(key.0);
        serde_json::from_value(relay.call(call).await?).map_err(|_| cdht::Error::Encoding)
    }
    async fn get(
        &self,
        node: &cdht::NodeId,
        key: &cdht::RecordKey,
        subkey: u32,
    ) -> Result<Option<cdht::SignedValue>, cdht::Error> {
        let Network::Relay(relay) = self;
        let mut call = request("get", node)?;
        call["key"] = serde_json::json!(key.0);
        call["subkey"] = serde_json::json!(subkey);
        serde_json::from_value(relay.call(call).await?).map_err(|_| cdht::Error::Encoding)
    }
    async fn set(
        &self,
        node: &cdht::NodeId,
        descriptor: &cdht::Descriptor,
        subkey: u32,
        value: &cdht::SignedValue,
    ) -> Result<cdht::SetOutcome, cdht::Error> {
        let Network::Relay(relay) = self;
        let encode = |_| cdht::Error::Encoding;
        let mut call = request("set", node)?;
        call["subkey"] = serde_json::json!(subkey);
        call["descriptor"] = serde_json::to_value(descriptor).map_err(encode)?;
        call["value"] = serde_json::to_value(value).map_err(encode)?;
        let mut answer = relay.call(call).await?;
        if answer.as_str() == Some("accepted") {
            return Ok(cdht::SetOutcome::Accepted);
        }
        serde_json::from_value(answer["newer"].take())
            .map(cdht::SetOutcome::Newer)
            .map_err(encode)
    }
    async fn watch(
        &self,
        _: &cdht::NodeId,
        _: &cdht::RecordKey,
    ) -> Result<cdht::WatchId, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn cancel_watch(&self, _: &cdht::NodeId, _: cdht::WatchId) -> Result<(), cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
    async fn changes(
        &self,
        _: &cdht::NodeId,
        _: cdht::WatchId,
    ) -> Result<Vec<cdht::Change>, cdht::Error> {
        Err(cdht::Error::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records which isolation every opened scope got.
    #[derive(Default)]
    struct Recorder(Vec<(Scope, Isolation)>);
    impl Open for &mut Recorder {
        type Network = Network;
        fn open(&mut self, scope: Scope, isolation: Isolation) -> Result<Network, ComposeError> {
            self.0.push((scope, isolation));
            Deployment(&Lent::Relay {
                endpoint: "http://127.0.0.1:9".into(),
            })
            .open(scope, isolation)
        }
    }

    #[test]
    fn every_scope_gets_its_own_circuit_and_none_is_shared() {
        let mut recorder = Recorder::default();
        let mut circuits = Circuits::new(&mut recorder);
        let first = circuits.registration([1; 32]).expect("registration");
        let other = circuits.lend(Scope::Community([2; 32])).expect("second community");
        let Network::Relay(wallet) = &first.wallet;
        let Network::Relay(community) = &first.community;
        let Network::Relay(other) = &other;
        assert_eq!(wallet.scope(), Scope::Wallet);
        assert_eq!(community.scope(), Scope::Community([1; 32]));
        let isolations = [wallet.isolation(), community.isolation(), other.isolation()];
        for (i, a) in isolations.iter().enumerate() {
            for b in &isolations[i + 1..] {
                assert_ne!(a, b, "two scopes share a circuit");
            }
        }
        // A scope is never lent twice, so its circuit is never handed to a second user.
        assert!(circuits.lend(Scope::Wallet).is_err());
        assert!(circuits.lend(Scope::Community([1; 32])).is_err());
        assert!(circuits.registration([2; 32]).is_err());
        drop(circuits);
        assert_eq!(recorder.0.len(), 3, "a refused scope opens nothing");
    }

    #[test]
    fn a_refused_open_lends_nothing() {
        let mut circuits = Circuits::new(Deployment(&Lent::Bootstrap {}));
        let refused = circuits.lend(Scope::Wallet).err().map(|e| e.to_string());
        assert!(refused.is_some_and(|e| e.contains("ephemeral transport identity")));
        // The bootstrap refusal is not a lent scope: nothing half-opened stays behind.
        assert!(circuits.lent.is_empty());
    }

    #[test]
    fn the_relay_is_loopback_only() {
        for good in [
            "http://127.0.0.1:7000/",
            "http://[::1]:7000/records",
            "https://records.localhost:8443/",
            "http://localhost:1/",
        ] {
            assert!(relay_endpoint(good).is_ok(), "{good}");
        }
        for bad in [
            "http://10.0.0.1:7000/",
            "https://records.toy.test/",
            "https://localhost.example/",
            "ftp://127.0.0.1/",
            "http://user@127.0.0.1/",
            "http://127.0.0.1/?x=1",
            "not a url",
        ] {
            assert!(relay_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn lent_networks_parse_strictly() {
        let relay: Lent =
            serde_json::from_str(r#"{"kind":"relay","endpoint":"http://127.0.0.1:1/"}"#)
                .expect("relay");
        assert!(matches!(relay, Lent::Relay { .. }));
        let bootstrap: Lent = serde_json::from_str(r#"{"kind":"bootstrap"}"#).expect("bootstrap");
        assert_eq!(bootstrap, Lent::Bootstrap {});
        assert!(serde_json::from_str::<Lent>(r#"{"kind":"bootstrap","identity":"x"}"#).is_err());
        assert!(serde_json::from_str::<Lent>(r#"{"kind":"tor"}"#).is_err());
    }

    #[test]
    fn helper_answers_map_to_record_errors() {
        assert_eq!(answer(r#"{"ok":"accepted"}"#).ok(), Some(serde_json::json!("accepted")));
        assert_eq!(answer(r#"{"err":"BadSignature"}"#).err(), Some(cdht::Error::BadSignature));
        assert_eq!(answer(r#"{"err":"other"}"#).err(), Some(cdht::Error::Unavailable));
        assert_eq!(answer("garbage").err(), Some(cdht::Error::Encoding));
        assert!(index(&[5; 32]).is_err());
        assert!(index(&[1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]).is_err());
        assert_eq!(index(&[4; 32]).ok(), Some(4));
    }
}
