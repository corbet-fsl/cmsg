//! Public deployment budgets; custody and readiness remain with original owners.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroUsize};

/// Pinned isolated-page inputs. All limits are explicit; no identity, credential,
/// transport factory, gateway or authority result can be supplied here.
/// These data types also support native schema generation without Wasm types.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub transport: Transport,
    pub messages: Messages,
    pub discovery: Discovery,
    pub records: Records,
    pub storage: Option<Storage>,
    /// Original signed PeerInfo wire bytes, never an unsigned peer roster.
    pub bootstrap: Vec<Vec<u8>>,
    pub maximum_bootstrap_bytes: NonZeroUsize,
    pub record_concurrency: NonZeroUsize,
    pub application_queue: NonZeroUsize,
    pub application_payload: NonZeroUsize,
    pub startup_millis: NonZeroU32,
    pub window: EnvelopeWindow,
    /// Local CWST IndexedDB name, not a URL or exported Store.
    pub database: String,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub streams: usize,
    pub bootstrap_ms: u64,
    pub operation_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Messages {
    pub max_payload: usize,
    pub timeout_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub peers: NonZeroUsize,
    pub lanes: NonZeroUsize,
    pub timeout_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Records {
    pub consensus_width: NonZeroUsize,
    pub watches: NonZeroUsize,
}

/// Optional original local record storage, including inbound watch budgets.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub records: usize,
    pub bytes: usize,
    pub watches: Watches,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Watches {
    pub min_duration_us: u64,
    pub max_duration_us: u64,
    pub member_per_record: NonZeroUsize,
    pub public_per_record: NonZeroUsize,
    pub capacity: NonZeroUsize,
}

/// Original ENV0 freshness bounds; the runtime supplies actual wall time.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeWindow {
    pub behind_us: u64,
    pub ahead_us: u64,
}

#[cfg(all(target_arch = "wasm32", feature = "browser-tor"))]
mod runtime {
    use super::*;
    use crate::door::{browser, network_browser, ErrorCode, Result};
    use cmsh::tor_discovery::TorWatcher;
    use sha2::{Digest, Sha256};

    /// No member watch signer is available to this deployment. Forced restore
    /// reads do not require watches; never substitute node signing for one.
    pub struct RefuseWatches;

    impl TorWatcher for RefuseWatches {
        fn public_key(
            &self,
            _key: &cdht::RecordKey,
        ) -> std::result::Result<cdht::NodeId, cdht::Error> {
            Err(cdht::Error::WatchRefused)
        }

        fn question<'a>(
            &'a self,
            _key: &'a cdht::RecordKey,
            _question: &'a cdht::rpc::Question,
            _destination: &'a cdht::NodeId,
        ) -> cmsh::BoxFuture<'a, std::result::Result<cdht::rpc::SignedOperation, cdht::Error>>
        {
            Box::pin(async { Err(cdht::Error::WatchRefused) })
        }
    }

    impl Configuration {
        /// Validate deployment shape before attaching; original constructors
        /// still validate again when real custody starts Tor and Records.
        pub(crate) fn composer(
            self,
            community: &str,
        ) -> Result<Box<dyn crate::door::VaultComposer>> {
            if !(1..=64).contains(&self.transport.streams)
                || !(1..=600_000).contains(&self.transport.bootstrap_ms)
                || !(1..=60_000).contains(&self.transport.operation_ms)
                || self.discovery.timeout_ms == 0
                || self.discovery.lanes > self.discovery.peers
                || self.bootstrap.len() > self.discovery.peers.get()
                || self.records.consensus_width.get() > 20
                || self.record_concurrency.get() > self.transport.streams
                || self.application_queue.get() > 1024
                || self.application_payload.get() > 32 * 1024
                || self.database.is_empty()
            {
                return Err(ErrorCode::InvalidRequest);
            }
            let messages = ctrn::MessageLimits {
                max_payload: self.messages.max_payload,
                timeout_ms: self.messages.timeout_ms,
            };
            messages.validate().map_err(|_| ErrorCode::InvalidRequest)?;
            let storage = self
                .storage
                .map(|storage| -> Result<_> {
                    let watches = cdht::watches::WatchLimits {
                        min_duration_us: storage.watches.min_duration_us,
                        max_duration_us: storage.watches.max_duration_us,
                        member_per_record: storage.watches.member_per_record,
                        public_per_record: storage.watches.public_per_record,
                        capacity: storage.watches.capacity,
                    };
                    // Reuse the original inbound policy validation. Refusing
                    // client watches does not disable serving others' watches.
                    cdht::watches::InboundWatches::new(watches)
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    Ok((
                        cdht::Capacity {
                            records: storage.records,
                            bytes: storage.bytes,
                        },
                        watches,
                    ))
                })
                .transpose()?;
            let mut remaining = self.maximum_bootstrap_bytes.get();
            let mut bootstrap = Vec::with_capacity(self.bootstrap.len());
            for bytes in self.bootstrap {
                remaining = remaining
                    .checked_sub(bytes.len())
                    .ok_or(ErrorCode::Capacity)?;
                let peer = cdht::rpc::UnverifiedPeerInfoBytes::from_bytes(bytes)
                    .map_err(|_| ErrorCode::InvalidRequest)?;
                peer.verify_extension(&browser::records::Verifier)
                    .map_err(|_| ErrorCode::InvalidRequest)?;
                bootstrap.push(peer);
            }
            // Fixed domain plus the immutable Door community, never a second
            // caller-selected scope. This namespace is public, not key material.
            let mut scope = Sha256::new();
            scope.update(b"cmsg.tor.scope.v1\0");
            scope.update(community.as_bytes());
            Ok(Box::new(browser::restore::Composer::new(
                browser::restore::Configuration {
                    transport: network_browser::Configuration {
                        limits: ctrn::Limits {
                            streams: self.transport.streams,
                            bootstrap_ms: self.transport.bootstrap_ms,
                            operation_ms: self.transport.operation_ms,
                        },
                        messages,
                    },
                    records: browser::records::Configuration {
                        discovery: cmsh::tor_discovery::TorDiscoveryLimits {
                            peers: self.discovery.peers,
                            lanes: self.discovery.lanes,
                            timeout_ms: self.discovery.timeout_ms,
                        },
                        records: cmsh::tor_records::TorRecordLimits {
                            consensus_width: self.records.consensus_width,
                            watches: self.records.watches,
                        },
                        storage,
                        bootstrap,
                        maximum_bootstrap_bytes: self.maximum_bootstrap_bytes,
                        record_concurrency: self.record_concurrency,
                        application_queue: self.application_queue,
                        application_payload: self.application_payload,
                        startup_millis: self.startup_millis,
                    },
                    scope: ctrn::Scope(scope.finalize().into()),
                    window: cdht::rpc::envelope::TimeWindow {
                        behind_us: self.window.behind_us,
                        ahead_us: self.window.ahead_us,
                    },
                    watcher: RefuseWatches,
                    database: self.database,
                },
            )))
        }
    }
}
