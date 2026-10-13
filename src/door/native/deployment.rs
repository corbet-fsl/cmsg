//! Public native deployment data; actual custody begins only after login.
use super::{Clock, DeviceConfiguration, Embedded, Pairing};
use crate::door::{
    browser::deployment as budgets, catalog, scenario, ErrorCode, Result, Role, VaultComposer,
};
use cmsh::tor_discovery::TorWatcher;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

/// Public service configuration plus optional already-enrolled restoration.
/// Absence of Tor selects the existing partial device host explicitly.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeDeployment {
    pub runtime: DeviceConfiguration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_tor: Option<TorDeployment>,
}

/// Original public Tor network with explicit resource budgets and local paths.
/// Private network overrides belong to trusted fixture construction, not JSON.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TorDeployment {
    pub state_directory: PathBuf,
    pub cache_directory: PathBuf,
    /// Existing private directory for CWST's encrypted checkpoint and lock file.
    pub store_directory: PathBuf,
    pub transport: budgets::Transport,
    pub messages: budgets::Messages,
    pub discovery: budgets::Discovery,
    pub records: budgets::Records,
    pub storage: Option<budgets::Storage>,
    /// Original signed PeerInfo wire bytes, not an unsigned roster.
    pub bootstrap: Vec<Vec<u8>>,
    pub maximum_bootstrap_bytes: NonZeroUsize,
    pub driver_tasks: NonZeroUsize,
    pub record_concurrency: NonZeroUsize,
    pub application_queue: NonZeroUsize,
    pub application_payload: NonZeroUsize,
    pub startup_millis: NonZeroU32,
    pub window: budgets::EnvelopeWindow,
    /// Trusted fixture construction only: a private Tor network (authorities, fallback
    /// caches) for loopback end-to-end runs. Never read from JSON, never serialized.
    #[serde(skip)]
    #[schemars(skip)]
    private_network: Option<arti_client::config::TorClientConfigBuilder>,
}

impl TorDeployment {
    /// Replace the public Tor network with a private one. Only embedding code can call this;
    /// a deployment file cannot carry network overrides.
    pub fn with_private_network(
        mut self,
        network: arti_client::config::TorClientConfigBuilder,
    ) -> Self {
        self.private_network = Some(network);
        self
    }
}

impl NativeDeployment {
    /// See [`TorDeployment::with_private_network`]; refused when no native Tor is configured.
    pub fn with_private_network(
        mut self,
        network: arti_client::config::TorClientConfigBuilder,
    ) -> Result<Self> {
        let tor = self.native_tor.take().ok_or(ErrorCode::InvalidRequest)?;
        self.native_tor = Some(tor.with_private_network(network));
        Ok(self)
    }

    /// The same from the private-network fixture document (`TOR_FIXTURE_JSON` of the
    /// ctrn driver), which is a serialized Arti client configuration.
    pub fn with_private_network_json(self, fixture: &[u8]) -> Result<Self> {
        let network = serde_json::from_slice(fixture).map_err(|_| ErrorCode::InvalidRequest)?;
        self.with_private_network(network)
    }
}

/// No client watch signer is available. Forced recovery reads use polling;
/// the transport node's signer must never substitute for record authority.
struct RefuseWatches;
impl TorWatcher for RefuseWatches {
    fn public_key(&self, _key: &cdht::RecordKey) -> std::result::Result<cdht::NodeId, cdht::Error> {
        Err(cdht::Error::WatchRefused)
    }

    fn question<'a>(
        &'a self,
        _key: &'a cdht::RecordKey,
        _question: &'a cdht::rpc::Question,
        _destination: &'a cdht::NodeId,
    ) -> cmsh::BoxFuture<'a, std::result::Result<cdht::rpc::SignedOperation, cdht::Error>> {
        Box::pin(async { Err(cdht::Error::WatchRefused) })
    }
}

impl NativeDeployment {
    pub(super) async fn start(
        self,
        lifetime_seconds: u64,
        clock: Arc<dyn Clock>,
    ) -> Result<Embedded> {
        let Some(tor) = self.native_tor else {
            return Embedded::configured(self.runtime, lifetime_seconds, clock).await;
        };
        if self.runtime.role != Role::Member {
            return Err(ErrorCode::Unauthorized);
        }
        let pairing = Pairing {
            origin: self.runtime.origin.clone(),
            role: self.runtime.role,
            actions: catalog().into_iter().map(|action| action.action).collect(),
            lifetime_seconds,
        };
        Embedded::start_composed(
            move || async move {
                let community = self.runtime.community.clone();
                let (door, board) = self.runtime.construct_restoring()?;
                let composer = tor.composer(&community, board)?;
                Ok((door, composer))
            },
            pairing,
            clock,
        )
        .await
    }
}

impl TorDeployment {
    fn composer(
        mut self,
        community: &str,
        board: Option<crate::door::board::PendingBoard>,
    ) -> Result<Box<dyn VaultComposer>> {
        // Check public shape early; original Node, Arti, discovery and Records
        // validators still run when the original login starts actual custody.
        if !(1..=1024).contains(&self.transport.streams)
            || !(1..=600_000).contains(&self.transport.bootstrap_ms)
            || !(1..=60_000).contains(&self.transport.operation_ms)
            || self.discovery.timeout_ms == 0
            || self.discovery.lanes > self.discovery.peers
            || self.bootstrap.len() > self.discovery.peers.get()
            || self.records.consensus_width.get() > 20
            || self.driver_tasks.get() > self.transport.streams
            || self.record_concurrency > self.driver_tasks
            || self.application_queue.get() > 1024
            || self.application_payload.get() > 32 * 1024
            || !self.state_directory.is_absolute()
            || !self.cache_directory.is_absolute()
            || self.state_directory == self.cache_directory
            || !self.store_directory.is_absolute()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let directory =
            std::fs::symlink_metadata(&self.store_directory).map_err(|_| ErrorCode::Unavailable)?;
        if !directory.is_dir() {
            return Err(ErrorCode::InvalidRequest);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if directory.permissions().mode() & 0o077 != 0 {
                return Err(ErrorCode::Unauthorized);
            }
        }
        let private = self.private_network.take();
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
            peer.verify_extension(&scenario::Verifier)
                .map_err(|_| ErrorCode::InvalidRequest)?;
            bootstrap.push(peer);
        }
        // Same public namespace as browser deployment; never caller-selected.
        let mut scope = Sha256::new();
        scope.update(b"cmsg.tor.scope.v1\0");
        scope.update(community.as_bytes());
        Ok(Box::new(
            scenario::restore::Composer::new(scenario::restore::Configuration {
                network: scenario::network::Configuration {
                    tor: private.unwrap_or_default(),
                    directories: ctrn::arti::Directories {
                        state: self.state_directory,
                        cache: self.cache_directory,
                    },
                    scope: ctrn::Scope(scope.finalize().into()),
                    transport: ctrn::Limits {
                        streams: self.transport.streams,
                        bootstrap_ms: self.transport.bootstrap_ms,
                        operation_ms: self.transport.operation_ms,
                    },
                    messages,
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
                    driver_tasks: self.driver_tasks,
                    record_concurrency: self.record_concurrency,
                    application_queue: self.application_queue,
                    application_payload: self.application_payload,
                    startup_timeout: Duration::from_millis(self.startup_millis.get().into()),
                },
                window: cdht::rpc::envelope::TimeWindow {
                    behind_us: self.window.behind_us,
                    ahead_us: self.window.ahead_us,
                },
                watcher: RefuseWatches,
                backend: cwst::native::FileBackend::new(self.store_directory),
            })
            .with_board(board),
        ))
    }
}
