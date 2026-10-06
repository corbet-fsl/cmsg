//! One already-enrolled restoration using original browser and custody owners.
use super::{
    identity::{TransportClient, TransportOwner},
    mesh, records, VaultComposer,
};
use crate::door::{
    custody, login, network_browser, ClientToken, Door, ErrorCode, Event, Output, Result,
};
use ckmg::Clock;
use cmsh::tor_discovery::TorWatcher;
use futures_util::{
    future::{LocalBoxFuture, Shared},
    FutureExt,
};

/// Trusted Rust construction only. No root, record credential, authority result
/// or recovery callback is accepted; the watcher is an actual original owner.
pub struct Configuration<W: TorWatcher> {
    pub transport: network_browser::Configuration,
    pub records: records::Configuration,
    pub scope: ctrn::Scope,
    pub window: cdht::rpc::envelope::TimeWindow,
    pub watcher: W,
    pub database: String,
}

type Network<W> = records::Network<TransportClient, W>;
type Mesh<W> = mesh::Owner<TransportClient, W>;
type Completion = Shared<LocalBoxFuture<'static, Result<()>>>;

/// Consumes at most one original pending login's recovery custody. Bound Vault
/// ownership moves to Door; transport, Records and Mesh remain retained here.
/// Completion comes only from the parent’s fresh session/Vault finalizer.
pub struct Composer<W: TorWatcher + 'static> {
    configuration: Option<Configuration<W>>,
    client: Option<TransportClient>,
    transport: Option<TransportOwner>,
    network: Option<Network<W>>,
    mesh: Option<Mesh<W>>,
    mesh_drain: Option<mesh::Drain<TransportClient, W>>,
    database: Option<cwst::browser::IndexedDb>,
    closed: bool,
    draining: Option<Completion>,
}

// A dropped restoration future must invalidate owners retained in the composer,
// even when the composer itself survives cancellation.
struct Attempt<'a, W: TorWatcher + 'static> {
    composer: &'a mut Composer<W>,
    bound: bool,
}
impl<W: TorWatcher + 'static> Drop for Attempt<'_, W> {
    fn drop(&mut self) {
        if !self.bound {
            self.composer.close();
        }
    }
}

impl<W: TorWatcher + 'static> Composer<W> {
    pub fn new(configuration: Configuration<W>) -> Self {
        Self {
            configuration: Some(configuration),
            client: None,
            transport: None,
            network: None,
            mesh: None,
            mesh_drain: None,
            database: None,
            closed: false,
            draining: None,
        }
    }

    async fn restore(
        &mut self,
        door: &mut Door,
        origin: &str,
        token: &ClientToken,
        now: u64,
    ) -> Result<()> {
        let config = self.configuration.take().ok_or(ErrorCode::Refused)?;
        let (prepared, binding) = door.prepare_login_recovery(origin, token, now).await?;
        let (client, owner) = door
            .prepare_browser_transport(
                origin,
                &prepared,
                binding.clone(),
                config.scope,
                config.transport,
                config.window,
            )
            .await?;
        // Retain before taking member authority or crossing another await.
        self.transport = Some(owner);
        self.client = Some(client.clone());
        let member = self
            .transport
            .as_mut()
            .ok_or(ErrorCode::Unavailable)?
            .take_member_authority()?;
        self.network = Some(Network::start(client, config.watcher, config.records).await?);
        let network = self
            .network
            .as_ref()
            .ok_or(ErrorCode::Unavailable)?
            .records()?
            .network();
        let checkpoint = {
            let mut record = prepared
                .tor_records(network.clone())
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
            record
                .checkpoint(&prepared.locator())
                .await
                .map_err(|_| ErrorCode::Unavailable)?
        }; // The borrowed passkey record is dropped before consuming PreparedOpen.
        let backend = cwst::browser::IndexedDb::open(&config.database)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        self.database = Some(backend.clone());
        // Use the original runtime clock after the network/database awaits.
        let completed = custody::SystemClock.now().map_err(|_| ErrorCode::Clock)?;
        if completed < now {
            return Err(ErrorCode::Clock);
        }
        let candidate = door
            .current_policy(origin)?
            .with_current(completed, |current| {
                prepared.prepare_recovery(&checkpoint, current, binding.member(), completed)
            })
            .map_err(|_| ErrorCode::Unavailable)?
            .map_err(|_| ErrorCode::Unauthorized)?;
        let owners = member.prepare_recovery(&candidate, network.clone()).await?;
        let restored = owners.open(network, backend).await?;
        door.bind_vault_with_intent(origin, restored.vault, restored.intent)
            .await?;
        let retained = self.network.take().ok_or(ErrorCode::Unavailable)?;
        let (cleanup, binding) = Mesh::prepare_bind(door, origin, retained);
        self.mesh_drain = Some(cleanup);
        self.mesh = Some(binding.await?);
        Ok(())
    }
}

impl<W: TorWatcher + 'static> VaultComposer for Composer<W> {
    fn after_dispatch<'a>(
        &'a mut self,
        door: &'a mut Door,
        origin: &'a str,
        token: &'a ClientToken,
        action: &'a str,
        output: &'a mut Output,
        now: u64,
    ) -> LocalBoxFuture<'a, Result<()>> {
        async move {
            let Output::Ok { result, events } = output else {
                self.close();
                return Ok(()); // Preserve the original refusal unchanged.
            };
            let status = if matches!(action, "login.start" | "login.poll" | "login.cancel") {
                serde_json::from_value::<login::Status>(result.clone()).ok()
            } else {
                None
            };
            if events.iter().any(|event| {
                matches!(
                    event,
                    Event::ClientRevoked | Event::VaultLocked | Event::MeshDisconnected
                )
            }) || matches!(
                status,
                Some(login::Status::Cancelled | login::Status::Expired)
            ) || (self.configuration.is_none() && matches!(status, Some(login::Status::Idle)))
            {
                self.close();
                return Ok(());
            }
            if !matches!(action, "login.start" | "login.poll")
                || status != Some(login::Status::AuthenticatedPendingCustody)
            {
                return Ok(());
            }
            if self.closed {
                return Err(ErrorCode::Unavailable);
            }
            let mut attempt = Attempt {
                composer: self,
                bound: false,
            };
            if attempt.composer.configuration.is_some() {
                attempt.composer.restore(door, origin, token, now).await?;
            }
            attempt
                .composer
                .mesh
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .records()?;
            let status = door.complete_login_recovery(origin, token, now).await?;
            attempt
                .composer
                .mesh
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .records()?;
            *result = serde_json::to_value(status).map_err(|_| ErrorCode::Unavailable)?;
            attempt.bound = true;
            Ok(())
        }
        .boxed_local()
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.configuration.take();
        let mesh_drain = self.mesh_drain.take();
        if let Some(cleanup) = &mesh_drain {
            cleanup.close();
        }
        let mesh = self.mesh.take();
        let network = self.network.take();
        let transport = self.transport.take();
        if let Some(mesh) = &mesh {
            mesh.close();
        }
        if let Some(network) = &network {
            network.close();
        }
        if let Some(transport) = &transport {
            transport.close();
        }
        self.client.take();
        self.database.take(); // The bound original Vault owns its Store connection.
        let drain = async move {
            let mesh = match mesh {
                Some(mesh) => mesh.shutdown().await,
                None => Ok(()),
            };
            let binding = match mesh_drain {
                Some(cleanup) => cleanup.drain().await,
                None => Ok(()),
            };
            let network = match network {
                Some(network) => network.shutdown().await,
                None => Ok(()),
            };
            let transport = match transport {
                Some(transport) => transport.shutdown().await,
                None => Ok(()),
            };
            mesh.and(binding).and(network).and(transport)
        }
        .boxed_local()
        .shared();
        self.draining = Some(drain.clone());
        // Drop/cancellation cannot leave shutdown dependent on another actor turn.
        wasm_bindgen_futures::spawn_local(async move {
            let _ = drain.await;
        });
    }

    fn drain(&mut self) -> LocalBoxFuture<'_, Result<()>> {
        self.close();
        let drain = self.draining.clone();
        async move {
            match drain {
                Some(drain) => drain.await,
                None => Ok(()),
            }
        }
        .boxed_local()
    }
}
impl<W: TorWatcher + 'static> Drop for Composer<W> {
    fn drop(&mut self) {
        self.close();
    }
}
