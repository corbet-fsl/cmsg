//! One already-enrolled restoration on the native owner's existing LocalSet.
use super::{mesh, network};
use crate::door::{login, ClientToken, Door, ErrorCode, Event, Output, Result, VaultComposer};
use cmsh::tor_discovery::TorWatcher;
use cwst::backend::Backend;
use futures_util::{future::LocalBoxFuture, FutureExt};

/// Trusted construction with original network settings, record watcher and
/// durable Store backend. No credentials, authority verdict or callback inputs.
pub struct Configuration<W: TorWatcher, B: Backend> {
    pub network: network::Configuration,
    pub window: cdht::rpc::envelope::TimeWindow,
    pub watcher: W,
    pub backend: B,
}

/// Consumes one login's original recovery custody. Door owns the bound Vault;
/// this owner retains its network, Mesh and independently awaitable cleanup.
/// Use through Embedded::start_composed on its existing active LocalSet.
pub struct Composer<W: TorWatcher + 'static, B: Backend + 'static> {
    configuration: Option<Configuration<W, B>>,
    board: Option<crate::door::board::PendingBoard>,
    network: Option<network::Network<W>>,
    network_drain: Option<network::Drain>,
    mesh: Option<mesh::Owner<W>>,
    mesh_drain: Option<mesh::Drain<W>>,
    closed: bool,
}

// Covers both restoration and every fresh completion check, including when the
// caller drops only the dispatch future and retains the composer itself.
struct Attempt<'a, W: TorWatcher + 'static, B: Backend + 'static> {
    composer: &'a mut Composer<W, B>,
    completed: bool,
}
impl<W: TorWatcher + 'static, B: Backend + 'static> Drop for Attempt<'_, W, B> {
    fn drop(&mut self) {
        if !self.completed {
            self.composer.close();
        }
    }
}

impl<W: TorWatcher + 'static, B: Backend + 'static> Composer<W, B> {
    pub fn new(configuration: Configuration<W, B>) -> Self {
        Self {
            configuration: Some(configuration),
            board: None,
            network: None,
            network_drain: None,
            mesh: None,
            mesh_drain: None,
            closed: false,
        }
    }

    pub(crate) fn with_board(mut self, board: Option<crate::door::board::PendingBoard>) -> Self {
        self.board = board;
        self
    }

    async fn restore(
        &mut self,
        door: &mut Door,
        origin: &str,
        token: &ClientToken,
        now: u64,
    ) -> Result<()> {
        let config = self.configuration.take().ok_or(ErrorCode::Refused)?;
        let (prepared, binding, stamps) = door.prepare_login_recovery(origin, token, now).await?;
        let (client, owner) =
            door.prepare_native_transport(origin, &prepared, binding.clone(), config.window)?;
        let (drain, startup) =
            network::Network::prepare(client, owner, config.network, config.watcher);
        // Cleanup must remain reachable even if startup is cancelled or times out.
        self.network_drain = Some(drain);
        self.network = Some(startup.await?);
        let retained = self.network.as_ref().ok_or(ErrorCode::Unavailable)?;
        // C8 A: a registered device-key member's custody was bound when the app started
        // (`composer::restore_device_login`); its Vault is not recovered a second time.
        if let Some(eager) = door.take_eager_binding(origin) {
            let peers = retained.records()?.network();
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            let waves = peers.clone();
            let mut owner = eager.owner;
            owner.enable_groups(Some(crate::door::facades::verified_peers(
                peers,
                door.current_policy(origin)?,
            )))?;
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            bind_waves(door, origin, waves)?;
            if let Some(board) = self.board.take() {
                owner.bind_board(door, origin, board)?;
            }
            return self.bind_mesh(door, origin).await;
        }
        let member = retained.take_member_authority()?;
        let network = retained.records()?.network();
        let peers = network.clone();
        #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
        let waves = network.clone();
        // A device-key login's stamp trust verifies its stamp checkpoint and lineage.
        let restored = door
            .recover_login_vault(
                origin,
                prepared,
                &binding,
                stamps,
                member,
                network,
                config.backend,
                now,
            )
            .await?;
        let mut owner = door
            .bind_vault_with_board_owner(origin, restored.vault, restored.intent, restored.lifetime)
            .await?;
        // Every native device has groups: peers are verified, never claimed.
        owner.enable_verified_groups(peers, door.current_policy(origin)?)?;
        #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
        bind_waves(door, origin, waves)?;
        if let Some(board) = self.board.take() {
            board.bind(door, origin, owner)?;
        }
        self.bind_mesh(door, origin).await
    }

    async fn bind_mesh(&mut self, door: &mut Door, origin: &str) -> Result<()> {
        let retained = self.network.take().ok_or(ErrorCode::Unavailable)?;
        let (drain, binding) = mesh::Owner::prepare_bind(door, origin, retained);
        self.mesh_drain = Some(drain);
        self.mesh = Some(binding.await?);
        Ok(())
    }
}

impl<W: TorWatcher + 'static, B: Backend + 'static> VaultComposer for Composer<W, B> {
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
                return Ok(()); // Preserve the original refusal.
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
            ) || (self.configuration.is_none() && status == Some(login::Status::Idle))
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
                completed: false,
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
            // Never cache completion: even a later poll checks the exact session,
            // bound Vault, forced lineage and fresh live device membership again.
            let status = door.complete_login_recovery(origin, token, now).await?;
            attempt
                .composer
                .mesh
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .records()?;
            *result = serde_json::to_value(status).map_err(|_| ErrorCode::Unavailable)?;
            attempt.completed = true;
            Ok(())
        }
        .boxed_local()
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(drain) = &self.mesh_drain {
            drain.close();
        }
        if let Some(drain) = &self.network_drain {
            drain.close();
        }
        self.mesh.take();
        self.network.take();
        self.configuration.take();
        self.board.take();
        // Original independent cleanup already runs on this same LocalSet.
        // Keep both completion handles for the parent's pre-Store drain barrier.
    }

    fn drain(&mut self) -> LocalBoxFuture<'_, Result<()>> {
        self.close();
        async move {
            let mesh = match &self.mesh_drain {
                Some(drain) => drain.drain().await,
                None => Ok(()),
            };
            let network = match &self.network_drain {
                Some(drain) => drain.drain().await,
                None => Ok(()),
            };
            mesh.and(network)
        }
        .boxed_local()
    }
}

impl<W: TorWatcher + 'static, B: Backend + 'static> Drop for Composer<W, B> {
    fn drop(&mut self) {
        self.close();
    }
}

/// A device the platform equipped with the wave and outcome circuits also runs waves: the
/// ports and the proof worker read the same verified community trust. Both restore paths
/// (the eager C8 A binding and the device-login recovery) bind them the same way.
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
fn bind_waves<N: cdht::Network + Clone + 'static>(
    door: &mut Door,
    origin: &str,
    network: N,
) -> Result<()> {
    if let Some(device) = door.wave_device(origin) {
        let charter = door.current_policy(origin)?;
        crate::door::inbox_waves::native::bind_device(
            door,
            origin,
            &device,
            crate::door::inbox_lineage::TorHandleOpener::new(network),
            charter,
        )?;
    }
    Ok(())
}
