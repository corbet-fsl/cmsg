//! One already-enrolled restoration on the native owner's existing LocalSet.
use super::{mesh, network};
use crate::door::{
    custody, login, ClientToken, Door, ErrorCode, Event, Output, Result, VaultComposer,
};
use ckmg::Clock;
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
        let (prepared, binding) = door.prepare_login_recovery(origin, token, now).await?;
        let (client, owner) =
            door.prepare_native_transport(origin, &prepared, binding.clone(), config.window)?;
        let (drain, startup) =
            network::Network::prepare(client, owner, config.network, config.watcher);
        // Cleanup must remain reachable even if startup is cancelled or times out.
        self.network_drain = Some(drain);
        self.network = Some(startup.await?);
        let retained = self.network.as_ref().ok_or(ErrorCode::Unavailable)?;
        let member = retained.take_member_authority()?;
        let network = retained.records()?.network();
        let checkpoint = {
            let mut record = prepared
                .tor_records(network.clone())
                .await
                .map_err(|_| ErrorCode::Unavailable)?;
            record
                .checkpoint(&prepared.locator())
                .await
                .map_err(|_| ErrorCode::Unavailable)?
        }; // Release the borrowed record before consuming PreparedOpen.
        let completed = custody::SystemClock.now().map_err(|_| ErrorCode::Clock)?;
        if completed < now {
            return Err(ErrorCode::Clock);
        }
        let candidate = door
            .current_policy(origin)?
            .with_current(completed, |current| {
                prepared.prepare_recovery(&checkpoint, current, None, binding.member(), completed)
            })
            .map_err(|_| ErrorCode::Unavailable)?
            .map_err(|_| ErrorCode::Unauthorized)?;
        // Original recovery performs forced lineage reads and fresh HTTPS checks
        // before lending Store custody. Missing records never create new state.
        let owners = member.prepare_recovery(&candidate, network.clone()).await?;
        let peers = network.clone();
        let restored = owners.open(network, config.backend).await?;
        let mut owner = door
            .bind_vault_with_board_owner(origin, restored.vault, restored.intent, restored.lifetime)
            .await?;
        // Every native device has groups: peers are verified, never claimed.
        owner.enable_verified_groups(peers, door.current_policy(origin)?)?;
        if let Some(board) = self.board.take() {
            board.bind(door, origin, owner)?;
        }
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
