//! Trusted browser ownership of original Mesh over the retained Tor application port.
use super::records::{Identity, Network, Records};
use crate::door::{facades::MeshLifetime, Door, ErrorCode, Result};
use cmsh::tor_discovery::TorWatcher;
use futures_channel::oneshot;
use futures_util::{
    future::{AbortHandle, Abortable, LocalBoxFuture, Shared},
    FutureExt,
};
use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    sync::Arc,
};

type Completion = Shared<LocalBoxFuture<'static, Result<()>>>;

struct Control<I: Identity, W: TorWatcher + 'static> {
    network: RefCell<Option<Network<I, W>>>,
    closed: Cell<bool>,
    spawned: Cell<bool>,
    pump: RefCell<Option<AbortHandle>>,
    pump_done: RefCell<Option<oneshot::Receiver<()>>>,
    finished: RefCell<Option<oneshot::Sender<Result<()>>>>,
    done: Completion,
}
impl<I: Identity, W: TorWatcher + 'static> Control<I, W> {
    fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        let network = self.network.borrow_mut().take();
        if let Some(network) = &network {
            // Invalidate application replies and custody synchronously, before
            // polling any drain future or waiting for a receive pump to finish.
            network.close();
        }
        if let Some(pump) = self.pump.borrow_mut().take() {
            pump.abort();
        }
        let pump_done = self.pump_done.borrow_mut().take();
        let finished = self.finished.borrow_mut().take();
        wasm_bindgen_futures::spawn_local(async move {
            let network_result = match network {
                Some(network) => network.shutdown().await,
                None => Ok(()),
            };
            let pump_result = match pump_done {
                Some(done) => done.await.map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Reconcile",
                        ErrorCode::Reconcile,
                        &__cause,
                    )
                }),
                None => Ok(()),
            };
            if let Some(finished) = finished {
                let _ = finished.send(network_result.and(pump_result));
            }
        });
    }

    fn records(&self) -> Result<Arc<Records<I, W>>> {
        let result = {
            let network = self.network.borrow();
            network
                .as_ref()
                .ok_or(ErrorCode::Unavailable)
                .and_then(|network| network.records().cloned())
        };
        if result.is_err() {
            self.close();
        }
        result
    }
}

struct PumpExit<I: Identity, W: TorWatcher + 'static>(Weak<Control<I, W>>);
impl<I: Identity, W: TorWatcher + 'static> Drop for PumpExit<I, W> {
    fn drop(&mut self) {
        if let Some(control) = self.0.upgrade() {
            control.close();
        }
    }
}

// One original backend, one bound listener, therefore exactly one receive pump.
// Mesh owns its queue and forwarding algorithm; this only retains task completion.
struct Spawner<I: Identity, W: TorWatcher + 'static>(Weak<Control<I, W>>);
impl<I: Identity, W: TorWatcher + 'static> cmsh::Spawn for Spawner<I, W> {
    fn spawn(&self, future: cmsh::BoxFuture<'static, ()>) {
        let Some(control) = self.0.upgrade() else {
            return;
        };
        if control.closed.get() || control.spawned.replace(true) {
            control.close();
            return;
        }
        let (abort, registration) = AbortHandle::new_pair();
        let (finished, completion) = oneshot::channel();
        *control.pump.borrow_mut() = Some(abort);
        *control.pump_done.borrow_mut() = Some(completion);
        let exit = PumpExit(Rc::downgrade(&control));
        wasm_bindgen_futures::spawn_local(async move {
            let _exit = exit;
            let _ = Abortable::new(future, registration).await;
            let _ = finished.send(());
        });
    }
}

/// Closure and task completion for the exact bound Mesh/network lifetime.
pub struct Drain<I: Identity, W: TorWatcher + 'static>(Rc<Control<I, W>>);
impl<I: Identity, W: TorWatcher + 'static> Drain<I, W> {
    pub fn close(&self) {
        self.0.close();
    }
    pub async fn drain(&self) -> Result<()> {
        self.0.done.clone().await
    }
}

/// Retain with the Vault composer; Door's bound Mesh independently retains the
/// same shutdown capability. Neither owner can keep a failed network alive.
/// This is Rust-only construction, not member admission or runtime readiness.
#[must_use = "retain with the composer; drop closes and drains the bound network"]
pub struct Owner<I: Identity, W: TorWatcher + 'static> {
    control: Rc<Control<I, W>>,
}
impl<I: Identity, W: TorWatcher + 'static> Owner<I, W> {
    /// Consume the actual, already scoped Records network. The parent supplies
    /// the matching member origin; the existing Door binding validates it.
    /// BoundMesh opens and retains the original application listener exactly once.
    /// Failure or cancellation closes the network and schedules its owned drain.
    pub fn bind<'a>(
        door: &'a mut Door,
        origin: &'a str,
        network: Network<I, W>,
    ) -> LocalBoxFuture<'a, Result<Self>> {
        Self::prepare_bind(door, origin, network).1
    }

    /// Expose only close/completion before awaiting the actual bind. A cancelled
    /// bind cannot hide its network/pump drain from the parent Store barrier.
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn prepare_bind<'a>(
        door: &'a mut Door,
        origin: &'a str,
        network: Network<I, W>,
    ) -> (Drain<I, W>, LocalBoxFuture<'a, Result<Self>>) {
        let (finished, completion) = oneshot::channel();
        let owner = Self {
            control: Rc::new(Control {
                network: RefCell::new(Some(network)),
                closed: Cell::new(false),
                spawned: Cell::new(false),
                pump: RefCell::new(None),
                pump_done: RefCell::new(None),
                finished: RefCell::new(Some(finished)),
                done: async move {
                    completion.await.map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Reconcile",
                            ErrorCode::Reconcile,
                            &__cause,
                        )
                    })?
                }
                .boxed_local()
                .shared(),
            }),
        };
        // Install ownership before returning the future: even an unpolled bind
        // must close and drain the supplied running network when dropped.
        let cleanup = Drain(owner.control.clone());
        let binding = async move {
            let applications = owner
                .control
                .network
                .borrow()
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .applications()?
                .clone();
            let mesh = cmsh::Mesh::builder(Arc::new(Spawner(Rc::downgrade(&owner.control))))
                .backend(applications)
                .build()
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::InvalidRequest",
                        ErrorCode::InvalidRequest,
                        &__cause,
                    )
                })?;
            let control = owner.control.clone();
            // Facade destruction revokes the same network retained by the composer.
            let lifetime = MeshLifetime::new(move || control.close());
            door.bind_mesh_owned(origin, mesh, Some(lifetime)).await?;
            if let Err(error) = owner.control.records() {
                door.meshes.remove(origin);
                return Err(error);
            }
            Ok(owner)
        }
        .boxed_local();
        (cleanup, binding)
    }

    /// Original Records owner for the parent composer, while the network is live.
    pub fn records(&self) -> Result<Arc<Records<I, W>>> {
        self.control.records()
    }

    /// Revoke delivery, outstanding replies and transport custody immediately.
    /// Drain runs independently so actor/composer failure cannot abandon cleanup.
    pub fn close(&self) {
        self.control.close();
    }

    /// Wait for the original Records/Ferry shutdown and the single Mesh pump.
    /// Call before Vault/Store shutdown when the actor can still await cleanup.
    pub async fn shutdown(self) -> Result<()> {
        self.close();
        self.control.done.clone().await
    }
}
impl<I: Identity, W: TorWatcher + 'static> Drop for Owner<I, W> {
    fn drop(&mut self) {
        self.control.close();
    }
}
