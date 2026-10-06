//! Native lifetime composition of the original Mesh and shared Tor application port.
use super::network::{Applications, Network, Records};
use crate::door::{facades::MeshLifetime, Door, ErrorCode, Result};
use cmsh::tor_discovery::TorWatcher;
use futures_util::{
    future::{LocalBoxFuture, Shared},
    FutureExt,
};
use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    runtime::Handle,
    sync::{oneshot, Notify},
    task::JoinHandle,
};

type Completion = Shared<LocalBoxFuture<'static, Result<()>>>;

struct TaskState {
    closed: bool,
    spawned: bool,
    pump: Option<JoinHandle<()>>,
    failure: Option<ErrorCode>,
}

// The Send side contains original public transport handles and task tracking
// only. The non-Send Network/TransportOwner never crosses this boundary.
struct Tasks {
    applications: Option<Arc<Applications>>,
    state: Mutex<TaskState>,
    stop: Notify,
}
impl Tasks {
    fn close(&self) {
        if let Some(applications) = &self.applications {
            applications.close();
        }
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        if let Some(pump) = &state.pump {
            pump.abort();
        }
        drop(state);
        self.stop.notify_one();
    }

    fn exited(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // BoundMesh may already have closed its listener before dropping its
        // lifetime guard. Either exit stops the graph; a successful join alone
        // says nothing about reachability or why the original listener ended.
        state.closed = true;
        drop(state);
        if let Some(applications) = &self.applications {
            applications.close();
        }
        // Do not abort this task from its own destructor: retain its actual
        // completion/panic for the independent local drain to join.
        self.stop.notify_one();
    }

    fn live(&self) -> Result<()> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed || !state.spawned || state.pump.as_ref().is_none_or(JoinHandle::is_finished)
        {
            return Err(state.failure.unwrap_or(ErrorCode::Unavailable));
        }
        Ok(())
    }

    async fn drain(&self) -> Result<()> {
        let task = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pump
            .take();
        if let Some(task) = task {
            match task.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {}
                Err(_) => return Err(ErrorCode::Reconcile),
            }
        }
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        match state.failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.close();
    }
}

struct PumpExit(std::sync::Weak<Tasks>);
impl Drop for PumpExit {
    fn drop(&mut self) {
        if let Some(tasks) = self.0.upgrade() {
            tasks.exited();
        }
    }
}

struct Spawner {
    runtime: Handle,
    tasks: Arc<Tasks>,
}
impl cmsh::Spawn for Spawner {
    fn spawn(&self, future: cmsh::BoxFuture<'static, ()>) {
        let mut state = self
            .tasks
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // One original backend/listener means exactly one original receive
        // pump, including completed tasks. No replacement listener is opened.
        if state.closed || state.spawned {
            state.failure.get_or_insert(ErrorCode::Reconcile);
            drop(state);
            self.tasks.close();
            drop(future);
            return;
        }
        state.spawned = true;
        let exit = PumpExit(Arc::downgrade(&self.tasks));
        state.pump = Some(self.runtime.spawn(async move {
            let _exit = exit;
            future.await;
        }));
    }
}

struct Control<W: TorWatcher + 'static> {
    network: RefCell<Option<Network<W>>>,
    closed: Cell<bool>,
    tasks: Arc<Tasks>,
    done: Completion,
}
impl<W: TorWatcher + 'static> Control<W> {
    fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        if let Some(network) = self.network.borrow().as_ref() {
            network.close();
        }
        self.tasks.close();
    }

    fn records(&self) -> Result<Arc<Records<W>>> {
        let result = self.tasks.live().and_then(|()| {
            self.network
                .borrow()
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .records()
                .cloned()
        });
        if result.is_err() {
            self.close();
        }
        result
    }
}

struct DrainExit<W: TorWatcher + 'static>(Weak<Control<W>>);
impl<W: TorWatcher + 'static> Drop for DrainExit<W> {
    fn drop(&mut self) {
        if let Some(control) = self.0.upgrade() {
            control.close();
        }
    }
}

async fn drain<W: TorWatcher + 'static>(
    control: Rc<Control<W>>,
    finished: oneshot::Sender<Result<()>>,
    _exit: DrainExit<W>,
) {
    loop {
        tokio::select! {
            biased;
            _ = control.tasks.stop.notified() => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                // Original service loss can close the application queue while
                // Mesh is backpressured on its bounded consumer queue. Observe
                // only the original network lifetime, never infer readiness.
                let lost = control.network.borrow().as_ref()
                    .is_none_or(|network| network.records().is_err());
                if lost { break; }
            }
        }
    }
    control.close();
    let network = control.network.borrow_mut().take();
    let network_done = async {
        match network {
            Some(network) => network.shutdown().await,
            None => Ok(()),
        }
    };
    let (network_result, pump_result) = tokio::join!(network_done, control.tasks.drain());
    let _ = finished.send(network_result.and(pump_result));
}

/// Only closure and completion of this Mesh/network lifetime, never authority.
pub struct Drain<W: TorWatcher + 'static>(Rc<Control<W>>);
impl<W: TorWatcher + 'static> Drain<W> {
    pub fn close(&self) {
        self.0.close();
    }
    pub async fn drain(&self) -> Result<()> {
        self.0.done.clone().await
    }
}

/// Retain with native Vault composition on the Network's existing Tokio
/// LocalSet. Facade teardown owns the same close capability independently.
/// Before destroying that LocalSet, await shutdown; no new runtime is created.
#[must_use = "retain with native composition; drop closes and schedules network drain"]
pub struct Owner<W: TorWatcher + 'static> {
    control: Rc<Control<W>>,
}
impl<W: TorWatcher + 'static> Owner<W> {
    /// Consume the already scoped network. Its original application queue is
    /// the sole Mesh backend; BoundMesh retains the actual original listener.
    /// Call on the same active LocalSet as Network, even to construct this future.
    /// Parent may take Network::take_member_authority before this move if needed.
    pub fn bind<'a>(
        door: &'a mut Door,
        origin: &'a str,
        network: Network<W>,
    ) -> LocalBoxFuture<'a, Result<Self>> {
        Self::prepare_bind(door, origin, network).1
    }

    /// Retain the cleanup handle before awaiting the binding. Cancellation may
    /// discard this future but cannot hide its actual task-completion barrier.
    pub fn prepare_bind<'a>(
        door: &'a mut Door,
        origin: &'a str,
        network: Network<W>,
    ) -> (Drain<W>, LocalBoxFuture<'a, Result<Self>>) {
        let runtime = Handle::current();
        let applications = network.applications().cloned();
        let (finished, completion) = oneshot::channel();
        let owner = Self {
            control: Rc::new(Control {
                network: RefCell::new(Some(network)),
                closed: Cell::new(false),
                tasks: Arc::new(Tasks {
                    applications: applications.as_ref().ok().cloned(),
                    state: Mutex::new(TaskState {
                        closed: false,
                        spawned: false,
                        pump: None,
                        failure: None,
                    }),
                    stop: Notify::new(),
                }),
                done: async move { completion.await.map_err(|_| ErrorCode::Reconcile)? }
                    .boxed_local()
                    .shared(),
            }),
        };
        // Installed before the returned future is polled: dropping an unpolled
        // or cancelled bind still closes and independently drains this network.
        let exit = DrainExit(Rc::downgrade(&owner.control));
        tokio::task::spawn_local(drain(owner.control.clone(), finished, exit));
        let cleanup = Drain(owner.control.clone());
        let binding = async move {
            let bound = async {
                if owner.control.closed.get() {
                    return Err(ErrorCode::Unavailable);
                }
                let mesh = cmsh::Mesh::builder(Arc::new(Spawner {
                    runtime,
                    tasks: owner.control.tasks.clone(),
                }))
                .backend(applications?)
                .build()
                .map_err(|_| ErrorCode::InvalidRequest)?;
                let control = owner.control.clone();
                let lifetime = MeshLifetime::new(move || control.close());
                door.bind_mesh_owned(origin, mesh, Some(lifetime)).await?;
                if let Err(error) = owner.control.records() {
                    // Only this bind could have installed this facade while Door
                    // was exclusively borrowed. Drop that failed original listener.
                    door.meshes.remove(origin);
                    return Err(error);
                }
                Ok(())
            }
            .await;
            if let Err(error) = bound {
                owner.close();
                // Keep the original bind refusal, but join actual cleanup before
                // returning it. Cancellation still leaves the independent drain.
                let _ = owner.control.done.clone().await;
                return Err(error);
            }
            Ok(owner)
        }
        .boxed_local();
        (cleanup, binding)
    }

    /// Original authenticated Records for parent composition; no Backend adapter.
    pub fn records(&self) -> Result<Arc<Records<W>>> {
        self.control.records()
    }

    /// Forward only the original verified observation to retained transport custody.
    pub fn observe_lineage(
        &self,
        observed: &cvlt::VerifiedLineageObservation<'_>,
        now: u64,
    ) -> Result<()> {
        let result = self.control.tasks.live().and_then(|()| {
            self.control
                .network
                .borrow()
                .as_ref()
                .ok_or(ErrorCode::Unavailable)?
                .observe_lineage(observed, now)
        });
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Synchronously stop admission, replies, receive work and transport custody.
    pub fn close(&self) {
        self.control.close();
    }

    /// Independent drain survives cancellation of this waiter. Parent must
    /// await it before Vault/Store teardown and before exiting the LocalSet.
    pub async fn shutdown(self) -> Result<()> {
        self.close();
        self.control.done.clone().await
    }
}
impl<W: TorWatcher + 'static> Drop for Owner<W> {
    fn drop(&mut self) {
        self.control.close();
    }
}
