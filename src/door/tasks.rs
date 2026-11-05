//! The one spawn/sleep seam of the background jobs (courier, wave job): the same job
//! logic runs on the native owner thread (tokio `LocalSet`) and in the browser vault
//! frame (`wasm_bindgen_futures`). Nothing else differs between the two runtimes.
use super::Door;
use std::{future::Future, rc::Rc, time::Duration};

/// The Door shared between the embedder's dispatcher and the jobs of its bound Meshes.
/// Each side locks it per call; no job holds it across a network send.
pub type SharedDoor = Rc<tokio::sync::Mutex<Door>>;

/// Wait `duration` on the current runtime.
pub async fn sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::sleep(duration).await;
}

/// A job started on the current thread's executor. Dropping it does not stop the job.
pub struct Task<T> {
    #[cfg(not(target_arch = "wasm32"))]
    handle: tokio::task::JoinHandle<T>,
    #[cfg(target_arch = "wasm32")]
    handle: futures_channel::oneshot::Receiver<T>,
}

impl<T> Task<T> {
    /// Wait for the job to end; `None` when it panicked or was cancelled.
    pub async fn finished(self) -> Option<T> {
        self.handle.await.ok()
    }
}

/// Start `future` on the current thread: the native owner's `LocalSet` or the browser's
/// microtask queue.
pub fn spawn<F, T>(future: F) -> Task<T>
where
    F: Future<Output = T> + 'static,
    T: 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        Task {
            handle: tokio::task::spawn_local(future),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let (done, handle) = futures_channel::oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = done.send(future.await);
        });
        Task { handle }
    }
}
