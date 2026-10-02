use super::*;
use futures_channel::{mpsc, oneshot};
use futures_util::{future::LocalBoxFuture, FutureExt, StreamExt};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

struct Admission(Rc<Cell<usize>>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
struct Command {
    bytes: String,
    reply: oneshot::Sender<Output>,
    _admission: Admission,
}

/// Owns a bounded local actor. Dropping a JavaScript Promise cannot cancel an
/// admitted child effect; disposal closes admission and waits for the actor.
#[wasm_bindgen]
pub struct BrowserRuntime {
    sender: RefCell<mpsc::Sender<Command>>,
    pending: Rc<Cell<usize>>,
    closed: Cell<bool>,
    done: futures_util::future::Shared<LocalBoxFuture<'static, Result<()>>>,
}

fn now() -> Result<u64> {
    let value = js_sys::Date::now() / 1000.0;
    if !value.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&value) {
        return Err(ErrorCode::Clock);
    }
    Ok(value as u64)
}
fn output(value: Output) -> JsValue {
    // Output contains only JSON-compatible primitives and the owner's Value.
    serde_json::to_string(&value)
        .expect("Output is JSON-compatible")
        .into()
}
fn refusal(error: ErrorCode) -> js_sys::Promise {
    js_sys::Promise::resolve(&output(Output::Error { error }))
}

impl BrowserRuntime {
    /// Trusted Rust composition entry. Actual facades remain on this browser's
    /// owner task; the local capability is never returned to JavaScript.
    pub fn attach(door: Door, origin: String, role: Role) -> Result<Self> {
        let actual = web_sys::window()
            .ok_or(ErrorCode::Unavailable)?
            .location()
            .origin()
            .map_err(|_| ErrorCode::Unavailable)?;
        // Page runtimes cannot house decrypted Vault custody. The isolated
        // vault frame owns that lifetime behind the separate UI channel.
        if origin != actual || !door.vaults.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        Self::owned(door, origin, role)
    }

    /// Private entry used only after the frame checks its actual vault origin
    /// and expected direct parent Window. Never exported as an unrestricted JS constructor.
    pub(super) fn owned(mut door: Door, origin: String, role: Role) -> Result<Self> {
        let time = now()?;
        let token = door.pair_client(
            &origin,
            role,
            catalog().into_iter().map(|a| a.action).collect(),
            time,
            time.checked_add(MAX_GRANT_SECONDS)
                .ok_or(ErrorCode::Clock)?,
        )?;
        let (sender, mut receiver) = mpsc::channel::<Command>(MAX_CLIENTS);
        let (finished, completion) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            // The task is the sole Door owner. A panic terminates this owner;
            // there is no shared Door to recover or reuse after a partial effect.
            while let Some(command) = receiver.next().await {
                let result = match now() {
                    Ok(time) => {
                        door.dispatch(
                            &origin,
                            token.expose_for_transport(),
                            command.bytes.as_bytes(),
                            time,
                        )
                        .await
                    }
                    Err(error) => Output::Error { error },
                };
                // A vanished waiter does not alter child completion ownership.
                let _ = command.reply.send(result);
            }
            door.revoke(&token);
            door.close_owned().await;
            let _ = finished.send(());
        });
        Ok(Self {
            sender: RefCell::new(sender),
            pending: Rc::new(Cell::new(0)),
            closed: Cell::new(false),
            done: async move { completion.await.map_err(|_| ErrorCode::Reconcile) }
                .boxed_local()
                .shared(),
        })
    }
}

#[wasm_bindgen]
impl BrowserRuntime {
    /// Configure actual unauthenticated Foyer and optional Forum/Board transports.
    /// Vault/Mesh owners remain unavailable; construction is not readiness.
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: String) -> std::result::Result<BrowserRuntime, JsValue> {
        Self::configured(&configuration).map_err(|error| output(Output::Error { error }))
    }

    /// Original bytes pass through the same duplicate-key/version/action gate.
    pub fn invoke(&self, request: String) -> js_sys::Promise {
        if self.closed.get() {
            return refusal(ErrorCode::Unavailable);
        }
        if request.len() > MAX_BODY_BYTES || self.pending.get() >= MAX_CLIENTS {
            return refusal(ErrorCode::Capacity);
        }
        let (reply, result) = oneshot::channel();
        self.pending.set(self.pending.get() + 1);
        let command = Command {
            bytes: request,
            reply,
            _admission: Admission(self.pending.clone()),
        };
        if self.sender.borrow_mut().try_send(command).is_err() {
            return refusal(ErrorCode::Unavailable);
        }
        future_to_promise(async move {
            // Admission succeeded: a lost actor reply cannot prove no effect.
            Ok(output(result.await.unwrap_or(Output::Error {
                error: ErrorCode::Reconcile,
            })))
        })
    }

    /// Idempotent drain: no new requests are admitted, existing requests finish,
    /// then actual Mesh listeners close before resolution. Vault custody is
    /// forbidden here and belongs to the separate isolated-origin runtime.
    pub fn dispose(&self) -> js_sys::Promise {
        self.closed.set(true);
        self.sender.borrow_mut().close_channel();
        let done = self.done.clone();
        future_to_promise(async move {
            done.await
                .map_err(|error| output(Output::Error { error }))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl BrowserRuntime {
    fn configured(raw: &str) -> Result<Self> {
        if raw.len() > MAX_BODY_BYTES {
            return Err(ErrorCode::Capacity);
        }
        let configuration: Configuration =
            serde_json::from_str(raw).map_err(|_| ErrorCode::InvalidRequest)?;
        let origin = configuration.origin.clone();
        let role = configuration.role;
        let door = configuration.construct()?;
        Self::attach(door, origin, role)
    }
}

impl Drop for BrowserRuntime {
    fn drop(&mut self) {
        self.sender.get_mut().close_channel();
    }
}
