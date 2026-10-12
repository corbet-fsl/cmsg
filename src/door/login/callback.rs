//! Top-level vault-origin page for the native CLI's original passkey callback.
//! The minimal trusted page consumes the launch before loading this module;
//! Passkeys independently verifies its consumption, context and original wire.
use super::*;
use futures_util::future::{AbortHandle, Abortable};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::prelude::*;

fn json(status: CallbackStatus) -> String {
    serde_json::to_string(&status).expect("callback status is a fixed enum")
}
fn refused(_: impl Sized) -> JsValue {
    JsValue::from_str("unavailable")
}

#[wasm_bindgen]
pub struct CliLogin {
    prepared: RefCell<Option<cfyr::passkeys::browser::LoopbackCeremony>>,
    state: Rc<Cell<CallbackStatus>>,
    abort: RefCell<Option<AbortHandle>>,
}

#[wasm_bindgen]
impl CliLogin {
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: String, launch: String) -> std::result::Result<CliLogin, JsValue> {
        if configuration.len() > MAX_BODY_BYTES || launch.len() > 1025 {
            return Err(refused(()));
        }
        let configuration: Configuration = serde_json::from_str(&configuration).map_err(refused)?;
        let window = web_sys::window().ok_or_else(|| refused(()))?;
        let top = window.top().map_err(refused)?.ok_or_else(|| refused(()))?;
        if !js_sys::Object::is(window.as_ref(), top.as_ref()) {
            return Err(refused(()));
        }
        let mut page =
            url::Url::parse(&window.location().href().map_err(refused)?).map_err(refused)?;
        page.set_fragment(None);
        if page.as_str() != configuration.page {
            return Err(refused(()));
        }
        let launch = zeroize::Zeroizing::new(launch);
        let prepared = cfyr::passkeys::browser::LoopbackCeremony::from_consumed_fragment(
            configuration.context().map_err(refused)?,
            &launch,
        )
        .map_err(refused)?;
        Ok(Self {
            prepared: RefCell::new(Some(prepared)),
            state: Rc::new(Cell::new(CallbackStatus::Ready)),
            abort: RefCell::new(None),
        })
    }

    pub fn status(&self) -> String {
        json(self.state.get())
    }

    /// Start once, after the page's explicit Continue click. Only a coarse state
    /// crosses to JavaScript; the callback bytes remain inside the owner.
    pub fn begin(&self) -> js_sys::Promise {
        let Some(prepared) = self.prepared.borrow_mut().take() else {
            return js_sys::Promise::resolve::<wasm_bindgen::JsValue>(
                &json(self.state.get()).into(),
            );
        };
        let state = self.state.clone();
        state.set(CallbackStatus::Running);
        let (abort, registration) = AbortHandle::new_pair();
        *self.abort.borrow_mut() = Some(abort);
        wasm_bindgen_futures::future_to_promise(async move {
            let final_state = match Abortable::new(prepared.complete(), registration).await {
                Ok(Ok(())) => CallbackStatus::HandedBack,
                Ok(Err(cfyr::passkeys::Error::Cancelled)) => CallbackStatus::Cancelled,
                Ok(Err(_)) => CallbackStatus::Reconcile,
                Err(_) => CallbackStatus::Reconcile,
            };
            state.set(final_state);
            Ok(json(final_state).into())
        })
    }

    /// Cancel owner work without claiming that a callback already sent rolled back.
    pub fn cancel(&self) -> String {
        if matches!(
            self.state.get(),
            CallbackStatus::Ready | CallbackStatus::Running
        ) {
            self.prepared.borrow_mut().take();
            if let Some(abort) = self.abort.borrow_mut().take() {
                abort.abort();
            }
            self.state
                .set(if self.state.get() == CallbackStatus::Ready {
                    CallbackStatus::Cancelled
                } else {
                    CallbackStatus::Reconcile
                });
        }
        self.status()
    }
}

impl Drop for CliLogin {
    fn drop(&mut self) {
        if let Some(abort) = self.abort.get_mut().take() {
            abort.abort();
        }
    }
}
