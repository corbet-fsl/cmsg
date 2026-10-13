//! Trusted top-level CMSG page owner. Only redacted handover status is exported.
use super::*;
use cfyr::passkeys::browser::PopupHandoff;
use futures_util::future::{AbortHandle, Abortable};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::prelude::*;
fn json(status: CallbackStatus) -> String {
    serde_json::to_string(&status).expect("fixed callback status")
}
fn refused(_: impl Sized) -> JsValue {
    JsValue::from_str("unavailable")
}

#[wasm_bindgen]
pub struct PopupLogin {
    prepared: Rc<RefCell<Option<PopupHandoff>>>,
    state: Rc<Cell<CallbackStatus>>,
    abort: RefCell<Option<AbortHandle>>,
}
#[wasm_bindgen]
impl PopupLogin {
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: String, launch: String) -> std::result::Result<PopupLogin, JsValue> {
        if configuration.len() > MAX_BODY_BYTES || launch.len() > 1025 {
            return Err(refused(()));
        }
        let config: Configuration = serde_json::from_str(&configuration).map_err(refused)?;
        let launch = zeroize::Zeroizing::new(launch);
        let owner = PopupHandoff::from_consumed_fragment(
            config.context().map_err(refused)?,
            &config.page,
            &launch,
        )
        .map_err(refused)?;
        Ok(Self {
            prepared: Rc::new(RefCell::new(Some(owner))),
            state: Rc::new(Cell::new(CallbackStatus::Running)),
            abort: RefCell::new(None),
        })
    }
    pub fn status(&self) -> String {
        json(self.state.get())
    }
    /// Original public request acceptance before the page enables Continue.
    pub fn ready(&self) -> js_sys::Promise {
        let Some(mut owner) = self.prepared.borrow_mut().take() else {
            return js_sys::Promise::reject(&refused(()));
        };
        let (abort, registration) = AbortHandle::new_pair();
        *self.abort.borrow_mut() = Some(abort);
        let prepared = self.prepared.clone();
        let state = self.state.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let operation = async move {
                let result = owner.ready().await;
                (owner, result)
            };
            match Abortable::new(operation, registration).await {
                Ok((owner, Ok(()))) => {
                    *prepared.borrow_mut() = Some(owner);
                    state.set(CallbackStatus::Ready);
                    Ok(json(CallbackStatus::Ready).into())
                }
                _ => {
                    state.set(CallbackStatus::Cancelled);
                    Err(refused(()))
                }
            }
        })
    }
    /// Called directly by the popup's Continue click, with no member channel hop.
    pub fn begin(&self) -> js_sys::Promise {
        if self.state.get() != CallbackStatus::Ready {
            return js_sys::Promise::reject(&refused(()));
        }
        let Some(owner) = self.prepared.borrow_mut().take() else {
            return js_sys::Promise::reject(&refused(()));
        };
        let (abort, registration) = AbortHandle::new_pair();
        *self.abort.borrow_mut() = Some(abort);
        self.state.set(CallbackStatus::Running);
        let state = self.state.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            let status = match Abortable::new(owner.complete(), registration).await {
                Ok(Ok(())) => CallbackStatus::HandedBack,
                Ok(Err(cfyr::passkeys::Error::Cancelled)) => CallbackStatus::Cancelled,
                _ => CallbackStatus::Reconcile,
            };
            state.set(status);
            Ok(json(status).into())
        })
    }
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
impl Drop for PopupLogin {
    fn drop(&mut self) {
        self.prepared.borrow_mut().take();
        if let Some(abort) = self.abort.get_mut().take() {
            abort.abort();
        }
    }
}
