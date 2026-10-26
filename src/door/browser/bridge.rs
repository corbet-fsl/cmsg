//! Browser-owned channels carry only the original registry bytes and outputs.
//! Neither this framing nor a transferred port creates remote member authority.
use super::*;
use futures_channel::{mpsc, oneshot};
use futures_util::{future::LocalBoxFuture, FutureExt, StreamExt};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::{future_to_promise, JsFuture};
use web_sys::{MessageEvent, MessagePort, Window};

mod host;
pub use host::VaultHost;

use super::{
    VaultBridgeReply as Reply, VaultBridgeRequest as Request, BRIDGE_CONNECT as CONNECT,
    BRIDGE_MAX_REQUEST as MAX_REQUEST, BRIDGE_READY as READY,
};
impl Request {
    fn id(&self) -> u32 {
        match self {
            Self::Invoke { id, .. } | Self::Close { id } | Self::Ack { id, .. } => *id,
        }
    }
}
fn window() -> Result<Window> {
    web_sys::window().ok_or(ErrorCode::Unavailable)
}
fn actual_origin() -> Result<String> {
    window()?.location().origin().map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })
}
fn same_source(event: &MessageEvent, expected: &Window, origin: &str) -> bool {
    event.is_trusted()
        && event.origin() == origin
        && event
            .source()
            .is_some_and(|source| js_sys::Object::is(source.as_ref(), expected.as_ref()))
}
fn close_transfers(event: &MessageEvent) {
    for value in event.ports().iter() {
        if let Ok(port) = value.dyn_into::<MessagePort>() {
            port.close();
        }
    }
}
fn payload(event: &MessageEvent, maximum: usize) -> Result<String> {
    if !event.is_trusted() || event.ports().length() != 0 {
        close_transfers(event);
        return Err(ErrorCode::InvalidRequest);
    }
    let value = event.data().as_string().ok_or(ErrorCode::InvalidRequest)?;
    if value.len() > maximum {
        return Err(ErrorCode::Capacity);
    }
    Ok(value)
}
fn post<T: Serialize>(port: &MessagePort, message: &T) -> Result<()> {
    let bytes = serde_json::to_string(message).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    port.post_message(&JsValue::from_str(&bytes))
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::Reconcile",
                ErrorCode::Reconcile,
                &__cause,
            )
        })
}
fn output(output: Output) -> JsValue {
    serde_json::to_string(&output)
        .expect("registry output is JSON")
        .into()
}
fn error(error: ErrorCode) -> JsValue {
    output(Output::Error { error })
}
type Completion = futures_util::future::Shared<LocalBoxFuture<'static, Result<()>>>;
