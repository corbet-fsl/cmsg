//! The device's runner lock in the browser: one `navigator.locks.request` per member
//! origin across every tab of this device (decided 2026-11-05). The holder binds the
//! Mesh and runs every job; a tab without it binds no Mesh and its Mesh actions answer
//! `runner_elsewhere` (`door::runner`). `steal` takes the lock from the holder, whose
//! request then rejects: the old holder ends its jobs and Mesh at once.
use crate::door::{runner::RunnerGate, runner::RunnerState, ErrorCode, Result};
use futures_channel::oneshot;
use js_sys::{Function, Object, Promise, Reflect};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// The lock name of one member origin's runner.
pub fn lock_name(origin: &str) -> String {
    format!("cmsg.runner.v1 {origin}")
}

/// How to ask for the lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// Only when no other tab holds it (at login).
    IfAvailable,
    /// Take it from the tab that holds it (`runner.take`).
    Steal,
}

type OnLost = Rc<RefCell<Option<Box<dyn FnOnce()>>>>;

/// The held runner lock. Dropping it releases the lock; losing it to a steal runs the
/// `on_lost` action once and flips the gate to `Elsewhere`.
pub struct Held {
    release: Option<Function>,
    on_lost: OnLost,
}

impl Held {
    /// What to end when another tab takes the lock (the jobs and the Mesh).
    pub fn on_lost(&self, end: impl FnOnce() + 'static) {
        *self.on_lost.borrow_mut() = Some(Box::new(end));
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // A clean release is no loss: forget the action first.
        self.on_lost.borrow_mut().take();
        if let Some(release) = self.release.take() {
            let _ = release.call0(&JsValue::UNDEFINED);
        }
    }
}

fn locks() -> Result<JsValue> {
    let navigator =
        Reflect::get(&js_sys::global(), &"navigator".into()).map_err(|_| ErrorCode::Unavailable)?;
    let locks = Reflect::get(&navigator, &"locks".into()).map_err(|_| ErrorCode::Unavailable)?;
    if locks.is_undefined() || locks.is_null() {
        return Err(ErrorCode::Unavailable);
    }
    Ok(locks)
}

/// Ask for the runner lock of `origin`. `Ok(None)` is "another tab holds it" (only with
/// [`Ask::IfAvailable`]). On a grant `gate` reads `Here`; on a later loss it reads
/// `Elsewhere` before the loss action runs.
pub async fn acquire(origin: &str, ask: Ask, gate: RunnerGate) -> Result<Option<Held>> {
    let locks = locks()?;
    let request: Function = Reflect::get(&locks, &"request".into())
        .map_err(|_| ErrorCode::Unavailable)?
        .dyn_into()
        .map_err(|_| ErrorCode::Unavailable)?;
    let options = Object::new();
    let flag = match ask {
        Ask::IfAvailable => "ifAvailable",
        Ask::Steal => "steal",
    };
    Reflect::set(&options, &flag.into(), &JsValue::TRUE).map_err(|_| ErrorCode::Unavailable)?;
    // The callback reports the grant (a release function) or the refusal (null lock).
    let (granted, grant) = oneshot::channel::<Option<Function>>();
    let granted = Rc::new(RefCell::new(Some(granted)));
    let callback = Closure::once_into_js(move |lock: JsValue| -> JsValue {
        let Some(granted) = granted.borrow_mut().take() else {
            return JsValue::UNDEFINED;
        };
        if lock.is_null() {
            let _ = granted.send(None);
            return JsValue::UNDEFINED;
        }
        // Held until `release` resolves this promise.
        let mut release = None;
        let held = Promise::new(&mut |resolve, _| release = Some(resolve));
        let _ = granted.send(release);
        held.into()
    });
    let pending: Promise = request
        .call3(&locks, &lock_name(origin).into(), &options, &callback)
        .map_err(|_| ErrorCode::Unavailable)?
        .dyn_into()
        .map_err(|_| ErrorCode::Unavailable)?;
    let on_lost: OnLost = Rc::default();
    // The request settles when the lock is released (resolve) or stolen (AbortError).
    let lost = on_lost.clone();
    let watched = gate.clone();
    wasm_bindgen_futures::spawn_local(async move {
        if JsFuture::from(pending).await.is_err() {
            watched.set(RunnerState::Elsewhere);
            if let Some(end) = lost.borrow_mut().take() {
                end();
            }
        }
    });
    match grant.await.map_err(|_| ErrorCode::Unavailable)? {
        Some(release) => {
            gate.set(RunnerState::Here);
            Ok(Some(Held {
                release: Some(release),
                on_lost,
            }))
        }
        None => {
            gate.set(RunnerState::Elsewhere);
            Ok(None)
        }
    }
}
