//! Original browser challenge plus a frame-local synchronous gesture control.
//! The Door retains completion; the member channel never owns the ceremony.
use super::session::{origin, passkey_error, State};
use super::*;
use cfyr::passkeys::{browser::PopupCeremony, CeremonyKind, CeremonyRequest, CeremonyResult};
use futures_channel::oneshot;
use futures_util::{
    future::{AbortHandle, Abortable, LocalBoxFuture},
    FutureExt,
};
use std::{cell::RefCell, rc::Rc};

type PasskeyResult = std::result::Result<CeremonyResult, cfyr::passkeys::Error>;
struct Prepared {
    owner: PopupCeremony,
    sender: oneshot::Sender<PasskeyResult>,
}
#[derive(Default)]
struct Slot {
    generation: u64,
    status: Option<CallbackStatus>,
    prepared: Option<Prepared>,
    abort: Option<AbortHandle>,
    deadline: Option<gloo_timers::callback::Timeout>,
}
impl Slot {
    fn cancel(&mut self) {
        if matches!(
            self.status,
            Some(CallbackStatus::Ready | CallbackStatus::Running)
        ) {
            self.prepared.take();
            if let Some(abort) = self.abort.take() {
                abort.abort();
            }
            self.status = Some(CallbackStatus::Cancelled);
        }
        self.deadline.take();
    }
}

/// Private trusted-frame control. No grant, credential, PRF or capability can be
/// extracted; only its coarse status and synchronous own-window gesture exist.
#[derive(Clone, Default)]
pub(crate) struct Gesture(Rc<RefCell<Slot>>);
struct CancelOnDrop {
    gesture: Gesture,
    generation: u64,
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let mut slot = self.gesture.0.borrow_mut();
        if slot.generation == self.generation {
            slot.cancel();
        }
    }
}
impl Gesture {
    pub(crate) fn status(&self) -> Option<CallbackStatus> {
        self.0.borrow().status
    }
    pub(crate) fn cancel(&self) {
        self.0.borrow_mut().cancel();
    }

    pub(crate) fn open(&self) -> Result<()> {
        let generation = self.0.borrow().generation;
        let Some(mut prepared) = self.0.borrow_mut().prepared.take() else {
            return Err(ErrorCode::Refused);
        };
        // Intentionally synchronous: the trusted frame's real click must still
        // be active here. Neither actor queue nor member postMessage launches it.
        if let Err(error) = prepared.owner.open() {
            let _ = prepared.sender.send(Err(error));
            self.0.borrow_mut().status = Some(CallbackStatus::Failed);
            return Err(passkey_error(error));
        }
        let (abort, registration) = AbortHandle::new_pair();
        {
            let mut slot = self.0.borrow_mut();
            slot.abort = Some(abort);
            slot.status = Some(CallbackStatus::Running);
        }
        let state = self.0.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let result = match Abortable::new(prepared.owner.wait(), registration).await {
                Ok(result) => result,
                Err(_) => Err(cfyr::passkeys::Error::Cancelled),
            };
            {
                let mut slot = state.borrow_mut();
                if slot.generation == generation {
                    slot.status = Some(match &result {
                        Ok(_) => CallbackStatus::HandedBack,
                        Err(_) => CallbackStatus::Cancelled,
                    });
                    slot.abort.take();
                    slot.deadline.take();
                }
            }
            let _ = prepared.sender.send(result);
        });
        Ok(())
    }

    fn prepare(&self, owner: PopupCeremony) -> Result<LocalBoxFuture<'static, PasskeyResult>> {
        if matches!(
            self.status(),
            Some(CallbackStatus::Ready | CallbackStatus::Running)
        ) {
            return Err(ErrorCode::Refused);
        }
        let (sender, result) = oneshot::channel();
        let generation = self
            .0
            .borrow()
            .generation
            .checked_add(1)
            .ok_or(ErrorCode::Capacity)?;
        let weak = Rc::downgrade(&self.0);
        let timer = gloo_timers::callback::Timeout::new(120_000, move || {
            if let Some(slot) = weak.upgrade() {
                let mut slot = slot.borrow_mut();
                if slot.generation == generation {
                    slot.cancel();
                }
            }
        });
        *self.0.borrow_mut() = Slot {
            generation,
            status: Some(CallbackStatus::Ready),
            prepared: Some(Prepared { owner, sender }),
            abort: None,
            deadline: Some(timer),
        };
        let guard = CancelOnDrop {
            gesture: self.clone(),
            generation,
        };
        Ok(async move {
            let _guard = guard;
            result
                .await
                .unwrap_or(Err(cfyr::passkeys::Error::Cancelled))
        }
        .boxed_local())
    }
}

pub(super) async fn start(door: &mut Door, key: &[u8; 32]) -> Result<Status> {
    let origin = origin(door, key)?;
    match door.logins.get(key) {
        Some(State::Cancelled | State::Expired) => {
            door.logins.remove(key);
        }
        Some(State::Refused(error)) if *error != ErrorCode::Reconcile => {
            door.logins.remove(key);
        }
        Some(_) => return Err(ErrorCode::Refused),
        None => {}
    }
    let gesture = door.browser_gesture.clone().ok_or(ErrorCode::Unavailable)?;
    if matches!(
        gesture.status(),
        Some(CallbackStatus::Ready | CallbackStatus::Running)
    ) {
        return Err(ErrorCode::Refused);
    }
    let config = door
        .login_configuration
        .get(&origin)
        .ok_or(ErrorCode::Unavailable)?
        .clone();
    let context = config.context()?;
    let binding = door.foyers.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    if binding.uncertain {
        return Err(ErrorCode::Reconcile);
    }
    let client = binding
        .sessions
        .clients
        .get_mut(&binding.sessions.primary)
        .ok_or(ErrorCode::Unavailable)?;
    binding.uncertain = true;
    let challenge = match client.begin_browser_login().await {
        Ok(value) => value,
        Err(error) => {
            let error = foyer::map_error(error);
            binding.uncertain = error == ErrorCode::Reconcile;
            return Err(error);
        }
    };
    let owner = PopupCeremony::prepare(
        context,
        CeremonyRequest {
            kind: CeremonyKind::Authentication,
            options: challenge.options,
        },
        &config.page,
        120_000,
    )
    .map_err(|error| {
        binding.uncertain = false;
        passkey_error(error)
    })?;
    let expires = door.clock_floor.checked_add(120).ok_or_else(|| {
        binding.uncertain = false;
        ErrorCode::Clock
    })?;
    let future = gesture.prepare(owner).map_err(|error| {
        binding.uncertain = false;
        error
    })?;
    door.logins.insert(
        *key,
        State::Waiting {
            future,
            ceremony: challenge.ceremony,
            expires,
        },
    );
    Ok(Status::Pending {
        expires_at: expires,
    })
}
