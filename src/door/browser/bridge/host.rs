use super::*;

struct Admission(Rc<Cell<usize>>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
struct Command {
    id: u32,
    request: String,
    _admission: Admission,
}
struct Retained {
    challenge: String,
    bytes: usize,
    _admission: Admission,
    _timeout: gloo_timers::callback::Timeout,
}
struct State {
    sender: RefCell<mpsc::Sender<Command>>,
    port: RefCell<Option<MessagePort>>,
    handler: RefCell<Option<Closure<dyn FnMut(MessageEvent)>>>,
    pending: Rc<Cell<usize>>,
    sequence: Cell<u32>,
    closing: Cell<bool>,
    close_id: Cell<Option<u32>>,
    retained: RefCell<BTreeMap<u32, Retained>>,
    reply_bytes: Cell<usize>,
    handshake: RefCell<Option<gloo_timers::callback::Timeout>>,
}
impl State {
    fn close(&self) {
        self.closing.set(true);
        self.sender.borrow_mut().close_channel();
    }
    fn reply(&self, value: Reply) {
        if let Some(port) = self.port.borrow().as_ref() {
            if post(port, &value).is_err() {
                self.close();
            }
        }
    }
    fn receive(&self, event: MessageEvent) {
        let request = payload(&event, MAX_REQUEST).and_then(|bytes| {
            serde_json::from_str::<Request>(&bytes).map_err(|_| ErrorCode::InvalidRequest)
        });
        let Ok(request) = request else {
            self.close();
            return;
        };
        if !matches!(request, Request::Ack { .. }) {
            if self.closing.get() || self.sequence.get().checked_add(1) != Some(request.id()) {
                self.close();
                return;
            }
            self.sequence.set(request.id());
        }
        match request {
            Request::Close { id } => {
                self.close_id.set(Some(id));
                self.close();
            }
            Request::Invoke { id, request } => {
                if request.len() > MAX_BODY_BYTES || self.pending.get() >= MAX_CLIENTS {
                    // An overflow response per untrusted request would itself
                    // create an unbounded outgoing MessagePort queue.
                    self.close();
                    return;
                }
                self.pending.set(self.pending.get() + 1);
                let command = Command {
                    id,
                    request,
                    _admission: Admission(self.pending.clone()),
                };
                let refused = self.sender.borrow_mut().try_send(command).is_err();
                if refused {
                    self.close();
                }
            }
            Request::Ack { id, challenge } => {
                let valid = self
                    .retained
                    .borrow()
                    .get(&id)
                    .is_some_and(|reply| reply.challenge == challenge);
                if !valid {
                    self.close();
                    return;
                }
                if let Some(reply) = self.retained.borrow_mut().remove(&id) {
                    self.reply_bytes.set(self.reply_bytes.get() - reply.bytes);
                }
            }
        }
    }

    fn complete(self: &Rc<Self>, command: Command, output: Output) {
        let mut random = [0; 16];
        if getrandom::fill(&mut random).is_err() {
            self.close();
            return;
        }
        // Flow control only: this value conveys no action or remote authority.
        // A peer cannot acknowledge an unread reply using request-known IDs.
        let challenge = data_encoding::HEXLOWER.encode(&random);
        let reply = Reply::Output {
            id: command.id,
            output,
            challenge: challenge.clone(),
        };
        let Ok(bytes) = serde_json::to_string(&reply) else {
            self.close();
            return;
        };
        if bytes.len() > BRIDGE_MAX_REPLY
            || bytes.len() > BRIDGE_MAX_REPLY.saturating_sub(self.reply_bytes.get())
        {
            self.close();
            return;
        }
        let weak = Rc::downgrade(self);
        let timeout = gloo_timers::callback::Timeout::new(BRIDGE_ACK_MILLIS, move || {
            if let Some(state) = weak.upgrade() {
                state.close();
            }
        });
        self.reply_bytes.set(self.reply_bytes.get() + bytes.len());
        self.retained.borrow_mut().insert(
            command.id,
            Retained {
                challenge,
                bytes: bytes.len(),
                _admission: command._admission,
                _timeout: timeout,
            },
        );
        if let Some(port) = self.port.borrow().as_ref() {
            if port.post_message(&JsValue::from_str(&bytes)).is_err() {
                self.close();
            }
        }
    }
}

/// Isolated vault-frame owner. It retains the custody Wasm instance and accepts
/// only its configured top-level member Window through one bounded channel.
#[wasm_bindgen]
pub struct VaultHost {
    state: Rc<State>,
    window: Window,
    hello: Closure<dyn FnMut(MessageEvent)>,
    leaving: Closure<dyn FnMut(web_sys::Event)>,
    done: Completion,
}
impl VaultHost {
    /// Trusted Rust composition inside the pinned vault frame. Ceremony results
    /// must enter through original cpky custody, never this public API channel.
    pub fn attach(door: Door, member_origin: String, vault_origin: String) -> Result<Self> {
        vault_pair(&member_origin, &vault_origin)?;
        let window = window()?;
        if actual_origin()? != vault_origin {
            return Err(ErrorCode::Unauthorized);
        }
        let parent = window
            .parent()
            .map_err(|_| ErrorCode::Unavailable)?
            .ok_or(ErrorCode::Unauthorized)?;
        let top = window
            .top()
            .map_err(|_| ErrorCode::Unavailable)?
            .ok_or(ErrorCode::Unauthorized)?;
        if js_sys::Object::is(parent.as_ref(), window.as_ref())
            || !js_sys::Object::is(parent.as_ref(), top.as_ref())
        {
            return Err(ErrorCode::Unauthorized);
        }
        let runtime = BrowserRuntime::owned(door, vault_origin, Role::Member)?;
        let (sender, mut receiver) = mpsc::channel::<Command>(MAX_CLIENTS);
        let state = Rc::new(State {
            sender: RefCell::new(sender),
            port: RefCell::new(None),
            handler: RefCell::new(None),
            pending: Rc::new(Cell::new(0)),
            sequence: Cell::new(0),
            closing: Cell::new(false),
            close_id: Cell::new(None),
            retained: RefCell::new(BTreeMap::new()),
            reply_bytes: Cell::new(0),
            handshake: RefCell::new(None),
        });
        let weak = Rc::downgrade(&state);
        *state.handshake.borrow_mut() = Some(gloo_timers::callback::Timeout::new(
            BRIDGE_ACK_MILLIS,
            move || {
                if let Some(state) = weak.upgrade() {
                    state.close();
                }
            },
        ));
        let weak = Rc::downgrade(&state);
        let target = parent;
        let announce_origin = member_origin.clone();
        let hello = Closure::wrap(Box::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() != Some(READY) {
                return;
            }
            let Some(state) = weak.upgrade() else {
                close_transfers(&event);
                return;
            };
            if !same_source(&event, &target, &member_origin)
                || event.ports().length() != 0
                || state.port.borrow().is_some()
                || state.closing.get()
            {
                close_transfers(&event);
                return;
            }
            let connect = || -> Result<()> {
                let channel = web_sys::MessageChannel::new().map_err(|_| ErrorCode::Unavailable)?;
                let port = channel.port1();
                let weak = Rc::downgrade(&state);
                let handler = Closure::wrap(Box::new(move |event| {
                    if let Some(state) = weak.upgrade() {
                        state.receive(event);
                    }
                }) as Box<dyn FnMut(MessageEvent)>);
                port.set_onmessage(Some(handler.as_ref().unchecked_ref()));
                port.set_onmessageerror(Some(handler.as_ref().unchecked_ref()));
                port.start();
                *state.handler.borrow_mut() = Some(handler);
                *state.port.borrow_mut() = Some(port);
                state.handshake.borrow_mut().take();
                let transfer = js_sys::Array::new();
                transfer.push(channel.port2().as_ref());
                target
                    .post_message_with_transfer(
                        &JsValue::from_str(CONNECT),
                        &member_origin,
                        &transfer,
                    )
                    .map_err(|_| ErrorCode::Unavailable)?;
                state.reply(Reply::Ready);
                Ok(())
            };
            if connect().is_err() {
                state.close();
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        let weak = Rc::downgrade(&state);
        let leaving = Closure::wrap(Box::new(move |_: web_sys::Event| {
            if let Some(state) = weak.upgrade() {
                state.close();
            }
        }) as Box<dyn FnMut(web_sys::Event)>);
        let (finished, completion) = oneshot::channel();
        let owner = state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            // Admitted work survives a vanished UI waiter. The original owner
            // completes before closure; no channel timeout means rollback.
            while let Some(command) = receiver.next().await {
                let mut command = command;
                let result =
                    JsFuture::from(runtime.invoke(std::mem::take(&mut command.request))).await;
                let result = result
                    .ok()
                    .and_then(|value| value.as_string())
                    .and_then(|bytes| serde_json::from_str::<Output>(&bytes).ok());
                owner.complete(
                    command,
                    result.unwrap_or(Output::Error {
                        error: ErrorCode::Reconcile,
                    }),
                );
            }
            let disposed = JsFuture::from(runtime.dispose())
                .await
                .map_err(|_| ErrorCode::Reconcile);
            owner.reply(Reply::Closed {
                id: owner.close_id.get(),
                error: disposed.err(),
            });
            if let Some(port) = owner.port.borrow_mut().take() {
                port.set_onmessage(None);
                port.set_onmessageerror(None);
                port.close();
            }
            owner.handler.borrow_mut().take();
            owner.retained.borrow_mut().clear();
            owner.handshake.borrow_mut().take();
            let _ = finished.send(disposed);
        });
        let host = Self {
            state,
            window,
            hello,
            leaving,
            done: async move { completion.await.map_err(|_| ErrorCode::Reconcile)? }
                .boxed_local()
                .shared(),
        };
        // Construct the Drop guard before registering either listener: every
        // later setup failure removes both callbacks and drains the real owner.
        host.window
            .add_event_listener_with_callback("message", host.hello.as_ref().unchecked_ref())
            .map_err(|_| ErrorCode::Unavailable)?;
        host.window
            .add_event_listener_with_callback("pagehide", host.leaving.as_ref().unchecked_ref())
            .map_err(|_| ErrorCode::Unavailable)?;
        // Configuration/Wasm startup can finish after the frame's load event.
        // Announce only after both guards exist; the UI answers with the same
        // original handshake and this owner still verifies its exact parent.
        host.window
            .parent()
            .map_err(|_| ErrorCode::Unavailable)?
            .ok_or(ErrorCode::Unauthorized)?
            .post_message(&JsValue::from_str(READY), &announce_origin)
            .map_err(|_| ErrorCode::Unavailable)?;
        Ok(host)
    }
}
#[wasm_bindgen]
impl VaultHost {
    /// Construct only actual partial owners. Complete login still requires the
    /// original cpky frame/popup custody + G3 + durable Vault constructor.
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: String) -> std::result::Result<VaultHost, JsValue> {
        let make = || -> Result<Self> {
            if configuration.len() > MAX_BODY_BYTES {
                return Err(ErrorCode::Capacity);
            }
            let config: VaultHostConfiguration =
                serde_json::from_str(&configuration).map_err(|_| ErrorCode::InvalidRequest)?;
            if config.runtime.role != Role::Member {
                return Err(ErrorCode::Unauthorized);
            }
            let origin = config.runtime.origin.clone();
            Self::attach(config.runtime.construct()?, config.member_origin, origin)
        };
        make().map_err(error)
    }
    pub fn dispose(&self) -> js_sys::Promise {
        self.state.close();
        let done = self.done.clone();
        future_to_promise(async move {
            done.await.map_err(error)?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
impl Drop for VaultHost {
    fn drop(&mut self) {
        let _ = self
            .window
            .remove_event_listener_with_callback("message", self.hello.as_ref().unchecked_ref());
        let _ = self
            .window
            .remove_event_listener_with_callback("pagehide", self.leaving.as_ref().unchecked_ref());
        self.state.close();
        // The UI keeps this frame alive until actual owner drain is acknowledged.
    }
}
