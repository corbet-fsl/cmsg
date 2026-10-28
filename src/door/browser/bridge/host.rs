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
    gesture: login::browser::Gesture,
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
        self.gesture.cancel();
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
            serde_json::from_str::<Request>(&bytes).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            })
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
    /// A registration's wallet parts (passport, wallet Door, companion), kept for the frame's
    /// life and dropped with it, after everything above.
    retained: Option<super::super::registration::Retained>,
}
impl VaultHost {
    /// Trusted Rust composition inside the pinned vault frame. Ceremony results
    /// must enter through original cpky custody, never this public API channel.
    pub fn attach(door: Door, member_origin: String, vault_origin: String) -> Result<Self> {
        Self::attach_owned(door, member_origin, vault_origin, None, None)
    }

    /// Retain the parent's real custody composer inside the same origin-pinned
    /// actor. No application JSON or JavaScript callback can install this port.
    pub fn attach_with_composer(
        door: Door,
        member_origin: String,
        vault_origin: String,
        composer: Box<dyn VaultComposer>,
    ) -> Result<Self> {
        Self::attach_owned(door, member_origin, vault_origin, None, Some(composer))
    }

    /// The deployment's one wallet custody frame (`https://wallet.<base>`) for a member page on
    /// that base: the frame's actual origin must be exactly the pinned wallet origin.
    pub fn attach_wallet(
        door: Door,
        member_origin: String,
        wallet_origin: String,
        composer: Option<Box<dyn VaultComposer>>,
    ) -> Result<Self> {
        let wallet = wallet_origin.clone();
        Self::attach_owned(door, member_origin, wallet_origin, Some(wallet), composer)
    }

    fn attach_owned(
        mut door: Door,
        member_origin: String,
        vault_origin: String,
        wallet_origin: Option<String>,
        composer: Option<Box<dyn VaultComposer>>,
    ) -> Result<Self> {
        vault_pair(&member_origin, &vault_origin, wallet_origin.as_deref())?;
        let window = window()?;
        if actual_origin()? != vault_origin {
            return Err(ErrorCode::Unauthorized);
        }
        let parent = window
            .parent()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .ok_or(ErrorCode::Unauthorized)?;
        let top = window
            .top()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .ok_or(ErrorCode::Unauthorized)?;
        if js_sys::Object::is(parent.as_ref(), window.as_ref())
            || !js_sys::Object::is(parent.as_ref(), top.as_ref())
        {
            return Err(ErrorCode::Unauthorized);
        }
        let gesture = login::browser::Gesture::default();
        door.browser_gesture = Some(gesture.clone());
        let runtime =
            BrowserRuntime::owned_with_composer(door, vault_origin, Role::Member, composer)?;
        let (sender, mut receiver) = mpsc::channel::<Command>(MAX_CLIENTS);
        let state = Rc::new(State {
            gesture,
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
                let channel = web_sys::MessageChannel::new().map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Unavailable",
                        ErrorCode::Unavailable,
                        &__cause,
                    )
                })?;
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
                    .map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "ErrorCode::Unavailable",
                            ErrorCode::Unavailable,
                            &__cause,
                        )
                    })?;
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
            // Disposal carries no value; a rejection stays a Reconcile error.
            let disposed = JsFuture::from(runtime.dispose())
                .await
                .map(|_| ())
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::Reconcile",
                        ErrorCode::Reconcile,
                        &__cause,
                    )
                });
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
            retained: None,
        };
        // Construct the Drop guard before registering either listener: every
        // later setup failure removes both callbacks and drains the real owner.
        host.window
            .add_event_listener_with_callback("message", host.hello.as_ref().unchecked_ref())
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        host.window
            .add_event_listener_with_callback("pagehide", host.leaving.as_ref().unchecked_ref())
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        // Configuration/Wasm startup can finish after the frame's load event.
        // Announce only after both guards exist; the UI answers with the same
        // original handshake and this owner still verifies its exact parent.
        host.window
            .parent()
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?
            .ok_or(ErrorCode::Unauthorized)?
            .post_message(&JsValue::from_str(READY), &announce_origin)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
        Ok(host)
    }
}
#[wasm_bindgen]
impl VaultHost {
    /// Redacted presentation for the actual frame's Continue control.
    pub fn login_status(&self) -> String {
        serde_json::to_string(&self.state.gesture.status())
            .expect("the gesture status is a fixed local enum and always serializes")
    }
    /// Synchronous trusted-frame activation, never dispatched through the UI port.
    pub fn continue_login(&self) -> std::result::Result<(), JsValue> {
        if self.state.closing.get() {
            return Err(error(ErrorCode::Unavailable));
        }
        self.state.gesture.open().map_err(error)
    }
    /// Cancel only the prepared/passkey phase. Server completion remains owned
    /// by Door and cannot be rolled back through this presentation control.
    pub fn cancel_login(&self) {
        self.state.gesture.cancel();
    }
    /// Install the real restore composer only when Tor deployment is configured.
    /// Construction grants no custody; original login and recovery still gate it.
    #[wasm_bindgen(constructor)]
    pub fn new(configuration: String) -> std::result::Result<VaultHost, JsValue> {
        let make = || -> Result<Self> {
            if configuration.len() > MAX_BODY_BYTES {
                return Err(ErrorCode::Capacity);
            }
            let config: VaultHostConfiguration =
                serde_json::from_str(&configuration).map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "ErrorCode::InvalidRequest",
                        ErrorCode::InvalidRequest,
                        &__cause,
                    )
                })?;
            if config.runtime.role != Role::Member {
                return Err(ErrorCode::Unauthorized);
            }
            let origin = config.runtime.origin.clone();
            match config.browser_tor {
                Some(deployment) => {
                    #[cfg(feature = "browser-tor")]
                    {
                        let community = config.runtime.community.clone();
                        let (door, board) = config.runtime.construct_restoring()?;
                        let composer = deployment.composer(&community, board)?;
                        Self::attach_with_composer(door, config.member_origin, origin, composer)
                    }
                    #[cfg(not(feature = "browser-tor"))]
                    {
                        let _ = deployment;
                        Err(ErrorCode::Unavailable)
                    }
                }
                None => Self::attach(config.runtime.construct()?, config.member_origin, origin),
            }
        };
        make().map_err(error)
    }
    /// The deployment's one wallet custody frame: register this device (or resume a half
    /// registration) with the wallet passkey in this frame's own window, then attach the
    /// composed community Door for the member page. Call from the frame's own control (the
    /// first WebAuthn creation needs this frame's activation). Resolves to the attached host.
    pub fn wallet(configuration: String) -> js_sys::Promise {
        future_to_promise(async move {
            let host = Self::wallet_inner(configuration).await.map_err(|e| {
                // Composer errors never carry secrets; the stage name helps the operator.
                web_sys::console::warn_1(&JsValue::from_str(&e.to_string()));
                error(ErrorCode::Unavailable)
            })?;
            Ok(JsValue::from(host))
        })
    }

    /// Calibrate this device for the deployment's browser prover (decided 2026-10-23): once per
    /// circuit version, when the page is idle, with a shipped dummy input; the measurement stays in
    /// this origin. Resolves to the forecast JSON (`class`, `predicted_millis`, `window_seconds`,
    /// `fits`) or `null` when the device was needed for a real proof first. Call from the wallet
    /// frame on its first open; it does nothing for a deployment without a prover.
    pub fn calibrate(configuration: String) -> js_sys::Promise {
        future_to_promise(async move {
            #[cfg(feature = "browser-prover")]
            {
                if configuration.len() > MAX_BODY_BYTES {
                    return Err(error(ErrorCode::Capacity));
                }
                let config: VaultHostConfiguration =
                    serde_json::from_str(&configuration).map_err(|__cause| {
                        crate::door::cause::emit(
                            file!(),
                            line!(),
                            "error ErrorCode::InvalidRequest",
                            error(ErrorCode::InvalidRequest),
                            &__cause,
                        )
                    })?;
                let (Some(wallet_origin), Some(registration)) =
                    (config.wallet_origin, config.registration)
                else {
                    return Err(error(ErrorCode::InvalidRequest));
                };
                if actual_origin().map_err(error)? != wallet_origin {
                    return Err(error(ErrorCode::Unauthorized));
                }
                let Some(deployment) = &registration.prover else {
                    return Ok(JsValue::NULL);
                };
                let forecast =
                    super::super::prover::calibrate(deployment)
                        .await
                        .map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "error ErrorCode::Unavailable",
                                error(ErrorCode::Unavailable),
                                &__cause,
                            )
                        })?;
                Ok(match forecast {
                    Some(forecast) => {
                        JsValue::from_str(&serde_json::to_string(&forecast).map_err(|__cause| {
                            crate::door::cause::emit(
                                file!(),
                                line!(),
                                "error ErrorCode::Unavailable",
                                error(ErrorCode::Unavailable),
                                &__cause,
                            )
                        })?)
                    }
                    None => JsValue::NULL,
                })
            }
            #[cfg(not(feature = "browser-prover"))]
            {
                let _ = configuration;
                Ok(JsValue::NULL)
            }
        })
    }

    async fn wallet_inner(
        configuration: String,
    ) -> std::result::Result<VaultHost, crate::door::composer_core::ComposeError> {
        use crate::door::composer_core::{ComposeError, DeviceKeys};
        let refused = |reason: &str| ComposeError::Config(reason.into());
        if configuration.len() > MAX_BODY_BYTES {
            return Err(refused("configuration size"));
        }
        let config: VaultHostConfiguration =
            serde_json::from_str(&configuration).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "refused configuration",
                    refused("configuration"),
                    &__cause,
                )
            })?;
        let (Some(wallet_origin), Some(registration)) = (config.wallet_origin, config.registration)
        else {
            return Err(refused("wallet frame configuration"));
        };
        if config.runtime.role != Role::Member
            || config.runtime.origin != wallet_origin
            || registration.passkey_origin != wallet_origin
        {
            return Err(refused("wallet frame origin"));
        }
        // The member page and this frame are a pinned wallet pair before any ceremony runs.
        vault_pair(&config.member_origin, &wallet_origin, Some(&wallet_origin)).map_err(
            |__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "refused wallet pair",
                    refused("wallet pair"),
                    &__cause,
                )
            },
        )?;
        if actual_origin().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "refused frame origin",
                refused("frame origin"),
                &__cause,
            )
        })? != wallet_origin
        {
            return Err(refused("frame origin"));
        }
        let context =
            cfyr::passkeys::Context::new(&registration.passkey_origin, &registration.rp_id)
                .map_err(|__cause| {
                    crate::door::cause::emit(
                        file!(),
                        line!(),
                        "refused passkey context",
                        refused("passkey context"),
                        &__cause,
                    )
                })?;
        let mut keys = DeviceKeys::new(
            cfyr::passkeys::Client::new(context, cfyr::passkeys::browser::Browser),
            &registration.passkey_origin,
        );
        let networks = registration.networks(config.browser_tor.as_ref()).await?;
        // The deployment's browser prover, authenticated against its pinned digests before any
        // ceremony: the account genesis then proves in a Web Worker of this origin. Without one
        // the account actor is not bound.
        #[cfg(feature = "browser-prover")]
        let prover = match &registration.prover {
            Some(deployment) => Some(super::super::prover::lend_deployed(deployment).await?),
            None => None,
        };
        #[cfg(not(feature = "browser-prover"))]
        let prover = None;
        let (door, retained) = super::super::registration::compose_browser_device(
            &registration,
            &wallet_origin,
            &config.runtime.community,
            &mut keys,
            networks,
            prover,
        )
        .await?;
        let mut host = Self::attach_wallet(door, config.member_origin, wallet_origin, None)
            .map_err(|e| ComposeError::Step("attach", format!("{e:?}")))?;
        host.retained = Some(retained);
        Ok(host)
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
