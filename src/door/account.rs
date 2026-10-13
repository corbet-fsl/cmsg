//! Account lifecycle actions, served by one per-origin account actor.
//!
//! The actor owns the current-policy borrow, the held HTTPS lease and the
//! prepared or pending account across the user-visible actions. Foyer stays the
//! only owner of Charter and Follower; the actor never receives a policy handle
//! of its own beyond the one the trusted embedder lends it. Exactly one action is
//! in flight (the Door dispatcher is `&mut`), the actor ends with its grant,
//! logout or shutdown, and no secret crosses a message: commands carry nothing
//! and replies carry only counters and times.
use super::actor::Actor;
use super::*;

/// Where the current common checkpoint stands for this member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "checkpoint", rename_all = "snake_case", deny_unknown_fields)]
pub enum Checkpoint {
    /// The complete current roster contains this member; `account_open` can run.
    Ready,
    /// A frozen slot can legitimately precede this member's enrollment. Waiting
    /// does not extend the held lease or grant.
    Pending { eligible_at: u64 },
}

/// Result of `account_enroll`: the signed delegation is registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Enrolled {
    pub checkpoint: Checkpoint,
}

/// Result of `account_open` and `account_reopen`: the operator accepted the
/// request and the verified response is durable (state B). Not yet active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    pub accepted_at: u64,
}

/// Result of `account_activate`: the account record is durable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub version: u64,
    pub accepted_at: u64,
    /// False when the acknowledgement of the sent request is still owed; repeat
    /// the action to finish it.
    pub outbox_settled: bool,
}

/// Body of `community_join`. The voucher is the member's own `cvch1.` text; it is
/// needed only while the community's lobby still asks for it. The handle is the
/// member's chosen community handle, reserved once (a repeat with the same handle
/// is a no-op; a different one than already reserved is refused).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    #[serde(default)]
    pub voucher: Option<String>,
    #[serde(default)]
    pub handle: Option<String>,
}

/// One input the member can still supply to an enabled gate of the community.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GateStep {
    pub gate: String,
    pub provider: String,
    /// Stable client dispatch key of the step.
    pub id: String,
}

/// Where the community join stands. Every call resumes from the durable state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
pub enum Joined {
    /// The community still wants something the member has not supplied (or no
    /// admission policy is enabled yet). Supply one of the steps and call again.
    NeedsSteps { steps: Vec<GateStep> },
    /// Admitted and enrolled; the common checkpoint does not list the member yet.
    /// Calling again later continues the setup.
    CheckpointPending { eligible_at: u64 },
    /// The account is active.
    Active {
        version: u64,
        accepted_at: u64,
        outbox_settled: bool,
    },
}

/// The gate stage of a join: what the lobby still lacks.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Gate {
    pub ready: bool,
    pub steps: Vec<GateStep>,
}

/// The actions. Only `Join` carries data, and that is the member's own voucher
/// text, which is bound to the member and useless to anyone else; nothing about
/// the account, the request or the policy is chosen by a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Command {
    Enroll,
    Open,
    Reopen,
    Activate,
    /// Pass the community's gates (submitting the voucher when one is needed).
    Join(JoinRequest),
}

/// Typed answer of one command.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Answer {
    Enrolled(Enrolled),
    Opened(Opened),
    Reopened(Opened),
    Activated(Activation),
    Gate(Gate),
}

macro_rules! accessor {
    ($name:ident, $variant:ident, $type:ty) => {
        pub(super) fn $name(self) -> Result<$type> {
            match self {
                Self::$variant(value) => Ok(value),
                _ => Err(ErrorCode::Unavailable),
            }
        }
    };
}
impl Answer {
    accessor!(enrolled, Enrolled, Enrolled);
    accessor!(opened, Opened, Opened);
    accessor!(reopened, Reopened, Opened);
    accessor!(activated, Activated, Activation);
    accessor!(gate, Gate, Gate);

    /// The open step answers `Opened`, or `Reopened` when a pending request was
    /// resumed; either way the request is accepted.
    pub(super) fn opened_or_reopened(self) -> Result<Opened> {
        match self {
            Self::Opened(value) | Self::Reopened(value) => Ok(value),
            _ => Err(ErrorCode::Unavailable),
        }
    }
}

/// What the account already holds, as far as repeating an action needs to know.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) trait Standing {
    /// The accepted, active account, if any.
    async fn active(&mut self) -> Option<Activation>;
    /// Whether a durable pending request exists.
    async fn pending(&mut self) -> bool;
}

/// How a command is served when the member repeats setup (the PWA runs every
/// action on each arrival).
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Repeat {
    /// Fully answered from existing state; nothing new is written.
    Answer(Answer),
    /// Serve this command (possibly rewritten, `open` resumes as `reopen`).
    As(Command),
}

/// An active account answers all four actions with its existing state. A durable
/// pending request means the member enrolled and opened: enrolling reports the
/// checkpoint ready and opening resumes the stored request instead of building
/// another. Otherwise the command runs as asked.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn repeat<S: Standing>(command: Command, state: &mut S) -> Repeat {
    if let Some(active) = state.active().await {
        return Repeat::Answer(match command {
            Command::Enroll => Answer::Enrolled(Enrolled {
                checkpoint: Checkpoint::Ready,
            }),
            Command::Open => Answer::Opened(Opened {
                accepted_at: active.accepted_at,
            }),
            Command::Reopen => Answer::Reopened(Opened {
                accepted_at: active.accepted_at,
            }),
            Command::Activate => Answer::Activated(active),
            Command::Join(_) => Answer::Gate(Gate {
                ready: true,
                steps: Vec::new(),
            }),
        });
    }
    match command {
        Command::Enroll if state.pending().await => Repeat::Answer(Answer::Enrolled(Enrolled {
            checkpoint: Checkpoint::Ready,
        })),
        Command::Open if state.pending().await => Repeat::As(Command::Reopen),
        other => Repeat::As(other),
    }
}

/// Whether the lobby still lists an unsatisfied admission condition. A lobby
/// without the field is never taken as satisfied.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) fn lacks(lobby: &Value) -> bool {
    lobby
        .get("missing")
        .and_then(Value::as_array)
        .is_none_or(|missing| !missing.is_empty())
}

/// The inputs the lobby offers, in the server's order. Unreadable entries are
/// left out rather than guessed.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) fn lobby_steps(lobby: &Value) -> Vec<GateStep> {
    let text = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut steps = Vec::new();
    for descriptor in lobby
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(gate), Some(provider)) = (text(descriptor, "gate"), text(descriptor, "provider"))
        else {
            continue;
        };
        for step in descriptor
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = text(step, "id") {
                steps.push(GateStep {
                    gate: gate.clone(),
                    provider: provider.clone(),
                    id,
                });
            }
        }
    }
    steps
}

type Reply = Result<Answer>;

/// The bound actor of one origin and the instant its authority ends.
pub struct AccountActor {
    actor: Actor<Command, Reply>,
    expires: u64,
}

impl AccountActor {
    pub(super) fn expired(&self, now: u64) -> bool {
        now >= self.expires || !self.actor.is_live()
    }

    pub(super) async fn call(&mut self, command: Command) -> Result<Answer> {
        self.actor
            .call(command)
            .await
            .map_err(|_| ErrorCode::Unavailable)?
    }
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub use run::AccountParts;

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod run {
    use super::super::{
        accounting::{
            existing_active, has_pending, issue_account_admission, AccountAdmission,
            AccountingIntents, CheckpointAcquisition, CommunityAccount, CurrentEnrollment,
            SubmittedEnrollment,
        },
        actor::Mailbox,
        custody::SystemClock,
        foyer::{map_error, Transport},
        passport::GlobalPassport,
    };
    use super::*;
    use ckmg::{Authority, Clock, Entropy};
    use cvlt::Records;

    /// Everything the trusted embedder lends the actor. Single-use intents are
    /// reserved up front by the recovery composer and are consumed by use.
    pub struct AccountParts<B: cwst::backend::Backend, C, E, A, R, G> {
        pub membership: cfyr::membership::LiveMembership<Transport>,
        pub policy: cfyr::policy::CurrentPolicy<Transport>,
        pub account: CommunityAccount<B, C, E, A, R>,
        pub global: GlobalPassport<B, C, E, A, R>,
        pub device: [u8; 32],
        pub intents: AccountingIntents,
        pub request_intent: ckmg::IntentAdmission,
        pub rng: G,
        pub prover: ckmg::wallet_engine::native_prover::NativeProver,
    }

    fn clock() -> u64 {
        SystemClock.now().unwrap_or(u64::MAX)
    }

    /// The actor's view of the enrollment while one admission is held.
    enum Stage<'p> {
        Admitted(AccountAdmission<'p>),
        Waiting(SubmittedEnrollment<'p>),
        Ready(CurrentEnrollment<'p>),
        Spent,
    }

    impl<'p> Stage<'p> {
        /// The held admission, whichever step it currently lives in.
        fn admission(&mut self) -> Option<&mut AccountAdmission<'p>> {
            match self {
                Self::Admitted(admission) => Some(admission),
                Self::Waiting(submitted) => Some(submitted.admission_mut()),
                Self::Ready(current) => Some(current.admission_mut()),
                Self::Spent => None,
            }
        }
    }

    /// What the actor does after answering.
    enum Next {
        /// Keep the held admission for the next action.
        Stay,
        /// Drop it; the next action starts from a fresh admission.
        Restart,
        /// Drop it and serve this same action from a fresh admission.
        Carry,
    }

    impl<B, C, E, A, R> Standing for CommunityAccount<B, C, E, A, R>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        async fn active(&mut self) -> Option<Activation> {
            existing_active(self).await.map(|done| Activation {
                version: done.version,
                accepted_at: done.accepted_at,
                outbox_settled: done.outbox_settled,
            })
        }
        async fn pending(&mut self) -> bool {
            has_pending(self).await
        }
    }

    impl AccountActor {
        /// Start the actor future. Nothing runs until the first action; it ends
        /// at `expires`, or when the Door drops it.
        pub fn start<B, C, E, A, R, G>(parts: AccountParts<B, C, E, A, R, G>, expires: u64) -> Self
        where
            B: cwst::backend::Backend + 'static,
            C: Clock + 'static,
            E: Entropy + 'static,
            A: Authority + 'static,
            R: Records + 'static,
            G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng + 'static,
        {
            Self {
                actor: Actor::new(|mailbox| run(mailbox, parts)),
                expires,
            }
        }
    }

    /// Read the lobby through the held member lease and, when something is still
    /// missing and the member brought a voucher, submit it once. The server alone
    /// decides; a voucher the lobby no longer needs is not sent.
    async fn gate(
        membership: &mut cfyr::membership::LiveMembership<Transport>,
        join: &JoinRequest,
    ) -> Result<Gate> {
        let mut lease = membership
            .observe_lease(clock)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let mut lobby = lease.lobby(clock).await.map_err(map_error)?;
        if let Some(handle) = join.handle.as_deref() {
            match lobby.get("handle").and_then(Value::as_str) {
                // Resumed: this handle is already the member's.
                Some(current) if current == handle => {}
                Some(_) => return Err(ErrorCode::Refused),
                None => {
                    // Malformed is InvalidRequest, taken is Refused.
                    if !lease
                        .handle_available(handle, clock)
                        .await
                        .map_err(map_error)?
                    {
                        return Err(ErrorCode::Refused);
                    }
                    lobby = lease
                        .reserve_handle(handle, clock)
                        .await
                        .map_err(map_error)?;
                }
            }
        }
        if let (true, Some(code)) = (lacks(&lobby), join.voucher.as_deref()) {
            lobby = lease.submit_voucher(code, clock).await.map_err(map_error)?;
        }
        Ok(Gate {
            ready: !lacks(&lobby),
            steps: lobby_steps(&lobby),
        })
    }

    async fn admit<'p, B, C, E, A, R, G>(
        membership: &mut cfyr::membership::LiveMembership<Transport>,
        policy: &'p mut cfyr::policy::CurrentPolicy<Transport>,
        global: &mut GlobalPassport<B, C, E, A, R>,
        device: [u8; 32],
        rng: &mut G,
    ) -> Result<AccountAdmission<'p>>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        let lease = membership
            .observe_lease(clock)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let challenge = lease
            .account_challenge(policy, clock)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        issue_account_admission(challenge, global, device, rng).await
    }

    async fn run<B, C, E, A, R, G>(
        mailbox: Mailbox<Command, Reply>,
        parts: AccountParts<B, C, E, A, R, G>,
    ) where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        let AccountParts {
            mut membership,
            mut policy,
            mut account,
            mut global,
            device,
            mut intents,
            mut request_intent,
            mut rng,
            prover,
        } = parts;
        let mut carried = None;
        loop {
            let first = match carried.take() {
                Some(command) => command,
                None => mailbox.next().await,
            };
            if let Command::Join(join) = &first {
                // The gates come before any admission: an active account is
                // already through them, otherwise the lobby decides.
                let reply = match repeat(first.clone(), &mut account).await {
                    Repeat::Answer(answer) => Ok(answer),
                    Repeat::As(_) => gate(&mut membership, join).await.map(Answer::Gate),
                };
                mailbox.reply(reply);
                continue;
            }
            let admission =
                match admit(&mut membership, &mut policy, &mut global, device, &mut rng).await {
                    Ok(admission) => admission,
                    Err(error) => {
                        mailbox.reply(Err(error));
                        continue;
                    }
                };
            // The credential issued with this admission is kept in the Vault
            // before anything else uses the admission; the same one is a no-op.
            if let Err(error) = account
                .store_community_credential(admission.community_credential())
                .await
            {
                mailbox.reply(Err(error));
                continue;
            }
            let mut stage = Stage::Admitted(admission);
            let mut command = first;
            loop {
                let (reply, next) = serve(
                    &mut stage,
                    command.clone(),
                    &mut account,
                    &mut intents,
                    &mut request_intent,
                    &prover,
                )
                .await;
                match next {
                    Next::Carry => {
                        carried = Some(command);
                        break;
                    }
                    Next::Restart => {
                        mailbox.reply(reply);
                        break;
                    }
                    Next::Stay => {
                        mailbox.reply(reply);
                        command = mailbox.next().await;
                    }
                }
            }
        }
    }

    /// Resolve a registered delegation into the checkpoint state.
    async fn checkpoint<'p>(
        stage: &mut Stage<'p>,
        submitted: SubmittedEnrollment<'p>,
    ) -> Result<Checkpoint> {
        match submitted.current_checkpoint().await {
            Ok(CheckpointAcquisition::Pending {
                enrollment,
                eligible_at,
            }) => {
                *stage = Stage::Waiting(enrollment);
                Ok(Checkpoint::Pending { eligible_at })
            }
            Ok(CheckpointAcquisition::Ready(current)) => {
                *stage = Stage::Ready(current);
                Ok(Checkpoint::Ready)
            }
            Err(error) => Err(error),
        }
    }

    async fn serve<'p, B, C, E, A, R>(
        stage: &mut Stage<'p>,
        command: Command,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intents: &mut AccountingIntents,
        request_intent: &mut ckmg::IntentAdmission,
        prover: &ckmg::wallet_engine::native_prover::NativeProver,
    ) -> (Reply, Next)
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let command = match repeat(command, account).await {
            Repeat::Answer(answer) => return (Ok(answer), Next::Stay),
            Repeat::As(command) => command,
        };
        match command {
            Command::Enroll => match std::mem::replace(stage, Stage::Spent) {
                Stage::Admitted(admission) => {
                    let result = async {
                        let prepared = admission.delegate(account, intents).await?;
                        let submitted = prepared.submit_for_initialization().await?;
                        checkpoint(stage, submitted).await
                    }
                    .await;
                    (
                        result.map(|checkpoint| Answer::Enrolled(Enrolled { checkpoint })),
                        Next::Stay,
                    )
                }
                Stage::Waiting(submitted) => {
                    let result = checkpoint(stage, submitted).await;
                    (
                        result.map(|checkpoint| Answer::Enrolled(Enrolled { checkpoint })),
                        Next::Stay,
                    )
                }
                Stage::Ready(current) => {
                    *stage = Stage::Ready(current);
                    (
                        Ok(Answer::Enrolled(Enrolled {
                            checkpoint: Checkpoint::Ready,
                        })),
                        Next::Stay,
                    )
                }
                Stage::Spent => (Err(ErrorCode::Unavailable), Next::Carry),
            },
            Command::Open => {
                let current = match std::mem::replace(stage, Stage::Spent) {
                    Stage::Ready(current) => current,
                    Stage::Waiting(submitted) => {
                        match checkpoint(stage, submitted).await {
                            Ok(_) => match std::mem::replace(stage, Stage::Spent) {
                                Stage::Ready(current) => current,
                                other => {
                                    // Still waiting for the next slot: keep the lease.
                                    *stage = other;
                                    return (Err(ErrorCode::Unavailable), Next::Stay);
                                }
                            },
                            Err(error) => return (Err(error), Next::Restart),
                        }
                    }
                    other => {
                        *stage = other;
                        return (Err(ErrorCode::Unavailable), Next::Stay);
                    }
                };
                // Whatever happens, the enrollment is consumed; recovery after a
                // failure is `account_reopen` from the durable state.
                let result = open(current, account, request_intent, prover).await;
                (
                    result.map(|at| Answer::Opened(Opened { accepted_at: at })),
                    Next::Restart,
                )
            }
            Command::Reopen => {
                let Some(admission) = stage.admission() else {
                    return (Err(ErrorCode::Unavailable), Next::Carry);
                };
                match admission.reopen(account).await {
                    Ok(at) => (Ok(Answer::Reopened(Opened { accepted_at: at })), Next::Stay),
                    Err(error) => (Err(error), Next::Restart),
                }
            }
            Command::Join(_) => (Err(ErrorCode::Unavailable), Next::Carry),
            Command::Activate => {
                let Some(admission) = stage.admission() else {
                    return (Err(ErrorCode::Unavailable), Next::Carry);
                };
                match admission.activate(account).await {
                    Ok(done) => (
                        Ok(Answer::Activated(Activation {
                            version: done.version,
                            accepted_at: done.accepted_at,
                            outbox_settled: done.outbox_settled,
                        })),
                        Next::Restart,
                    ),
                    Err(error) => (Err(error), Next::Restart),
                }
            }
        }
    }

    /// Prepare, prove, sign, stage state A, send and advance to state B.
    async fn open<'p, B, C, E, A, R>(
        current: CurrentEnrollment<'p>,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intent: &mut ckmg::IntentAdmission,
        prover: &ckmg::wallet_engine::native_prover::NativeProver,
    ) -> Result<u64>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let prepared = current.prepare_account(account).await?;
        let mut proven = prepared.prove(account, prover).await?;
        let staged = proven.stage(account, intent).await?;
        proven.send(account, &staged).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::actor::Mailbox;
    use super::*;

    #[test]
    fn an_answer_converts_only_to_its_own_result_type() {
        let enrolled = || {
            Answer::Enrolled(Enrolled {
                checkpoint: Checkpoint::Ready,
            })
        };
        let opened = || Answer::Opened(Opened { accepted_at: 5 });
        let reopened = || Answer::Reopened(Opened { accepted_at: 6 });
        let activated = || {
            Answer::Activated(Activation {
                version: 0,
                accepted_at: 7,
                outbox_settled: true,
            })
        };
        assert_eq!(enrolled().enrolled().unwrap().checkpoint, Checkpoint::Ready);
        assert_eq!(opened().opened().unwrap().accepted_at, 5);
        assert_eq!(reopened().reopened().unwrap().accepted_at, 6);
        assert!(activated().activated().unwrap().outbox_settled);
        for wrong in [enrolled(), reopened(), activated()] {
            assert_eq!(wrong.opened(), Err(ErrorCode::Unavailable));
        }
        for wrong in [opened(), reopened(), activated()] {
            assert_eq!(wrong.enrolled(), Err(ErrorCode::Unavailable));
        }
        for wrong in [enrolled(), opened(), activated()] {
            assert_eq!(wrong.reopened(), Err(ErrorCode::Unavailable));
        }
        for wrong in [enrolled(), opened(), reopened()] {
            assert_eq!(wrong.activated(), Err(ErrorCode::Unavailable));
        }
    }

    #[test]
    fn the_actor_handle_expires_with_its_grant_or_when_the_actor_ends() {
        let live = AccountActor {
            actor: Actor::new(|mailbox: Mailbox<Command, Reply>| async move {
                loop {
                    let _ = mailbox.next().await;
                }
            }),
            expires: 100,
        };
        assert!(!live.expired(99));
        assert!(live.expired(100));
        let mut ended = AccountActor {
            actor: Actor::new(|_: Mailbox<Command, Reply>| async {}),
            expires: u64::MAX,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let mut call = Box::pin(ended.call(Command::Open));
        assert_eq!(
            std::future::Future::poll(call.as_mut(), &mut cx),
            std::task::Poll::Ready(Err(ErrorCode::Unavailable))
        );
        drop(call);
        assert!(ended.expired(0));
    }

    /// A standing double that counts every probe; it has no write at all, so a
    /// repeated action provably cannot create state through this seam.
    struct Fake {
        active: Option<Activation>,
        pending: bool,
        probes: usize,
    }
    impl Standing for Fake {
        async fn active(&mut self) -> Option<Activation> {
            self.probes += 1;
            self.active.clone()
        }
        async fn pending(&mut self) -> bool {
            self.probes += 1;
            self.pending
        }
    }
    fn done() -> Activation {
        Activation {
            version: 0,
            accepted_at: 7,
            outbox_settled: true,
        }
    }
    fn block<T>(future: impl std::future::Future<Output = T>) -> T {
        futures_executor::block_on(future)
    }
    fn all() -> [Command; 5] {
        [
            Command::Enroll,
            Command::Open,
            Command::Reopen,
            Command::Activate,
            Command::Join(JoinRequest {
                voucher: Some("cvch1.x".into()),
                handle: Some("h".into()),
            }),
        ]
    }

    #[test]
    fn every_action_repeated_on_an_active_account_returns_the_same_existing_state() {
        let mut state = Fake {
            active: Some(done()),
            pending: true,
            probes: 0,
        };
        for command in all() {
            let first = block(repeat(command.clone(), &mut state));
            let second = block(repeat(command, &mut state));
            assert_eq!(first, second);
            assert!(matches!(first, Repeat::Answer(_)));
        }
        assert_eq!(
            block(repeat(Command::Activate, &mut state)),
            Repeat::Answer(Answer::Activated(done()))
        );
        assert_eq!(
            block(repeat(Command::Open, &mut state)),
            Repeat::Answer(Answer::Opened(Opened { accepted_at: 7 }))
        );
        assert_eq!(
            block(repeat(Command::Reopen, &mut state)),
            Repeat::Answer(Answer::Reopened(Opened { accepted_at: 7 }))
        );
        assert_eq!(
            block(repeat(Command::Enroll, &mut state)),
            Repeat::Answer(Answer::Enrolled(Enrolled {
                checkpoint: Checkpoint::Ready
            }))
        );
    }

    #[test]
    fn a_durable_pending_request_makes_enroll_ready_and_open_resume_as_reopen() {
        let mut state = Fake {
            active: None,
            pending: true,
            probes: 0,
        };
        assert_eq!(
            block(repeat(Command::Enroll, &mut state)),
            Repeat::Answer(Answer::Enrolled(Enrolled {
                checkpoint: Checkpoint::Ready
            }))
        );
        assert_eq!(
            block(repeat(Command::Open, &mut state)),
            Repeat::As(Command::Reopen)
        );
        assert_eq!(
            block(repeat(Command::Reopen, &mut state)),
            Repeat::As(Command::Reopen)
        );
        assert_eq!(
            block(repeat(Command::Activate, &mut state)),
            Repeat::As(Command::Activate)
        );
    }

    #[test]
    fn a_first_run_without_state_serves_each_action_as_asked() {
        let mut state = Fake {
            active: None,
            pending: false,
            probes: 0,
        };
        for command in all() {
            assert_eq!(
                block(repeat(command.clone(), &mut state)),
                Repeat::As(command)
            );
        }
        assert!(state.probes > 0);
    }

    #[test]
    fn an_active_account_is_through_the_gates_and_a_first_run_asks_the_lobby() {
        let mut active = Fake {
            active: Some(done()),
            pending: false,
            probes: 0,
        };
        assert_eq!(
            block(repeat(Command::Join(JoinRequest::default()), &mut active)),
            Repeat::Answer(Answer::Gate(Gate {
                ready: true,
                steps: Vec::new()
            }))
        );
        let mut fresh = Fake {
            active: None,
            pending: true,
            probes: 0,
        };
        // A durable pending request does not skip the gates: only an active
        // account does, because the lobby is the server's to answer.
        assert_eq!(
            block(repeat(Command::Join(JoinRequest::default()), &mut fresh)),
            Repeat::As(Command::Join(JoinRequest::default()))
        );
    }

    #[test]
    fn the_lobby_is_read_strictly_and_steps_keep_the_servers_order() {
        use serde_json::json;
        assert!(lacks(&json!({})));
        assert!(lacks(&json!({"missing": [{"kind": "gates"}]})));
        assert!(!lacks(&json!({"missing": []})));
        let lobby = json!({
            "steps": [
                {"gate": "voucher", "provider": "sponsor", "steps": [{"id": "code"}, {"id": 7}]},
                {"provider": "no-gate", "steps": [{"id": "x"}]},
                {"gate": "pow", "provider": "local", "steps": [{"id": "solve"}]}
            ]
        });
        let ids: Vec<_> = lobby_steps(&lobby)
            .into_iter()
            .map(|step| (step.gate, step.provider, step.id))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("voucher".into(), "sponsor".into(), "code".into()),
                ("pow".into(), "local".into(), "solve".into())
            ]
        );
        assert!(lobby_steps(&json!({"steps": "bad"})).is_empty());
    }
}
