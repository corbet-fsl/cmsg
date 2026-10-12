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

/// The four actions. A command carries no data: nothing about the account, the
/// request or the policy is chosen by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Command {
    Enroll,
    Open,
    Reopen,
    Activate,
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
        foyer::Transport,
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
            let admission =
                match admit(&mut membership, &mut policy, &mut global, device, &mut rng).await {
                    Ok(admission) => admission,
                    Err(error) => {
                        mailbox.reply(Err(error));
                        continue;
                    }
                };
            let mut stage = Stage::Admitted(admission);
            let mut command = first;
            loop {
                let (reply, next) = serve(
                    &mut stage,
                    command,
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
        // Idempotent setup: a returning member repeats every action. An active
        // account answers all four with its existing state and changes nothing.
        if let Some(active) = existing_active(account).await {
            let reply = match command {
                Command::Enroll => Answer::Enrolled(Enrolled {
                    checkpoint: Checkpoint::Ready,
                }),
                Command::Open => Answer::Opened(Opened {
                    accepted_at: active.accepted_at,
                }),
                Command::Reopen => Answer::Reopened(Opened {
                    accepted_at: active.accepted_at,
                }),
                Command::Activate => Answer::Activated(Activation {
                    version: active.version,
                    accepted_at: active.accepted_at,
                    outbox_settled: active.outbox_settled,
                }),
            };
            return (Ok(reply), Next::Stay);
        }
        // A durable pending request means this member already enrolled and
        // opened: enrolling reports the checkpoint as ready and opening resumes
        // the stored request (byte-identical resend) instead of building another.
        let command = match command {
            Command::Open if has_pending(account).await => Command::Reopen,
            other => other,
        };
        if command == Command::Enroll && has_pending(account).await {
            return (
                Ok(Answer::Enrolled(Enrolled {
                    checkpoint: Checkpoint::Ready,
                })),
                Next::Stay,
            );
        }
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
}
