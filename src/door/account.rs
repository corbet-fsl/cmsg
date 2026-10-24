//! Account lifecycle actions, served by one per-origin account actor.
//!
//! The actor owns the current-policy borrow, the held HTTPS lease and the
//! prepared or pending account across the user-visible actions. Foyer stays the
//! only owner of Charter and Follower; the actor never receives a policy handle
//! of its own beyond the one the trusted embedder lends it. Exactly one action is
//! in flight (the Door dispatcher is `&mut`), the actor ends with its grant,
//! logout or shutdown, and no secret crosses a message: commands carry nothing
//! and replies carry only counters and times.
use super::accounting::ProvenUpdate;
use super::actor::Actor;
use super::*;

mod update;
pub use update::{Applied, Shared};

/// The account actor's prover, lent by the embedder (decision 2026-10-22): a native device
/// lends its bounded `NativeProver`; a browser lends its `BrowserProver` (a Web Worker on the
/// wallet origin, `browser::prover::lend`) and [`RefusingProver`] only while none is
/// configured. The port only answers which prover a proof runs on; the proof itself stays
/// inside the account vault.
pub trait AccountProver: Send + Sync {
    /// The prover of an account open's genesis proof, or the build's honest refusal.
    fn genesis(&self) -> Result<GenesisProver<'_>>;
}

/// What a genesis proof runs on. A build without the native prover has no inhabited variant.
pub enum GenesisProver<'a> {
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    Native(&'a ckmg::wallet_engine::native_prover::NativeProver),
    /// The browser prover: the private input goes to a Web Worker behind the engine's port.
    #[cfg(feature = "browser-prover")]
    Browser(&'a ckmg::wallet_engine::browser_prover::BrowserProver),
    #[doc(hidden)]
    None(std::convert::Infallible, std::marker::PhantomData<&'a ()>),
}

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
impl AccountProver for ckmg::wallet_engine::native_prover::NativeProver {
    fn genesis(&self) -> Result<GenesisProver<'_>> {
        Ok(GenesisProver::Native(self))
    }
}

#[cfg(feature = "browser-prover")]
impl AccountProver for ckmg::wallet_engine::browser_prover::BrowserProver {
    fn genesis(&self) -> Result<GenesisProver<'_>> {
        Ok(GenesisProver::Browser(self))
    }
}

/// The port of a build that lends no prover (a browser build whose wallet origin has not
/// configured the browser prover, see `door::browser::prover::lend`): every proof is refused
/// with `Unavailable` before any vault or network step; nothing is faked.
pub struct RefusingProver;

impl AccountProver for RefusingProver {
    fn genesis(&self) -> Result<GenesisProver<'_>> {
        Err(ErrorCode::Unavailable)
    }
}

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

/// Body of `community_join`. The voucher is the member's own link text (the part
/// after `#`, `cvch3.` and hex); it is needed only while the community's lobby still asks for it. The handle is the
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
    /// Remember the creation id of the claim this member made; the next admission
    /// presents it. Carries the id only, which is bound to the claimed member.
    Creation(String),
    /// Send a proven update through the held account (trusted embedding only).
    Update(Shared<ProvenUpdate>),
    /// Finish the update that is still owed, if any.
    Resume,
    /// The caller applied the acceptance of this request: forget the stored bytes.
    Settle([u8; 32]),
    /// Background record job, step 1: begin this epoch's record unless it is
    /// cached (the trusted embedding's record configuration rides along).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    RecordPrepare(Shared<super::record::RecordJob>),
    /// Background record job, step 2: commit the proof made off the actor.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    RecordFinish(Shared<std::cell::Cell<Option<super::record::RecordProof>>>),
    /// Wave wallet: reopen the account witness under this verified current roster.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    WitnessLoad(Shared<std::sync::Arc<ckmg::wallet_engine::account::Checkpoint>>),
    /// Wave wallet: make this accepted witness state the durable one.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    WitnessStore(Shared<ckmg::wallet_engine::account::Account>),
    /// Wave wallet: the verified current common roster, read through a fresh
    /// admission of this active member (never from a cache of the actor).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    Roster,
    /// How many vouchers the accepted account may still hand out in this sponsor
    /// role (member 0, admin 1, root 2), read from its committed state. Reads only.
    VoucherRemaining(u8),
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
    /// The creation id was noted for the next admission.
    Noted,
    /// The operator accepted the update.
    Updated(Shared<Applied>),
    /// The acceptance of the owed update, or nothing was owed.
    Owed(Option<Shared<Applied>>),
    /// The stored update was forgotten.
    Settled,
    /// Record job: the work to prove off the actor, or nothing (cached).
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    RecordWork(
        super::record::RecordWindow,
        Option<Shared<std::cell::Cell<Option<super::record::RecordWork>>>>,
    ),
    /// Record job: the epoch's record is cached.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    RecordCached,
    /// Wave wallet: the reopened account witness.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    Witness(Shared<ckmg::wallet_engine::account::Account>),
    /// Wave wallet: the witness state is durable.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    WitnessStored,
    /// Wave wallet: the verified current common roster.
    #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
    Roster(Shared<super::accounting::VerifiedRoster>),
    /// Vouchers the account may still hand out (before the device's open links).
    Remaining(u64),
    /// Open was refused after the checkpoint slot its proof was bound to had ended
    /// (`eligible_at` = that slot's end): a crossed scheduled boundary. The join
    /// restarts enrollment and Open as a fresh operation (`enroll_and_open`).
    SlotCrossed {
        eligible_at: u64,
    },
    /// Open overran the genesis proof window: the device refused to sign or send
    /// the elapsed request, or the operator refused it with the reason expired.
    /// The join re-prepares as a fresh operation at most `GENESIS_REPREPARES` times.
    WindowElapsed,
    /// Reopen found the elapsed state A and the operator's signed status proved it
    /// can no longer commit: it is discarded, the join prepares a fresh request.
    Discarded,
    /// Reopen found the elapsed state A too early for the operator's time to prove
    /// it; the join reports `checkpoint_pending` until this operator time.
    ElapsedPending {
        eligible_at: u64,
    },
}

macro_rules! accessor {
    ($name:ident, $variant:ident, $type:ty) => {
        pub(super) fn $name(self) -> Result<$type> {
            match self {
                Self::$variant(value) => Ok(value),
                // A crossed slot not restarted is the refusal it replaced.
                Self::SlotCrossed { .. } => Err(ErrorCode::Unauthorized),
                Self::WindowElapsed => Err(ErrorCode::ProofWindowElapsed),
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
    accessor!(updated, Updated, Shared<Applied>);
    accessor!(owed, Owed, Option<Shared<Applied>>);
    accessor!(remaining, Remaining, u64);

    /// The open step answers `Opened`, or `Reopened` when a pending request was
    /// resumed; either way the request is accepted.
    pub(super) fn opened_or_reopened(self) -> Result<Opened> {
        match self {
            Self::Opened(value) | Self::Reopened(value) => Ok(value),
            Self::SlotCrossed { .. } => Err(ErrorCode::Unauthorized),
            Self::WindowElapsed => Err(ErrorCode::ProofWindowElapsed),
            _ => Err(ErrorCode::Unavailable),
        }
    }
}

/// The outcome of Open, judged at `now` against the end of the checkpoint slot its
/// proof was bound to. A refusal once that slot has ended is the crossed scheduled
/// boundary (the device refresh refuses the next slot's publication), not a verdict
/// on the member: it becomes `SlotCrossed`, which the join restarts.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
fn open_outcome(result: Result<u64>, slot_end: u64, now: u64) -> Result<Answer> {
    match result {
        Ok(accepted_at) => Ok(Answer::Opened(Opened { accepted_at })),
        Err(ErrorCode::ProofWindowElapsed) => Ok(Answer::WindowElapsed),
        Err(ErrorCode::Unauthorized) if now >= slot_end => Ok(Answer::SlotCrossed {
            eligible_at: slot_end,
        }),
        Err(error) => Err(error),
    }
}

/// How often one join restarts a crossed checkpoint slot as a fresh operation.
pub(super) const SLOT_RESTARTS: usize = 2;

/// How often one join re-prepares after an overrun of the genesis proof window.
/// A second overrun surfaces `ProofWindowElapsed`.
pub(super) const GENESIS_REPREPARES: usize = 1;

/// The account steps a join runs after its gate, one command at a time.
pub(super) trait Steps {
    async fn call(&mut self, command: Command) -> Result<Answer>;
}

/// Enroll, then open. A crossed checkpoint slot restarts both as a fresh operation
/// (a fresh admission, delegation and proof; the old one is spent), at most
/// `SLOT_RESTARTS` times. When the fresh enrollment waits for the next slot, the
/// answer is `Pending`: the join reports `checkpoint_pending` meanwhile and the
/// next join continues. Any other refusal ends the join as before.
pub(super) async fn enroll_and_open(steps: &mut impl Steps) -> Result<Checkpoint> {
    let mut restarts = 0;
    let mut reprepares = 0;
    loop {
        let checkpoint = steps.call(Command::Enroll).await?.enrolled()?.checkpoint;
        if let Checkpoint::Pending { .. } = checkpoint {
            return Ok(checkpoint);
        }
        match steps.call(Command::Open).await? {
            Answer::SlotCrossed { .. } if restarts < SLOT_RESTARTS => restarts += 1,
            Answer::WindowElapsed if reprepares < GENESIS_REPREPARES => reprepares += 1,
            // The elapsed state A of the previous attempt is gone; the re-prepare
            // counted above follows now (a discard needs a state A, so this ends).
            Answer::Discarded => {}
            Answer::ElapsedPending { eligible_at } => {
                return Ok(Checkpoint::Pending { eligible_at })
            }
            answer => {
                answer.opened_or_reopened()?;
                return Ok(Checkpoint::Ready);
            }
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
/// Commands with their own path in the actor (never answered from standing).
fn own_path(command: &Command) -> bool {
    match command {
        Command::Update(_)
        | Command::Resume
        | Command::Settle(_)
        | Command::Join(_)
        | Command::VoucherRemaining(_) => true,
        #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
        Command::RecordPrepare(_)
        | Command::RecordFinish(_)
        | Command::WitnessLoad(_)
        | Command::WitnessStore(_)
        | Command::Roster => true,
        _ => false,
    }
}

pub(super) async fn repeat<S: Standing>(command: Command, state: &mut S) -> Repeat {
    // Updates have their own path, and the lobby is asked again on every join:
    // an active member whose community changed its gates is held there.
    if own_path(&command) {
        return Repeat::As(command);
    }
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
            Command::Creation(_) => Answer::Noted,
            Command::Join(_)
            | Command::Update(_)
            | Command::Resume
            | Command::Settle(_)
            | Command::VoucherRemaining(_) => {
                unreachable!("returned above")
            }
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            Command::RecordPrepare(_)
            | Command::RecordFinish(_)
            | Command::WitnessLoad(_)
            | Command::WitnessStore(_)
            | Command::Roster => unreachable!("returned above"),
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

/// The answer to `command` from the existing state alone, asked BEFORE any
/// fresh admission. `Some` means the actor replies without admitting; `None`
/// means the command needs an admission (it may still be rewritten later, as
/// `open` resumes as `reopen`).
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn before_admission<S: Standing>(
    command: &Command,
    state: &mut S,
) -> Option<Answer> {
    match repeat(command.clone(), state).await {
        Repeat::Answer(answer) => Some(answer),
        Repeat::As(_) => None,
    }
}

/// The lobby of the community, as far as a join needs it.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) trait Lobby {
    async fn gate(&mut self, join: &JoinRequest) -> Result<Gate>;
}

/// Pass the gates. The lobby is asked every time, also for an active account: a
/// member whose community changed its gates is held there (`ready` false) until
/// the new steps are done, and then continues through the same resumable steps.
/// When the lobby cannot be reached an ACTIVE account keeps working: the server
/// is the authority (it refuses every non-lobby action of a member held in the
/// lobby with `HeldInLobby`), so an unreachable lobby must not lock active
/// members out. A new account still needs the lobby, so it fails closed.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) async fn join<L: Lobby>(
    lobby: &mut L,
    request: &JoinRequest,
    active: bool,
) -> Result<Answer> {
    match lobby.gate(request).await {
        Ok(gate) => Ok(Answer::Gate(gate)),
        Err(ErrorCode::Unavailable) if active => Ok(Answer::Gate(Gate {
            ready: true,
            steps: Vec::new(),
        })),
        Err(error) => Err(error),
    }
}

/// Whether the lobby still lists an unsatisfied admission condition. When the
/// lobby says a passport is required, the global requirements it lists are
/// proven by that fresh passport at admission, so a gate group counts each of
/// them as passed; the server alone decides at admission. A lobby without the
/// field, or an entry this device cannot read, is never taken as satisfied.
#[cfg_attr(
    not(all(feature = "native-prover", not(target_arch = "wasm32"))),
    allow(dead_code)
)]
pub(super) fn lacks(lobby: &Value) -> bool {
    let Some(missing) = lobby.get("missing").and_then(Value::as_array) else {
        return true;
    };
    let passport = lobby.get("passport_required").and_then(Value::as_bool) == Some(true);
    missing.iter().any(|entry| {
        let needed = entry.get("needed").and_then(Value::as_u64);
        let (true, Some("gates"), Some(needed)) =
            (passport, entry.get("kind").and_then(Value::as_str), needed)
        else {
            return true;
        };
        let global = entry
            .get("alternatives")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|alternative| {
                alternative["requirement"]["level"].as_str() == Some("global")
                    && alternative["reason"].as_str() == Some("proof_required")
            })
            .count();
        needed > global as u64
    })
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
pub use run::{bind_account_actor, bind_native_account, AccountParts};

#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
mod run {
    use super::super::vouching::Book;
    use super::super::{
        accounting::{
            existing_active, has_pending, issue_account_admission, voucher_remaining,
            AcceptedResponse, AccountAdmission, AccountingIntents, CheckpointAcquisition,
            CommunityAccount, CurrentEnrollment, Elapsed, SignedApplyExtended, SubmittedEnrollment,
        },
        actor::Mailbox,
        custody::SystemClock,
        foyer::{map_error, Transport},
        passport::GlobalPassport,
    };
    use super::update::{self, Credentials, UpdateStore, UpdateWire};
    use super::*;
    use ckmg::{Authority, Clock, Entropy};
    use cvlt::Records;

    /// Everything the trusted embedder lends the actor. Single-use intents are
    /// reserved up front by the recovery composer and are consumed by use.
    pub struct AccountParts<
        B: cwst::backend::Backend,
        C,
        E,
        A,
        R,
        GB: cwst::backend::Backend,
        GC,
        GE,
        GA,
        GR,
        G,
    > {
        pub membership: cfyr::membership::LiveMembership<Transport>,
        pub policy: cfyr::policy::CurrentPolicy<Transport>,
        pub account: CommunityAccount<B, C, E, A, R>,
        pub global: GlobalPassport<GB, GC, GE, GA, GR>,
        pub device: [u8; 32],
        pub intents: AccountingIntents,
        pub request_intent: ckmg::IntentAdmission,
        pub rng: G,
        pub prover: std::sync::Arc<dyn AccountProver>,
    }

    fn clock() -> u64 {
        SystemClock.now().unwrap_or(u64::MAX)
    }

    /// Name the step that refused (error codes only, never request data) on stderr
    /// of the embedding process, so an `unavailable` answer says where it came from.
    fn trace(step: &'static str) -> impl FnOnce(ErrorCode) -> ErrorCode {
        move |error| {
            eprintln!("account actor: {step}: {error:?}");
            error
        }
    }

    /// Write the voucher custody when it changed; the compare-and-swap value for
    /// the next write is returned.
    async fn save_book<B, C, E, A, R>(
        account: &mut CommunityAccount<B, C, E, A, R>,
        raw: Option<Zeroizing<Vec<u8>>>,
        book: &Book,
    ) -> Result<Option<Zeroizing<Vec<u8>>>>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let encoded = book.encode()?;
        if raw.as_deref().map(Vec::as_slice) == Some(encoded.as_slice()) {
            return Ok(raw);
        }
        account
            .replace_voucher_custody(raw.as_deref().map(Vec::as_slice), &encoded)
            .await?;
        Ok(Some(encoded))
    }

    /// The owed update lives in its own Vault record (never the voucher book),
    /// written by compare-and-swap like every other custody change.
    struct Custodian<'a, B: cwst::backend::Backend, C, E, A, R>(
        &'a mut CommunityAccount<B, C, E, A, R>,
    );

    impl<B, C, E, A, R> UpdateStore for Custodian<'_, B, C, E, A, R>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        async fn stored(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.0.update_outbox().await?.map(|bytes| bytes.to_vec()))
        }
        async fn persist(&mut self, outbox: &[u8]) -> Result<()> {
            if outbox.is_empty() {
                return Err(ErrorCode::Refused);
            }
            let current = self.0.update_outbox().await?;
            self.0
                .replace_update_outbox(current.as_deref().map(Vec::as_slice), outbox)
                .await
        }
        async fn clear(&mut self) -> Result<()> {
            let current = self.0.update_outbox().await?;
            self.0
                .replace_update_outbox(current.as_deref().map(Vec::as_slice), &[])
                .await
        }
    }

    /// One fresh admission with the account and the single-use intents: the
    /// whole update protocol for one call.
    struct Live<'a, 'p, B: cwst::backend::Backend, C, E, A, R> {
        admission: &'a mut AccountAdmission<'p>,
        account: &'a mut CommunityAccount<B, C, E, A, R>,
        intents: &'a mut AccountingIntents,
    }

    impl<B, C, E, A, R> UpdateStore for Live<'_, '_, B, C, E, A, R>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        async fn stored(&mut self) -> Result<Option<Vec<u8>>> {
            Custodian(&mut *self.account).stored().await
        }
        async fn persist(&mut self, outbox: &[u8]) -> Result<()> {
            Custodian(&mut *self.account).persist(outbox).await
        }
        async fn clear(&mut self) -> Result<()> {
            Custodian(&mut *self.account).clear().await
        }
    }

    impl<B, C, E, A, R> UpdateWire for Live<'_, '_, B, C, E, A, R>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        async fn sign(&mut self, proven: &ProvenUpdate) -> Result<SignedApplyExtended> {
            self.admission
                .sign_update_request(self.account, proven, self.intents)
                .await
        }
        async fn restore(&mut self, outbox: Vec<u8>) -> Result<SignedApplyExtended> {
            self.admission.restore_signed(outbox)
        }
        async fn send(&mut self, signed: &SignedApplyExtended) -> Result<AcceptedResponse> {
            self.admission.send_signed(signed).await
        }
    }

    /// The lobby through the held member lease.
    struct Asking<'a, B: cwst::backend::Backend, C, E, A, R> {
        membership: &'a mut cfyr::membership::LiveMembership<Transport>,
        account: &'a mut CommunityAccount<B, C, E, A, R>,
    }

    impl<B, C, E, A, R> Lobby for Asking<'_, B, C, E, A, R>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        async fn gate(&mut self, request: &JoinRequest) -> Result<Gate> {
            gate(self.membership, self.account, request).await
        }
    }

    /// Everything one fresh admission needs.
    struct Fresh<
        'a,
        B: cwst::backend::Backend,
        C,
        E,
        A,
        R,
        GB: cwst::backend::Backend,
        GC,
        GE,
        GA,
        GR,
        G,
    > {
        membership: &'a mut cfyr::membership::LiveMembership<Transport>,
        policy: &'a mut cfyr::policy::CurrentPolicy<Transport>,
        account: &'a mut CommunityAccount<B, C, E, A, R>,
        global: &'a mut GlobalPassport<GB, GC, GE, GA, GR>,
        device: [u8; 32],
        rng: &'a mut G,
        creation: Option<&'a str>,
    }

    impl<B, C, E, A, R, GB, GC, GE, GA, GR, G> Credentials
        for Fresh<'_, B, C, E, A, R, GB, GC, GE, GA, GR, G>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        GB: cwst::backend::Backend,
        GC: Clock,
        GE: Entropy,
        GA: Authority,
        GR: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        async fn stored(&mut self) -> Result<Option<Vec<u8>>> {
            self.account.stored_community_credential().await
        }
        async fn renew(&mut self) -> Result<()> {
            let admission = admit(
                self.membership,
                self.policy,
                self.global,
                self.device,
                self.rng,
                self.creation,
            )
            .await?;
            self.account
                .store_community_credential(admission.community_credential())
                .await
        }
    }

    /// What an update call asks of one fresh admission.
    enum Task<'a> {
        Apply(&'a ProvenUpdate),
        Resume,
    }

    /// Run an update task through a fresh admission (signed once, stored before
    /// the send, re-sent unchanged on retry).
    async fn update_flow<B, C, E, A, R, GB, GC, GE, GA, GR, G>(
        task: Task<'_>,
        parts: &mut Fresh<'_, B, C, E, A, R, GB, GC, GE, GA, GR, G>,
        intents: &mut AccountingIntents,
    ) -> Result<Option<Shared<Applied>>>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        GB: cwst::backend::Backend,
        GC: Clock,
        GE: Entropy,
        GA: Authority,
        GR: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        if matches!(task, Task::Resume) && Custodian(&mut *parts.account).stored().await?.is_none()
        {
            return Ok(None);
        }
        let mut admission = admit(
            &mut *parts.membership,
            &mut *parts.policy,
            &mut *parts.global,
            parts.device,
            &mut *parts.rng,
            parts.creation,
        )
        .await?;
        parts
            .account
            .store_community_credential(admission.community_credential())
            .await?;
        let mut live = Live {
            admission: &mut admission,
            account: &mut *parts.account,
            intents,
        };
        match task {
            Task::Apply(proven) => update::apply(&mut live, proven)
                .await
                .map(|applied| Some(Shared::new(applied))),
            Task::Resume => update::resume(&mut live)
                .await
                .map(|applied| applied.map(Shared::new)),
        }
    }

    /// Register the account's record recipient under one fresh admission.
    async fn record_recipient<B, C, E, A, R, GB, GC, GE, GA, GR, G>(
        parts: &mut Fresh<'_, B, C, E, A, R, GB, GC, GE, GA, GR, G>,
        intents: &mut AccountingIntents,
    ) -> Result<()>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        GB: cwst::backend::Backend,
        GC: Clock,
        GE: Entropy,
        GA: Authority,
        GR: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        let mut admission = admit(
            &mut *parts.membership,
            &mut *parts.policy,
            &mut *parts.global,
            parts.device,
            &mut *parts.rng,
            parts.creation,
        )
        .await?;
        parts
            .account
            .store_community_credential(admission.community_credential())
            .await?;
        admission
            .register_record_recipient(&mut *parts.account, intents)
            .await
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
        pub fn start<B, C, E, A, R, GB, GC, GE, GA, GR, G>(
            parts: AccountParts<B, C, E, A, R, GB, GC, GE, GA, GR, G>,
            expires: u64,
        ) -> Self
        where
            B: cwst::backend::Backend + 'static,
            C: Clock + 'static,
            E: Entropy + 'static,
            A: Authority + 'static,
            R: Records + 'static,
            GB: cwst::backend::Backend + 'static,
            GC: Clock + 'static,
            GE: Entropy + 'static,
            GA: Authority + 'static,
            GR: Records + 'static,
            G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng + 'static,
        {
            Self {
                actor: Actor::new(|mailbox| run(mailbox, parts)),
                expires,
            }
        }
    }

    /// Start the actor from complete parts and bind it to the member origin.
    pub fn bind_account_actor<B, C, E, A, R, GB, GC, GE, GA, GR>(
        door: &mut super::super::Door,
        origin: &str,
        parts: AccountParts<B, C, E, A, R, GB, GC, GE, GA, GR, cwlt::passport::rand::rngs::OsRng>,
        expires: u64,
    ) -> super::super::Result<()>
    where
        B: cwst::backend::Backend + 'static,
        C: Clock + 'static,
        E: Entropy + 'static,
        A: Authority + 'static,
        R: Records + 'static,
        GB: cwst::backend::Backend + 'static,
        GC: Clock + 'static,
        GE: Entropy + 'static,
        GA: Authority + 'static,
        GR: Records + 'static,
    {
        door.bind_account(origin, AccountActor::start(parts, expires))
    }

    /// Production composer of the native path: recover the community account
    /// from the original recovery owners, reserve the THREE distinct single-use
    /// intents (root, device delegation, account request; each admits exactly
    /// one signature), start the account actor and bind it to the member origin.
    /// `community_join` and the account actions work on a native device only
    /// after this runs. The actor ends with the recovery lease (`intents.expires`).
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_native_account<B, N>(
        door: &mut super::super::Door,
        origin: &str,
        owners: super::super::custody::InitialRecoveryOwners<'static, 'static, N>,
        // The actor's own authenticated community session. The recovery lease holds the
        // Door's session for the Vault's whole life; admissions need an independent one.
        membership: cfyr::membership::LiveMembership<Transport>,
        policy: cfyr::policy::CurrentPolicy<Transport>,
        network: N,
        backend: B,
        global: GlobalPassport<
            B,
            SystemClock,
            ckmg::SystemEntropy,
            super::super::custody::InitialRecoveryAuthority<'static, 'static, SystemClock, N>,
            cvlt::PasskeyRecords<cvlt::TorPasskeyRecord<'static, N>>,
        >,
        device: [u8; 32],
        prover: std::sync::Arc<dyn AccountProver>,
    ) -> super::super::Result<()>
    where
        B: cwst::backend::Backend + 'static,
        N: cdht::Network + Clone + 'static,
    {
        let (owners, intents, request_intent) = owners.with_accounting_intents()?;
        let account = owners.open_community_account(network, backend).await?;
        let expires = intents.expires;
        let actor = AccountActor::start(
            AccountParts {
                membership,
                policy,
                account,
                global,
                device,
                intents,
                request_intent,
                rng: cwlt::passport::rand::rngs::OsRng,
                prover,
            },
            expires,
        );
        door.bind_account(origin, actor)
    }

    /// Read the lobby through the held member lease and, when something is still
    /// missing and the member brought a voucher, submit it once. The server alone
    /// decides; a voucher the lobby no longer needs is not sent.
    async fn gate<B, C, E, A, R>(
        membership: &mut cfyr::membership::LiveMembership<Transport>,
        account: &mut CommunityAccount<B, C, E, A, R>,
        join: &JoinRequest,
    ) -> Result<Gate>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
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
            // The bond nonce is chosen once per link and kept in the Vault for
            // every retry, even after a restart: the issuer's device derives
            // the bond from the first notice it receives. It is saved before it
            // is used, and the bond is saved as soon as it exists.
            let raw = account.voucher_custody().await?;
            let mut book = Book::decode(raw.as_deref().map(Vec::as_slice))?;
            let nonce = book.nonce_for(code)?;
            let mut written = save_book(account, raw, &book).await?;
            let redeemed = lease
                .submit_voucher(
                    code,
                    join.handle.as_deref(),
                    nonce,
                    &book.package_for(code),
                    clock,
                )
                .await
                .map_err(map_error)?;
            book.add_vouchee_bond(code, &redeemed.bond)?;
            save_book(account, written.take(), &book).await?;
            lobby = redeemed.lobby;
        }
        Ok(Gate {
            ready: !lacks(&lobby),
            steps: lobby_steps(&lobby),
        })
    }

    async fn admit<'p, GB, GC, GE, GA, GR, G>(
        membership: &mut cfyr::membership::LiveMembership<Transport>,
        policy: &'p mut cfyr::policy::CurrentPolicy<Transport>,
        global: &mut GlobalPassport<GB, GC, GE, GA, GR>,
        device: [u8; 32],
        rng: &mut G,
        creation: Option<&str>,
    ) -> Result<AccountAdmission<'p>>
    where
        GB: cwst::backend::Backend,
        GC: Clock,
        GE: Entropy,
        GA: Authority,
        GR: Records,
        G: cwlt::passport::rand::RngCore + cwlt::passport::rand::CryptoRng,
    {
        let lease = membership.observe_lease(clock).await.map_err(|error| {
            eprintln!("account actor: lease observe: {error:?}");
            ErrorCode::Unavailable
        })?;
        let challenge = lease
            .account_challenge(policy, clock)
            .await
            .map_err(|error| {
                eprintln!("account actor: account challenge: {error:?}");
                ErrorCode::Reconcile
            })?;
        issue_account_admission(challenge, global, device, rng, creation).await
    }

    async fn run<B, C, E, A, R, GB, GC, GE, GA, GR, G>(
        mailbox: Mailbox<Command, Reply>,
        parts: AccountParts<B, C, E, A, R, GB, GC, GE, GA, GR, G>,
    ) where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
        GB: cwst::backend::Backend,
        GC: Clock,
        GE: Entropy,
        GA: Authority,
        GR: Records,
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
        let mut creation: Option<String> = None;
        // The accepted update whose settlement the caller has not confirmed.
        let mut owed: Option<Shared<Applied>> = None;
        loop {
            let first = match carried.take() {
                Some(command) => command,
                None => mailbox.next().await,
            };
            if let Command::Creation(id) = &first {
                creation = Some(id.clone());
                mailbox.reply(Ok(Answer::Noted));
                continue;
            }
            if let Command::Join(request) = &first {
                // The gates come before any admission, and the lobby decides
                // every time, also for an active member whose gates changed.
                let active_account = existing_active(&mut account).await.is_some();
                let mut reply = join(
                    &mut Asking {
                        membership: &mut membership,
                        account: &mut account,
                    },
                    request,
                    active_account,
                )
                .await;
                let through = matches!(&reply, Ok(Answer::Gate(Gate { ready: true, .. })))
                    && existing_active(&mut account).await.is_some();
                if through {
                    // Login chores of an active member: a credential about to
                    // end is renewed, and an update whose answer was lost is
                    // finished (its acceptance waits for `Resume`).
                    let mut parts = Fresh {
                        membership: &mut membership,
                        policy: &mut policy,
                        account: &mut account,
                        global: &mut global,
                        device,
                        rng: &mut rng,
                        creation: creation.as_deref(),
                    };
                    if let Err(error) = update::renew_on_login(&mut parts, clock()).await {
                        reply = Err(error);
                    } else if owed.is_none() {
                        owed = update_flow(Task::Resume, &mut parts, &mut intents)
                            .await
                            .ok()
                            .flatten();
                    }
                    // The ledger seals each epoch's record packet to this key; the
                    // registration is idempotent, so every login repeats it. A
                    // failure leaves login intact: the record waits for the next one.
                    if reply.is_ok() {
                        if let Err(error) = record_recipient(&mut parts, &mut intents).await {
                            eprintln!("account actor: record recipient: {error:?}");
                        }
                    }
                }
                mailbox.reply(reply);
                continue;
            }
            match &first {
                Command::Update(proven) => {
                    let mut parts = Fresh {
                        membership: &mut membership,
                        policy: &mut policy,
                        account: &mut account,
                        global: &mut global,
                        device,
                        rng: &mut rng,
                        creation: creation.as_deref(),
                    };
                    let reply = update_flow(Task::Apply(proven), &mut parts, &mut intents)
                        .await
                        .and_then(|applied| applied.ok_or(ErrorCode::Unavailable))
                        .map(|applied| {
                            owed = Some(applied.clone());
                            Answer::Updated(applied)
                        });
                    mailbox.reply(reply);
                    continue;
                }
                Command::Resume => {
                    let reply = match owed.clone() {
                        Some(done) => Ok(Some(done)),
                        None => {
                            let mut parts = Fresh {
                                membership: &mut membership,
                                policy: &mut policy,
                                account: &mut account,
                                global: &mut global,
                                device,
                                rng: &mut rng,
                                creation: creation.as_deref(),
                            };
                            update_flow(Task::Resume, &mut parts, &mut intents).await
                        }
                    };
                    if let Ok(done) = &reply {
                        owed = done.clone();
                    }
                    mailbox.reply(reply.map(Answer::Owed));
                    continue;
                }
                #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
                Command::RecordPrepare(job) => {
                    // The actor's own session is the independent same-key source
                    // the reception needs (the Door's is held by the recovery lease).
                    let reply = match membership.observe_lease(clock).await {
                        Ok(lease) => match lease.common_record(&mut policy, clock) {
                            Ok(source) => account
                                .record_prepare(source, &job.configuration, &job.prover)
                                .await
                                .map(|(window, work)| {
                                    Answer::RecordWork(
                                        window,
                                        work.map(|work| {
                                            Shared::new(std::cell::Cell::new(Some(work)))
                                        }),
                                    )
                                }),
                            Err(_) => Err(ErrorCode::Unavailable),
                        },
                        Err(_) => Err(ErrorCode::Unavailable),
                    };
                    mailbox.reply(reply);
                    continue;
                }
                #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
                Command::RecordFinish(proof) => {
                    let reply = match proof.take() {
                        Some(proof) => account
                            .record_finish(proof)
                            .await
                            .map(|()| Answer::RecordCached),
                        None => Err(ErrorCode::InvalidRequest),
                    };
                    mailbox.reply(reply);
                    continue;
                }
                #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
                Command::WitnessLoad(roster) => {
                    let reply = account
                        .witness_load(std::sync::Arc::clone(roster))
                        .await
                        .map(|witness| Answer::Witness(Shared::new(witness)));
                    mailbox.reply(reply);
                    continue;
                }
                #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
                Command::WitnessStore(witness) => {
                    let reply = account
                        .witness_store(witness)
                        .await
                        .map(|()| Answer::WitnessStored);
                    mailbox.reply(reply);
                    continue;
                }
                #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
                Command::Roster => {
                    // Only an active member reads the roster; the admission is fresh
                    // and is dropped with this reply.
                    let reply = if existing_active(&mut account).await.is_none() {
                        Err(ErrorCode::Unavailable)
                    } else {
                        match admit(
                            &mut membership,
                            &mut policy,
                            &mut global,
                            device,
                            &mut rng,
                            creation.as_deref(),
                        )
                        .await
                        {
                            Ok(mut admission) => admission
                                .current_roster()
                                .await
                                .map(|roster| Answer::Roster(Shared::new(roster))),
                            Err(error) => Err(error),
                        }
                    };
                    mailbox.reply(reply);
                    continue;
                }
                Command::Settle(id) => {
                    let reply = update::settle(&mut Custodian(&mut account), *id).await;
                    if reply.is_ok() && owed.as_ref().is_some_and(|done| done.request_id() == *id) {
                        owed = None;
                    }
                    mailbox.reply(reply.map(|()| Answer::Settled));
                    continue;
                }
                Command::VoucherRemaining(role) => {
                    let reply = voucher_remaining(&mut account, *role, clock())
                        .await
                        .map(Answer::Remaining);
                    mailbox.reply(reply);
                    continue;
                }
                _ => {}
            }
            // An action the existing state already answers (an ACTIVE account,
            // or enrolling with a durable pending request) is answered before
            // any fresh admission: a second admission would bring a credential
            // that differs from the stored one and is refused.
            if let Some(answer) = before_admission(&first, &mut account).await {
                mailbox.reply(Ok(answer));
                continue;
            }
            let admission = match admit(
                &mut membership,
                &mut policy,
                &mut global,
                device,
                &mut rng,
                creation.as_deref(),
            )
            .await
            {
                Ok(admission) => admission,
                Err(error) => {
                    mailbox.reply(Err(trace("admission")(error)));
                    continue;
                }
            };
            // The credential issued with this admission is kept in the Vault
            // before anything else uses the admission; the same one is a no-op.
            if let Err(error) = account
                .store_community_credential(admission.community_credential())
                .await
            {
                mailbox.reply(Err(trace("community credential")(error)));
                continue;
            }
            let mut stage = Stage::Admitted(admission);
            let mut command = first;
            loop {
                // A join re-presents the same creation id on every call; while a
                // registered enrollment is held it is already admitted with it.
                if let Command::Creation(id) = &command {
                    if creation.as_deref() == Some(id.as_str())
                        && matches!(stage, Stage::Waiting(_) | Stage::Ready(_))
                    {
                        mailbox.reply(Ok(Answer::Noted));
                        command = mailbox.next().await;
                        continue;
                    }
                }
                let (reply, next) = serve(
                    &mut stage,
                    command.clone(),
                    &mut account,
                    &mut intents,
                    &mut request_intent,
                    &*prover,
                )
                .await;
                match next {
                    Next::Carry => {
                        carried = Some(command);
                        break;
                    }
                    Next::Restart => {
                        // The creation id has done its work once the account is active.
                        if matches!(reply, Ok(Answer::Activated(_))) {
                            creation = None;
                        }
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
        prover: &dyn AccountProver,
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
                        let prepared = admission
                            .delegate(account, intents)
                            .await
                            .map_err(trace("delegate"))?;
                        let submitted = prepared
                            .submit_for_initialization()
                            .await
                            .map_err(trace("submit"))?;
                        checkpoint(stage, submitted)
                            .await
                            .map_err(trace("checkpoint"))
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
                // failure is `account_reopen` from the durable state, or a fresh
                // operation when the proof's checkpoint slot has ended meanwhile.
                let slot_end = current.slot_end();
                let result = open(current, account, request_intent, prover).await;
                (open_outcome(result, slot_end, clock()), Next::Restart)
            }
            Command::Reopen => {
                let Some(admission) = stage.admission() else {
                    return (Err(ErrorCode::Unavailable), Next::Carry);
                };
                match admission.reopen(account).await {
                    Ok(at) => (Ok(Answer::Reopened(Opened { accepted_at: at })), Next::Stay),
                    // Elapsed state A: only the operator's signed status settles it.
                    Err(ErrorCode::ProofWindowElapsed) => {
                        match admission
                            .settle_elapsed(account, intents, request_intent)
                            .await
                        {
                            Ok(Elapsed::Adopted(at)) => (
                                Ok(Answer::Reopened(Opened { accepted_at: at })),
                                Next::Restart,
                            ),
                            Ok(Elapsed::Discarded) => (Ok(Answer::Discarded), Next::Restart),
                            Ok(Elapsed::Wait(eligible_at)) => {
                                (Ok(Answer::ElapsedPending { eligible_at }), Next::Restart)
                            }
                            Err(error) => (Err(error), Next::Restart),
                        }
                    }
                    Err(error) => (Err(error), Next::Restart),
                }
            }
            // A registered enrollment (waiting for its checkpoint slot, or ready) was
            // admitted through the gates: the next join continues it. Dropping it for
            // a fresh admission would need a second custody round for one join.
            Command::Join(_) if matches!(stage, Stage::Waiting(_) | Stage::Ready(_)) => (
                Ok(Answer::Gate(Gate {
                    ready: true,
                    steps: Vec::new(),
                })),
                Next::Stay,
            ),
            Command::Join(_)
            | Command::Creation(_)
            | Command::Update(_)
            | Command::Resume
            | Command::Settle(_)
            | Command::VoucherRemaining(_) => (Err(ErrorCode::Unavailable), Next::Carry),
            #[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
            Command::RecordPrepare(_)
            | Command::RecordFinish(_)
            | Command::WitnessLoad(_)
            | Command::WitnessStore(_)
            | Command::Roster => (Err(ErrorCode::Unavailable), Next::Carry),
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
        prover: &dyn AccountProver,
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

    /// Scripted account steps: answers in order, commands recorded.
    struct Script {
        answers: std::collections::VecDeque<Result<Answer>>,
        commands: Vec<Command>,
    }

    impl Script {
        fn new(answers: Vec<Result<Answer>>) -> Self {
            Self {
                answers: answers.into(),
                commands: Vec::new(),
            }
        }
    }

    impl Steps for Script {
        async fn call(&mut self, command: Command) -> Result<Answer> {
            self.commands.push(command);
            self.answers.pop_front().expect("scripted answer")
        }
    }

    fn ready() -> Result<Answer> {
        Ok(Answer::Enrolled(Enrolled {
            checkpoint: Checkpoint::Ready,
        }))
    }

    #[test]
    fn open_refused_after_its_checkpoint_slot_ended_is_a_crossed_slot() {
        // The injected clock: the proof was bound to the slot ending at 1_800.
        let end = 1_800;
        assert_eq!(
            open_outcome(Ok(1_750), end, 1_810),
            Ok(Answer::Opened(Opened { accepted_at: 1_750 }))
        );
        assert_eq!(
            open_outcome(Err(ErrorCode::Unauthorized), end, end),
            Ok(Answer::SlotCrossed { eligible_at: end })
        );
        assert_eq!(
            open_outcome(Err(ErrorCode::Unauthorized), end, end + 45),
            Ok(Answer::SlotCrossed { eligible_at: end })
        );
        // Inside the slot a refusal is a verdict; other refusals never restart.
        assert_eq!(
            open_outcome(Err(ErrorCode::Unauthorized), end, end - 1),
            Err(ErrorCode::Unauthorized)
        );
        for error in [
            ErrorCode::Reconcile,
            ErrorCode::Unavailable,
            ErrorCode::Refused,
        ] {
            assert_eq!(open_outcome(Err(error), end, end + 1), Err(error));
        }
        // Not restarted, a crossed slot reads as the refusal it replaced.
        let crossed = || Answer::SlotCrossed { eligible_at: end };
        assert_eq!(crossed().opened(), Err(ErrorCode::Unauthorized));
        assert_eq!(crossed().opened_or_reopened(), Err(ErrorCode::Unauthorized));
    }

    #[test]
    fn an_overrun_re_prepares_once_and_a_second_surfaces_proof_window_elapsed() {
        assert_eq!(
            open_outcome(Err(ErrorCode::ProofWindowElapsed), 1_800, 1_000),
            Ok(Answer::WindowElapsed)
        );
        let elapsed = || Ok(Answer::WindowElapsed);
        let opened = || Ok(Answer::Opened(Opened { accepted_at: 2_000 }));
        // Expired refusal, one fresh preparation, then the account opens.
        let mut steps = Script::new(vec![ready(), elapsed(), ready(), opened()]);
        assert_eq!(block(enroll_and_open(&mut steps)), Ok(Checkpoint::Ready));
        assert_eq!(
            steps.commands,
            [
                Command::Enroll,
                Command::Open,
                Command::Enroll,
                Command::Open
            ]
        );
        // A second overrun surfaces the typed error; no third preparation.
        let mut steps = Script::new(vec![ready(), elapsed(), ready(), elapsed()]);
        assert_eq!(
            block(enroll_and_open(&mut steps)),
            Err(ErrorCode::ProofWindowElapsed)
        );
        assert_eq!(steps.commands.len(), 4);
        assert_eq!(ErrorCode::ProofWindowElapsed.exit_code(), 75);
    }

    #[test]
    fn an_elapsed_state_a_is_discarded_before_the_one_fresh_preparation() {
        let elapsed = || Ok(Answer::WindowElapsed);
        let discarded = || Ok(Answer::Discarded);
        let opened = || Ok(Answer::Opened(Opened { accepted_at: 2_000 }));
        // Expired refusal with state A kept: the next open resumes it, the
        // operator's status discards it, and only then the fresh request opens.
        let mut steps = Script::new(vec![
            ready(),
            elapsed(),
            ready(),
            discarded(),
            ready(),
            opened(),
        ]);
        assert_eq!(block(enroll_and_open(&mut steps)), Ok(Checkpoint::Ready));
        assert_eq!(steps.commands.len(), 6);
        // A second overrun after the fresh preparation surfaces the typed error.
        let mut steps = Script::new(vec![
            ready(),
            elapsed(),
            ready(),
            discarded(),
            ready(),
            elapsed(),
        ]);
        assert_eq!(
            block(enroll_and_open(&mut steps)),
            Err(ErrorCode::ProofWindowElapsed)
        );
        assert_eq!(steps.commands.len(), 6);
        // Too early for the operator's time: the join waits for that operator time.
        let mut steps = Script::new(vec![
            ready(),
            elapsed(),
            ready(),
            Ok(Answer::ElapsedPending { eligible_at: 1_915 }),
        ]);
        assert_eq!(
            block(enroll_and_open(&mut steps)),
            Ok(Checkpoint::Pending { eligible_at: 1_915 })
        );
        assert_eq!(ErrorCode::DiscardedRequestAccepted.exit_code(), 69);
    }

    #[test]
    fn a_crossed_slot_restarts_enrollment_and_open_at_most_twice() {
        let crossed = || Ok(Answer::SlotCrossed { eligible_at: 1_800 });
        let opened = || Ok(Answer::Opened(Opened { accepted_at: 2_000 }));
        // No crossing: one enrollment, one open.
        let mut steps = Script::new(vec![ready(), opened()]);
        assert_eq!(block(enroll_and_open(&mut steps)), Ok(Checkpoint::Ready));
        assert_eq!(steps.commands, [Command::Enroll, Command::Open]);
        // Two crossings: two fresh operations, then the account opens.
        let mut steps = Script::new(vec![
            ready(),
            crossed(),
            ready(),
            crossed(),
            ready(),
            opened(),
        ]);
        assert_eq!(block(enroll_and_open(&mut steps)), Ok(Checkpoint::Ready));
        assert_eq!(steps.commands.len(), 6);
        // A third crossing ends the join with the refusal; no third restart.
        let mut steps = Script::new(vec![
            ready(),
            crossed(),
            ready(),
            crossed(),
            ready(),
            crossed(),
        ]);
        assert_eq!(
            block(enroll_and_open(&mut steps)),
            Err(ErrorCode::Unauthorized)
        );
        assert!(steps.answers.is_empty());
        // The fresh enrollment waits for the next slot: checkpoint_pending meanwhile.
        let pending = Checkpoint::Pending { eligible_at: 2_100 };
        let mut steps = Script::new(vec![
            ready(),
            crossed(),
            Ok(Answer::Enrolled(Enrolled {
                checkpoint: pending.clone(),
            })),
        ]);
        assert_eq!(block(enroll_and_open(&mut steps)), Ok(pending));
        assert_eq!(
            steps.commands,
            [Command::Enroll, Command::Open, Command::Enroll]
        );
        // Any other refusal ends the join as before, without a restart.
        let mut steps = Script::new(vec![ready(), Err(ErrorCode::Reconcile)]);
        assert_eq!(
            block(enroll_and_open(&mut steps)),
            Err(ErrorCode::Reconcile)
        );
        assert_eq!(steps.commands, [Command::Enroll, Command::Open]);
    }

    // A browser prover over the retained original artifacts (CWLT_NATIVE_PROVER_FIXTURE) and a
    // worker that answers nothing: only the port's variant is under test here.
    #[cfg(feature = "browser-prover")]
    struct NoWorker;
    #[cfg(feature = "browser-prover")]
    impl ckmg::wallet_engine::browser_prover::ProofWorker for NoWorker {
        fn prove<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<String, ckmg::wallet_engine::Error>,
                    > + 'a,
            >,
        > {
            Box::pin(async { Err(ckmg::wallet_engine::Error::Crypto) })
        }
        fn cancel(&self) {}
    }

    #[cfg(feature = "browser-prover")]
    #[test]
    fn a_browser_prover_lends_the_browser_variant_while_the_refusing_port_stays_a_refusal() {
        use ckmg::wallet_engine::browser_prover::{
            BrowserProver, BrowserProverConfig, SrsLocation,
        };
        use sha2::{Digest, Sha256};
        let directory = std::path::PathBuf::from(
            std::env::var_os("CWLT_NATIVE_PROVER_FIXTURE")
                .expect("genuine original retained extension artifact prerequisite"),
        );
        let circuit = std::fs::read(directory.join("circuits.json")).unwrap();
        let verification_key = std::fs::read(directory.join("keys.json")).unwrap();
        let digest = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
        let prover = BrowserProver::new(
            BrowserProverConfig {
                scope: ckmg::wallet_engine::account::GenesisProofScope {
                    circuit_digest: digest(&circuit),
                    verifying_key_digest: digest(&verification_key),
                },
                program: ckmg::wallet_engine::browser_prover::Program::Update,
                circuit,
                verification_key,
                srs: SrsLocation {
                    g1_path: "/prover/srs/g1-1048576.dat".into(),
                    g2_path: "/prover/srs/g2.dat".into(),
                    points: 1 << 20,
                },
                timeout: std::time::Duration::from_secs(240),
                max_threads: 8,
            },
            std::sync::Arc::new(NoWorker),
        )
        .unwrap();
        let port: std::sync::Arc<dyn AccountProver> = std::sync::Arc::new(prover);
        assert!(matches!(port.genesis(), Ok(GenesisProver::Browser(_))));
        // The port of a build that lends no prover is unchanged.
        let refusing: std::sync::Arc<dyn AccountProver> = std::sync::Arc::new(RefusingProver);
        assert!(matches!(refusing.genesis(), Err(ErrorCode::Unavailable)));
    }

    #[test]
    fn the_browser_port_refuses_every_proof_honestly() {
        let port: std::sync::Arc<dyn AccountProver> = std::sync::Arc::new(RefusingProver);
        assert!(matches!(port.genesis(), Err(ErrorCode::Unavailable)));
    }

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
                voucher: Some("cvch2.x".into()),
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
        for command in all().into_iter().filter(|c| !matches!(c, Command::Join(_))) {
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

    /// Row 17: a join repeated after activation is answered before the actor
    /// would admit again, every time with the same result; only an account
    /// that is not active yet reaches an admission.
    #[test]
    fn a_repeat_after_activation_is_answered_before_any_fresh_admission() {
        let mut active = Fake {
            active: Some(done()),
            pending: false,
            probes: 0,
        };
        for command in all().into_iter().filter(|c| !matches!(c, Command::Join(_))) {
            let first = block(before_admission(&command, &mut active));
            let again = block(before_admission(&command, &mut active));
            assert!(first.is_some(), "{command:?} would be admitted again");
            assert_eq!(first, again);
            assert_eq!(
                first,
                match block(repeat(command, &mut active)) {
                    Repeat::Answer(answer) => Some(answer),
                    Repeat::As(_) => None,
                }
            );
        }
        let mut fresh = Fake {
            active: None,
            pending: false,
            probes: 0,
        };
        for command in [
            Command::Enroll,
            Command::Open,
            Command::Reopen,
            Command::Activate,
        ] {
            assert_eq!(block(before_admission(&command, &mut fresh)), None);
        }
        // A join's gates are always asked; they never answer from the state here.
        let join = all().into_iter().find(|c| matches!(c, Command::Join(_)));
        assert_eq!(block(before_admission(&join.unwrap(), &mut active)), None);
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

    /// A scripted lobby: the standing of the account and what the lobby answers.
    struct Hall {
        active: bool,
        asked: usize,
        answer: Result<Gate>,
    }
    impl Lobby for Hall {
        async fn gate(&mut self, _: &JoinRequest) -> Result<Gate> {
            self.asked += 1;
            match &self.answer {
                Ok(gate) => Ok(Gate {
                    ready: gate.ready,
                    steps: gate.steps.clone(),
                }),
                Err(error) => Err(*error),
            }
        }
    }
    fn step() -> GateStep {
        GateStep {
            gate: "pow".into(),
            provider: "local".into(),
            id: "solve".into(),
        }
    }

    #[test]
    fn every_join_asks_the_lobby_also_for_an_active_account() {
        for command in [Command::Join(JoinRequest::default())] {
            for pending in [true, false] {
                let mut state = Fake {
                    active: Some(done()),
                    pending,
                    probes: 0,
                };
                assert_eq!(
                    block(repeat(command.clone(), &mut state)),
                    Repeat::As(command.clone())
                );
            }
        }
    }

    #[test]
    fn an_active_member_whose_gates_changed_is_held_in_the_lobby() {
        let mut hall = Hall {
            active: true,
            asked: 0,
            answer: Ok(Gate {
                ready: false,
                steps: vec![step()],
            }),
        };
        assert_eq!(
            block(join(&mut hall, &JoinRequest::default(), true)),
            Ok(Answer::Gate(Gate {
                ready: false,
                steps: vec![step()]
            }))
        );
        assert_eq!(hall.asked, 1);
        // Once the member supplied the step the lobby is satisfied and the same
        // resumable steps run again (an active account answers them from state).
        hall.answer = Ok(Gate {
            ready: true,
            steps: Vec::new(),
        });
        assert_eq!(
            block(join(&mut hall, &JoinRequest::default(), true)),
            Ok(Answer::Gate(Gate {
                ready: true,
                steps: Vec::new()
            }))
        );
        let mut state = Fake {
            active: Some(done()),
            pending: false,
            probes: 0,
        };
        assert!(matches!(
            block(repeat(Command::Open, &mut state)),
            Repeat::Answer(Answer::Opened(_))
        ));
    }

    #[test]
    fn an_unreachable_lobby_keeps_an_active_member_working_and_stops_a_new_one() {
        let ready = Ok(Answer::Gate(Gate {
            ready: true,
            steps: Vec::new(),
        }));
        for active in [true, false] {
            for error in [
                ErrorCode::Unavailable,
                ErrorCode::Reconcile,
                ErrorCode::Refused,
            ] {
                let mut hall = Hall {
                    active,
                    asked: 0,
                    answer: Err(error),
                };
                let reply = block(join(&mut hall, &JoinRequest::default(), active));
                if active && error == ErrorCode::Unavailable {
                    assert_eq!(reply, ready);
                } else {
                    // Only "unreachable" opens for an active member; a refusal or an
                    // uncertain outcome never reads as ready.
                    assert_eq!(reply, Err(error));
                }
            }
        }
    }

    #[test]
    fn updates_take_their_own_path() {
        let mut state = Fake {
            active: Some(done()),
            pending: true,
            probes: 0,
        };
        for command in [Command::Resume, Command::Settle([1; 32])] {
            assert_eq!(
                block(repeat(command.clone(), &mut state)),
                Repeat::As(command)
            );
        }
    }

    #[test]
    fn the_lobby_is_read_strictly_and_steps_keep_the_servers_order() {
        use serde_json::json;
        assert!(lacks(&json!({})));
        assert!(lacks(&json!({"missing": [{"kind": "gates"}]})));
        assert!(!lacks(&json!({"missing": []})));
        let global = json!({"requirement": {"gate": "development", "level": "global"}, "reason": "proof_required"});
        let voucher = json!({"requirement": {"gate": "cvch", "level": "community"}, "reason": "proof_required"});
        let disabled = json!({"requirement": {"gate": "development", "level": "global"}, "reason": "disabled"});
        let lobby = |passport: bool, needed: u64, alternatives: Value| json!({"passport_required": passport, "missing": [{"kind": "gates", "needed": needed, "alternatives": alternatives}]});
        // The passport proves the global requirement at admission.
        assert!(!lacks(&lobby(true, 1, json!([global.clone()]))));
        // Without a required passport, nothing global is assumed.
        assert!(lacks(&lobby(false, 1, json!([global.clone()]))));
        // A community requirement still lacks; a disabled global one is not proven.
        assert!(lacks(&lobby(
            true,
            2,
            json!([global.clone(), voucher.clone()])
        )));
        assert!(lacks(&lobby(true, 1, json!([voucher]))));
        assert!(lacks(&lobby(true, 1, json!([disabled]))));
        // Unreadable groups and other kinds of missing never count as satisfied.
        assert!(lacks(
            &json!({"passport_required": true, "missing": [{"kind": "gates", "alternatives": [global]}]})
        ));
        assert!(lacks(
            &json!({"passport_required": true, "missing": [{"kind": "membership"}]})
        ));
        assert!(lacks(
            &json!({"passport_required": true, "missing": [{"kind": "gates", "needed": 1}]})
        ));
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
