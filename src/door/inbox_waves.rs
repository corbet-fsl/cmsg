//! Wave actions of the Inbox door: send, answer, close and punish a wave, the
//! messages of the other device, and the two short calls of the background
//! proof worker. Thin: every fact and mutation is an owner's (Waves, Contacts,
//! Threads); this module only orders them, and records the member's action
//! durably before any proof exists. A proof never blocks the member.
//!
//! The verifier, policy, G2 and peer-lineage capabilities arrive as a
//! [`WavePorts`] bundle installed per member origin by the trusted embedding
//! runtime ([`Door::bind_waves`]); no client can supply or replace them. The
//! prover is a host component that holds the wallet openings: it calls
//! `inbox.wave_job_next`, proves WITHOUT holding the Door, and returns the
//! result through `inbox.wave_job_done`.
pub mod account_ports;
mod desk;
/// The device side (ports and worker), shared by the native device and the browser.
#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    all(feature = "browser-prover", target_arch = "wasm32")
))]
pub mod device;
pub(crate) mod engine;
pub mod feed_trust;
#[cfg(any(
    all(feature = "native-prover", not(target_arch = "wasm32")),
    all(feature = "browser-prover", target_arch = "wasm32")
))]
pub mod lazy;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod native;
mod ports;
pub mod production;
mod signing;
pub mod types;
#[cfg(all(feature = "native-prover", not(target_arch = "wasm32")))]
pub mod verifier;
pub mod wallet;
pub mod witness;
pub mod worker;

use super::*;
pub use ports::{
    verify_outcome_with, verify_reservation_with, AccountSigner, ContactRequest, HandleRequest,
    Policy, ReceiptRequest, WavePorts,
};
pub use types::*;

/// One request to the bound Vault. The Vault answers with the matching variant.
pub(crate) enum Command {
    Send(WaveSend),
    Decide(WaveDecide),
    Punish(WavePunish),
    Receive(WaveIncoming),
    List,
    Outbox,
    Delivered(Delivered),
    NextJob,
    JobDone(JobDone),
    Retry([u8; 32]),
    Recover,
}
pub(crate) enum Answer {
    Status(WaveStatus),
    List(WaveList),
    Outbox(Outbox),
    Relation(cnbx::Relation),
    Job(Box<JobOffer>),
    Done,
}

impl Door {
    /// Trusted embedding control, absent from every callable projection: install
    /// the wave capabilities of an already configured member origin.
    pub fn bind_waves(&mut self, origin: &str, ports: Box<dyn WavePorts>) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|set| set.contains(origin))
            || self.wave_ports.contains_key(origin)
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.wave_ports.insert(origin.into(), ports);
        Ok(())
    }

    /// Trusted embedding control, absent from every callable projection: install what a
    /// compose may warm on this device for an already configured member origin (see
    /// [`WavePrewarm`]).
    pub fn bind_wave_prewarm(
        &mut self,
        origin: &str,
        prewarm: std::rc::Rc<dyn WavePrewarm>,
    ) -> Result<()> {
        if !self
            .config
            .origins
            .get(&Role::Member)
            .is_some_and(|set| set.contains(origin))
            || self.wave_prewarm.contains_key(origin)
        {
            return Err(ErrorCode::Unauthorized);
        }
        self.wave_prewarm.insert(origin.into(), prewarm);
        Ok(())
    }
}

/// Speculative sender reservation, option (b) (decided 2026-11-05): while the member composes,
/// the device warms only what the send will need locally (witness load, prover, setup). It sends
/// nothing: no Hello, no reserve, no request to the counterpart, the Mesh, the forum or the issuer.
/// The reserve still follows the counterpart's Terms after the member sends.
pub trait WavePrewarm {
    /// Warm, best effort; a failed warm-up only means the send loads everything itself.
    fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;
}

/// A warm-up that runs until it has succeeded once. A warm-up that returned `true` has cached
/// what the send needs for good, so later calls do nothing; one that is still running is not
/// started twice. A third-party client may call `inbox.wave_prewarm` as often as it likes.
pub struct WarmOnce<F> {
    warm: F,
    warmed: std::rc::Rc<std::cell::Cell<bool>>,
    running: std::rc::Rc<std::cell::Cell<bool>>,
}

impl<F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool>>>> WarmOnce<F> {
    pub fn new(warm: F) -> Self {
        Self {
            warm,
            warmed: Default::default(),
            running: Default::default(),
        }
    }
}

impl<F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool>>>> WavePrewarm
    for WarmOnce<F>
{
    fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
        if self.warmed.get() || self.running.replace(true) {
            return Box::pin(async {});
        }
        let run = (self.warm)();
        let warmed = std::rc::Rc::clone(&self.warmed);
        let running = std::rc::Rc::clone(&self.running);
        Box::pin(async move {
            if run.await {
                warmed.set(true);
            }
            running.set(false);
        })
    }
}

/// `inbox.wave_prewarm`: the member started composing. Inside the same current-policy and
/// clock bracket as every other Inbox action (refused below the signed minimum version), it
/// wakes the origin's wave worker for a round now and starts the origin's bound warm-up in the
/// background, then answers at once. It records nothing in the vault and sends nothing: no
/// Hello, no reserve, no request to the counterpart, the Mesh, the forum or the issuer.
pub(super) async fn wave_prewarm(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Empty, Vec<Event>)> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let mut policy = door.current_policy(&origin)?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let ((), completed) = current::read(
        vault.as_mut(),
        &mut policy,
        current::Scope {
            community: &door.config.community,
            expires,
            floor: door.clock_floor,
        },
        |_| Box::pin(async { Ok(()) }),
    )
    .await?;
    door.observe(completed)?;
    // The origin's wave worker runs its next round now (witness, roster, trust, provers).
    // Any client may call this as often as it likes: wake at most once per round cadence.
    let now = door.clock_floor;
    let due = door
        .wave_prewarm_woke
        .get(&origin)
        .is_none_or(|last| now >= last.saturating_add(wave_job::Cadence::default().check));
    if due {
        door.wave_prewarm_woke.insert(origin.clone(), now);
        door.wake_wave_worker(&origin);
    }
    if let Some(prewarm) = door.wave_prewarm.get(&origin) {
        let warm = prewarm.prewarm();
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(warm);
        #[cfg(not(target_arch = "wasm32"))]
        warm.await;
    }
    Ok((Empty {}, vec![]))
}

/// One request to the bound Vault, wave or conversation, with its reply.
pub(super) enum Op {
    Waves(Box<Command>),
    Chat(inbox_conversation::Command),
}
pub(super) enum Reply {
    Waves(Answer),
    Chat(inbox_conversation::Answer),
}

/// Run one request against the bound Vault together with this origin's ports,
/// inside the same current-policy and clock bracket as every other Inbox action.
pub(super) async fn run_op(door: &mut Door, key: &[u8; 32], op: Op) -> Result<Reply> {
    let grant = door.grants.get(key).ok_or(ErrorCode::Unauthorized)?;
    let origin = grant.origin.clone();
    let expires = grant.expires;
    let mut policy = door.current_policy(&origin)?;
    let ports = door.wave_ports.get(&origin).ok_or(ErrorCode::Unavailable)?;
    let vault = door.vaults.get_mut(&origin).ok_or(ErrorCode::Unavailable)?;
    let (reply, completed) = current::read_with(
        vault.as_mut(),
        ports.as_ref(),
        &mut policy,
        current::Scope {
            community: &door.config.community,
            expires,
            floor: door.clock_floor,
        },
        move |vault, ports| match op {
            Op::Waves(command) => {
                Box::pin(async move { vault.waves(*command, ports).await.map(Reply::Waves) })
            }
            Op::Chat(command) => {
                Box::pin(async move { vault.conversation(command, ports).await.map(Reply::Chat) })
            }
        },
    )
    .await?;
    door.observe(completed)?;
    Ok(reply)
}

/// What a thread step returns.
pub(super) enum ThreadOut {
    /// A key package or a Welcome.
    Bytes(Vec<u8>),
    /// The wires of messages the join sent.
    Wires(Vec<Vec<u8>>),
}

impl ThreadOut {
    pub(super) fn bytes(self) -> Result<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::Wires(_) => Err(ErrorCode::Unavailable),
        }
    }
}

/// One step of a vouching's direct thread.
pub(super) enum ThreadStep {
    KeyPackage {
        conversation: [u8; 32],
    },
    Create {
        peer: String,
        conversation: [u8; 32],
        package: Vec<u8>,
    },
    Join {
        peer: String,
        conversation: [u8; 32],
        welcome: Vec<u8>,
    },
}

/// Run one thread step for `origin` inside the same current-policy and clock
/// bracket as every other Inbox action. Returns the key package or the Welcome
/// (empty for a join).
pub(super) async fn run_thread(
    door: &mut Door,
    origin: &str,
    step: ThreadStep,
) -> Result<ThreadOut> {
    let expires = door
        .grants
        .values()
        .filter(|grant| grant.origin == origin)
        .map(|grant| grant.expires)
        .max()
        .ok_or(ErrorCode::Unauthorized)?;
    let mut policy = door.current_policy(origin)?;
    let ports = door.wave_ports.get(origin).ok_or(ErrorCode::Unavailable)?;
    let vault = door.vaults.get_mut(origin).ok_or(ErrorCode::Unavailable)?;
    let (reply, completed) = current::read_with(
        vault.as_mut(),
        ports.as_ref(),
        &mut policy,
        current::Scope {
            community: &door.config.community,
            expires,
            floor: door.clock_floor,
        },
        move |vault, ports| match step {
            ThreadStep::KeyPackage { conversation } => Box::pin(async move {
                vault
                    .voucher_key_package(conversation, ports)
                    .await
                    .map(ThreadOut::Bytes)
            }),
            ThreadStep::Create {
                peer,
                conversation,
                package,
            } => Box::pin(async move {
                vault
                    .voucher_create(&peer, conversation, &package, ports)
                    .await
                    .map(ThreadOut::Bytes)
            }),
            ThreadStep::Join {
                peer,
                conversation,
                welcome,
            } => Box::pin(async move {
                vault
                    .voucher_join(&peer, conversation, &welcome, ports)
                    .await
                    .map(ThreadOut::Wires)
            }),
        },
    )
    .await?;
    door.observe(completed)?;
    Ok(reply)
}

async fn run(door: &mut Door, key: &[u8; 32], command: Command) -> Result<(Answer, Vec<Event>)> {
    match run_op(door, key, Op::Waves(Box::new(command))).await? {
        Reply::Waves(answer) => Ok((answer, vec![])),
        Reply::Chat(_) => Err(ErrorCode::Unavailable),
    }
}

fn status(answer: Answer) -> Result<WaveStatus> {
    match answer {
        Answer::Status(status) => Ok(status),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_send(
    door: &mut Door,
    key: &[u8; 32],
    request: WaveSend,
) -> Result<(WaveStatus, Vec<Event>)> {
    let (answer, events) = run(door, key, Command::Send(request)).await?;
    Ok((status(answer)?, events))
}

pub(super) async fn wave_decide(
    door: &mut Door,
    key: &[u8; 32],
    request: WaveDecide,
) -> Result<(WaveStatus, Vec<Event>)> {
    let (answer, events) = run(door, key, Command::Decide(request)).await?;
    Ok((status(answer)?, events))
}

pub(super) async fn wave_punish(
    door: &mut Door,
    key: &[u8; 32],
    request: WavePunish,
) -> Result<(cnbx::Relation, Vec<Event>)> {
    match run(door, key, Command::Punish(request)).await? {
        (Answer::Relation(relation), events) => Ok((relation, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_receive(
    door: &mut Door,
    key: &[u8; 32],
    request: WaveIncoming,
) -> Result<(WaveStatus, Vec<Event>)> {
    let (answer, events) = run(door, key, Command::Receive(request)).await?;
    Ok((status(answer)?, events))
}

pub(super) async fn waves(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(WaveList, Vec<Event>)> {
    match run(door, key, Command::List).await? {
        (Answer::List(list), events) => Ok((list, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_outbox(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Outbox, Vec<Event>)> {
    match run(door, key, Command::Outbox).await? {
        (Answer::Outbox(outbox), events) => Ok((outbox, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_delivered(
    door: &mut Door,
    key: &[u8; 32],
    request: Delivered,
) -> Result<(Empty, Vec<Event>)> {
    match run(door, key, Command::Delivered(request)).await? {
        (Answer::Done, events) => Ok((Empty {}, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_job_next(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(JobOffer, Vec<Event>)> {
    match run(door, key, Command::NextJob).await? {
        (Answer::Job(offer), events) => Ok((*offer, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn wave_job_done(
    door: &mut Door,
    key: &[u8; 32],
    request: JobDone,
) -> Result<(WaveStatus, Vec<Event>)> {
    let (answer, events) = run(door, key, Command::JobDone(request)).await?;
    Ok((status(answer)?, events))
}

pub(super) async fn wave_job_retry(
    door: &mut Door,
    key: &[u8; 32],
    request: JobRef,
) -> Result<(Empty, Vec<Event>)> {
    match run(door, key, Command::Retry(request.id)).await? {
        (Answer::Done, events) => Ok((Empty {}, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

/// Host start-up: a restart found the worker gone, so jobs it was proving go
/// back to the queue.
pub(super) async fn wave_jobs_recover(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(Empty, Vec<Event>)> {
    match run(door, key, Command::Recover).await? {
        (Answer::Done, events) => Ok((Empty {}, events)),
        _ => Err(ErrorCode::Unavailable),
    }
}

#[cfg(test)]
mod prewarm_tests {
    use super::*;
    use std::{cell::Cell, collections::BTreeSet, rc::Rc};

    const ORIGIN: &str = "https://omega.example.test";

    fn door() -> Door {
        let configuration = Configuration::new(
            "omega".into(),
            BTreeMap::from([(Role::Member, BTreeSet::from([ORIGIN.to_owned()]))]),
        )
        .unwrap();
        Door::new(configuration)
    }

    struct Counting(Rc<Cell<u32>>);
    impl WavePrewarm for Counting {
        fn prewarm(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
            self.0.set(self.0.get() + 1);
            Box::pin(async {})
        }
    }

    async fn compose(door: &mut Door, origin: &str) -> Result<serde_json::Value> {
        let key = [7u8; 32];
        door.grants.insert(
            key,
            Grant {
                origin: origin.to_owned(),
                actions: BTreeSet::from(["inbox.wave_prewarm".to_owned()]),
                expires: u64::MAX,
            },
        );
        let action = super::super::registry::action("inbox.wave_prewarm").unwrap();
        let outcome = (action.handler)(door, &key, "{}").await.map(|(v, _)| v);
        door.grants.remove(&key);
        outcome
    }

    #[tokio::test]
    async fn a_compose_outside_the_current_policy_bracket_warms_nothing() {
        // Without a bound vault there is no current-policy bracket: the action is refused
        // like every Inbox action, and the bound warm-up never runs.
        let mut door = door();
        let warmed = Rc::new(Cell::new(0));
        door.bind_wave_prewarm(ORIGIN, Rc::new(Counting(warmed.clone())))
            .unwrap();
        assert_eq!(
            compose(&mut door, ORIGIN).await,
            Err(ErrorCode::Unavailable)
        );
        assert_eq!(warmed.get(), 0);
        // The action reads nothing and records nothing: it is a Read of the Inbox family.
        let described = super::super::registry::catalog()
            .into_iter()
            .find(|action| action.action == "inbox.wave_prewarm")
            .unwrap();
        assert!(matches!(
            described.effect,
            super::super::registry::Effect::Read
        ));
        assert_eq!(described.family, super::super::registry::Family::Inbox);
    }

    #[tokio::test]
    async fn a_warm_up_runs_until_it_succeeds_once_and_never_twice_at_a_time() {
        let runs = Rc::new(Cell::new(0u32));
        let outcome = Rc::new(Cell::new(false));
        let (counted, result) = (runs.clone(), outcome.clone());
        let once = WarmOnce::new(move || {
            counted.set(counted.get() + 1);
            let result = result.get();
            Box::pin(async move {
                tokio::task::yield_now().await;
                result
            })
        });
        // A second call while the first runs does nothing.
        let first = once.prewarm();
        once.prewarm().await;
        assert_eq!(runs.get(), 1);
        first.await;
        // The first failed, so the next call tries again; it succeeds.
        outcome.set(true);
        once.prewarm().await;
        assert_eq!(runs.get(), 2);
        // After a success nothing runs again.
        once.prewarm().await;
        assert_eq!(runs.get(), 2);
    }
    #[test]
    fn only_a_member_origin_gets_one_warm_up() {
        let mut door = door();
        let warm = || Rc::new(Counting(Rc::new(Cell::new(0))));
        assert_eq!(
            door.bind_wave_prewarm("https://other.example.test", warm()),
            Err(ErrorCode::Unauthorized)
        );
        assert_eq!(door.bind_wave_prewarm(ORIGIN, warm()), Ok(()));
        assert_eq!(
            door.bind_wave_prewarm(ORIGIN, warm()),
            Err(ErrorCode::Unauthorized)
        );
    }
}
