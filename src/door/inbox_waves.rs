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
mod desk;
pub(crate) mod engine;
mod ports;
mod signing;
pub mod account_ports;
pub mod production;
pub mod types;
pub mod wallet;
pub mod worker;

use super::*;
pub use ports::{
    verify_outcome_with, verify_reservation_with, AccountSigner, ContactRequest, Policy, ReceiptRequest, WavePorts,
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
    KeyPackage { conversation: [u8; 32] },
    Create { peer: String, conversation: [u8; 32], package: Vec<u8> },
    Join { peer: String, conversation: [u8; 32], welcome: Vec<u8> },
}

/// Run one thread step for `origin` inside the same current-policy and clock
/// bracket as every other Inbox action. Returns the key package or the Welcome
/// (empty for a join).
pub(super) async fn run_thread(door: &mut Door, origin: &str, step: ThreadStep) -> Result<ThreadOut> {
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
            ThreadStep::KeyPackage { conversation } => {
                Box::pin(async move {
                    vault
                        .voucher_key_package(conversation, ports)
                        .await
                        .map(ThreadOut::Bytes)
                })
            }
            ThreadStep::Create { peer, conversation, package } => Box::pin(async move {
                vault
                    .voucher_create(&peer, conversation, &package, ports)
                    .await
                    .map(ThreadOut::Bytes)
            }),
            ThreadStep::Join { peer, conversation, welcome } => Box::pin(async move {
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
