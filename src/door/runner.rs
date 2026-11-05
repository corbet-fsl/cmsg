//! One wave runner per device across tabs (decided 2026-11-05).
//!
//! In the browser every tab has its own vault frame and Door. Exactly one of them holds
//! the device's runner lock (`navigator.locks`, `browser::runner`): it binds the Mesh and
//! runs every background job. A Door without the lock answers its Mesh actions (the
//! Inbox and Mesh families) with the typed [`ErrorCode::RunnerElsewhere`], never a generic
//! refusal, and `runner.take` moves the runner here. A native device is one process and
//! is always the runner: it binds no gate.
use super::*;
use std::{cell::Cell, rc::Rc};

/// Where this device's runner is, as this Door sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerState {
    /// This Door binds the Mesh and runs the jobs.
    Here,
    /// Another tab of this device does; `runner.take` moves it here.
    Elsewhere,
}

/// Result of `runner.status` and `runner.take`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunnerStatus {
    pub state: RunnerState,
}

/// The runner state of one member origin, shared by the Door and the embedding that
/// holds (or lost) the lock. The lock's loss flips it synchronously, before the next
/// dispatch.
#[derive(Clone, Default)]
pub struct RunnerGate(Rc<Cell<bool>>);

impl RunnerGate {
    pub fn elsewhere(&self) -> bool {
        self.0.get()
    }
    pub fn set(&self, state: RunnerState) {
        self.0.set(state == RunnerState::Elsewhere);
    }
    pub fn state(&self) -> RunnerState {
        if self.elsewhere() {
            RunnerState::Elsewhere
        } else {
            RunnerState::Here
        }
    }
}

impl Door {
    /// Trusted embedding control: the runner gate of `origin`. Set once per origin.
    pub fn set_runner_gate(&mut self, origin: &str, gate: RunnerGate) -> Result<()> {
        if self.runner_gates.contains_key(origin) {
            return Err(ErrorCode::Unauthorized);
        }
        self.runner_gates.insert(origin.to_owned(), gate);
        Ok(())
    }

    pub(super) fn runner_state(&self, origin: &str) -> RunnerState {
        self.runner_gates
            .get(origin)
            .map_or(RunnerState::Here, RunnerGate::state)
    }

    /// The Mesh actions of a Door without the runner answer `RunnerElsewhere`.
    pub(super) fn runner_check(&self, origin: &str, family: registry::Family) -> Result<()> {
        if matches!(family, registry::Family::Inbox | registry::Family::Mesh)
            && self.runner_state(origin) == RunnerState::Elsewhere
        {
            return Err(ErrorCode::RunnerElsewhere);
        }
        Ok(())
    }
}

fn origin_of<'a>(door: &'a Door, key: &[u8; 32]) -> Result<&'a str> {
    door.grants
        .get(key)
        .map(|grant| grant.origin.as_str())
        .ok_or(ErrorCode::Unauthorized)
}

pub(super) async fn status(
    door: &mut Door,
    key: &[u8; 32],
    _: Empty,
) -> Result<(RunnerStatus, Vec<Event>)> {
    let origin = origin_of(door, key)?;
    Ok((
        RunnerStatus {
            state: door.runner_state(origin),
        },
        vec![],
    ))
}

/// The takeover itself is the embedding's (it requests the lock with `steal` after this
/// dispatch and answers the new state); the Door only reports where the runner is.
pub(super) async fn take(
    door: &mut Door,
    key: &[u8; 32],
    body: Empty,
) -> Result<(RunnerStatus, Vec<Event>)> {
    status(door, key, body).await
}
