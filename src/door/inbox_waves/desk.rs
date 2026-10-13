//! The device-local wave desk: one durable table of waves in progress and of
//! the background proof jobs. A member's action is recorded here (in the same
//! checkpoint as its Waves/Contacts/Threads effect) before any proving starts.
//! The desk stores public contexts, statements, proofs and queued messages only:
//! never an opening, a key, a balance or a message body.
use super::super::*;
use super::types::*;

pub(super) const OWNER: &str = "cmsg.waves";
pub(super) const KEY: &[u8] = b"desk.v1";
pub const MAX_WAVES: usize = 128;
pub const MAX_JOBS: usize = 256;
pub const MAX_ATTEMPTS: u8 = 5;
pub const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum JobStage {
    /// Recorded; no work started.
    Recorded,
    /// Handed to the host worker.
    Proving,
    /// Retries are used up; visible, never dropped.
    Stalled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub id: [u8; 32],
    pub nonce: [u8; 32],
    pub work: Work,
    pub stage: JobStage,
    pub attempts: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub nonce: [u8; 32],
    pub peer: String,
    pub role: u8,
    pub stage: Stage,
    pub hello: Hello,
    pub terms: Option<Terms>,
    /// This device's own reservation, once proved.
    pub own: Option<Blob>,
    /// The other device's reservation, verified when it arrived.
    pub theirs: Option<Blob>,
    pub receipt_digest: Option<[u8; 32]>,
    pub key_package: Option<Vec<u8>>,
    pub welcome: Option<Vec<u8>>,
    /// Set once this member's conversation exists on this device.
    pub opened: bool,
    pub outbox: Vec<Envelope>,
    /// Sequence of the next queued message.
    #[serde(default)]
    pub next_out: u64,
    /// Sequence of the last accepted message from the other device.
    #[serde(default)]
    pub last_in: Option<u64>,
}

impl Session {
    /// Queue one message for the other device, bound to this wave's
    /// conversation, to `sender` and to the next sequence.
    pub fn enqueue(&mut self, sender: &str, message: WaveMessage) {
        self.outbox.push(Envelope {
            version: WAVE_VERSION,
            conversation: self.hello.conversation,
            sender: sender.into(),
            sequence: self.next_out,
            message,
        });
        self.next_out += 1;
    }

    /// Accept an incoming envelope only if it is of this version, bound to this
    /// conversation and peer, and strictly newer than the last accepted one.
    pub fn admit(&mut self, peer: &str, envelope: &Envelope) -> bool {
        if envelope.version != WAVE_VERSION
            || envelope.conversation != self.hello.conversation
            || envelope.sender != peer
            || self.last_in.is_some_and(|last| envelope.sequence <= last)
        {
            return false;
        }
        self.last_in = Some(envelope.sequence);
        true
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Desk {
    pub waves: Vec<Session>,
    pub jobs: Vec<Job>,
}

impl Desk {
    pub fn load<B: cwst::backend::Backend>(store: &cwst::Store<B>) -> Result<Self> {
        match store.read(OWNER, KEY).map_err(|_| ErrorCode::Unavailable)? {
            None => Ok(Self::default()),
            Some(bytes) => Self::decode(bytes),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(ErrorCode::Capacity);
        }
        let desk: Self = serde_json::from_slice(bytes).map_err(|_| ErrorCode::Unavailable)?;
        if desk.waves.len() > MAX_WAVES || desk.jobs.len() > MAX_JOBS {
            return Err(ErrorCode::Capacity);
        }
        Ok(desk)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| ErrorCode::Unavailable)?;
        if bytes.len() > MAX_BYTES {
            return Err(ErrorCode::Capacity);
        }
        Ok(bytes)
    }

    pub fn wave(&self, nonce: &[u8; 32]) -> Option<&Session> {
        self.waves.iter().find(|wave| &wave.nonce == nonce)
    }

    pub fn wave_mut(&mut self, nonce: &[u8; 32]) -> Result<&mut Session> {
        self.waves
            .iter_mut()
            .find(|wave| &wave.nonce == nonce)
            .ok_or(ErrorCode::Refused)
    }

    pub fn add(&mut self, session: Session) -> Result<()> {
        if self.wave(&session.nonce).is_some() {
            return Err(ErrorCode::Refused);
        }
        if self.waves.len() >= MAX_WAVES {
            return Err(ErrorCode::Capacity);
        }
        self.waves.push(session);
        Ok(())
    }

    pub fn job_id(nonce: &[u8; 32], work: Work) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"cmsg.wave-job.v1");
        hash.update(nonce);
        hash.update([work as u8]);
        hash.finalize().into()
    }

    /// Record the member's action as work. Idempotent per (wave, work).
    pub fn record(&mut self, nonce: [u8; 32], work: Work) -> Result<[u8; 32]> {
        let id = Self::job_id(&nonce, work);
        if self.jobs.iter().any(|job| job.id == id) {
            return Ok(id);
        }
        if self.jobs.len() >= MAX_JOBS {
            return Err(ErrorCode::Capacity);
        }
        self.jobs.push(Job {
            id,
            nonce,
            work,
            stage: JobStage::Recorded,
            attempts: 0,
        });
        Ok(id)
    }

    /// The oldest recorded job; the host worker takes it.
    pub fn take(&mut self) -> Option<Job> {
        let job = self
            .jobs
            .iter_mut()
            .find(|job| job.stage == JobStage::Recorded)?;
        job.stage = JobStage::Proving;
        job.attempts += 1;
        Some(job.clone())
    }

    pub fn job(&self, id: &[u8; 32]) -> Option<&Job> {
        self.jobs.iter().find(|job| &job.id == id)
    }

    /// The proof was verified and applied: the job is finished and dropped.
    pub fn finish(&mut self, id: &[u8; 32]) -> Result<()> {
        let at = self
            .jobs
            .iter()
            .position(|job| &job.id == id && job.stage == JobStage::Proving)
            .ok_or(ErrorCode::Refused)?;
        self.jobs.remove(at);
        Ok(())
    }

    /// Building or proving failed: back to the queue, or stalled when the
    /// attempts are used up. A job is never removed by failure.
    pub fn fail(&mut self, id: &[u8; 32]) -> Result<()> {
        let job = self
            .jobs
            .iter_mut()
            .find(|job| &job.id == id && job.stage == JobStage::Proving)
            .ok_or(ErrorCode::Refused)?;
        job.stage = if job.attempts >= MAX_ATTEMPTS {
            JobStage::Stalled
        } else {
            JobStage::Recorded
        };
        Ok(())
    }

    /// A restart found the worker gone: proving jobs go back to the queue.
    pub fn recover(&mut self) {
        for job in &mut self.jobs {
            if job.stage == JobStage::Proving {
                job.stage = JobStage::Recorded;
            }
        }
    }

    /// Give a stalled job a fresh set of attempts.
    pub fn retry(&mut self, id: &[u8; 32]) -> Result<()> {
        let job = self
            .jobs
            .iter_mut()
            .find(|job| &job.id == id && job.stage == JobStage::Stalled)
            .ok_or(ErrorCode::Refused)?;
        job.stage = JobStage::Recorded;
        job.attempts = 0;
        Ok(())
    }

    pub fn stalled(&self) -> u32 {
        let count = self
            .jobs
            .iter()
            .filter(|job| job.stage == JobStage::Stalled)
            .count();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    pub fn status(&self, session: &Session) -> WaveStatus {
        let jobs = self
            .jobs
            .iter()
            .filter(|job| job.nonce == session.nonce)
            .count();
        WaveStatus {
            nonce: session.nonce,
            peer: session.peer.clone(),
            role: session.role,
            stage: session.stage,
            conversation: session.opened.then_some(session.hello.conversation),
            pending: u32::try_from(jobs + session.outbox.len()).unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(nonce: u8) -> Session {
        Session {
            nonce: [nonce; 32],
            peer: "peer".into(),
            role: 0,
            stage: Stage::Hello,
            hello: Hello {
                conversation: [9; 32],
                group: [1; 32],
                contact_policy: [2; 32],
                history: [3; 32],
                opened_at: 10,
                expires_at: 20,
                sender_authority: [4; 32],
                sender_challenge: [5; 32],
            },
            terms: None,
            own: None,
            theirs: None,
            receipt_digest: None,
            key_package: None,
            welcome: None,
            opened: false,
            outbox: vec![],
            next_out: 0,
            last_in: None,
        }
    }

    #[test]
    fn an_action_is_recorded_once_and_never_lost_by_failure() {
        let mut desk = Desk::default();
        desk.add(session(1)).unwrap();
        assert_eq!(desk.add(session(1)), Err(ErrorCode::Refused));
        let id = desk.record([1; 32], Work::ReserveSender).unwrap();
        assert_eq!(desk.record([1; 32], Work::ReserveSender), Ok(id));
        assert_eq!(desk.jobs.len(), 1);
        assert_eq!(desk.fail(&id), Err(ErrorCode::Refused));
        for attempt in 1..=MAX_ATTEMPTS {
            let job = desk.take().unwrap();
            assert_eq!(job.attempts, attempt);
            desk.fail(&id).unwrap();
        }
        // Retries are used up: visible, not dropped, not offered again.
        assert!(desk.take().is_none());
        assert_eq!(desk.job(&id).unwrap().stage, JobStage::Stalled);
        assert_eq!(desk.finish(&id), Err(ErrorCode::Refused));
        desk.retry(&id).unwrap();
        assert_eq!(desk.retry(&id), Err(ErrorCode::Refused));
        let job = desk.take().unwrap();
        desk.finish(&job.id).unwrap();
        assert!(desk.job(&id).is_none());
    }

    #[test]
    fn a_restart_requeues_proving_jobs() {
        let mut desk = Desk::default();
        desk.add(session(1)).unwrap();
        let id = desk.record([1; 32], Work::Answer).unwrap();
        desk.take().unwrap();
        assert!(desk.take().is_none());
        desk.recover();
        assert_eq!(desk.take().unwrap().id, id);
    }

    #[test]
    fn the_desk_is_bounded_and_round_trips() {
        let mut desk = Desk::default();
        for n in 0..MAX_WAVES {
            let mut s = session(0);
            s.nonce = [n as u8; 32];
            s.nonce[1] = (n / 256) as u8 + 1;
            desk.add(s).unwrap();
        }
        assert_eq!(desk.add(session(255)), Err(ErrorCode::Capacity));
        let bytes = desk.encode().unwrap();
        assert_eq!(Desk::decode(&bytes).unwrap(), desk);
        assert_eq!(Desk::decode(b"{"), Err(ErrorCode::Unavailable));
        assert_eq!(
            Desk::decode(&vec![b' '; MAX_BYTES + 1]),
            Err(ErrorCode::Capacity)
        );
        let status = desk.status(&desk.waves[0]);
        assert_eq!(status.stage, Stage::Hello);
        assert_eq!(status.conversation, None);
    }

    #[test]
    fn jobs_are_bounded() {
        let mut desk = Desk::default();
        for n in 0..MAX_JOBS {
            let mut nonce = [0u8; 32];
            nonce[0] = n as u8;
            nonce[1] = (n / 256) as u8;
            desk.record(nonce, Work::Close).unwrap();
        }
        assert_eq!(
            desk.record([255; 32], Work::Close),
            Err(ErrorCode::Capacity)
        );
    }
}
