//! The account side of one wave job: the production [`WaveWallet`].
//!
//! For a reservation job it takes the member's accepted account witness, reserves the
//! slot, has the update accepted by the community accounting, activates the reservation
//! under the counterpart's contact signature, and proves the `wave` evidence. Every step
//! persists the new witness state before the next one starts, so a job that restarts after
//! a crash resumes from the slot's phase and never reserves twice.
//!
//! Nothing here owns a key, a prover or a transport: they are the four small capabilities
//! below, supplied by the trusted embedding runtime.
//!
//! | Capability | Production source |
//! |---|---|
//! | [`WalletState`] | the sealed account in Vault custody (`Account::seal`) |
//! | [`WaveProver`] | cwlt `NativeProver` over the account group (`Update`) and the wave group (`Wave`, `Outcome`) |
//! | [`UpdateSink`] | the D2 update actor (`Door::account_update`), returns the accepted certificate |
//! | [`ContactAuthority`] | the roster key check (`Account::verify_contact`) |
use super::production::WaveWallet;
use super::types::{Blob, ProveJob, Proved, Work};
use super::super::{ErrorCode, Result};
use ckmg::wallet_engine::account::{
    Account, Acknowledgment, Candidate, Certificate, Evidence, OsEntropy, Reserve, Resolution,
    Settled, SettledOutcome, UpdateInput, WaveContext as EvidenceContext,
};

/// Where the member's account witness lives between jobs.
#[allow(async_fn_in_trait)]
pub trait WalletState {
    /// The newest durable witness state.
    async fn load(&mut self) -> Result<Account>;
    /// Make `account` the newest durable state. Called before the next step starts.
    async fn store(&mut self, account: &Account) -> Result<()>;
}

/// Proves circuit inputs. Blocking work belongs on the implementation's own worker.
#[allow(async_fn_in_trait)]
pub trait WaveProver {
    /// Proof of one account update.
    async fn prove_update(&mut self, input: &UpdateInput) -> Result<Vec<u8>>;
    /// Proof of a `wave` or `outcome` evidence.
    async fn prove_evidence(&mut self, evidence: &Evidence) -> Result<Vec<u8>>;
}

/// Gets one proven update accepted by the community accounting.
#[allow(async_fn_in_trait)]
pub trait UpdateSink {
    /// Send the update (idempotent on retry) and return the issuer certificate of the
    /// accepted state.
    async fn apply(&mut self, candidate: &Candidate, proof: Vec<u8>) -> Result<Certificate>;
}

/// Checks the counterpart's consent to the transcript.
pub trait ContactAuthority {
    fn verify(&self, account: &Account, reserve: &Reserve, signature: &[u8; 64]) -> Result<()>;
}

/// The roster-key check the update circuit performs, in the same words.
pub struct RosterContactAuthority;
impl ContactAuthority for RosterContactAuthority {
    fn verify(&self, account: &Account, reserve: &Reserve, signature: &[u8; 64]) -> Result<()> {
        account
            .verify_contact(reserve, signature)
            .map_err(|_| ErrorCode::Refused)
    }
}

/// Fixed public inputs of the wave circuits for this community.
#[derive(Clone, Debug)]
pub struct WaveScope {
    /// The wave proof scope field.
    pub scope: [u8; 32],
    /// The issuer certificate key field.
    pub issuer_key: [u8; 32],
}

pub struct AccountWallet<S, P, U, C, K> {
    pub state: S,
    pub prover: P,
    pub sink: U,
    pub authority: C,
    pub clock: K,
    pub wave: WaveScope,
}

impl<S, P, U, C, K> AccountWallet<S, P, U, C, K>
where
    S: WalletState,
    P: WaveProver,
    U: UpdateSink,
    C: ContactAuthority,
    K: Fn() -> u64,
{
    fn reserve_of(account: &Account, job: &ProveJob) -> Result<(Reserve, bool)> {
        let sender = job.work == Work::ReserveSender;
        let (own, peer) = if sender {
            (&job.sender, &job.recipient)
        } else {
            (&job.recipient, &job.sender)
        };
        let index = account
            .roster()
            .entries()
            .iter()
            .position(|row| row.member == peer.owner)
            .ok_or(ErrorCode::Refused)?;
        Ok((
            Reserve {
                peer_index: index,
                role: own.role,
                nonce: own.nonce,
                group: own.group,
                contact_policy: own.contact_policy,
                opened_at: Some(own.opened_at),
                expires_at: Some(own.expires_at),
            },
            sender,
        ))
    }

    /// Prove, send for acceptance and keep the accepted state.
    async fn advance(&mut self, candidate: Candidate) -> Result<(Account, Candidate)> {
        let proof = self.prover.prove_update(&candidate.input).await?;
        let certificate = self.sink.apply(&candidate, proof).await?;
        let accepted = candidate.next.clone().with_certificate(certificate);
        self.state.store(&accepted).await?;
        Ok((accepted, candidate))
    }

    async fn reservation(&mut self, job: &ProveJob) -> Result<Proved> {
        let mut account = self.state.load().await?;
        let (reserve, sender) = Self::reserve_of(&account, job)?;
        let own = if sender { &job.sender } else { &job.recipient };
        let signature: [u8; 64] = job
            .contact_signature
            .as_deref()
            .and_then(|s| s.try_into().ok())
            .ok_or(ErrorCode::Refused)?;
        // The counterpart's consent is checked before anything is reserved.
        self.authority.verify(&account, &reserve, &signature)?;
        // The sender proves at the common lease start; the recipient at its own clock.
        let at = if sender { own.opened_at } else { (self.clock)() };
        let event = match account.event_for(&own.nonce) {
            Some(event) => event,
            None => {
                let candidate = account
                    .reserve(reserve, at, &mut OsEntropy)
                    .map_err(|_| ErrorCode::Refused)?;
                let event = candidate.event.ok_or(ErrorCode::Refused)?;
                account = self.advance(candidate).await?.0;
                event
            }
        };
        let phase = account.slot(&event).map(|s| s.phase).ok_or(ErrorCode::Refused)?;
        if phase == 1 {
            let candidate = account
                .activate(&event, at, signature, &mut OsEntropy)
                .map_err(|_| ErrorCode::Refused)?;
            account = self.advance(candidate).await?.0;
        } else if phase != 2 {
            return Err(ErrorCode::Refused);
        }
        let evidence = account
            .wave_evidence(
                &event,
                &EvidenceContext {
                    history: own.history,
                    challenge: own.challenge,
                },
                &self.wave.scope,
                &self.wave.issuer_key,
                None,
            )
            .map_err(|_| ErrorCode::Refused)?;
        let proof = self.prover.prove_evidence(&evidence).await?;
        Ok(Proved {
            blob: Blob {
                statement: statement_of(&evidence, "wave")?,
                proof,
            },
            receipt_digest: None,
            wallet: vec![],
        })
    }
}

fn signature_of(receipt: &super::types::Receipt) -> Result<[u8; 64]> {
    receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ErrorCode::Refused)
}

impl<S, P, U, C, K> AccountWallet<S, P, U, C, K>
where
    S: WalletState,
    P: WaveProver,
    U: UpdateSink,
    C: ContactAuthority,
    K: Fn() -> u64,
{
    /// The recipient settles its slot under its own signed receipt (and the sender's
    /// acknowledgment of an Answer), then proves the `outcome` evidence.
    async fn settlement(&mut self, job: &ProveJob) -> Result<Proved> {
        let answer = job.work == Work::Answer;
        let own = &job.recipient;
        let receipt = job.resolution.as_ref().ok_or(ErrorCode::Refused)?;
        let resolution = Resolution {
            kind: if answer { 1 } else { 2 },
            issued_at: receipt.issued_at,
            history_digest: own.history,
            ed25519_receipt_digest: job.receipt_digest.ok_or(ErrorCode::Refused)?,
            signature: signature_of(receipt)?,
        };
        let acknowledgment = if answer {
            let ack = job.acknowledgment.as_ref().ok_or(ErrorCode::Refused)?;
            Some(Acknowledgment {
                issued_at: ack.issued_at,
                signature: signature_of(ack)?,
            })
        } else {
            None
        };
        let mut account = self.state.load().await?;
        let event = account.event_for(&own.nonce).ok_or(ErrorCode::Refused)?;
        let phase = account.slot(&event).map(|s| s.phase).ok_or(ErrorCode::Refused)?;
        if phase == 2 {
            let candidate = account
                .settle(
                    &event,
                    &resolution,
                    acknowledgment.as_ref(),
                    (self.clock)(),
                    None,
                    None,
                    &mut OsEntropy,
                )
                .map_err(|_| ErrorCode::Refused)?;
            account = self.advance(candidate).await?.0;
        } else if phase != 3 {
            return Err(ErrorCode::Refused);
        }
        let settled = Settled {
            outcome: if answer {
                SettledOutcome::Answer
            } else {
                SettledOutcome::Close
            },
            resolution: Some(resolution),
            acknowledgment,
        };
        let evidence = account
            .wave_evidence(
                &event,
                &EvidenceContext {
                    history: own.history,
                    challenge: own.challenge,
                },
                &self.wave.scope,
                &self.wave.issuer_key,
                Some(&settled),
            )
            .map_err(|_| ErrorCode::Refused)?;
        let proof = self.prover.prove_evidence(&evidence).await?;
        Ok(Proved {
            blob: Blob {
                statement: statement_of(&evidence, "outcome")?,
                proof,
            },
            receipt_digest: None,
            wallet: vec![],
        })
    }

    /// Burn the contact on both sides under the counterpart's contact consent. A wave that
    /// never reserved, or already settled, has nothing to burn.
    async fn punishment(&mut self, job: &ProveJob) -> Result<Proved> {
        let mut account = self.state.load().await?;
        let nothing = || Proved {
            blob: Blob {
                statement: vec![],
                proof: vec![],
            },
            receipt_digest: None,
            wallet: vec![],
        };
        let Some(event) = account.event_for(&job.nonce) else {
            return Ok(nothing());
        };
        if account.slot(&event).map(|s| s.phase) == Some(2) {
            let signature: [u8; 64] = job
                .contact_signature
                .as_deref()
                .and_then(|s| s.try_into().ok())
                .ok_or(ErrorCode::Refused)?;
            let candidate = account
                .punish(&event, (self.clock)(), signature, &mut OsEntropy)
                .map_err(|_| ErrorCode::Refused)?;
            account = self.advance(candidate).await?.0;
        }
        drop(account);
        Ok(nothing())
    }
}

/// The public statement of an evidence: the member of the tagged body the verifier reads.
fn statement_of(evidence: &Evidence, member: &str) -> Result<Vec<u8>> {
    let body: serde_json::Value = serde_json::from_str(
        &evidence.statement_json().map_err(|_| ErrorCode::Refused)?,
    )
    .map_err(|_| ErrorCode::Refused)?;
    serde_json::to_vec(body.get(member).ok_or(ErrorCode::Refused)?).map_err(|_| ErrorCode::Refused)
}

impl<S, P, U, C, K> WaveWallet for AccountWallet<S, P, U, C, K>
where
    S: WalletState,
    P: WaveProver,
    U: UpdateSink,
    C: ContactAuthority,
    K: Fn() -> u64,
{
    async fn prove_job(&mut self, job: &ProveJob) -> Result<Proved> {
        match job.work {
            Work::ReserveSender | Work::ReserveRecipient => self.reservation(job).await,
            Work::Answer | Work::Close => self.settlement(job).await,
            Work::Punish => self.punishment(job).await,
        }
    }
}
