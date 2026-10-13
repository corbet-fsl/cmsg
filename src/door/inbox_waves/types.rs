//! Wire and action types of the wave door actions.
//!
//! PROVISIONAL (DEVIATION): the decided design fixes what a wave proves and what
//! a release commits, but not the messages two devices exchange. `WaveMessage`
//! is the smallest exchange that carries exactly the public contexts, statements
//! and proofs the owners already require; it is the single place to change when
//! the protocol is decided. No message carries an opening, a key or a balance.
use super::super::*;

/// Where one wave stands on this device. The same value serves both roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Sender: the hello is out, the recipient's terms are awaited.
    Hello,
    /// The reservation is recorded; its proof is built in the background.
    Reserving,
    /// Sender: the offer is out, the recipient's reservation is awaited.
    Offered,
    /// Recipient: the reservation is out, the welcome is awaited.
    Reserved,
    /// Sender: the conversation exists and the welcome is out.
    Released,
    /// Recipient: the welcome arrived; the member may answer or close.
    Ready,
    /// Recipient: answered. The conversation is open; the Answer proof settles
    /// in the background and never blocks it.
    Claimed,
    /// The Answer is settled on this device.
    Answered,
    Closed,
    Punished,
}

/// Public terms the sender fixes when it starts a wave.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub conversation: [u8; 32],
    pub group: [u8; 32],
    pub contact_policy: [u8; 32],
    pub history: [u8; 32],
    pub opened_at: u64,
    pub expires_at: u64,
    pub sender_authority: [u8; 32],
    pub sender_challenge: [u8; 32],
}

/// Public terms the recipient fixes for its own reservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub recipient_authority: [u8; 32],
    pub recipient_challenge: [u8; 32],
}

/// A public statement with its proof, both opaque to the door.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub statement: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Answer,
    Close,
}

/// What one device sends to the other. Every variant names the wave by nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WaveMessage {
    Hello {
        nonce: [u8; 32],
        hello: Hello,
    },
    Terms {
        nonce: [u8; 32],
        terms: Terms,
    },
    Offer {
        nonce: [u8; 32],
        reservation: Blob,
        receipt_digest: [u8; 32],
    },
    Reservation {
        nonce: [u8; 32],
        reservation: Blob,
        key_package: Vec<u8>,
    },
    Welcome {
        nonce: [u8; 32],
        welcome: Vec<u8>,
    },
    Outcome {
        nonce: [u8; 32],
        decision: Decision,
        outcome: Blob,
    },
}

impl WaveMessage {
    pub fn nonce(&self) -> &[u8; 32] {
        match self {
            Self::Hello { nonce, .. }
            | Self::Terms { nonce, .. }
            | Self::Offer { nonce, .. }
            | Self::Reservation { nonce, .. }
            | Self::Welcome { nonce, .. }
            | Self::Outcome { nonce, .. } => nonce,
        }
    }
}

/// What the background worker is asked to prove. The worker holds the wallet
/// openings; nothing in this request is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProveJob {
    pub id: [u8; 32],
    pub nonce: [u8; 32],
    pub work: Work,
    pub sender: cnbx::WaveContext,
    pub recipient: cnbx::WaveContext,
    /// The receipt digest the Answer settles (recipient Answer only).
    pub receipt_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Work {
    ReserveSender,
    ReserveRecipient,
    Answer,
    Close,
    Punish,
}

/// A proved job, as the worker returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proved {
    pub blob: Blob,
    /// Digest of the signed receipt this proof created or settled (sender
    /// reservation) or none.
    pub receipt_digest: Option<[u8; 32]>,
    /// The wallet's own new records, adopted with the same checkpoint.
    pub wallet: Vec<WalletRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WalletRecord {
    pub owner: String,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

// ---- action bodies and results -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaveSend {
    pub peer: String,
}

/// Answer or close one wave addressed to this member.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaveDecide {
    pub nonce: [u8; 32],
    pub decision: Decision,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WavePunish {
    pub peer: String,
    /// The wave the punishment answers, when it came from one.
    pub nonce: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaveIncoming {
    pub peer: String,
    pub message: WaveMessage,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaveStatus {
    pub nonce: [u8; 32],
    pub peer: String,
    pub role: u8,
    pub stage: Stage,
    pub conversation: Option<[u8; 32]>,
    /// Unfinished background work for this wave (proof jobs, queued messages).
    pub pending: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaveList {
    pub waves: Vec<WaveStatus>,
    /// Jobs that used up their attempts and wait for attention.
    pub stalled: u32,
}

/// What the host worker does next.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobOffer {
    pub job: Option<ProveJob>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobResult {
    Proved {
        proved: Proved,
    },
    /// Building or proving failed or stayed uncertain. The member's action is
    /// kept; the job returns to the queue.
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobDone {
    pub id: [u8; 32],
    pub result: JobResult,
}

/// Messages queued for the other device. The host delivers them and confirms.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Outbox {
    pub messages: Vec<Queued>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Queued {
    pub peer: String,
    pub message: WaveMessage,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Delivered {
    pub nonce: [u8; 32],
    /// The kind of message that reached the other device.
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobRef {
    pub id: [u8; 32],
}
