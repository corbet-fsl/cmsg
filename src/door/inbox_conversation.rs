//! Conversation actions of the Inbox door: send, receive, acknowledge and retry
//! over one released direct conversation. Thin: Threads encrypts and decrypts,
//! Delivery makes the wire and the receipt durable, Contacts decides who may
//! write. A message is part of history only after the shared checkpoint; the
//! wires returned here are already durable and go to the Mesh unchanged.
//!
//! A conversation opened by a Claimed Answer is Pending in Contacts until the
//! settled Answer upgrades it. While this member's own Answer is Claimed in the
//! Waves journal the recipient may SEND at once (claim-aware authority); a
//! reverted claim leaves the durable messages pending until the settled Answer
//! or a fresh claim. Receiving always waits for Established, so the sender's
//! device shows nothing before it has verified the Answer proof.
use super::inbox_waves::engine::{inbox_error, Devices, Env};
use super::*;
use ckmg::{Authority, Clock, Entropy, SecureStore};
use cwst::backend::Backend;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationSend {
    pub peer: String,
    pub conversation: [u8; 32],
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Wired {
    pub peer: String,
    pub conversation: [u8; 32],
    /// A durable transport item (ciphertext or signed receipt) from the Mesh.
    pub wire: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConversationRetry {
    pub peer: String,
    pub conversation: [u8; 32],
    pub message: [u8; 32],
}

/// The durable wire of a message this member sent.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sent {
    pub message: [u8; 32],
    pub status: Option<cnbx::DeliveryStatus>,
    pub wire: Vec<u8>,
}

/// A received message and the signed receipt to send back.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Received {
    /// `None` for a wire already accepted before: only its receipt repeats.
    pub message: Option<cnbx::Message>,
    pub receipt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Acked {
    pub message: [u8; 32],
    /// True when the receipt had already been accepted (no second checkpoint).
    pub repeated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Retried {
    pub wire: Vec<u8>,
}

pub(crate) enum Command {
    Send(ConversationSend),
    Receive(Wired),
    Ack(Wired),
    Retry(ConversationRetry),
}
pub(crate) enum Answer {
    Sent(Sent),
    Received(Received),
    Acked(Acked),
    Retried(Retried),
}

fn operation() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    Entropy::fill(&mut ckmg::SystemEntropy, &mut bytes).map_err(|_| ErrorCode::Unavailable)?;
    Ok(bytes)
}

impl<'a, S, C, R, A, B> Env<'a, S, C, R, A, B>
where
    S: SecureStore,
    C: Clock,
    R: Entropy,
    A: Authority,
    B: Backend,
{
    pub(crate) async fn conversation(&mut self, command: Command) -> Result<Answer> {
        match command {
            Command::Send(request) => self.chat_send(request).await.map(Answer::Sent),
            Command::Receive(request) => self.chat_receive(request).await.map(Answer::Received),
            Command::Ack(request) => self.chat_ack(request).await.map(Answer::Acked),
            Command::Retry(request) => self.chat_retry(request).await.map(Answer::Retried),
        }
    }

    fn contacts_journal(&self) -> Result<ctcs::Contacts> {
        ctcs::Contacts::load(self.binding.clone(), self.store)
            .map_err(|error| inbox_error(cnbx::Error::Contacts(error)))
    }

    async fn peers(&mut self) -> Result<Devices<'a>> {
        let own = self.keys.lineage().await.map_err(facades::keys_error)?;
        Ok(Devices {
            own,
            ports: self.ports,
        })
    }

    async fn chat_send(&mut self, request: ConversationSend) -> Result<Sent> {
        self.refuse_blocked(&request.peer)?;
        let contacts = self.contacts_journal()?;
        let claim = self.claim_for(&request.peer, &request.conversation)?;
        let mut view = self
            .inbox
            .view(request.conversation, self.store)
            .map_err(inbox_error)?;
        if let Some(claim) = &claim {
            view = view.with_claim(claim.clone());
        }
        let (mut for_authority, mut for_keys, mut for_commit) = (
            self.peers().await?,
            self.peers().await?,
            self.peers().await?,
        );
        let mut authority = match &claim {
            Some(claim) => {
                cnbx::ContactAuthority::with_claim(&contacts, &mut for_authority, claim)
            }
            None => cnbx::ContactAuthority::new(&contacts, &mut for_authority),
        };
        let published = {
            let mut port = cnbx::KeyPort {
                keys: self.keys,
                handle: self.threads,
                devices: &mut for_keys,
            };
            let pending = view
                .send(&mut port, &mut authority, request.text.as_bytes())
                .await
                .map_err(inbox_error)?;
            pending
                .commit(
                    &mut port,
                    &mut authority,
                    &mut for_commit,
                    self.store,
                    operation()?,
                )
                .await
                .map_err(inbox_error)?
        };
        let message = *published
            .outgoing_ids()
            .first()
            .ok_or(ErrorCode::Reconcile)?;
        let mut for_wire = self.peers().await?;
        let wire = published
            .outgoing(
                self.keys,
                self.delivery,
                &mut for_wire,
                self.store,
                operation()?,
            )
            .await
            .map_err(inbox_error)?;
        Ok(Sent {
            message,
            status: published.delivery_status(&message),
            wire: wire.bytes().to_vec(),
        })
    }

    async fn chat_receive(&mut self, request: Wired) -> Result<Received> {
        // A blocked sender is refused before anything is decrypted.
        self.refuse_blocked(&request.peer)?;
        let contacts = self.contacts_journal()?;
        let view = self
            .inbox
            .view(request.conversation, self.store)
            .map_err(inbox_error)?;
        let (mut for_authority, mut for_keys, mut for_receive, mut for_commit) = (
            self.peers().await?,
            self.peers().await?,
            self.peers().await?,
            self.peers().await?,
        );
        let mut authority = cnbx::ContactAuthority::new(&contacts, &mut for_authority);
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut for_keys,
        };
        let receiving = match view
            .receive(&request.wire, &mut port, &mut authority, &mut for_receive)
            .await
            .map_err(inbox_error)?
        {
            cnbx::Receive::Duplicate(receipt) => {
                return Ok(Received {
                    message: None,
                    receipt: receipt.bytes().to_vec(),
                });
            }
            cnbx::Receive::Pending(receiving) => receiving,
        };
        let prepared = receiving
            .prepare_receipt(self.keys, self.delivery)
            .await
            .map_err(inbox_error)?;
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut for_keys,
        };
        let published = prepared
            .commit(
                &mut port,
                &mut authority,
                &mut for_commit,
                self.store,
                operation()?,
            )
            .await
            .map_err(inbox_error)?;
        let message = published
            .history()
            .last()
            .cloned()
            .ok_or(ErrorCode::Reconcile)?;
        let receipt = published.receipt(&message.id).map_err(inbox_error)?;
        Ok(Received {
            receipt: receipt.bytes().to_vec(),
            message: Some(message),
        })
    }

    async fn chat_ack(&mut self, request: Wired) -> Result<Acked> {
        self.refuse_blocked(&request.peer)?;
        let contacts = self.contacts_journal()?;
        let view = self
            .inbox
            .view(request.conversation, self.store)
            .map_err(inbox_error)?;
        let (mut for_authority, mut for_ack, mut for_keys, mut for_commit) = (
            self.peers().await?,
            self.peers().await?,
            self.peers().await?,
            self.peers().await?,
        );
        let mut authority = cnbx::ContactAuthority::new(&contacts, &mut for_authority);
        match view
            .acknowledge(&request.wire, &mut for_ack)
            .await
            .map_err(inbox_error)?
        {
            cnbx::Acknowledgement::AlreadyAccepted(message) => Ok(Acked {
                message,
                repeated: true,
            }),
            cnbx::Acknowledgement::Pending(pending) => {
                let mut port = cnbx::KeyPort {
                    keys: self.keys,
                    handle: self.threads,
                    devices: &mut for_keys,
                };
                let published = pending
                    .commit(
                        &mut port,
                        &mut authority,
                        &mut for_commit,
                        self.store,
                        operation()?,
                    )
                    .await
                    .map_err(inbox_error)?;
                let message = published
                    .history()
                    .last()
                    .map(|message| message.id)
                    .ok_or(ErrorCode::Reconcile)?;
                Ok(Acked {
                    message,
                    repeated: false,
                })
            }
        }
    }

    async fn chat_retry(&mut self, request: ConversationRetry) -> Result<Retried> {
        self.refuse_blocked(&request.peer)?;
        let mut view = self
            .inbox
            .view(request.conversation, self.store)
            .map_err(inbox_error)?;
        if let Some(claim) = self.claim_for(&request.peer, &request.conversation)? {
            view = view.with_claim(claim);
        }
        let mut devices = self.peers().await?;
        let wire = view
            .retry(&request.message, &mut devices)
            .await
            .map_err(inbox_error)?;
        Ok(Retried {
            wire: wire.bytes().to_vec(),
        })
    }
}

async fn run(door: &mut Door, key: &[u8; 32], command: Command) -> Result<Answer> {
    match inbox_waves::run_op(door, key, inbox_waves::Op::Chat(command)).await? {
        inbox_waves::Reply::Chat(answer) => Ok(answer),
        inbox_waves::Reply::Waves(_) => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn send(
    door: &mut Door,
    key: &[u8; 32],
    request: ConversationSend,
) -> Result<(Sent, Vec<Event>)> {
    match run(door, key, Command::Send(request)).await? {
        Answer::Sent(sent) => Ok((sent, vec![])),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn receive(
    door: &mut Door,
    key: &[u8; 32],
    request: Wired,
) -> Result<(Received, Vec<Event>)> {
    match run(door, key, Command::Receive(request)).await? {
        Answer::Received(received) => Ok((received, vec![])),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn acknowledge(
    door: &mut Door,
    key: &[u8; 32],
    request: Wired,
) -> Result<(Acked, Vec<Event>)> {
    match run(door, key, Command::Ack(request)).await? {
        Answer::Acked(acked) => Ok((acked, vec![])),
        _ => Err(ErrorCode::Unavailable),
    }
}

pub(super) async fn retry(
    door: &mut Door,
    key: &[u8; 32],
    request: ConversationRetry,
) -> Result<(Retried, Vec<Event>)> {
    match run(door, key, Command::Retry(request)).await? {
        Answer::Retried(retried) => Ok((retried, vec![])),
        _ => Err(ErrorCode::Unavailable),
    }
}
