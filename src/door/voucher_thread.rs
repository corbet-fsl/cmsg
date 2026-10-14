//! The direct thread of a vouching, on the bound Vault.
//!
//! The newcomer's single-use key package travels in the sealed redemption
//! notice, the sponsor's device creates the thread and returns the Welcome in the
//! bond-sealed reply, and the newcomer joins from it (`vouching` carries them).
//! This module is the Inbox side of those three steps. Each is idempotent so any
//! interruption simply repeats it: the Welcome is committed in the SAME
//! transaction as the thread (`THREAD_OWNER`), and a message the newcomer wrote
//! before the thread exists waits in `QUEUE_OWNER` until the join sends it.
use super::inbox_conversation::{operation, ConversationSend};
use super::inbox_waves::engine::{inbox_error, Devices, Env};
use super::*;
use ckmg::{Authority, Clock, Entropy, SecureStore};
use cwst::backend::Backend;
use cwst::Change;

/// Companion record: conversation id to the Welcome the sponsor created.
pub(crate) const THREAD_OWNER: &str = "cmsg.voucher.welcome";
/// Messages written before the thread existed: conversation id to a JSON list.
pub(crate) const QUEUE_OWNER: &str = "cmsg.voucher.queue";
/// Most messages one device keeps waiting for a thread.
const MAXIMUM_QUEUED: usize = 64;

fn step(conversation: &[u8; 32], name: &str) -> [u8; 32] {
    *ckmg::hash(&[b"cmsg.voucher-thread.v1".as_slice(), conversation, name.as_bytes()].concat())
        .value()
}

impl<'a, S, C, R, A, B> Env<'a, S, C, R, A, B>
where
    S: SecureStore,
    C: Clock,
    R: Entropy,
    A: Authority,
    B: Backend,
{
    async fn voucher_devices(&mut self) -> Result<Devices<'a>> {
        let own = self.keys.lineage().await.map_err(facades::keys_error)?;
        Ok(Devices {
            own,
            ports: self.ports,
        })
    }

    /// The newcomer's key package for the thread of `conversation`; its private
    /// part is committed with the thread slot before the bytes are returned.
    pub(crate) async fn voucher_key_package(&mut self, conversation: [u8; 32]) -> Result<Vec<u8>> {
        let view = self
            .inbox
            .view(conversation, self.store)
            .map_err(inbox_error)?;
        let mut devices = self.voucher_devices().await?;
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut devices,
        };
        let opened = view
            .key_package(&mut port)
            .await
            .map_err(inbox_error)?
            .commit(
                &mut port,
                &mut cthr::Unavailable,
                self.store,
                step(&conversation, "key-package"),
            )
            .await
            .map_err(inbox_error)?;
        match opened.events().first() {
            Some(cnbx::ConversationEvent::KeyPackage { bytes }) => Ok(bytes.clone()),
            _ => Err(ErrorCode::Refused),
        }
    }

    /// The sponsor's device creates the direct thread for the newcomer's key
    /// package and returns the Welcome. A repeat returns the stored Welcome.
    pub(crate) async fn voucher_create(
        &mut self,
        peer: &str,
        conversation: [u8; 32],
        package: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(welcome) = self
            .store
            .read(THREAD_OWNER, &conversation)
            .map_err(|_| ErrorCode::Reconcile)?
        {
            return Ok(welcome.to_vec());
        }
        let contacts = ctcs::Contacts::load(self.binding.clone(), self.store)
            .map_err(|error| inbox_error(cnbx::Error::Contacts(error)))?;
        let view = self
            .inbox
            .view(conversation, self.store)
            .map_err(inbox_error)?;
        let (mut for_authority, mut for_keys) =
            (self.voucher_devices().await?, self.voucher_devices().await?);
        let mut authority = cnbx::ContactAuthority::new(&contacts, &mut for_authority);
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut for_keys,
        };
        view.create_direct(&mut port, &mut authority, peer, package)
            .await
            .map_err(inbox_error)?
            .commit_with_welcome(
                &mut port,
                &mut authority,
                self.store,
                step(&conversation, "create"),
                THREAD_OWNER,
                &conversation,
            )
            .await
            .map_err(inbox_error)?;
        self.store
            .read(THREAD_OWNER, &conversation)
            .map_err(|_| ErrorCode::Reconcile)?
            .map(<[u8]>::to_vec)
            .ok_or(ErrorCode::Reconcile)
    }

    /// The newcomer's device joins the thread from the Welcome, then sends what
    /// was written while it did not exist. A thread that is already joined is
    /// not an error: the queue is still drained.
    pub(crate) async fn voucher_join(
        &mut self,
        peer: &str,
        conversation: [u8; 32],
        welcome: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let contacts = ctcs::Contacts::load(self.binding.clone(), self.store)
            .map_err(|error| inbox_error(cnbx::Error::Contacts(error)))?;
        let view = self
            .inbox
            .view(conversation, self.store)
            .map_err(inbox_error)?;
        let (mut for_authority, mut for_keys) =
            (self.voucher_devices().await?, self.voucher_devices().await?);
        let mut authority = cnbx::ContactAuthority::new(&contacts, &mut for_authority);
        let mut port = cnbx::KeyPort {
            keys: self.keys,
            handle: self.threads,
            devices: &mut for_keys,
        };
        let joined = match view
            .join_direct(&mut port, &mut authority, peer, welcome)
            .await
        {
            Ok(preparing) => preparing
                .commit(
                    &mut port,
                    &mut authority,
                    self.store,
                    step(&conversation, "join"),
                )
                .await
                .map(|_| ()),
            Err(error) => Err(error),
        };
        match joined {
            Ok(()) | Err(cnbx::Error::Threads(cthr::Error::State)) => {}
            Err(error) => return Err(inbox_error(error)),
        }
        self.voucher_flush(peer, conversation).await
    }

    fn queued(&self, conversation: &[u8; 32]) -> Result<Vec<String>> {
        match self
            .store
            .read(QUEUE_OWNER, conversation)
            .map_err(|_| ErrorCode::Reconcile)?
        {
            None => Ok(Vec::new()),
            Some(bytes) => serde_json::from_slice(bytes).map_err(|_| ErrorCode::Reconcile),
        }
    }

    async fn write_queue(&mut self, conversation: &[u8; 32], queue: &[String]) -> Result<()> {
        let version = self.store.version().map_err(|_| ErrorCode::Reconcile)?;
        let bytes = serde_json::to_vec(queue).map_err(|_| ErrorCode::Unavailable)?;
        let change = if queue.is_empty() {
            Change::Delete {
                owner: QUEUE_OWNER,
                key: conversation,
            }
        } else {
            Change::Put {
                owner: QUEUE_OWNER,
                key: conversation,
                value: &bytes,
            }
        };
        self.store
            .commit(version, operation()?, &[change], &[])
            .await
            .map(|_| ())
            .map_err(|_| ErrorCode::Reconcile)
    }

    /// Keep a message for a thread that does not exist yet. It is stored before
    /// the caller is told, so it survives a restart.
    pub(crate) async fn voucher_queue(
        &mut self,
        conversation: [u8; 32],
        text: String,
    ) -> Result<()> {
        let mut queue = self.queued(&conversation)?;
        if queue.len() >= MAXIMUM_QUEUED {
            return Err(ErrorCode::Capacity);
        }
        queue.push(text);
        self.write_queue(&conversation, &queue).await
    }

    /// Whether `conversation` is a voucher contact that has no thread yet, so a
    /// message waits instead of failing.
    pub(crate) fn voucher_waiting(&self, peer: &str, conversation: &[u8; 32]) -> Result<bool> {
        let contacts = ctcs::Contacts::load(self.binding.clone(), self.store)
            .map_err(|error| inbox_error(cnbx::Error::Contacts(error)))?;
        let relation = contacts
            .relation(peer)
            .map_err(|error| inbox_error(cnbx::Error::Contacts(error)))?;
        Ok(relation.state == ctcs::State::Established
            && relation.conversation == Some(*conversation))
    }

    /// Send, oldest first, what waited for the thread. Each message leaves the
    /// queue as soon as it is sent.
    pub(crate) async fn voucher_flush(
        &mut self,
        peer: &str,
        conversation: [u8; 32],
    ) -> Result<Vec<Vec<u8>>> {
        let mut queue = self.queued(&conversation)?;
        let mut wires = Vec::new();
        while !queue.is_empty() {
            let text = queue[0].clone();
            let sent = self
                .chat_send(ConversationSend {
                    peer: peer.to_owned(),
                    conversation,
                    text,
                })
                .await?;
            // Still waiting means the thread is not there: keep the rest.
            if sent.queued {
                break;
            }
            wires.push(sent.wire);
            queue.remove(0);
            self.write_queue(&conversation, &queue).await?;
        }
        Ok(wires)
    }
}
