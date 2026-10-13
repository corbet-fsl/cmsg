//! Contacts operations on the bound Vault. The Store lock is taken only after
//! the purpose key exists, because creating a key checkpoints through that Store.
use super::*;

impl<B, C, E, A, R, W> Custody<B, C, E, A, R, W>
where
    B: cwst::backend::Backend,
    C: ckmg::Clock,
    E: ckmg::Entropy,
    A: ckmg::Authority,
    R: cvlt::Records,
{
    pub(super) async fn blocking_rules_owned(&mut self) -> Result<Vec<String>> {
        let storage = self.vault.storage().clone();
        let store = storage.lock().await;
        self.check_scope(&store).await?;
        self.inbox
            .contacts(&store)
            .and_then(|contacts| contacts.blocking_rules())
            .map_err(contact_error)
    }

    pub(super) async fn contact_act_owned(
        &mut self,
        request: inbox::ContactAct,
    ) -> Result<cnbx::Relation> {
        let handle = cnbx::Contacts::key(self.vault.keys())
            .await
            .map_err(contact_error)?;
        let storage = self.vault.storage().clone();
        let mut store = storage.lock().await;
        self.check_scope(&store).await?;
        let contacts = self.inbox.contacts(&store).map_err(contact_error)?;
        let next = contacts
            .apply(
                &request.peer,
                request.action,
                self.vault.keys(),
                &handle,
                &mut store,
            )
            .await
            .map_err(contact_error)?;
        next.relation(&request.peer).map_err(contact_error)
    }

    /// Run `act` against the Inbox owners with this member's purpose keys. The
    /// keys are obtained BEFORE the Store lock: creating a key checkpoints
    /// through that same Store.
    async fn with_env<T, F>(&mut self, ports: &dyn inbox_waves::WavePorts, act: F) -> Result<T>
    where
        F: for<'e> AsyncFnOnce(&mut inbox_waves::engine::Env<'e, cvlt::KeyStore<B>, C, E, A, B>) -> Result<T>,
    {
        let contacts = cnbx::Contacts::key(self.vault.keys())
            .await
            .map_err(contact_error)?;
        let threads = self
            .vault
            .keys()
            .key(cnbx::threads_purpose())
            .await
            .map_err(keys_error)?;
        let delivery = self
            .vault
            .keys()
            .key(cnbx::delivery_purpose())
            .await
            .map_err(keys_error)?;
        let storage = self.vault.storage().clone();
        let mut store = storage.lock().await;
        self.check_scope(&store).await?;
        let mut env = inbox_waves::engine::Env {
            inbox: &self.inbox,
            binding: &self.binding,
            keys: self.vault.keys(),
            store: &mut store,
            ports,
            contacts: &contacts,
            threads: &threads,
            delivery: &delivery,
        };
        act(&mut env).await
    }

    pub(super) async fn conversation_owned(
        &mut self,
        command: inbox_conversation::Command,
        ports: &dyn inbox_waves::WavePorts,
    ) -> Result<inbox_conversation::Answer> {
        self.with_env(ports, async move |env| env.conversation(command).await)
            .await
    }

    pub(super) async fn waves_owned(
        &mut self,
        command: inbox_waves::Command,
        ports: &dyn inbox_waves::WavePorts,
    ) -> Result<inbox_waves::Answer> {
        use inbox_waves::{Answer, Command};
        self.with_env(ports, async move |env| {
            Ok(match command {
                Command::Send(request) => Answer::Status(env.send(&request.peer).await?),
                Command::Decide(request) => {
                    Answer::Status(env.decide(&request.nonce, request.decision).await?)
                }
                Command::Punish(request) => {
                    Answer::Relation(env.punish(&request.peer, request.nonce).await?)
                }
                Command::Receive(request) => {
                    Answer::Status(env.receive(&request.peer, request.envelope).await?)
                }
                Command::List => Answer::List(env.list()?),
                Command::Outbox => Answer::Outbox(env.outbox()?),
                Command::Delivered(request) => {
                    env.delivered(&request).await?;
                    Answer::Done
                }
                Command::NextJob => Answer::Job(Box::new(env.next_job().await?)),
                Command::JobDone(request) => Answer::Status(env.job_done(request).await?),
                Command::Retry(id) => {
                    env.retry_job(&id).await?;
                    Answer::Done
                }
                Command::Recover => {
                    env.recover_jobs().await?;
                    Answer::Done
                }
            })
        })
        .await
    }

    pub(super) async fn check_scope(&mut self, store: &cwst::Store<B>) -> Result<()> {
        let lineage = self.vault.keys().lineage().await.map_err(keys_error)?;
        if lineage.binding != self.binding || !store.is_scope(self.binding.community()) {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(())
    }
}

/// An uncertain or conflicting checkpoint must be reconciled by the owner, never
/// retried as a new operation.
pub(super) fn contact_error(error: cnbx::Error) -> ErrorCode {
    match error {
        cnbx::Error::Contacts(cnbx::ContactError::Authority) => ErrorCode::Unauthorized,
        cnbx::Error::Contacts(cnbx::ContactError::Storage | cnbx::ContactError::Conflict) => {
            ErrorCode::Reconcile
        }
        cnbx::Error::Contacts(cnbx::ContactError::Unavailable) => ErrorCode::Unavailable,
        cnbx::Error::Contacts(cnbx::ContactError::Limit) => ErrorCode::Capacity,
        cnbx::Error::Contacts(cnbx::ContactError::Encoding | cnbx::ContactError::Scope) => {
            ErrorCode::InvalidRequest
        }
        _ => ErrorCode::Refused,
    }
}
