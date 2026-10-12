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
