//! Recovery and activation from the durable pending companion.
//!
//! These run on a fresh admission: nothing in RAM survives a restart except what
//! the Store committed. Reopening re-sends the byte-identical stored outbox, never
//! a rebuilt or re-signed request. Activation is the gate before custody.
use super::genesis::operation;
use super::*;
use cwlt::account_owner::ReopenedPending;

/// Public, non-secret result of an activation.
#[derive(Debug, PartialEq, Eq)]
pub struct Activated {
    /// Accepted version; a genesis account is version zero.
    pub version: u64,
    /// Original operator acceptance time.
    pub accepted_at: u64,
    /// False when the outbox acknowledgement is still owed (repeat the action).
    pub outbox_settled: bool,
}

/// The accepted account when one is already active (idempotent setup: a
/// returning member repeats the actions and receives the existing account).
pub async fn existing_active<B, C, E, A, R>(
    account: &mut CommunityAccount<B, C, E, A, R>,
) -> Option<Activated>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    AccountAdmission::already_active(account).await.ok()
}

/// Whether a durable pending request already exists (the member enrolled and
/// opened before; a repeat resumes it instead of preparing a new request).
pub async fn has_pending<B, C, E, A, R>(account: &mut CommunityAccount<B, C, E, A, R>) -> bool
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    account.vault.reopen_pending_genesis(now()).await.is_ok()
}

impl AccountAdmission<'_> {
    /// Reopen the durable companion and require it to belong to this exact
    /// account, origin, pinned Balance payload and operator key.
    async fn reopen_checked<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<(CurrentAdmission, ReopenedPending)>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let current = self.current()?;
        let opened = account
            .vault
            .reopen_pending_genesis(now())
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if opened.binding.acceptance.operator_key != current.material.account_response_key {
            return Err(ErrorCode::Unauthorized);
        }
        let pending = PendingBinding::decode(&opened.binding.upper)?;
        account
            .check_pending(&pending, current.material_digest, &opened.outbox)
            .await?;
        Ok((current, opened))
    }

    /// Recover a pending request: when still in state A, re-send the identical
    /// stored outbox (the server answers an exact retry with the stored
    /// acceptance), verify the response and advance to state B. Returns the
    /// operator's acceptance time.
    pub async fn reopen<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<u64>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let (current, opened) = self.reopen_checked(account).await?;
        if let Some(response) = &opened.binding.response {
            return Ok(response.issuer.accepted_at);
        }
        let signed = SignedApplyExtended::from_outbox(
            opened.outbox.clone(),
            &current.material.extension_policy,
        )?;
        if signed.request_id() != opened.binding.acceptance.request_id {
            return Err(ErrorCode::Unauthorized);
        }
        signed.check_binding_digest(opened.binding.acceptance.request_digest)?;
        let response = self.send_signed(&signed).await?;
        let trust = response_trust(&self.current().map_err(|_| ErrorCode::Reconcile)?.material)
            .map_err(|_| ErrorCode::Reconcile)?;
        account
            .vault
            .advance_pending_genesis(&response.to_engine()?, &trust, operation()?, now())
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        Ok(response.acceptance().accepted_at)
    }

    /// The account may already be active (an earlier activation committed and
    /// only its confirmation was lost): report it and finish the outbox settle.
    async fn already_active<B, C, E, A, R>(
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<Activated>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let accepted = account
            .vault
            .restore_accepted_account()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let outbox_settled = account
            .vault
            .settle_account_outbox(operation()?)
            .await
            .unwrap_or(false);
        Ok(Activated {
            version: accepted.version(),
            accepted_at: accepted.accepted_at(),
            outbox_settled,
        })
    }

    /// The activation gate. Any failure releases nothing and leaves state B as
    /// it was: reopen B before the horizon, re-verify the stored response under
    /// the CURRENT trust and frontier, re-check admission, Keys and binding
    /// immediately before and after the one accepted commit.
    pub async fn activate<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
    ) -> Result<Activated>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let (current, opened) = match self.reopen_checked(account).await {
            Ok(value) => value,
            Err(refusal) => {
                return Self::already_active(account).await.map_err(|_| refusal);
            }
        };
        if !opened.accepted() {
            return Err(ErrorCode::Unavailable);
        }
        let trust = response_trust(&current.material)?;
        let activation = account
            .vault
            .begin_account_activation(&trust, now())
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        account.check(&current.origin).await?;
        let before = self.current()?;
        if before.material != current.material
            || before.material_digest != current.material_digest
            || before.grant != current.grant
            || before.origin != current.origin
        {
            return Err(ErrorCode::Unauthorized);
        }
        let pending = PendingBinding::decode(&opened.binding.upper)?;
        account
            .check_pending(&pending, before.material_digest, &opened.outbox)
            .await?;
        let activated = account
            .vault
            .commit_account_activation(activation, operation()?, operation()?)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        // The account is durable now; a failing recheck only reports uncertainty
        // and the next activation finds it already active.
        account
            .check(&current.origin)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        self.current().map_err(|_| ErrorCode::Reconcile)?;
        Ok(Activated {
            version: activated.version,
            accepted_at: activated.accepted_at,
            outbox_settled: activated.outbox_settled,
        })
    }
}
