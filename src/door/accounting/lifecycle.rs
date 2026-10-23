//! Recovery and activation from the durable pending companion.
//!
//! These run on a fresh admission: nothing in RAM survives a restart except what
//! the Store committed. Reopening re-sends the byte-identical stored outbox, never
//! a rebuilt or re-signed request. Activation is the gate before custody.
use super::genesis::operation;
use super::*;
use cblc::accounting::{self as acct, AccountStatusRequest, AccountStatusResponse};
use cblc::contracts::{AccountServiceRequest, AccountServiceResponse};
use ckmg::wallet_engine::account::{OwnerAbsence, GENESIS_DISCARD_COMMIT_MARGIN_SECONDS};
use cwlt::account_owner::ReopenedPending;

/// What the operator's own signed status allows for an elapsed state A. Only
/// operator times are compared; the device clock never decides.
#[derive(Debug, PartialEq, Eq)]
pub enum Elapsed {
    /// The request was accepted after all and only its response was lost: the
    /// status evidence advanced state A to state B (the operator's acceptance time).
    Adopted(u64),
    /// No account, observed at least the commit margin after the request's
    /// expiry: state A is discarded, a fresh request may be prepared.
    Discarded,
    /// No account yet, but observed too early to prove the request can no longer
    /// commit: ask again from this operator time on.
    Wait(u64),
}

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

/// How many vouchers the accepted account may still hand out at `now` in the
/// sponsor role `role`, from its committed state (cwlt `voucher_remaining`). An
/// account that is not active has none to read: `Unavailable`.
pub async fn voucher_remaining<B, C, E, A, R>(
    account: &mut CommunityAccount<B, C, E, A, R>,
    role: u8,
    now: u64,
) -> Result<u64>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
{
    let accepted = account
        .vault()
        .await?
        .restore_accepted_account()
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    accepted
        .voucher_remaining(role, now)
        .map_err(|_| ErrorCode::Unavailable)
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
    match account.vault().await {
        Ok(mut vault) => vault.reopen_pending_genesis(now()).await.is_ok(),
        Err(_) => false,
    }
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
        let opened = account.vault().await?
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
        // An elapsed request is never re-sent; the guarded discard decides.
        if current.now >= signed.expires_at() {
            return Err(ErrorCode::ProofWindowElapsed);
        }
        let response = self.send_signed(&signed).await?;
        let trust = response_trust(&self.current().map_err(|_| ErrorCode::Reconcile)?.material)
            .map_err(|_| ErrorCode::Reconcile)?;
        account.vault().await?
            .advance_pending_genesis(&response.to_engine()?, &trust, operation()?, now())
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        Ok(response.acceptance().accepted_at)
    }

    /// Settle a state A whose request window elapsed: one authenticated status
    /// (verified under the CURRENT operator key, which must be the sealed one)
    /// decides. An acceptance of exactly this request is adopted; an acceptance
    /// of a request this device discarded earlier is `DiscardedRequestAccepted`;
    /// no account at operator time >= `expires_at` +
    /// `GENESIS_DISCARD_COMMIT_MARGIN_SECONDS` discards state A in one custody step
    /// (the custody owner re-verifies the status itself); earlier, `Wait`.
    pub async fn settle_elapsed<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intents: &mut AccountingIntents,
        intent: &mut ckmg::IntentAdmission,
    ) -> Result<Elapsed>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let (current, opened) = self.reopen_checked(account).await?;
        if opened.accepted() {
            return Err(ErrorCode::Unavailable);
        }
        let signed = SignedApplyExtended::from_outbox(
            opened.outbox.clone(),
            &current.material.extension_policy,
        )?;
        if signed.request_id() != opened.binding.acceptance.request_id {
            return Err(ErrorCode::Unauthorized);
        }
        signed.check_binding_digest(opened.binding.acceptance.request_digest)?;
        let statement = signed.statement();
        let (request, status) = self
            .owner_status(account, intents, intent, statement.community, statement.owner)
            .await?;
        let discarded = account.vault().await?
            .discarded_genesis()
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        match verdict(&status, signed.request_id(), signed.expires_at(), &discarded)? {
            Verdict::Wait(eligible_at) => return Ok(Elapsed::Wait(eligible_at)),
            Verdict::Discard => {}
            Verdict::Adopt => {
                let acceptance = status.acceptance.ok_or(ErrorCode::Reconcile)?;
                let evidence = status.extended.ok_or(ErrorCode::Reconcile)?;
                let current = self.current()?;
                let response = AcceptedResponse::from_status(
                    acceptance,
                    evidence,
                    &signed,
                    &current.material.extension_policy,
                    &current.material.account_response_key,
                )?;
                let trust = response_trust(&current.material)?;
                account.vault().await?
                    .advance_pending_genesis(&response.to_engine()?, &trust, operation()?, now())
                    .await
                    .map_err(|_| ErrorCode::Reconcile)?;
                return Ok(Elapsed::Adopted(response.acceptance().accepted_at));
            }
        }
        let absence = owner_absence(&request, &status)?;
        account.vault().await?
            .discard_elapsed_pending_genesis(
                signed.expires_at(),
                &absence,
                operation()?,
                operation()?,
            )
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        Ok(Elapsed::Discarded)
    }

    /// One authenticated owner-lookup status (no request id) through this held
    /// HTTPS owner: a fresh root device authorization, a device-signed request
    /// under its own one-use intent, the response verified under the current
    /// operator key with the exact request binding.
    async fn owner_status<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intents: &mut AccountingIntents,
        intent: &mut ckmg::IntentAdmission,
        community: [u8; 32],
        owner: [u8; 32],
    ) -> Result<(AccountStatusRequest, AccountStatusResponse)>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let (authorization, _root, current, expires) =
            self.authorize_device(account, intents).await?;
        let expires_at = expires.min(
            current
                .now
                .saturating_add(current.material.policy.max_authorization_seconds),
        );
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| ErrorCode::Unavailable)?;
        if expires_at <= current.now || challenge == [0; 32] {
            return Err(ErrorCode::Unavailable);
        }
        let mut request = AccountStatusRequest {
            community,
            owner,
            request_id: None,
            challenge,
            chat_public_key: current.grant.chat_public_key.clone(),
            issued_at: current.now,
            expires_at,
            signature: String::new(),
        };
        let transcript =
            acct::account_status_bytes(&request).map_err(|_| ErrorCode::Unauthorized)?;
        account.check(&current.origin).await?;
        let lineage = account.vault().await?
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = account.vault().await?
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if B64.encode(device.value()) != current.grant.chat_public_key
            || B64.encode(lineage.root.value()) != authorization.root_public_key
        {
            return Err(ErrorCode::Unauthorized);
        }
        // Held until the signature exists; dropping it cancels unused intent.
        let _admitted = intent
            .admit(
                ckmg::AdmittedCommand {
                    binding: lineage.binding,
                    origin: current.origin.clone(),
                    action: ckmg::Action::SignDeviceEd25519,
                    device,
                    root: Some(lineage.root),
                    epoch: lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: Some(transcript.clone()),
                    expires: expires_at,
                },
                current.now,
            )
            .map_err(|_| ErrorCode::Unauthorized)?;
        let signature = account.vault().await?
            .keys()
            .sign_device_ed25519_current(&transcript, expires_at)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        request.signature = B64.encode(&signature);
        let wire = serde_json::to_value(AccountServiceRequest::Status {
            grant: current.grant.clone(),
            authorization,
            request: request.clone(),
        })
        .map_err(|_| ErrorCode::Unavailable)?;
        // A read: a failure changes nothing and the next join asks again.
        let response = self
            .lease
            .apply_account(wire, now)
            .await
            .map_err(|_| ErrorCode::Unavailable)?;
        let AccountServiceResponse::Status(status) =
            serde_json::from_value(response).map_err(|_| ErrorCode::Unavailable)?
        else {
            return Err(ErrorCode::Unavailable);
        };
        let after = self.current()?;
        if after.material != current.material || after.grant != current.grant {
            return Err(ErrorCode::Unauthorized);
        }
        acct::verify_account_status_response(&status, &request, &after.material.account_response_key)
            .map_err(|_| ErrorCode::Unauthorized)?;
        Ok((request, status))
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
        let accepted = account.vault().await?
            .restore_accepted_account()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let outbox_settled = account.vault().await?
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
        let activation = account.vault().await?
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
        let activated = account.vault().await?
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

/// What one verified owner-lookup status means for the elapsed state A of
/// `request_id`, from operator data alone: no device time is an input.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The status carries exactly this request's acceptance (a lost response).
    Adopt,
    /// No account, observed at least the commit margin after `expires_at`.
    Discard,
    /// No account yet, observed too early; ask again from this operator time.
    Wait(u64),
}

fn verdict(
    status: &AccountStatusResponse,
    request_id: [u8; 32],
    expires_at: u64,
    discarded: &[[u8; 32]],
) -> Result<Verdict> {
    if let Some(acceptance) = &status.acceptance {
        if acceptance.request_id == request_id {
            return Ok(Verdict::Adopt);
        }
        if discarded.contains(&acceptance.request_digest) {
            return Err(ErrorCode::DiscardedRequestAccepted);
        }
        // Another request of this owner is the account: not this device's to settle.
        return Err(ErrorCode::Reconcile);
    }
    let eligible_at = expires_at.saturating_add(GENESIS_DISCARD_COMMIT_MARGIN_SECONDS);
    if status.observed_at < eligible_at {
        return Ok(Verdict::Wait(eligible_at));
    }
    Ok(Verdict::Discard)
}

/// The raw signed values of a verified no-account status, for the custody
/// owner's own verification. Nothing here grants trust.
fn owner_absence(request: &AccountStatusRequest, status: &AccountStatusResponse) -> Result<OwnerAbsence> {
    fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
        B64.decode(value.as_bytes())
            .map_err(|_| ErrorCode::Unauthorized)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)
    }
    if status.acceptance.is_some() || request.request_id.is_some() {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(OwnerAbsence {
        community: request.community,
        owner: request.owner,
        challenge: request.challenge,
        chat_public_key: decode(&request.chat_public_key)?,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        request_signature: decode(&request.signature)?,
        observed_at: status.observed_at,
        signature: decode(&status.signature)?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::update_fixtures as fixtures;
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn status(observed_at: u64, acceptance: Option<cblc::accounting::AccountAcceptance>) -> AccountStatusResponse {
        AccountStatusResponse {
            status_request_digest: [1; 32],
            observed_at,
            acceptance,
            extended: None,
            signature: String::new(),
        }
    }

    #[test]
    fn only_operator_times_and_data_decide_an_elapsed_state_a() {
        let margin = GENESIS_DISCARD_COMMIT_MARGIN_SECONDS;
        let own = fixtures::signed(1);
        let (id, expires) = (own.request_id(), 1_000);
        // No account: early operator observations wait, the margin discards. The
        // verdict takes no device time, so a device clock far ahead cannot hurry it.
        for observed in [expires - 1, expires, expires + margin - 1] {
            assert_eq!(
                verdict(&status(observed, None), id, expires, &[]),
                Ok(Verdict::Wait(expires + margin))
            );
        }
        for observed in [expires + margin, u64::MAX] {
            assert_eq!(verdict(&status(observed, None), id, expires, &[]), Ok(Verdict::Discard));
        }
        // A lost response: this request's acceptance is adopted, never discarded,
        // however late the observation.
        let accepted = fixtures::accepted(&own, 150).acceptance().clone();
        assert_eq!(
            verdict(&status(u64::MAX, Some(accepted)), id, expires, &[]),
            Ok(Verdict::Adopt)
        );
        // An acceptance of a request this device discarded is the typed error;
        // any other request's acceptance is not this device's to settle.
        let earlier = fixtures::accepted(&fixtures::signed(2), 150).acceptance().clone();
        let digest = earlier.request_digest;
        assert_eq!(
            verdict(&status(expires + margin, Some(earlier.clone())), id, expires, &[digest]),
            Err(ErrorCode::DiscardedRequestAccepted)
        );
        assert_eq!(
            verdict(&status(expires + margin, Some(earlier)), id, expires, &[]),
            Err(ErrorCode::Reconcile)
        );
    }

    #[test]
    fn a_balance_signed_no_account_status_verifies_in_the_custody_engine() {
        let operator = SigningKey::from_bytes(&[5; 32]);
        let device = SigningKey::from_bytes(&[9; 32]);
        let mut request = AccountStatusRequest {
            community: [2; 32],
            owner: [3; 32],
            request_id: None,
            challenge: [4; 32],
            chat_public_key: B64.encode(device.verifying_key().as_bytes()),
            issued_at: 1_000,
            expires_at: 1_100,
            signature: String::new(),
        };
        let bytes = acct::account_status_bytes(&request).unwrap();
        request.signature = B64.encode(&device.sign(&bytes).to_bytes());
        let signed = [bytes, device.sign(&acct::account_status_bytes(&request).unwrap()).to_bytes().to_vec()].concat();
        let mut response = status(1_050, None);
        response.status_request_digest = Sha256::digest(signed).into();
        response.signature = B64.encode(
            &operator
                .sign(&acct::account_status_response_bytes(&response).unwrap())
                .to_bytes(),
        );
        let key = operator.verifying_key().to_bytes();
        acct::verify_account_status_response(&response, &request, &key).unwrap();
        let absence = owner_absence(&request, &response).unwrap();
        // The engine rebuilds both Balance messages itself and agrees.
        absence.verify(&key).unwrap();
        assert!(absence.verify(&SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes()).is_err());
        let mut late = absence.clone();
        late.observed_at += 1;
        assert!(late.verify(&key).is_err());
        // An acceptance or a request id is never an absence.
        let mut accepted = response.clone();
        accepted.acceptance = Some(fixtures::accepted(&fixtures::signed(1), 150).acceptance().clone());
        assert!(owner_absence(&request, &accepted).is_err());
    }
}
