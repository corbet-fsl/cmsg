//! Register this account's common-root record recipient with the community ledger.
//!
//! The ledger seals each epoch's record packet to this key; without a registration
//! the member has no record and cannot enter a Forum with accounting. The key is
//! derived inside Keys from the synced wallet root, so every device of the member
//! registers the same key and a repeat is idempotent at the ledger.
use super::*;
use cblc::contracts::{
    recipient_bytes, AccountServiceRequest, AccountServiceResponse, RecipientRequest,
};

impl AccountAdmission<'_> {
    /// Sign and send one `RegisterRecordRecipient`. The root authorizes the device
    /// and the device signs the request, each under its own one-use intent; the
    /// admission and the local owner are rechecked after every await. The account
    /// must already be accepted (the ledger refuses a registration without one).
    pub async fn register_record_recipient<B, C, E, A, R>(
        &mut self,
        account: &mut CommunityAccount<B, C, E, A, R>,
        intents: &mut AccountingIntents,
    ) -> Result<()>
    where
        B: cwst::backend::Backend,
        C: Clock,
        E: Entropy,
        A: Authority,
        R: Records,
    {
        let (authorization, _root_guard, current, expires) =
            self.authorize_device(account, intents).await?;
        let owner: [u8; 32] = B64
            .decode(current.grant.member_id.as_bytes())
            .map_err(|_| ErrorCode::Unauthorized)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let recipient_key = account
            .vault()
            .await?
            .keys()
            .with_record_recipient(|recipient| recipient.public_key())
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let expires_at = expires
            .min(
                current
                    .now
                    .saturating_add(current.material.policy.max_authorization_seconds),
            )
            .min(authorization.expires_at);
        if expires_at <= current.now {
            return Err(ErrorCode::Unauthorized);
        }
        let mut request = RecipientRequest {
            community: Sha256::digest(current.trust.community_id.as_bytes()).into(),
            owner,
            recipient_key,
            chat_public_key: current.grant.chat_public_key.clone(),
            issued_at: current.now,
            expires_at,
            signature: String::new(),
        };
        let transcript = recipient_bytes(&request).map_err(|_| ErrorCode::Unauthorized)?;
        account.check(&current.origin).await?;
        let lineage = account
            .vault()
            .await?
            .keys()
            .lineage()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = account
            .vault()
            .await?
            .keys()
            .device_public_key()
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        if lineage.binding.community() != self.cohort.scope
            || lineage.binding.member() != self.cohort.member
            || device.value() != &self.cohort.device
            || B64.encode(device.value()) != current.grant.chat_public_key
            || B64.encode(lineage.root.value()) != authorization.root_public_key
        {
            return Err(ErrorCode::Unauthorized);
        }
        // Held until the signature exists; dropping it cancels unused intent.
        let _admitted = intents
            .device
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
        let signature = account
            .vault()
            .await?
            .keys()
            .sign_device_ed25519_current(&transcript, expires_at)
            .await
            .map_err(|_| ErrorCode::Unauthorized)?;
        request.signature = B64.encode(&signature);
        account.check(&current.origin).await?;
        let after = self.current()?;
        if after.grant != current.grant || after.origin != current.origin || after.now >= expires_at
        {
            return Err(ErrorCode::Unauthorized);
        }
        let wire = serde_json::to_value(AccountServiceRequest::RegisterRecordRecipient {
            grant: current.grant,
            authorization,
            request,
        })
        .map_err(|_| ErrorCode::Unauthorized)?;
        let response = self
            .lease
            .apply_account(wire, now)
            .await
            .map_err(|_| ErrorCode::Reconcile)?;
        match serde_json::from_value(response).map_err(|_| ErrorCode::Reconcile)? {
            AccountServiceResponse::RecordRecipient {
                recipient_key: registered,
            } if registered == recipient_key => Ok(()),
            _ => Err(ErrorCode::Reconcile),
        }
    }
}
