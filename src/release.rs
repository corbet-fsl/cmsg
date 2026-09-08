//! Fixed-purpose account authorizations and private release preflight metadata.
//!
//! These operations do not issue receipts, debit counters, prove delivery or
//! implement recipient consent. A preflight and its signature are private peer
//! data; neither belongs in an operator authorization or telemetry payload.
use crate::{verify_admission, AdmissionGrant, Error, Member};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use openmls::prelude::BasicCredential;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_AUTHORIZATION_SECONDS: u64 = 300;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseContext {
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseAuthorizationTiming {
    pub nonce: String,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseReceipt {
    pub message: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectionalSendAuthorization {
    pub version: u32,
    pub purpose: String,
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub sender_id: String,
    pub request_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectionalReceiveAuthorization {
    pub version: u32,
    pub purpose: String,
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub member_id: String,
    pub receipt_hash: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePeer {
    pub member_id: String,
    pub chat_public_key: String,
}

/// Signed peer/challenge metadata, not a certification of withheld MLS contents.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePreflight {
    pub version: u32,
    pub context: ReleaseContext,
    pub sender: ReleasePeer,
    pub recipient: ReleasePeer,
    pub release_nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl Member {
    /// Authorize only our current certified account, hashing the actual blinded
    /// request locally. The caller must retain an independently generated nonce.
    pub fn authorize_release_send(
        &self,
        context: &ReleaseContext,
        blinded_request: &[u8],
        timing: &ReleaseAuthorizationTiming,
    ) -> Result<DirectionalSendAuthorization, Error> {
        let (grant, now) = self.current_release_admission(context)?;
        validate_window(now, timing.expires_at, context, &[&grant])?;
        if blinded_request.len() != 384 || decode::<32>(&timing.nonce).is_none() {
            return Err(Error::Admission);
        }
        let mut authorization = DirectionalSendAuthorization {
            version: 1,
            purpose: "authorized-send".into(),
            community_id: grant.community_id,
            policy_digest: grant.policy_digest,
            cohort_id: context.cohort_id.clone(),
            sender_id: grant.member_id,
            request_hash: B64.encode(&Sha256::digest(blinded_request)),
            nonce: timing.nonce.clone(),
            issued_at: now,
            expires_at: timing.expires_at,
            signature: String::new(),
        };
        authorization.signature = self.sign_release_statement(&send_bytes(&authorization)?)?;
        Ok(authorization)
    }

    /// Authorize a canonical 160-byte release receipt for our own identity and
    /// expected private challenge. The cfrm service must verify its blind RSA
    /// signature/domain; these client checks do not establish receipt validity.
    pub fn authorize_release_receive(
        &self,
        context: &ReleaseContext,
        receipt: &ReleaseReceipt,
        expected_release_nonce: &str,
        timing: &ReleaseAuthorizationTiming,
    ) -> Result<DirectionalReceiveAuthorization, Error> {
        let (grant, now) = self.current_release_admission(context)?;
        validate_window(now, timing.expires_at, context, &[&grant])?;
        let message = decode::<160>(&receipt.message).ok_or(Error::Admission)?;
        let owner = decode::<32>(&grant.member_id).ok_or(Error::Admission)?;
        let release_nonce = decode::<32>(expected_release_nonce).ok_or(Error::Admission)?;
        if decode::<384>(&receipt.signature).is_none()
            || decode::<32>(&timing.nonce).is_none()
            || message[64..96] != owner
            || message[128..160] != release_nonce
        {
            return Err(Error::Admission);
        }
        let envelope =
            serde_json::to_vec(&serde_json::json!([receipt.message, receipt.signature,]))
                .map_err(|_| Error::Admission)?;
        let mut authorization = DirectionalReceiveAuthorization {
            version: 1,
            purpose: "acknowledged-receive".into(),
            community_id: grant.community_id,
            policy_digest: grant.policy_digest,
            cohort_id: context.cohort_id.clone(),
            member_id: grant.member_id,
            receipt_hash: B64.encode(&Sha256::digest(envelope)),
            nonce: timing.nonce.clone(),
            issued_at: now,
            expires_at: timing.expires_at,
            signature: String::new(),
        };
        authorization.signature = self.sign_release_statement(&receive_bytes(&authorization)?)?;
        Ok(authorization)
    }

    /// Authenticate private metadata using current cvld credentials for both
    /// peers. This is not a recipient consent or content validity decision.
    pub fn sign_release_preflight(
        &self,
        context: &ReleaseContext,
        recipient_admission: &AdmissionGrant,
        release_nonce: &str,
        expires_at: u64,
    ) -> Result<ReleasePreflight, Error> {
        let (own, now) = self.current_release_admission(context)?;
        let recipient_key =
            decode::<32>(&recipient_admission.chat_public_key).ok_or(Error::Admission)?;
        verify_admission(
            recipient_admission,
            self.trust.as_ref().ok_or(Error::Admission)?,
            &recipient_key,
            now,
        )?;
        validate_window(now, expires_at, context, &[&own, recipient_admission])?;
        if own.member_id == recipient_admission.member_id || decode::<32>(release_nonce).is_none() {
            return Err(Error::Admission);
        }
        let mut preflight = ReleasePreflight {
            version: 1,
            context: context.clone(),
            sender: ReleasePeer {
                member_id: own.member_id,
                chat_public_key: own.chat_public_key,
            },
            recipient: ReleasePeer {
                member_id: recipient_admission.member_id.clone(),
                chat_public_key: recipient_admission.chat_public_key.clone(),
            },
            release_nonce: release_nonce.to_owned(),
            issued_at: now,
            expires_at,
            signature: String::new(),
        };
        preflight.signature = self.sign_release_statement(&preflight_bytes(&preflight)?)?;
        Ok(preflight)
    }

    /// Verify private preflight addressed to our current certified ID and key.
    pub fn verify_release_preflight(
        &self,
        preflight: &ReleasePreflight,
        sender_admission: &AdmissionGrant,
    ) -> Result<(), Error> {
        let (own, now) = self.current_release_admission(&preflight.context)?;
        let sender_key = decode::<32>(&sender_admission.chat_public_key).ok_or(Error::Admission)?;
        verify_admission(
            sender_admission,
            self.trust.as_ref().ok_or(Error::Admission)?,
            &sender_key,
            now,
        )?;
        if preflight.version != 1
            || preflight.sender.member_id != sender_admission.member_id
            || preflight.sender.chat_public_key != sender_admission.chat_public_key
            || preflight.recipient.member_id != own.member_id
            || preflight.recipient.chat_public_key != own.chat_public_key
            || preflight.sender.member_id == own.member_id
            || decode::<32>(&preflight.release_nonce).is_none()
            || preflight.issued_at < preflight.context.not_before
            || preflight.issued_at < own.issued_at
            || preflight.issued_at < sender_admission.issued_at
            || preflight.issued_at > now
            || now >= preflight.expires_at
        {
            return Err(Error::Admission);
        }
        validate_window(
            preflight.issued_at,
            preflight.expires_at,
            &preflight.context,
            &[&own, sender_admission],
        )?;
        let signature = decode::<64>(&preflight.signature).ok_or(Error::Admission)?;
        VerifyingKey::from_bytes(&sender_key)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &preflight_bytes(preflight)?,
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| Error::Admission)
    }

    fn current_release_admission(
        &self,
        context: &ReleaseContext,
    ) -> Result<(AdmissionGrant, u64), Error> {
        let now = self.authorization_time()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let basic = BasicCredential::try_from(self.credential.credential.clone())
            .map_err(|_| Error::Admission)?;
        let grant: AdmissionGrant =
            serde_json::from_slice(basic.identity()).map_err(|_| Error::Admission)?;
        verify_admission(&grant, trust, &self.chat_public_key(), now)?;
        if context.community_id != trust.community_id
            || context.policy_digest != trust.policy_digest
            || context.community_id.is_empty()
            || context.community_id.len() > 128
            || context.cohort_id.is_empty()
            || context.cohort_id.len() > 128
            || decode::<32>(&context.policy_digest).is_none()
            || context.not_before == 0
            || context.not_before >= context.expires_at
            || context.expires_at > MAX_SAFE_INTEGER
            || now < context.not_before
            || now >= context.expires_at
        {
            return Err(Error::Admission);
        }
        Ok((grant, now))
    }

    // Internal shared implementation only; callers can request the three fixed
    // typed roles above, not arbitrary bytes or private-key access.
    fn sign_release_statement(&self, bytes: &[u8]) -> Result<String, Error> {
        let signature = self.signer.sign(bytes).map_err(|_| Error::Admission)?;
        Ok(B64.encode(&signature))
    }
}

fn decode<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != (N * 8).div_ceil(6) {
        return None;
    }
    let bytes = B64.decode(value.as_bytes()).ok()?;
    if B64.encode(&bytes) != value {
        return None;
    }
    bytes.try_into().ok()
}

fn validate_window(
    issued_at: u64,
    expires_at: u64,
    context: &ReleaseContext,
    grants: &[&AdmissionGrant],
) -> Result<(), Error> {
    if expires_at <= issued_at
        || expires_at - issued_at > MAX_AUTHORIZATION_SECONDS
        || expires_at > context.expires_at
        || grants.iter().any(|grant| expires_at > grant.expires_at)
    {
        Err(Error::Admission)
    } else {
        Ok(())
    }
}

fn send_bytes(a: &DirectionalSendAuthorization) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.directional.authorize.v1",
        a.community_id,
        a.policy_digest,
        a.cohort_id,
        a.sender_id,
        a.request_hash,
        a.nonce,
        a.issued_at,
        a.expires_at,
    ]))
    .map_err(|_| Error::Admission)
}

fn receive_bytes(a: &DirectionalReceiveAuthorization) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        "cfrm.directional.redeem.v1",
        a.community_id,
        a.policy_digest,
        a.cohort_id,
        a.member_id,
        a.receipt_hash,
        a.nonce,
        a.issued_at,
        a.expires_at,
    ]))
    .map_err(|_| Error::Admission)
}

fn preflight_bytes(p: &ReleasePreflight) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        "cmsg.release.preflight.v1",
        p.context.community_id,
        p.context.policy_digest,
        p.context.cohort_id,
        p.context.not_before,
        p.context.expires_at,
        p.sender.member_id,
        p.sender.chat_public_key,
        p.recipient.member_id,
        p.recipient.chat_public_key,
        p.release_nonce,
        p.issued_at,
        p.expires_at,
    ]))
    .map_err(|_| Error::Admission)
}
