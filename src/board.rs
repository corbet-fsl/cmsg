//! Typed statements at the cmsg/cfrm boundary. No private key or generic
//! signing operation is exposed to the board or eligibility issuer.
use crate::{AdmissionGrant, DeviceAuthorization, Error, Member, OnionEndpoint};
use data_encoding::BASE64URL_NOPAD;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceUpdate {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub endpoint: Option<PresenceEndpoint>,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationRequest {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub policy_digest: String,
    pub nonce: String,
    pub blinded_request: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl Member {
    /// Sign a public lease (or a disconnect when `endpoint` is None). The host
    /// persists and increases the per-device sequence across restarts. The
    /// board's independently configured policy bounds the requested lifetime.
    pub fn sign_presence(
        &self,
        endpoint: Option<&OnionEndpoint>,
        sequence: u64,
        expires_at: u64,
    ) -> Result<PresenceUpdate, Error> {
        let (grant, _, now) = self.current_board_authorization(expires_at)?;
        if sequence == 0 || sequence > MAX_INTEGER {
            return Err(Error::Admission);
        }
        let mut update = PresenceUpdate {
            community_id: grant.community_id,
            member_id: grant.member_id,
            chat_public_key: grant.chat_public_key,
            sequence,
            issued_at: now,
            expires_at,
            endpoint: endpoint.map(|endpoint| PresenceEndpoint {
                host: endpoint.host().to_owned(),
                port: endpoint.port(),
            }),
            signature: String::new(),
        };
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cfrm.presence.v1",
            update.community_id,
            update.member_id,
            update.chat_public_key,
            update.sequence,
            update.issued_at,
            update.expires_at,
            update.endpoint,
        ]))
        .map_err(|_| Error::Admission)?;
        update.signature =
            BASE64URL_NOPAD.encode(&self.signer.sign(&bytes).map_err(|_| Error::Admission)?);
        Ok(update)
    }

    /// Authorize one aggregate allowance withdrawal. `policy_digest` and the
    /// prepared blinded request come from the client's pinned cfrm policy and
    /// permit epoch, not from an unverified signing challenge. This statement
    /// contains no recipient. Version 1 uses a 32-byte epoch context followed
    /// by the 384-byte RFC 9474 blinded request.
    pub fn authorize_allocation(
        &self,
        policy_digest: &str,
        nonce: &[u8; 32],
        blinded_request: &[u8],
        expires_at: u64,
    ) -> Result<AllocationRequest, Error> {
        let (grant, _, now) = self.current_board_authorization(expires_at)?;
        if !crate::admission::valid_member_id(policy_digest) || blinded_request.len() != 416 {
            return Err(Error::Admission);
        }
        let mut request = AllocationRequest {
            community_id: grant.community_id,
            member_id: grant.member_id,
            chat_public_key: grant.chat_public_key,
            policy_digest: policy_digest.to_owned(),
            nonce: BASE64URL_NOPAD.encode(nonce),
            blinded_request: BASE64URL_NOPAD.encode(blinded_request),
            issued_at: now,
            expires_at,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cfrm.allocation.reserve.v1",
            request.community_id,
            request.member_id,
            request.chat_public_key,
            request.policy_digest,
            request.nonce,
            BASE64URL_NOPAD.encode(&Sha256::digest(blinded_request)),
            request.issued_at,
            request.expires_at,
        ]))
        .map_err(|_| Error::Admission)?;
        request.signature =
            BASE64URL_NOPAD.encode(&self.signer.sign(&bytes).map_err(|_| Error::Admission)?);
        Ok(request)
    }

    pub(crate) fn current_board_authorization(
        &self,
        expires_at: u64,
    ) -> Result<(AdmissionGrant, DeviceAuthorization, u64), Error> {
        let now = self.authorization_time()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let grant = self.admission_grant()?;
        let authorization = self.device_authorization()?.ok_or(Error::Admission)?;
        crate::verify_admission(&grant, trust, &self.chat_public_key(), now)?;
        crate::verify_device_authorization(
            &authorization,
            &trust.community_id,
            &grant.member_id,
            &self.chat_public_key(),
            now,
        )?;
        if now == 0
            || now >= expires_at
            || expires_at > MAX_INTEGER
            || expires_at > grant.expires_at
            || expires_at > authorization.expires_at
        {
            return Err(Error::Admission);
        }
        Ok((grant, authorization, now))
    }
}
