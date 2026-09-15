//! Narrow owner signatures for cfrm's member-held profile experiment.
use crate::{verify_admission, Error, Member};
use data_encoding::BASE64URL_NOPAD;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileChallenge {
    pub version: u32,
    pub community_id: String,
    pub owner_member_id: String,
    pub owner_chat_public_key: String,
    pub onion_host: String,
    pub onion_port: u16,
    pub session_id: String,
    pub reader_nonce: String,
    pub owner_nonce: String,
    pub policy_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Member {
    /// Sign only our certified owner's fixed-domain profile challenge.
    /// Deployment-specific challenge lifetimes may be shorter than the 300s ceiling.
    pub fn sign_profile_challenge(
        &self,
        challenge: &ProfileChallenge,
        now: u64,
    ) -> Result<String, Error> {
        let bytes = self.validated_profile_challenge(challenge, now)?;
        let signature = self.signer.sign(&bytes).map_err(|_| Error::Admission)?;
        Ok(BASE64URL_NOPAD.encode(&signature))
    }

    /// Derive the challenge digest locally and bind it to the profile digest.
    /// No generic message-signing or private-key export API is provided.
    pub fn sign_profile_response(
        &self,
        challenge: &ProfileChallenge,
        profile_digest: &str,
        now: u64,
    ) -> Result<String, Error> {
        let challenge_bytes = self.validated_profile_challenge(challenge, now)?;
        if !valid32(profile_digest) {
            return Err(Error::Admission);
        }
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cfrm.profile.v1",
            "response",
            BASE64URL_NOPAD.encode(&Sha256::digest(&challenge_bytes)),
            profile_digest
        ]))
        .map_err(|_| Error::Admission)?;
        let signature = self.signer.sign(&bytes).map_err(|_| Error::Admission)?;
        Ok(BASE64URL_NOPAD.encode(&signature))
    }

    fn validated_profile_challenge(
        &self,
        c: &ProfileChallenge,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let grant = self.admission_grant()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let owner = verify_admission(&grant, trust, &self.chat_public_key(), now)?;
        if let Some(device) = self.device_authorization()? {
            crate::verify_device_authorization(
                &device,
                &trust.community_id,
                &owner,
                &self.chat_public_key(),
                now,
            )?;
        }
        if c.version != 1
            || c.owner_member_id != owner
            || c.community_id != trust.community_id
            || c.policy_digest != trust.policy_digest
            || c.owner_chat_public_key != BASE64URL_NOPAD.encode(&self.chat_public_key())
            || c.issued_at > now
            || now >= c.expires_at
            || c.issued_at < grant.issued_at
            || c.expires_at > grant.expires_at
            || c.expires_at - c.issued_at > 300
            || ![&c.session_id, &c.reader_nonce, &c.owner_nonce]
                .iter()
                .all(|s| valid32(s))
        {
            return Err(Error::Admission);
        }
        crate::OnionEndpoint::parse(&c.onion_host, c.onion_port)?;
        serde_json::to_vec(&serde_json::json!([
            "cfrm.profile.v1",
            "challenge",
            c.community_id,
            c.owner_member_id,
            c.owner_chat_public_key,
            c.onion_host,
            c.onion_port,
            c.session_id,
            c.reader_nonce,
            c.owner_nonce,
            c.policy_digest,
            c.issued_at,
            c.expires_at
        ]))
        .map_err(|_| Error::Admission)
    }
}

fn valid32(value: &str) -> bool {
    value.len() == 43
        && BASE64URL_NOPAD
            .decode(value.as_bytes())
            .is_ok_and(|b| b.len() == 32)
}
