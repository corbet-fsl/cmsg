//! Narrow owner signatures for cfrm's member-held profile experiment.
use crate::{Error, Member};
use serde::{Deserialize, Serialize};

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
        _challenge: &ProfileChallenge,
        _now: u64,
    ) -> Result<String, Error> {
        // Fail-first specification: implementation follows hosted red evidence.
        Err(Error::Admission)
    }

    /// Derive the challenge digest locally and bind it to the profile digest.
    /// No generic message-signing or private-key export API is provided.
    pub fn sign_profile_response(
        &self,
        _challenge: &ProfileChallenge,
        _profile_digest: &str,
        _now: u64,
    ) -> Result<String, Error> {
        Err(Error::Admission)
    }
}
