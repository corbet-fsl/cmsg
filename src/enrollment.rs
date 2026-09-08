//! Certified-key authorization for cfrm's immutable Semaphore enrollment.
//! Semaphore identity derivation, curve validation and the second possession proof stay in cfrm.
use crate::{verify_admission, AdmissionGrant, Error, Member};
use data_encoding::BASE64URL_NOPAD as B64;
use openmls::prelude::BasicCredential;
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
// The field bound exported as `r` by cfrm's pinned @zk-kit/baby-jubjub 1.0.3.
// Only canonical decimal comparison belongs here; no curve arithmetic is implemented.
const FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemaphoreEnrollmentChallenge {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub commitment: String,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Member {
    /// Sign the fixed cfrm enrollment statement using the currently admitted chat key.
    /// The trusted client must independently obtain `expected_wallet_commitment` from
    /// its persistent wallet identity, never copy it from the server challenge unnoticed.
    /// This signature does not prove Semaphore-key possession or register a binding.
    pub fn sign_semaphore_enrollment(
        &self,
        challenge: &SemaphoreEnrollmentChallenge,
        expected_wallet_commitment: &str,
    ) -> Result<String, Error> {
        let now = self.authorization_time()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        let basic = BasicCredential::try_from(self.credential.credential.clone())
            .map_err(|_| Error::Admission)?;
        let grant: AdmissionGrant =
            serde_json::from_slice(basic.identity()).map_err(|_| Error::Admission)?;
        let member_id = verify_admission(&grant, trust, &self.chat_public_key(), now)?;
        let c = challenge;
        if c.community_id != trust.community_id
            || c.member_id != member_id
            || c.chat_public_key != grant.chat_public_key
            || c.issued_at == 0
            || c.expires_at <= c.issued_at
            || c.expires_at - c.issued_at > 300
            || c.expires_at > MAX_SAFE_INTEGER
            || c.issued_at > now
            || now >= c.expires_at
            || c.issued_at < grant.issued_at
            || c.expires_at > grant.expires_at
            || !canonical_nonce(&c.challenge_id)
            || !canonical_commitment(&c.commitment)
            || !canonical_commitment(expected_wallet_commitment)
            || c.commitment != expected_wallet_commitment
        {
            return Err(Error::Admission);
        }
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cfrm.semaphore.enroll.v1",
            c.community_id,
            c.member_id,
            c.chat_public_key,
            c.commitment,
            c.challenge_id,
            c.issued_at,
            c.expires_at
        ]))
        .map_err(|_| Error::Admission)?;
        let signature = self.signer.sign(&bytes).map_err(|_| Error::Admission)?;
        Ok(B64.encode(&signature))
    }
}

fn canonical_nonce(value: &str) -> bool {
    value.len() == 43
        && B64
            .decode(value.as_bytes())
            .is_ok_and(|bytes| bytes.len() == 32 && B64.encode(&bytes) == value)
}

fn canonical_commitment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= FIELD_MODULUS.len()
        && matches!(value.as_bytes()[0], b'1'..=b'9')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() < FIELD_MODULUS.len() || value < FIELD_MODULUS)
}
