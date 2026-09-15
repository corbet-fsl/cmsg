use crate::Error;
use serde::{Deserialize, Serialize};

pub(crate) fn valid_member_id(value: &str) -> bool {
    value.len() == 43
        && data_encoding::BASE64URL_NOPAD
            .decode(value.as_bytes())
            .is_ok_and(|bytes| bytes.len() == 32)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionGrant {
    pub version: u32,
    pub issuer_key_id: String,
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub policy_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AdmissionTrust {
    pub community_id: String,
    pub policy_digest: String,
    pub issuer_public_key: [u8; 32],
}
/// Verify independently configured issuer trust and bind it to the MLS signing key.
pub fn verify_admission(
    grant: &AdmissionGrant,
    trust: &AdmissionTrust,
    chat_key: &[u8],
    now: u64,
) -> Result<String, Error> {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};
    let valid32 = |s: &str| {
        s.len() == 43
            && BASE64URL_NOPAD
                .decode(s.as_bytes())
                .is_ok_and(|b| b.len() == 32)
    };
    if grant.version != 1
        || grant.issued_at == 0
        || grant.community_id != trust.community_id
        || grant.policy_digest != trust.policy_digest
        || grant.issued_at > now
        || now >= grant.expires_at
        || grant.expires_at > 9_007_199_254_740_991
        || grant.community_id.is_empty()
        || grant.community_id.len() > 256
        || !grant
            .community_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
        || ![
            &grant.issuer_key_id,
            &grant.member_id,
            &grant.chat_public_key,
            &grant.policy_digest,
        ]
        .iter()
        .all(|s| valid32(s))
        || grant.chat_public_key != BASE64URL_NOPAD.encode(chat_key)
        || grant.issuer_key_id != BASE64URL_NOPAD.encode(&Sha256::digest(trust.issuer_public_key))
    {
        return Err(Error::Admission);
    }
    let signed = serde_json::to_vec(&serde_json::json!([
        "cvld.admission.v1",
        grant.issuer_key_id,
        grant.community_id,
        grant.member_id,
        grant.chat_public_key,
        grant.policy_digest,
        grant.issued_at,
        grant.expires_at,
    ]))
    .map_err(|_| Error::Admission)?;
    let signature = BASE64URL_NOPAD
        .decode(grant.signature.as_bytes())
        .map_err(|_| Error::Admission)?;
    let signature = Signature::from_slice(&signature).map_err(|_| Error::Admission)?;
    VerifyingKey::from_bytes(&trust.issuer_public_key)
        .map_err(|_| Error::Admission)?
        .verify_strict(&signed, &signature)
        .map_err(|_| Error::Admission)?;
    Ok(grant.member_id.clone())
}
