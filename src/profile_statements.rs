//! The exact domain-separated profile/discovery signing boundary used by cfrm.
//! Community policy stays with cfrm; these signatures authorize only the
//! certified local device and never expose an arbitrary-byte signing API.
use crate::{Error, Member, MAX_WIRE_BYTES};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::Signer;
use serde_json::Value;

const MAX_INTEGER: u64 = 9_007_199_254_740_991;

fn statement(bytes: &[u8]) -> Result<Vec<Value>, Error> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::Admission);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Admission)?;
    // cfrm sorts discovery objects before serializing. Exact canonical bytes
    // reject duplicate keys, appended data and alternate JSON interpretations.
    if serde_json::to_vec(&value).map_err(|_| Error::Admission)? != bytes {
        return Err(Error::Admission);
    }
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err(Error::Admission),
    }
}

fn text(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or(Error::Admission)
}

fn integer(value: &Value) -> Result<u64, Error> {
    value
        .as_u64()
        .filter(|value| *value > 0 && *value <= MAX_INTEGER)
        .ok_or(Error::Admission)
}

fn decoded(value: &Value) -> Result<Vec<u8>, Error> {
    let value = text(value)?;
    let bytes = B64.decode(value.as_bytes()).map_err(|_| Error::Admission)?;
    if bytes.is_empty() || B64.encode(&bytes) != value {
        return Err(Error::Admission);
    }
    Ok(bytes)
}

fn fixed(value: &Value, size: usize) -> Result<Vec<u8>, Error> {
    let bytes = decoded(value)?;
    if bytes.len() != size {
        return Err(Error::Admission);
    }
    Ok(bytes)
}

fn wrapping_key(value: &Value) -> Result<(), Error> {
    p256::PublicKey::from_sec1_bytes(&fixed(value, 65)?)
        .map(|_| ())
        .map_err(|_| Error::Admission)
}

fn discriminators(value: &Value) -> Result<(), Error> {
    let mut previous: Option<&str> = None;
    for pair in value.as_array().ok_or(Error::Admission)? {
        let pair = pair
            .as_array()
            .filter(|pair| pair.len() == 2)
            .ok_or(Error::Admission)?;
        let name = text(&pair[0])?;
        if name.is_empty()
            || name.len() > 32
            || !name.as_bytes()[0].is_ascii_alphabetic()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || previous.is_some_and(|previous| previous >= name)
            || !pair[1]
                .as_u64()
                .is_some_and(|value| value <= u32::MAX as u64)
        {
            return Err(Error::Admission);
        }
        previous = Some(name);
    }
    Ok(())
}

impl Member {
    /// Sign one supported canonical cfrm profile/discovery transcript.
    /// The member's Clock validates current issuer and root-device authority.
    /// This does not validate community policy or an embedding's intent to
    /// publish, query, distribute a key, or spend a profile-access allowance.
    pub fn sign_profile_statement(&self, bytes: &[u8]) -> Result<String, Error> {
        let fields = statement(bytes)?;
        self.validate_profile_statement(&fields)?;
        Ok(B64.encode(&self.signer.sign(bytes).map_err(|_| Error::Admission)?))
    }

    fn profile_signing_authority(
        &self,
        fields: &[Value],
        owner: Option<(usize, usize, usize)>,
        policy: Option<usize>,
        issued: Option<usize>,
        expires: usize,
    ) -> Result<(), Error> {
        let (grant, authorization, now) =
            self.current_board_authorization(integer(&fields[expires])?)?;
        if let Some((community, member, device)) = owner {
            if text(&fields[community])? != grant.community_id
                || text(&fields[member])? != grant.member_id
                || text(&fields[device])? != grant.chat_public_key
            {
                return Err(Error::Admission);
            }
        }
        if let Some(policy) = policy {
            if text(&fields[policy])? != grant.policy_digest {
                return Err(Error::Admission);
            }
        }
        if let Some(issued) = issued {
            let issued = integer(&fields[issued])?;
            if issued > now || issued < grant.issued_at.max(authorization.issued_at) {
                return Err(Error::Admission);
            }
        }
        Ok(())
    }

    fn validate_profile_statement(&self, fields: &[Value]) -> Result<(), Error> {
        let domain = fields
            .first()
            .and_then(Value::as_str)
            .ok_or(Error::Admission)?;
        match (domain, fields.len()) {
            ("cfrm.cached-profile.v1", 11) => {
                self.profile_signing_authority(fields, Some((1, 2, 3)), None, Some(6), 7)?;
                fixed(&fields[4], 32)?;
                integer(&fields[5])?;
                fixed(&fields[8], 12)?;
                fixed(&fields[9], 32)?;
                discriminators(&fields[10])?;
            }
            ("cfrm.discovery-request.v1", 10) => {
                self.profile_signing_authority(fields, Some((1, 3, 4)), Some(2), Some(7), 8)?;
                fixed(&fields[5], 32)?;
                fixed(&fields[6], 32)?;
                // Operation schemas, registry values and quotas belong to cfrm.
                if !fields[9].is_object() {
                    return Err(Error::Admission);
                }
            }
            ("cfrm.key-access.issue.v1", 9) => {
                self.profile_signing_authority(fields, Some((1, 2, 3)), None, Some(7), 8)?;
                fixed(&fields[4], 32)?;
                if fixed(&fields[5], 32)?.iter().all(|byte| *byte == 0) {
                    return Err(Error::Admission);
                }
                fixed(&fields[6], 32)?;
            }
            ("cfrm.profile-holder-key.v1", 7) => {
                self.profile_signing_authority(fields, Some((1, 2, 3)), None, Some(5), 6)?;
                wrapping_key(&fields[4])?;
            }
            ("cfrm.profile-holder.v1", 10) => {
                self.profile_signing_authority(fields, Some((1, 2, 3)), None, Some(8), 9)?;
                fixed(&fields[4], 32)?;
                fixed(&fields[5], 32)?;
                wrapping_key(&fields[6])?;
                fixed(&fields[7], 32)?;
            }
            ("cfrm.profile-holder-seed.v1", 6) => {
                let delegation_bytes = decoded(&fields[1])?;
                let delegation = statement(&delegation_bytes)?;
                if delegation.first().and_then(Value::as_str) != Some("cfrm.profile-holder.v1") {
                    return Err(Error::Admission);
                }
                self.validate_profile_statement(&delegation)?;
                let key: [u8; 32] = self
                    .chat_public_key()
                    .try_into()
                    .map_err(|_| Error::Admission)?;
                let signature =
                    Signature::from_slice(&fixed(&fields[2], 64)?).map_err(|_| Error::Admission)?;
                VerifyingKey::from_bytes(&key)
                    .map_err(|_| Error::Admission)?
                    .verify_strict(&delegation_bytes, &signature)
                    .map_err(|_| Error::Admission)?;
                wrapping_key(&fields[3])?;
                fixed(&fields[4], 12)?;
                fixed(&fields[5], 48)?;
            }
            ("cfrm.profile-key-challenge.v1", 12) => {
                self.profile_signing_authority(fields, Some((1, 4, 5)), Some(2), Some(10), 11)?;
                for index in [3, 6, 7, 9] {
                    fixed(&fields[index], 32)?;
                }
                wrapping_key(&fields[8])?;
            }
            ("cfrm.profile-key-grant.v1", 6) => {
                // The receiver binds this digest to its authenticated challenge;
                // the transcript carries no replaceable owner identity fields.
                self.profile_signing_authority(fields, None, None, None, 2)?;
                fixed(&fields[1], 32)?;
                wrapping_key(&fields[3])?;
                fixed(&fields[4], 12)?;
                fixed(&fields[5], 48)?;
            }
            _ => return Err(Error::Admission),
        }
        Ok(())
    }
}
