//! Member-owned identity, independently authorized devices, and sealed recovery.
//!
//! An eligibility issuer may attest admission but cannot authorize a new device
//! for an existing member. Device authorization requires the member root key.
use crate::{vault, Error};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_SAFE_TIME: u64 = 9_007_199_254_740_991;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceAuthorization {
    pub version: u32,
    pub community_id: String,
    pub member_id: String,
    pub root_public_key: String,
    pub device_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceAuthorization([redacted])")
    }
}

/// An account root. Pairing authorizes independently generated device keys;
/// copying an MLS conversation snapshot does not enroll a device.
pub struct MemberIdentity {
    community_id: String,
    member_id: String,
    signer: SigningKey,
}

impl std::fmt::Debug for MemberIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemberIdentity([redacted])")
    }
}

impl MemberIdentity {
    pub fn new(community_id: &str) -> Result<Self, Error> {
        validate_community(community_id)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| Error::Randomness)?;
        Self::from_signer(community_id, SigningKey::from_bytes(&secret))
    }

    fn from_signer(community_id: &str, signer: SigningKey) -> Result<Self, Error> {
        let member_id = member_id_for_root(community_id, &signer.verifying_key().to_bytes())?;
        Ok(Self {
            community_id: community_id.to_owned(),
            member_id,
            signer,
        })
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }
    pub fn community_id(&self) -> &str {
        &self.community_id
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.verifying_key().to_bytes()
    }

    /// Caller selects certificate lifetime. Renewing eligibility never expands
    /// this root-authorized lifetime or adds another authorized device.
    pub fn authorize_device(
        &self,
        device_public_key: &[u8],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<DeviceAuthorization, Error> {
        validate_lifetime(issued_at, expires_at)?;
        let key: [u8; 32] = device_public_key.try_into().map_err(|_| Error::Admission)?;
        let verifying = VerifyingKey::from_bytes(&key).map_err(|_| Error::Admission)?;
        if verifying.is_weak() {
            return Err(Error::Admission);
        }
        let mut authorization = DeviceAuthorization {
            version: 1,
            community_id: self.community_id.clone(),
            member_id: self.member_id.clone(),
            root_public_key: BASE64URL_NOPAD.encode(&self.public_key()),
            device_public_key: BASE64URL_NOPAD.encode(&key),
            issued_at,
            expires_at,
            signature: String::new(),
        };
        authorization.signature = BASE64URL_NOPAD.encode(
            &self
                .signer
                .sign(&authorization_bytes(&authorization)?)
                .to_bytes(),
        );
        Ok(authorization)
    }

    /// Encrypt the root for caller-owned storage. Context and expected member
    /// identity are authenticated; no plaintext private-key export is provided.
    pub fn seal(&self, wrapping_key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        let aad = identity_context(&self.community_id, &self.member_id, context)?;
        let secret = Zeroizing::new(self.signer.to_bytes());
        vault::seal(secret.as_ref(), wrapping_key, &aad)
    }

    pub fn restore(
        sealed: &[u8],
        wrapping_key: &[u8; 32],
        community_id: &str,
        expected_member_id: &str,
        context: &[u8],
    ) -> Result<Self, Error> {
        validate_community(community_id).map_err(|_| Error::InvalidStore)?;
        decode32(expected_member_id).map_err(|_| Error::InvalidStore)?;
        let aad = identity_context(community_id, expected_member_id, context)?;
        let plaintext = vault::open(sealed, wrapping_key, &aad)?;
        let secret = Zeroizing::new(
            <[u8; 32]>::try_from(plaintext.as_slice()).map_err(|_| Error::InvalidStore)?,
        );
        let identity = Self::from_signer(community_id, SigningKey::from_bytes(&secret))
            .map_err(|_| Error::InvalidStore)?;
        if identity.member_id != expected_member_id {
            return Err(Error::InvalidStore);
        }
        Ok(identity)
    }
}

pub fn member_id_for_root(community_id: &str, root_public_key: &[u8; 32]) -> Result<String, Error> {
    validate_community(community_id)?;
    let key = VerifyingKey::from_bytes(root_public_key).map_err(|_| Error::Admission)?;
    if key.is_weak() {
        return Err(Error::Admission);
    }
    let bytes = serde_json::to_vec(&serde_json::json!([
        "cmsg.member.v1",
        community_id,
        BASE64URL_NOPAD.encode(root_public_key)
    ]))
    .map_err(|_| Error::Admission)?;
    Ok(BASE64URL_NOPAD.encode(&Sha256::digest(bytes)))
}

pub fn verify_device_authorization(
    authorization: &DeviceAuthorization,
    community_id: &str,
    member_id: &str,
    device_public_key: &[u8],
    now: u64,
) -> Result<(), Error> {
    validate_lifetime(authorization.issued_at, authorization.expires_at)?;
    if authorization.version != 1
        || authorization.community_id != community_id
        || authorization.member_id != member_id
        || now < authorization.issued_at
        || now >= authorization.expires_at
        || now > MAX_SAFE_TIME
        || device_public_key.len() != 32
        || authorization.device_public_key != BASE64URL_NOPAD.encode(device_public_key)
        || authorization.signature.len() != 86
    {
        return Err(Error::Admission);
    }
    let root = decode32(&authorization.root_public_key)?;
    if member_id_for_root(community_id, &root)? != member_id {
        return Err(Error::Admission);
    }
    let device = decode32(&authorization.device_public_key)?;
    if VerifyingKey::from_bytes(&device)
        .map_err(|_| Error::Admission)?
        .is_weak()
    {
        return Err(Error::Admission);
    }
    let bytes = BASE64URL_NOPAD
        .decode(authorization.signature.as_bytes())
        .map_err(|_| Error::Admission)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| Error::Admission)?;
    VerifyingKey::from_bytes(&root)
        .map_err(|_| Error::Admission)?
        .verify_strict(&authorization_bytes(authorization)?, &signature)
        .map_err(|_| Error::Admission)
}

fn authorization_bytes(authorization: &DeviceAuthorization) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!([
        "cmsg.device.v1",
        authorization.community_id,
        authorization.member_id,
        authorization.root_public_key,
        authorization.device_public_key,
        authorization.issued_at,
        authorization.expires_at,
    ]))
    .map_err(|_| Error::Admission)
}

fn validate_community(community_id: &str) -> Result<(), Error> {
    if community_id.is_empty()
        || community_id.len() > 256
        || !community_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(Error::Admission);
    }
    Ok(())
}

fn validate_lifetime(issued_at: u64, expires_at: u64) -> Result<(), Error> {
    if issued_at == 0 || issued_at >= expires_at || expires_at > MAX_SAFE_TIME {
        return Err(Error::Admission);
    }
    Ok(())
}

fn decode32(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 43 {
        return Err(Error::Admission);
    }
    BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| Error::Admission)?
        .try_into()
        .map_err(|_| Error::Admission)
}

fn identity_context(community: &str, member: &str, context: &[u8]) -> Result<[u8; 32], Error> {
    if context.is_empty() || context.len() > 128 {
        return Err(Error::InvalidStore);
    }
    let bytes = serde_json::to_vec(&serde_json::json!([
        "cmsg.identity-store.v1",
        community,
        member,
        BASE64URL_NOPAD.encode(context)
    ]))
    .map_err(|_| Error::InvalidStore)?;
    Ok(Sha256::digest(bytes).into())
}
