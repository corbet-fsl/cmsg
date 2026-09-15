//! Versioned accounting signatures alongside the existing Ed25519 identities.
//! These private peer objects are witnesses, not operator credit authorizations.
use crate::{
    AdmissionGrant, AdmissionTrust, ContactResolution, ContactResolutionKind, DeviceAuthorization,
    Error, FirstContactPolicy, Member,
};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use openmls_traits::signatures::Signer as MlsSigner;
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_TIME: u64 = 9_007_199_254_740_991;
const RECEIPT_DOMAIN: &[u8] = b"cmsg.accounting-receipt.v1\0";

fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    let bytes = HEX.decode(value.as_bytes()).map_err(|_| Error::Admission)?;
    if HEX.encode(&bytes) != value {
        return Err(Error::Admission);
    }
    bytes.try_into().map_err(|_| Error::Admission)
}
fn member_bytes(value: &str) -> Result<[u8; 32], Error> {
    let bytes = B64.decode(value.as_bytes()).map_err(|_| Error::Admission)?;
    if B64.encode(&bytes) != value {
        return Err(Error::Admission);
    }
    bytes.try_into().map_err(|_| Error::Admission)
}
fn time(value: u64) -> Result<(), Error> {
    if value == 0 || value > MAX_TIME {
        return Err(Error::Admission);
    }
    Ok(())
}
fn scheme(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Admission);
    }
    Ok(())
}
fn public_key(bytes: &[u8; 64]) -> Result<VerifyingKey, Error> {
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..].copy_from_slice(bytes);
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error::Admission)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingDelegation {
    pub version: u32,
    pub hash_scheme: String,
    pub admission: AdmissionGrant,
    pub authorization: DeviceAuthorization,
    /// Canonical lowercase hex of uncompressed P-256 X || Y, without SEC1 prefix.
    pub account_public_key: String,
    pub state_secret_commitment: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
impl std::fmt::Debug for AccountingDelegation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingDelegation([redacted])")
    }
}
impl AccountingDelegation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!([
            "cmsg.accounting-delegation.v1",
            self.version,
            self.hash_scheme,
            self.admission.community_id,
            self.admission.member_id,
            self.authorization.device_public_key,
            self.account_public_key,
            self.state_secret_commitment,
            self.issued_at,
            self.expires_at,
            B64.encode(&hash(
                serde_json::to_vec(&self.admission).map_err(|_| Error::Admission)?
            )),
            B64.encode(&hash(
                serde_json::to_vec(&self.authorization).map_err(|_| Error::Admission)?
            )),
        ]))
        .map_err(|_| Error::Admission)
    }
    /// Digest includes the strict Ed25519 signature and its complete transcript.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        let mut bytes = b"cmsg.accounting-delegation-digest.v1\0".to_vec();
        let transcript = self.signing_bytes()?;
        bytes.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&transcript);
        let signature = B64
            .decode(self.signature.as_bytes())
            .map_err(|_| Error::Admission)?;
        if signature.len() != 64 || B64.encode(&signature) != self.signature {
            return Err(Error::Admission);
        }
        bytes.extend_from_slice(&signature);
        Ok(hash(bytes))
    }
}

/// Independent admission adapter entry point. New network input uses current
/// trusted time; historical calls are only for already authenticated local history.
pub fn verify_accounting_delegation(
    d: &AccountingDelegation,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    time(now)?;
    time(d.issued_at)?;
    time(d.expires_at)?;
    scheme(&d.hash_scheme)?;
    if d.version != 1
        || d.issued_at > now
        || now >= d.expires_at
        || d.issued_at >= d.expires_at
        || d.expires_at > d.admission.expires_at
        || d.expires_at > d.authorization.expires_at
    {
        return Err(Error::Admission);
    }
    let device = member_bytes(&d.authorization.device_public_key)?;
    public_key(&decode::<64>(&d.account_public_key)?)?;
    decode::<32>(&d.state_secret_commitment)?;
    for at in [now, d.issued_at] {
        crate::verify_admission(&d.admission, trust, &device, at)?;
        crate::verify_device_authorization(
            &d.authorization,
            &trust.community_id,
            &d.admission.member_id,
            &device,
            at,
        )?;
    }
    let signature = B64
        .decode(d.signature.as_bytes())
        .map_err(|_| Error::Admission)?;
    if signature.len() != 64 || B64.encode(&signature) != d.signature {
        return Err(Error::Admission);
    }
    EdKey::from_bytes(&device)
        .map_err(|_| Error::Admission)?
        .verify_strict(
            &d.signing_bytes()?,
            &EdSignature::from_slice(&signature).map_err(|_| Error::Admission)?,
        )
        .map_err(|_| Error::Admission)
}

/// A separate P-256 authority owned by a permanent member; its secret has no
/// plaintext export. MLS and identity signatures remain Ed25519.
pub struct AccountingKey {
    community_id: String,
    member_id: String,
    signer: SigningKey,
}
impl std::fmt::Debug for AccountingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingKey([redacted])")
    }
}
impl AccountingKey {
    pub fn new(member: &Member) -> Result<Self, Error> {
        if member.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let member_id = member.member_id()?;
        let community_id = member
            .trust
            .as_ref()
            .ok_or(Error::Admission)?
            .community_id
            .clone();
        for _ in 0..128 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| Error::Randomness)?;
            if let Ok(signer) = SigningKey::from_slice(bytes.as_ref()) {
                return Ok(Self {
                    community_id,
                    member_id,
                    signer,
                });
            }
        }
        Err(Error::Randomness)
    }
    pub fn public_key(&self) -> [u8; 64] {
        self.signer
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()[1..]
            .try_into()
            .expect("P-256 public key length")
    }
    pub fn member_id(&self) -> &str {
        &self.member_id
    }
    pub fn community_id(&self) -> &str {
        &self.community_id
    }
    pub fn seal(&self, wrapping_key: &[u8; 32], context: &[u8]) -> Result<Vec<u8>, Error> {
        let aad = key_context(
            &self.community_id,
            &self.member_id,
            &self.public_key(),
            context,
        )?;
        let secret = Zeroizing::new(self.signer.to_bytes());
        crate::vault::seal(secret.as_slice(), wrapping_key, &aad)
    }
    pub fn restore(
        sealed: &[u8],
        wrapping_key: &[u8; 32],
        community: &str,
        member: &str,
        expected_public_key: &[u8; 64],
        context: &[u8],
    ) -> Result<Self, Error> {
        member_bytes(member)?;
        public_key(expected_public_key)?;
        let aad = key_context(community, member, expected_public_key, context)?;
        let secret = crate::vault::open(sealed, wrapping_key, &aad)?;
        let signer = SigningKey::from_slice(secret.as_slice()).map_err(|_| Error::InvalidStore)?;
        let key = Self {
            community_id: community.to_owned(),
            member_id: member.to_owned(),
            signer,
        };
        if key.public_key() != *expected_public_key {
            return Err(Error::InvalidStore);
        }
        Ok(key)
    }
    pub(crate) fn issue(
        &self,
        member: &Member,
        delegation: &AccountingDelegation,
        resolution: ContactResolution,
        context: AccountingContactContext,
    ) -> Result<AccountingReceipt, Error> {
        if member.member_id()? != self.member_id
            || delegation.admission.member_id != self.member_id
            || delegation.admission.community_id != self.community_id
            || decode::<64>(&delegation.account_public_key)? != self.public_key()
        {
            return Err(Error::Admission);
        }
        let mut receipt = AccountingReceipt::prepare(member, delegation, resolution, context)?;
        let signature: Signature = self.signer.sign(&receipt.signing_bytes()?);
        receipt.signature = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec();
        Ok(receipt)
    }
    pub(crate) fn acknowledge(
        &self,
        member: &Member,
        delegation: &AccountingDelegation,
        answer: &AccountingReceipt,
    ) -> Result<AccountingAcknowledgment, Error> {
        if member.member_id()? != self.member_id
            || delegation.admission.member_id != self.member_id
            || delegation.admission.community_id != self.community_id
            || decode::<64>(&delegation.account_public_key)? != self.public_key()
        {
            return Err(Error::Admission);
        }
        let mut ack = AccountingAcknowledgment::prepare(member, delegation, answer)?;
        let signature: Signature = self.signer.sign(&ack.signing_bytes()?);
        ack.signature = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec();
        Ok(ack)
    }
}
fn key_context(
    community: &str,
    member: &str,
    public: &[u8; 64],
    context: &[u8],
) -> Result<[u8; 32], Error> {
    if community.is_empty() || community.len() > 256 || context.len() > 4096 {
        return Err(Error::InvalidStore);
    }
    serde_json::to_vec(&serde_json::json!([
        "cmsg.accounting-key.v1",
        community,
        member,
        HEX.encode(public),
        B64.encode(context)
    ]))
    .map(hash)
    .map_err(|_| Error::InvalidStore)
}

impl Member {
    /// Authorize one named cfrm proof request without exposing this device key or
    /// signing arbitrary bytes. cfrm independently recomputes statement/proof hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_account_request(
        &self,
        request_id: &[u8; 32],
        circuit_digest: &[u8; 32],
        verifying_key_digest: &[u8; 32],
        statement_digest: &[u8; 32],
        proof_digest: &[u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<AccountRequestAuthorization, Error> {
        self.member_id()?;
        let admission = self.admission_grant()?;
        let authorization = self.device_authorization()?.ok_or(Error::Admission)?;
        let now = self.authorization_time()?;
        time(issued_at)?;
        time(expires_at)?;
        if *request_id == [0; 32]
            || issued_at > now
            || now >= expires_at
            || issued_at >= expires_at
            || issued_at < admission.issued_at
            || issued_at < authorization.issued_at
            || expires_at > admission.expires_at
            || expires_at > authorization.expires_at
        {
            return Err(Error::Admission);
        }
        let mut result = AccountRequestAuthorization {
            request_id: *request_id,
            circuit_digest: *circuit_digest,
            verifying_key_digest: *verifying_key_digest,
            statement_digest: *statement_digest,
            proof_digest: *proof_digest,
            chat_public_key: B64.encode(&self.chat_public_key()),
            issued_at,
            expires_at,
            signature: String::new(),
        };
        result.signature = B64.encode(
            &MlsSigner::sign(&self.signer, &result.signing_bytes()?)
                .map_err(|_| Error::Admission)?,
        );
        Ok(result)
    }

    pub fn delegate_accounting(
        &self,
        key: &AccountingKey,
        hash_scheme: &str,
        state_secret_commitment: &[u8; 32],
        expires_at: u64,
    ) -> Result<AccountingDelegation, Error> {
        if key.member_id != self.member_id()?
            || key.community_id != self.trust.as_ref().ok_or(Error::Admission)?.community_id
        {
            return Err(Error::Admission);
        }
        self.delegate_accounting_public_key(
            &key.public_key(),
            hash_scheme,
            state_secret_commitment,
            expires_at,
        )
    }

    /// Delegate to an independently held P-256 key. This authorizes that key;
    /// possession is demonstrated by its subsequent accounting signatures.
    pub fn delegate_accounting_public_key(
        &self,
        account_public_key: &[u8; 64],
        hash_scheme: &str,
        state_secret_commitment: &[u8; 32],
        expires_at: u64,
    ) -> Result<AccountingDelegation, Error> {
        public_key(account_public_key)?;
        let mut d = AccountingDelegation {
            version: 1,
            hash_scheme: hash_scheme.to_owned(),
            admission: self.admission_grant()?,
            authorization: self.device_authorization()?.ok_or(Error::Admission)?,
            account_public_key: HEX.encode(account_public_key),
            state_secret_commitment: HEX.encode(state_secret_commitment),
            issued_at: self.authorization_time()?,
            expires_at,
            signature: String::new(),
        };
        d.signature = B64.encode(
            &MlsSigner::sign(&self.signer, &d.signing_bytes()?).map_err(|_| Error::Admission)?,
        );
        verify_accounting_delegation(
            &d,
            self.trust.as_ref().ok_or(Error::Admission)?,
            self.authorization_time()?,
        )?;
        Ok(d)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRequestAuthorization {
    pub request_id: [u8; 32],
    pub circuit_digest: [u8; 32],
    pub verifying_key_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub proof_digest: [u8; 32],
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
impl std::fmt::Debug for AccountRequestAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountRequestAuthorization([redacted])")
    }
}
impl AccountRequestAuthorization {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"cfrm.account.request.v1\0".to_vec();
        for field in [
            self.request_id,
            self.circuit_digest,
            self.verifying_key_digest,
            member_bytes(&self.chat_public_key)?,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        bytes.extend_from_slice(&self.proof_digest);
        Ok(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingContactContext {
    pub initiator_id: String,
    pub group_id: Vec<u8>,
    pub policy: FirstContactPolicy,
    pub responder_history_tip: [u8; 32],
    pub peer_history_tip: [u8; 32],
}

/// Private reservation context read from the existing strict introduction.
/// It is not a reservation proof or an operator admission authorization.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingIntroduction {
    pub community_id: String,
    pub responder_id: String,
    pub introduction_id: [u8; 32],
    pub contact: AccountingContactContext,
}
impl std::fmt::Debug for AccountingIntroduction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingIntroduction([redacted])")
    }
}
impl std::fmt::Debug for AccountingContactContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingContactContext([redacted])")
    }
}
impl Drop for AccountingContactContext {
    fn drop(&mut self) {
        self.initiator_id.zeroize();
        self.group_id.zeroize();
        self.responder_history_tip.zeroize();
        self.peer_history_tip.zeroize();
    }
}
impl AccountingContactContext {
    pub fn group_binding(&self) -> Result<[u8; 32], Error> {
        if self.group_id.is_empty() || self.group_id.len() > 256 {
            return Err(Error::Admission);
        }
        let mut bytes = b"cmsg.accounting-group.v1\0".to_vec();
        bytes.extend_from_slice(&(self.group_id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.group_id);
        Ok(hash(bytes))
    }
    pub fn policy_digest(&self) -> Result<[u8; 32], Error> {
        time(self.policy.response_deadline)?;
        if self.policy.max_intro_bytes == 0 || self.policy.max_intro_bytes > crate::MAX_DATA_BYTES {
            return Err(Error::Admission);
        }
        let mut bytes = b"cmsg.accounting-contact-policy.v1\0".to_vec();
        bytes.extend_from_slice(&self.policy.response_deadline.to_be_bytes());
        bytes.extend_from_slice(&(self.policy.max_intro_bytes as u32).to_be_bytes());
        Ok(hash(bytes))
    }
    pub fn history_digest(&self) -> [u8; 32] {
        let mut bytes = b"cmsg.accounting-contact-history.v1\0".to_vec();
        bytes.extend_from_slice(&self.responder_history_tip);
        bytes.extend_from_slice(&self.peer_history_tip);
        hash(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingReceipt {
    pub version: u32,
    pub delegation: AccountingDelegation,
    pub resolution: ContactResolution,
    pub contact: AccountingContactContext,
    pub issued_at: u64,
    /// P1363 r || s; strict low-S, exactly 64 bytes.
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for AccountingReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingReceipt([redacted])")
    }
}
impl AccountingReceipt {
    pub(crate) fn prepare(
        member: &Member,
        delegation: &AccountingDelegation,
        resolution: ContactResolution,
        contact: AccountingContactContext,
    ) -> Result<Self, Error> {
        if delegation.admission.member_id != member.member_id()? {
            return Err(Error::Admission);
        }
        let receipt = Self {
            version: 1,
            delegation: delegation.clone(),
            resolution,
            contact,
            issued_at: member.authorization_time()?,
            signature: Vec::new(),
        };
        receipt.validate(
            member.trust.as_ref().ok_or(Error::Admission)?,
            member.authorization_time()?,
        )?;
        Ok(receipt)
    }
    pub fn resolution_digest(&self) -> Result<[u8; 32], Error> {
        let mut bytes = b"cmsg.accounting-resolution-digest.v1\0".to_vec();
        let transcript = self.resolution.signing_bytes()?;
        bytes.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&transcript);
        if self.resolution.signature.len() != 64 {
            return Err(Error::Admission);
        }
        bytes.extend_from_slice(&self.resolution.signature);
        Ok(hash(bytes))
    }
    /// Exactly 357 bytes, SHA-256 hashed by P-256 ECDSA. Only recipient evidence
    /// is issued: role byte 1 and initiator==peer are mandatory in this version.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let r = &self.resolution;
        let mut bytes = RECEIPT_DOMAIN.to_vec();
        for field in [
            hash(r.community_id.as_bytes()),
            member_bytes(&r.responder_id)?,
            member_bytes(&r.peer_id)?,
            member_bytes(&self.contact.initiator_id)?,
            r.introduction_id,
            self.contact.group_binding()?,
            self.delegation.digest()?,
            self.contact.policy_digest()?,
            self.contact.history_digest(),
            self.resolution_digest()?,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.push(match r.kind {
            ContactResolutionKind::Answered => 1,
            ContactResolutionKind::ClosedForever => 2,
        });
        bytes.push(1);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(bytes)
    }
    fn validate(&self, trust: &AdmissionTrust, now: u64) -> Result<(), Error> {
        let r = &self.resolution;
        time(now)?;
        time(r.issued_at)?;
        time(self.issued_at)?;
        if self.version != 1
            || r.issued_at > self.issued_at
            || self.issued_at > now
            || r.community_id != trust.community_id
            || r.responder_id != self.delegation.admission.member_id
            || r.peer_id != self.contact.initiator_id
            || r.responder_id == r.peer_id
            || r.introduction_id == [0; 32]
            || B64.encode(&r.device_public_key) != self.delegation.authorization.device_public_key
        {
            return Err(Error::Admission);
        }
        for at in [now, self.issued_at] {
            verify_accounting_delegation(&self.delegation, trust, at)?;
        }
        for at in [now, r.issued_at] {
            if crate::member::verify_bound_identity_bytes(
                &r.identity_credential,
                &r.device_public_key,
                trust,
                at,
            )? != r.responder_id
            {
                return Err(Error::Admission);
            }
        }
        let key: [u8; 32] = r
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        EdKey::from_bytes(&key)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &r.signing_bytes()?,
                &EdSignature::from_slice(&r.signature).map_err(|_| Error::Admission)?,
            )
            .map_err(|_| Error::Admission)?;
        self.signing_bytes()?;
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        if self.signature.len() != 64 {
            return Err(Error::Admission);
        }
        let mut bytes = b"cmsg.accounting-receipt-digest.v1\0".to_vec();
        bytes.extend_from_slice(&self.signing_bytes()?);
        bytes.extend_from_slice(&self.signature);
        Ok(hash(bytes))
    }
}

/// Verifies current signer authority plus the unchanged Ed25519 receipt and the
/// new P-256 signature. It neither proves delivery nor consumes a ledger event.
pub fn verify_accounting_receipt(
    receipt: &AccountingReceipt,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    receipt.validate(trust, now)?;
    let signature = Signature::from_slice(&receipt.signature).map_err(|_| Error::Admission)?;
    if signature.normalize_s().is_some() {
        return Err(Error::Admission);
    }
    public_key(&decode::<64>(&receipt.delegation.account_public_key)?)?
        .verify(&receipt.signing_bytes()?, &signature)
        .map_err(|_| Error::Admission)
}

/// Verify archived evidence against the EXACT delegation already authenticated
/// when reserving the obligation. The caller must retrieve this anchor from its
/// accepted state, never copy it from newly received evidence.
pub fn verify_accounting_receipt_historical(
    receipt: &AccountingReceipt,
    trust: &AdmissionTrust,
    expected_delegation_digest: &[u8; 32],
    now: u64,
) -> Result<(), Error> {
    time(now)?;
    if now < receipt.issued_at || receipt.delegation.digest()? != *expected_delegation_digest {
        return Err(Error::Admission);
    }
    verify_accounting_receipt(receipt, trust, receipt.issued_at)
}

/// Original initiator acknowledgment of the exact recipient Answer receipt.
/// Recipient self-attestation supplies no such authority. This remains a private
/// proof witness, not an instruction to credit either member's account.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountingAcknowledgment {
    pub version: u32,
    pub delegation: AccountingDelegation,
    pub answer: AccountingReceipt,
    pub issued_at: u64,
    pub signature: Vec<u8>,
}
impl std::fmt::Debug for AccountingAcknowledgment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountingAcknowledgment([redacted])")
    }
}
impl AccountingAcknowledgment {
    pub(crate) fn prepare(
        member: &Member,
        delegation: &AccountingDelegation,
        answer: &AccountingReceipt,
    ) -> Result<Self, Error> {
        if delegation.admission.member_id != member.member_id()? {
            return Err(Error::Admission);
        }
        let answer =
            serde_json::from_slice(&serde_json::to_vec(answer).map_err(|_| Error::InvalidMessage)?)
                .map_err(|_| Error::InvalidMessage)?;
        let ack = Self {
            version: 1,
            delegation: delegation.clone(),
            answer,
            issued_at: member.authorization_time()?,
            signature: Vec::new(),
        };
        ack.validate(
            member.trust.as_ref().ok_or(Error::Admission)?,
            member.authorization_time()?,
        )?;
        Ok(ack)
    }
    /// Exactly 255 bytes, signed as SHA-256/P-256 with low-S P1363 encoding.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let r = &self.answer.resolution;
        let mut bytes = b"cmsg.accounting-ack.v1\0".to_vec();
        for field in [
            hash(r.community_id.as_bytes()),
            member_bytes(&self.answer.contact.initiator_id)?,
            member_bytes(&r.responder_id)?,
            r.introduction_id,
            self.answer.contact.group_binding()?,
            self.answer.digest()?,
            self.delegation.digest()?,
        ] {
            bytes.extend_from_slice(&field);
        }
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        Ok(bytes)
    }
    fn validate(&self, trust: &AdmissionTrust, now: u64) -> Result<(), Error> {
        time(self.issued_at)?;
        if self.version != 1
            || self.answer.resolution.kind != ContactResolutionKind::Answered
            || self.issued_at < self.answer.issued_at
            || self.issued_at > now
            || self.delegation.admission.member_id != self.answer.contact.initiator_id
            || self.delegation.hash_scheme != self.answer.delegation.hash_scheme
        {
            return Err(Error::Admission);
        }
        verify_accounting_receipt(&self.answer, trust, now)?;
        for at in [now, self.issued_at] {
            verify_accounting_delegation(&self.delegation, trust, at)?;
        }
        self.signing_bytes()?;
        Ok(())
    }
}
pub fn verify_accounting_acknowledgment(
    ack: &AccountingAcknowledgment,
    trust: &AdmissionTrust,
    now: u64,
) -> Result<(), Error> {
    ack.validate(trust, now)?;
    let signature = Signature::from_slice(&ack.signature).map_err(|_| Error::Admission)?;
    if signature.normalize_s().is_some() {
        return Err(Error::Admission);
    }
    public_key(&decode::<64>(&ack.delegation.account_public_key)?)?
        .verify(&ack.signing_bytes()?, &signature)
        .map_err(|_| Error::Admission)
}

/// Both anchors come from the accepted obligation's independently verified
/// enrollment provenance; neither may be supplied by the arriving peer object.
pub fn verify_accounting_acknowledgment_historical(
    ack: &AccountingAcknowledgment,
    trust: &AdmissionTrust,
    expected_recipient_delegation_digest: &[u8; 32],
    expected_initiator_delegation_digest: &[u8; 32],
    now: u64,
) -> Result<(), Error> {
    time(now)?;
    if now < ack.issued_at
        || ack.answer.delegation.digest()? != *expected_recipient_delegation_digest
        || ack.delegation.digest()? != *expected_initiator_delegation_digest
    {
        return Err(Error::Admission);
    }
    verify_accounting_acknowledgment(ack, trust, ack.issued_at)
}
