//! Fixed-purpose account authorizations and private release preflight metadata.
//!
//! These operations do not issue receipts, debit counters, prove delivery or
//! implement recipient consent. A preflight and its signature are private peer
//! data; neither belongs in an operator authorization or telemetry payload.
use crate::{verify_admission, AdmissionGrant, Error, Member};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_AUTHORIZATION_SECONDS: u64 = 300;

/// An owner changes only their own side of a contact restriction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContactDirectiveKind {
    Block,
    FreshInitiative,
}

/// Private, root-authorized contact control. The Inbox validates its predecessor
/// chain and commits it with the encrypted journal before using it. A signature
/// alone neither reopens a contact nor earns allowance.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactDirective {
    pub community_id: String,
    pub owner_id: String,
    pub peer_id: String,
    pub revision: u64,
    pub previous_digest: [u8; 32],
    pub peer_digest: [u8; 32],
    pub kind: ContactDirectiveKind,
    pub introduction_id: [u8; 32],
    pub initiator_id: String,
    pub group_id: Vec<u8>,
    pub policy: Option<crate::FirstContactPolicy>,
    pub until: Option<u64>,
    pub issued_at: u64,
    pub device_public_key: Vec<u8>,
    pub identity_credential: Vec<u8>,
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for ContactDirective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContactDirective([redacted])")
    }
}

impl Drop for ContactDirective {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.community_id.zeroize();
        self.owner_id.zeroize();
        self.peer_id.zeroize();
        self.previous_digest.zeroize();
        self.peer_digest.zeroize();
        self.introduction_id.zeroize();
        self.initiator_id.zeroize();
        self.group_id.zeroize();
        self.identity_credential.zeroize();
    }
}

impl ContactDirective {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        let policy = self
            .policy
            .map(|p| (p.response_deadline, p.max_intro_bytes));
        serde_json::to_vec(&serde_json::json!([
            "cmsg.contact-directive.v1",
            self.community_id,
            self.owner_id,
            self.peer_id,
            self.revision,
            B64.encode(&self.previous_digest),
            B64.encode(&self.peer_digest),
            self.kind,
            B64.encode(&self.introduction_id),
            self.initiator_id,
            B64.encode(&self.group_id),
            policy,
            self.until,
            self.issued_at,
            B64.encode(&self.device_public_key),
            B64.encode(&Sha256::digest(&self.identity_credential)),
        ]))
        .map_err(|_| Error::InvalidMessage)
    }

    /// Stable chain identifier; callers must authenticate the directive before
    /// accepting the digest as a predecessor. Signing encodings are canonical.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        let mut hash = Sha256::new();
        hash.update(b"cmsg.contact-directive-digest.v1\0");
        hash.update(&*zeroize::Zeroizing::new(self.signing_bytes()?));
        Ok(hash.finalize().into())
    }

    fn validate_shape(&self, verifier: &Member, at: u64) -> Result<(), Error> {
        if self.community_id
            != verifier
                .trust
                .as_ref()
                .ok_or(Error::Admission)?
                .community_id
            || !crate::admission::valid_member_id(&self.owner_id)
            || !crate::admission::valid_member_id(&self.peer_id)
            || self.owner_id == self.peer_id
            || self.revision == 0
            || self.revision > MAX_SAFE_INTEGER
            || self.issued_at == 0
            || self.issued_at > at
            || self.issued_at > MAX_SAFE_INTEGER
            || self.group_id.len() > 256
            || self.device_public_key.len() != 32
            || self.identity_credential.len() > 8192
            || (self.revision == 1) != (self.previous_digest == [0; 32])
        {
            return Err(Error::Admission);
        }
        match self.kind {
            ContactDirectiveKind::Block => {
                if self.policy.is_some()
                    || !self.initiator_id.is_empty()
                    || self
                        .until
                        .is_some_and(|until| until <= self.issued_at || until > MAX_SAFE_INTEGER)
                {
                    return Err(Error::Admission);
                }
            }
            ContactDirectiveKind::FreshInitiative => {
                let policy = self.policy.ok_or(Error::Admission)?;
                if self.until.is_some()
                    || self.introduction_id == [0; 32]
                    || self.group_id.is_empty()
                    || (self.initiator_id != self.owner_id && self.initiator_id != self.peer_id)
                    || policy.response_deadline <= at
                    || policy.response_deadline > MAX_SAFE_INTEGER
                    || policy.max_intro_bytes == 0
                    || policy.max_intro_bytes > crate::MAX_DATA_BYTES
                {
                    return Err(Error::Admission);
                }
            }
        }
        Ok(())
    }

    /// Historical calls are for authenticated saved journals only. New network
    /// input must use Member::verify_contact_directive with its current clock.
    pub(crate) fn verify_device_signature(&self, verifier: &Member, at: u64) -> Result<(), Error> {
        self.validate_shape(verifier, at)?;
        if verifier.verify_private_identity_credential(
            &self.identity_credential,
            &self.device_public_key,
            at,
        )? != self.owner_id
            || verifier.verify_private_identity_credential(
                &self.identity_credential,
                &self.device_public_key,
                self.issued_at,
            )? != self.owner_id
        {
            return Err(Error::Admission);
        }
        let key: [u8; 32] = self
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &zeroize::Zeroizing::new(self.signing_bytes()?),
                &Signature::from_slice(&self.signature).map_err(|_| Error::Admission)?,
            )
            .map_err(|_| Error::Admission)
    }
}

/// A peer's authenticated decision. An answer claim is not proof that a human
/// read a message, and this receipt alone never authorizes an operator credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContactResolutionKind {
    Answered,
    /// Closes this introduction permanently. A different introduction requires
    /// the separate owner-controlled contact policy and any required consent.
    ClosedForever,
}

/// Private first-contact receipt. All fields identify a contact pair: keep it on
/// the endpoints and feed only an independently verified private proof to a
/// policy service. The same introduction ID must be persisted by both endpoints.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContactResolution {
    pub community_id: String,
    pub responder_id: String,
    pub peer_id: String,
    pub introduction_id: [u8; 32],
    pub kind: ContactResolutionKind,
    pub issued_at: u64,
    pub device_public_key: Vec<u8>,
    pub identity_credential: Vec<u8>,
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for ContactResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContactResolution([redacted])")
    }
}

impl Drop for ContactResolution {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.community_id.zeroize();
        self.responder_id.zeroize();
        self.peer_id.zeroize();
        self.introduction_id.zeroize();
        self.identity_credential.zeroize();
    }
}

impl ContactResolution {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!([
            "cmsg.contact-resolution.v1",
            self.community_id,
            self.responder_id,
            self.peer_id,
            B64.encode(&self.introduction_id),
            self.kind,
            self.issued_at,
            B64.encode(&self.device_public_key),
            B64.encode(&Sha256::digest(&self.identity_credential)),
        ]))
        .map_err(|_| Error::InvalidMessage)
    }

    pub(crate) fn verify_device_signature(&self, verifier: &Member, at: u64) -> Result<(), Error> {
        if self.identity_credential.len() > 8192
            || verifier.verify_private_identity_credential(
                &self.identity_credential,
                &self.device_public_key,
                at,
            )? != self.responder_id
            || verifier.verify_private_identity_credential(
                &self.identity_credential,
                &self.device_public_key,
                self.issued_at,
            )? != self.responder_id
        {
            return Err(Error::Admission);
        }
        let key: [u8; 32] = self
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &zeroize::Zeroizing::new(self.signing_bytes()?),
                &Signature::from_slice(&self.signature).map_err(|_| Error::Admission)?,
            )
            .map_err(|_| Error::Admission)
    }
}

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
    /// Create one fixed-purpose private contact directive. The caller must use
    /// Inbox to validate and durably extend the owner chain before transmitting.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_contact_directive(
        &self,
        peer_id: &str,
        revision: u64,
        previous_digest: &[u8; 32],
        peer_digest: &[u8; 32],
        kind: ContactDirectiveKind,
        introduction_id: &[u8; 32],
        initiator_id: &str,
        group_id: &[u8],
        policy: Option<crate::FirstContactPolicy>,
        until: Option<u64>,
    ) -> Result<ContactDirective, Error> {
        if self.device_authorization()?.is_none() {
            return Err(Error::Admission);
        }
        let mut directive = ContactDirective {
            community_id: self
                .trust
                .as_ref()
                .ok_or(Error::Admission)?
                .community_id
                .clone(),
            owner_id: self.member_id()?,
            peer_id: peer_id.to_owned(),
            revision,
            previous_digest: *previous_digest,
            peer_digest: *peer_digest,
            kind,
            introduction_id: *introduction_id,
            initiator_id: initiator_id.to_owned(),
            group_id: group_id.to_vec(),
            policy,
            until,
            issued_at: self.authorization_time()?,
            device_public_key: self.chat_public_key(),
            identity_credential: self.private_identity_credential()?,
            signature: Vec::new(),
        };
        directive.validate_shape(self, directive.issued_at)?;
        directive.signature = self
            .signer
            .sign(&zeroize::Zeroizing::new(directive.signing_bytes()?))
            .map_err(|_| Error::Admission)?;
        Ok(directive)
    }

    /// Verify a current peer directive for this community and exact contact pair.
    /// Inbox supplies chain, consent, expiry and replay enforcement separately.
    pub fn verify_contact_directive(
        &self,
        directive: &ContactDirective,
        expected_owner: &str,
    ) -> Result<(), Error> {
        let own_id = self.member_id()?;
        if self.device_authorization()?.is_none()
            || directive.owner_id != expected_owner
            || !((directive.owner_id == own_id) ^ (directive.peer_id == own_id))
        {
            return Err(Error::Admission);
        }
        directive.verify_device_signature(self, self.authorization_time()?)
    }

    /// Sign a private answer/close declaration using this root-authorized device.
    /// Hosts must durably save the decision and its outbound receipt together
    /// before transmission. Signing alone does not apply a local closure.
    pub fn sign_contact_resolution(
        &self,
        peer_id: &str,
        introduction_id: &[u8; 32],
        kind: ContactResolutionKind,
    ) -> Result<ContactResolution, Error> {
        let responder_id = self.member_id()?;
        if self.device_authorization()?.is_none()
            || !crate::admission::valid_member_id(peer_id)
            || peer_id == responder_id
        {
            return Err(Error::Admission);
        }
        let mut resolution = ContactResolution {
            community_id: self
                .trust
                .as_ref()
                .ok_or(Error::Admission)?
                .community_id
                .clone(),
            responder_id,
            peer_id: peer_id.to_owned(),
            introduction_id: *introduction_id,
            kind,
            issued_at: self.authorization_time()?,
            device_public_key: self.chat_public_key(),
            identity_credential: self.private_identity_credential()?,
            signature: Vec::new(),
        };
        resolution.signature = self
            .signer
            .sign(&zeroize::Zeroizing::new(resolution.signing_bytes()?))
            .map_err(|_| Error::Admission)?;
        Ok(resolution)
    }

    /// Authenticate a peer's decision for the exact locally pending introduction.
    /// The caller retains replay/settlement state; this verifier issues no credit.
    pub fn verify_contact_resolution(
        &self,
        resolution: &ContactResolution,
        expected_peer: &str,
        introduction_id: &[u8; 32],
    ) -> Result<(), Error> {
        let own_id = self.member_id()?;
        let now = self.authorization_time()?;
        if self.device_authorization()?.is_none()
            || resolution.community_id != self.trust.as_ref().ok_or(Error::Admission)?.community_id
            || resolution.peer_id != own_id
            || resolution.responder_id != expected_peer
            || resolution.peer_id == resolution.responder_id
            || resolution.introduction_id != *introduction_id
            || resolution.issued_at == 0
            || resolution.issued_at > now
        {
            return Err(Error::Admission);
        }
        resolution.verify_device_signature(self, now)
    }

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
        self.member_id()?;
        let grant = self.admission_grant()?;
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

#[cfg(test)]
mod backdated_contact_tests {
    use super::*;
    use crate::{AdmissionTrust, Clock, MemberIdentity};
    use std::sync::Arc;

    struct FixedTime;

    impl Clock for FixedTime {
        fn now(&self) -> Result<u64, Error> {
            Ok(100)
        }
    }

    fn device(grant_start: u64, device_start: u64) -> Member {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let trust = AdmissionTrust {
            community_id: "synthetic-backdated-contact".into(),
            policy_digest: B64.encode(&[42; 32]),
            issuer_public_key: issuer.verifying_key().to_bytes(),
        };
        let root = MemberIdentity::new(&trust.community_id).unwrap();
        let mut member = Member::new_with_clock(Arc::new(FixedTime)).unwrap();
        let device_key = member.chat_public_key();
        let mut grant = AdmissionGrant {
            version: 1,
            issuer_key_id: B64.encode(&Sha256::digest(trust.issuer_public_key)),
            community_id: trust.community_id.clone(),
            member_id: root.member_id().to_owned(),
            chat_public_key: B64.encode(&device_key),
            policy_digest: trust.policy_digest.clone(),
            issued_at: grant_start,
            expires_at: 1000,
            signature: String::new(),
        };
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cvld.admission.v1",
            grant.issuer_key_id,
            grant.community_id,
            grant.member_id,
            grant.chat_public_key,
            grant.policy_digest,
            grant.issued_at,
            grant.expires_at,
        ]))
        .unwrap();
        grant.signature = B64.encode(&ed25519_dalek::Signer::sign(&issuer, &bytes).to_bytes());
        let authorization = root
            .authorize_device(&device_key, device_start, 1000)
            .unwrap();
        member
            .bind_device_admission(grant, trust, authorization, 100)
            .unwrap();
        member
    }

    // Check the malicious replacement is a real signature over the backdated
    // payload. Rejection must come from credential time bounds, not tampering.
    fn assert_signature_valid(member: &Member, bytes: &[u8], signature: &[u8]) {
        let key: [u8; 32] = member.chat_public_key().try_into().unwrap();
        VerifyingKey::from_bytes(&key)
            .unwrap()
            .verify_strict(bytes, &Signature::from_slice(signature).unwrap())
            .unwrap();
    }

    #[test]
    fn current_peer_rejects_authentically_signed_directive_before_credential_validity() {
        let peer = device(1, 1);
        let peer_id = peer.member_id().unwrap();
        // Each credential's valid-from bound must be checked independently.
        for (grant_start, device_start) in [(80, 80), (1, 80), (80, 1)] {
            let owner = device(grant_start, device_start);
            let owner_id = owner.member_id().unwrap();
            let mut directive = owner
                .sign_contact_directive(
                    &peer_id,
                    1,
                    &[0; 32],
                    &[0; 32],
                    ContactDirectiveKind::FreshInitiative,
                    &[7; 32],
                    &owner_id,
                    b"synthetic-fresh-group",
                    Some(crate::FirstContactPolicy {
                        response_deadline: 500,
                        max_intro_bytes: 512,
                    }),
                    None,
                )
                .unwrap();
            peer.verify_contact_directive(&directive, &owner_id)
                .unwrap();
            directive.issued_at = 79;
            let bytes = directive.signing_bytes().unwrap();
            directive.signature = owner.signer.sign(&bytes).unwrap();
            assert_signature_valid(&owner, &bytes, &directive.signature);
            assert!(matches!(
                peer.verify_contact_directive(&directive, &owner_id),
                Err(Error::Admission)
            ));
        }
    }

    #[test]
    fn current_peer_rejects_authentically_signed_resolution_before_credential_validity() {
        let peer = device(1, 1);
        let peer_id = peer.member_id().unwrap();
        let introduction_id = [7; 32];
        for (grant_start, device_start) in [(80, 80), (1, 80), (80, 1)] {
            let owner = device(grant_start, device_start);
            let owner_id = owner.member_id().unwrap();
            for kind in [
                ContactResolutionKind::Answered,
                ContactResolutionKind::ClosedForever,
            ] {
                let mut receipt = owner
                    .sign_contact_resolution(&peer_id, &introduction_id, kind)
                    .unwrap();
                peer.verify_contact_resolution(&receipt, &owner_id, &introduction_id)
                    .unwrap();
                receipt.issued_at = 79;
                let bytes = receipt.signing_bytes().unwrap();
                receipt.signature = owner.signer.sign(&bytes).unwrap();
                assert_signature_valid(&owner, &bytes, &receipt.signature);
                assert!(matches!(
                    peer.verify_contact_resolution(&receipt, &owner_id, &introduction_id),
                    Err(Error::Admission),
                ));
            }
        }
    }
}
