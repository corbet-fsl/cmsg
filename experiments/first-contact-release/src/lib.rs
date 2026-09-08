//! Isolated first-contact release experiment; no network or operator ledger.
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use cmsg::MAX_WIRE_BYTES;
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_STORE_BYTES: usize = 8 * MAX_WIRE_BYTES + 16 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Context {
    pub community_id: String,
    pub policy_digest: String,
    pub cohort_id: String,
    pub not_before: u64,
    pub expires_at: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Peer {
    pub member_id: String,
    pub chat_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenderCommit {
    pub context: Context,
    pub sender: Peer,
    pub authorization_nonce: String,
    pub blinded_request_hash: String,
    pub signature: String,
}

impl SenderCommit {
    /// Fixed statement encoding, never a signature or private-key export.
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "cfrm.directional.commit.v1",
            self.context.community_id,
            self.context.policy_digest,
            self.context.cohort_id,
            self.sender.member_id,
            self.sender.chat_public_key,
            self.authorization_nonce,
            self.blinded_request_hash,
            self.context.not_before,
            self.context.expires_at,
        ]))
        .expect("fixed serializable statement")
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientRedemption {
    pub context: Context,
    pub recipient: Peer,
    pub release_nonce: String,
    pub signature: String,
}

impl RecipientRedemption {
    pub fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([
            "cfrm.directional.redemption.v1",
            self.context.community_id,
            self.context.policy_digest,
            self.context.cohort_id,
            self.recipient.member_id,
            self.recipient.chat_public_key,
            self.release_nonce,
            self.context.not_before,
            self.context.expires_at,
        ]))
        .expect("fixed serializable statement")
    }
}

/// Trusted common operator keys with deliberately separate signing purposes.
pub struct OperatorTrust {
    pub sender_commit_key: [u8; 32],
    pub recipient_redemption_key: [u8; 32],
}

/// Private peer-to-peer metadata. This is not an authenticated preflight API.
#[derive(Clone)]
pub struct Preflight {
    pub context: Context,
    pub sender: Peer,
    pub recipient: Peer,
    pub release_nonce: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasedMaterial {
    pub welcome: Vec<u8>,
    pub first_ciphertext: Vec<u8>,
}

impl Drop for ReleasedMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidAttestation,
    InvalidStore,
    Declined,
    Expired,
    Randomness,
}

/// Owns the exact withheld MLS input. No public accessor exposes that input.
pub struct PendingRelease {
    state: State,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    context: Context,
    sender: Peer,
    recipient: Peer,
    release_nonce: String,
    authorization_nonce: String,
    request_hash: Option<String>,
    material: Option<ReleasedMaterial>,
    declined: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PendingRelease {
    pub fn prepare(
        context: Context,
        sender: Peer,
        recipient: Peer,
        material: ReleasedMaterial,
        now: u64,
    ) -> Result<Self, Error> {
        let state = State {
            context,
            sender,
            recipient,
            release_nonce: fresh_nonce()?,
            authorization_nonce: fresh_nonce()?,
            request_hash: None,
            material: Some(material),
            declined: false,
        };
        if !valid_state(&state) {
            return Err(Error::InvalidInput);
        }
        current(&state.context, now)?;
        Ok(Self { state })
    }

    pub fn preflight(&self) -> Preflight {
        Preflight {
            context: self.state.context.clone(),
            sender: self.state.sender.clone(),
            recipient: self.state.recipient.clone(),
            release_nonce: self.state.release_nonce.clone(),
        }
    }

    /// Bind one blind request after the recipient sees the private release nonce.
    pub fn bind_request(&mut self, request_hash: &str) -> Result<SenderCommit, Error> {
        if self.state.declined {
            return Err(Error::Declined);
        }
        if decode::<32>(request_hash).is_none()
            || self
                .state
                .request_hash
                .as_ref()
                .is_some_and(|bound| bound != request_hash)
        {
            return Err(Error::InvalidInput);
        }
        self.state.request_hash = Some(request_hash.to_owned());
        Ok(SenderCommit {
            context: self.state.context.clone(),
            sender: self.state.sender.clone(),
            authorization_nonce: self.state.authorization_nonce.clone(),
            blinded_request_hash: request_hash.to_owned(),
            signature: String::new(),
        })
    }

    pub fn release(
        &mut self,
        sender_commit: &SenderCommit,
        recipient_redemption: &RecipientRedemption,
        trust: &OperatorTrust,
        now: u64,
    ) -> Result<ReleasedMaterial, Error> {
        if self.state.declined {
            return Err(Error::Declined);
        }
        current(&self.state.context, now)?;
        if sender_commit.context != self.state.context
            || sender_commit.sender != self.state.sender
            || sender_commit.authorization_nonce != self.state.authorization_nonce
            || self.state.request_hash.as_ref() != Some(&sender_commit.blinded_request_hash)
            || recipient_redemption.context != self.state.context
            || recipient_redemption.recipient != self.state.recipient
            || recipient_redemption.release_nonce != self.state.release_nonce
            || trust.sender_commit_key == trust.recipient_redemption_key
        {
            return Err(Error::InvalidAttestation);
        }
        verify(
            &trust.sender_commit_key,
            &sender_commit.signing_bytes(),
            &sender_commit.signature,
        )?;
        verify(
            &trust.recipient_redemption_key,
            &recipient_redemption.signing_bytes(),
            &recipient_redemption.signature,
        )?;
        // There is no external spend here and the payload is immutable. Retries
        // therefore recover the exact same bytes, even after encrypted restore.
        self.state.material.clone().ok_or(Error::Declined)
    }

    pub fn decline(&mut self) {
        self.state.declined = true;
        self.state.material = None;
    }

    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&self.state).map_err(|_| Error::InvalidStore)?);
        if plaintext.len() > MAX_STORE_BYTES - 29 {
            return Err(Error::InvalidStore);
        }
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let encrypted = ChaCha20Poly1305::new(key.into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &store_aad(&self.state.context),
                },
            )
            .map_err(|_| Error::InvalidStore)?;
        let mut sealed = Vec::with_capacity(13 + encrypted.len());
        sealed.push(1);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&encrypted);
        Ok(sealed)
    }

    pub fn restore(
        sealed: &[u8],
        key: &[u8; 32],
        expected_context: &Context,
    ) -> Result<Self, Error> {
        if sealed.len() < 29
            || sealed.len() > MAX_STORE_BYTES
            || sealed[0] != 1
            || !valid_context(expected_context)
        {
            return Err(Error::InvalidStore);
        }
        let plaintext = Zeroizing::new(
            ChaCha20Poly1305::new(key.into())
                .decrypt(
                    Nonce::from_slice(&sealed[1..13]),
                    Payload {
                        msg: &sealed[13..],
                        aad: &store_aad(expected_context),
                    },
                )
                .map_err(|_| Error::InvalidStore)?,
        );
        let state: State = serde_json::from_slice(&plaintext).map_err(|_| Error::InvalidStore)?;
        if &state.context != expected_context || !valid_state(&state) {
            return Err(Error::InvalidStore);
        }
        Ok(Self { state })
    }
}

fn fresh_nonce() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::Randomness)?;
    Ok(B64.encode(&bytes))
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

fn valid_context(context: &Context) -> bool {
    !context.community_id.is_empty()
        && context.community_id.len() <= 128
        && !context.cohort_id.is_empty()
        && context.cohort_id.len() <= 128
        && decode::<32>(&context.policy_digest).is_some()
        && context.not_before > 0
        && context.not_before < context.expires_at
}

fn valid_peer(peer: &Peer) -> bool {
    decode::<32>(&peer.member_id).is_some() && decode::<32>(&peer.chat_public_key).is_some()
}

fn valid_state(state: &State) -> bool {
    valid_context(&state.context)
        && valid_peer(&state.sender)
        && valid_peer(&state.recipient)
        && state.sender.member_id != state.recipient.member_id
        && decode::<32>(&state.release_nonce).is_some()
        && decode::<32>(&state.authorization_nonce).is_some()
        && state.release_nonce != state.authorization_nonce
        && state
            .request_hash
            .as_ref()
            .is_none_or(|hash| decode::<32>(hash).is_some())
        && state.declined == state.material.is_none()
        && state.material.as_ref().is_none_or(|material| {
            !material.welcome.is_empty()
                && material.welcome.len() <= MAX_WIRE_BYTES
                && !material.first_ciphertext.is_empty()
                && material.first_ciphertext.len() <= MAX_WIRE_BYTES
        })
}

fn current(context: &Context, now: u64) -> Result<(), Error> {
    if now < context.not_before || now >= context.expires_at {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}

fn verify(key: &[u8; 32], message: &[u8], signature: &str) -> Result<(), Error> {
    let signature = decode::<64>(signature).ok_or(Error::InvalidAttestation)?;
    VerifyingKey::from_bytes(key)
        .map_err(|_| Error::InvalidAttestation)?
        .verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| Error::InvalidAttestation)
}

fn store_aad(context: &Context) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "cmsg.first-contact-release.store.v1",
        context.community_id,
        context.policy_digest,
        context.cohort_id,
        context.not_before,
        context.expires_at,
    ]))
    .expect("fixed serializable context")
}
