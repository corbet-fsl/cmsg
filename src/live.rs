//! Authenticated live-session envelopes. Transport success is not acceptance.
use crate::{Error, Member};
use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(crate) const PREFIX: &[u8] = b"cmsg.live.v1\0";
pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn id(bytes: &[u8; 32]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(bytes)
}
pub(crate) fn random() -> Result<[u8; 32], Error> {
    let mut value = [0; 32];
    getrandom::fill(&mut value).map_err(|_| Error::Randomness)?;
    if value == [0; 32] {
        return Err(Error::Randomness);
    }
    Ok(value)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Body {
    Hello {
        nonce: [u8; 32],
        until: u64,
    },
    Ready {
        nonce: [u8; 32],
        peer_nonce: [u8; 32],
    },
    Data {
        session: [u8; 32],
        message: [u8; 32],
        text: bool,
        payload: Vec<u8>,
    },
    Ack {
        session: [u8; 32],
        message: [u8; 32],
        digest: [u8; 32],
    },
    End {
        session: [u8; 32],
    },
}
impl Drop for Body {
    fn drop(&mut self) {
        if let Self::Data { payload, .. } = self {
            payload.zeroize();
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Envelope {
    pub version: u32,
    pub community: String,
    pub owner: String,
    pub peer: String,
    pub device: Vec<u8>,
    pub credential: Vec<u8>,
    pub group: Vec<u8>,
    pub introduction: [u8; 32],
    pub issued_at: u64,
    pub body: Body,
    pub signature: Vec<u8>,
}
impl Envelope {
    fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!([
            "cmsg.live-envelope.v1",
            self.version,
            self.community,
            self.owner,
            self.peer,
            self.device,
            hash(&self.credential),
            self.group,
            self.introduction,
            self.issued_at,
            self.body
        ]))
        .map_err(|_| Error::InvalidMessage)
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32], Error> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(hash(&bytes))
    }
    pub(crate) fn verify(&self, member: &Member, at: u64) -> Result<(), Error> {
        let trust = member.trust.as_ref().ok_or(Error::Admission)?;
        if self.version != 1
            || self.community != trust.community_id
            || self.owner == self.peer
            || !crate::admission::valid_member_id(&self.peer)
            || self.group.is_empty()
            || self.group.len() > 256
            || self.introduction == [0; 32]
            || self.issued_at == 0
            || self.issued_at > at
            || at > 9_007_199_254_740_991
        {
            return Err(Error::Admission);
        }
        for time in [at, self.issued_at] {
            if crate::member::verify_bound_identity_bytes(
                &self.credential,
                &self.device,
                trust,
                time,
            )? != self.owner
            {
                return Err(Error::Admission);
            }
        }
        match &self.body {
            Body::Hello { nonce, until }
                if *nonce != [0; 32]
                    && *until > self.issued_at
                    && *until <= 9_007_199_254_740_991 =>
            {
                ()
            }
            Body::Ready { nonce, peer_nonce } if *nonce != [0; 32] && *peer_nonce != [0; 32] => (),
            Body::Data {
                session,
                message,
                text,
                payload,
            } if *session != [0; 32]
                && *message != [0; 32]
                && !payload.is_empty()
                && payload.len() <= crate::MAX_DATA_BYTES =>
            {
                if *text {
                    crate::validate_text(payload)?;
                }
            }
            Body::Ack {
                session,
                message,
                digest,
            } if *session != [0; 32] && *message != [0; 32] && *digest != [0; 32] => (),
            Body::End { session } if *session != [0; 32] => (),
            _ => return Err(Error::InvalidMessage),
        }
        let key: [u8; 32] = self
            .device
            .as_slice()
            .try_into()
            .map_err(|_| Error::Admission)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| Error::Admission)?
            .verify_strict(
                &self.signing_bytes()?,
                &Signature::from_slice(&self.signature).map_err(|_| Error::Admission)?,
            )
            .map_err(|_| Error::Admission)
    }
}
impl Member {
    pub(crate) fn sign_live(
        &self,
        peer: &str,
        introduction: &[u8; 32],
        body: Body,
    ) -> Result<Envelope, Error> {
        let mut envelope = Envelope {
            version: 1,
            community: self
                .trust
                .as_ref()
                .ok_or(Error::Admission)?
                .community_id
                .clone(),
            owner: self.member_id()?,
            peer: peer.to_owned(),
            device: self.chat_public_key(),
            credential: self.private_identity_credential()?,
            group: self.policy_group_id()?,
            introduction: *introduction,
            issued_at: self.authorization_time()?,
            body,
            signature: Vec::new(),
        };
        envelope.signature = self
            .signer
            .sign(&envelope.signing_bytes()?)
            .map_err(|_| Error::Admission)?;
        envelope.verify(self, envelope.issued_at)?;
        Ok(envelope)
    }
    pub(crate) fn send_live(&mut self, envelope: &Envelope) -> Result<Vec<u8>, Error> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(envelope).map_err(|_| Error::InvalidMessage)?);
        self.send_policy_record(&bytes)
    }
}
pub(crate) fn session(a: &Envelope, b: &Envelope) -> Result<[u8; 32], Error> {
    if a.owner != b.peer
        || a.peer != b.owner
        || a.community != b.community
        || a.group != b.group
        || a.introduction != b.introduction
    {
        return Err(Error::Admission);
    }
    let (Body::Hello { nonce: an, .. }, Body::Hello { nonce: bn, .. }) = (&a.body, &b.body) else {
        return Err(Error::InvalidMessage);
    };
    let pair = if a.owner < b.owner {
        (&a.owner, &a.device, an, &b.owner, &b.device, bn)
    } else {
        (&b.owner, &b.device, bn, &a.owner, &a.device, an)
    };
    Ok(hash(
        &serde_json::to_vec(&serde_json::json!([
            "cmsg.live-session.v1",
            a.community,
            a.group,
            a.introduction,
            pair
        ]))
        .map_err(|_| Error::InvalidMessage)?,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeliveryStatus {
    Pending,
    Accepted,
    CanceledUnconfirmed,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveDelivery {
    pub message_id: [u8; 32],
    pub session_id: [u8; 32],
    pub peer_id: String,
    pub outgoing: bool,
    pub status: DeliveryStatus,
}
impl std::fmt::Debug for LiveDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveDelivery([redacted])")
    }
}
