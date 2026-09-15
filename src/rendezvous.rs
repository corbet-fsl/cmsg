use crate::{Error, Member};
use serde::{Deserialize, Serialize};

/// The cfrm rendezvous challenge is an exact, domain-separated signing request.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RendezvousEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RendezvousChallenge {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub endpoint: RendezvousEndpoint,
    pub challenge_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl Member {
    /// Sign only an authenticated cfrm registration statement for our own identity.
    /// This is not a generic signing oracle and never exposes private key bytes.
    pub fn sign_rendezvous(
        &self,
        challenge: &RendezvousChallenge,
        now: u64,
    ) -> Result<String, Error> {
        use data_encoding::BASE64URL_NOPAD;
        use openmls_traits::signatures::Signer;
        let grant = self.admission_grant()?;
        let trust = self.trust.as_ref().ok_or(Error::Admission)?;
        if challenge.member_id != self.member_id()?
            || challenge.community_id != trust.community_id
            || challenge.chat_public_key != BASE64URL_NOPAD.encode(&self.chat_public_key())
            || challenge.issued_at > now
            || now >= challenge.expires_at
            || challenge.expires_at > grant.expires_at
            || challenge.issued_at < grant.issued_at
            || challenge.challenge_id.len() != 43
            || !BASE64URL_NOPAD
                .decode(challenge.challenge_id.as_bytes())
                .is_ok_and(|b| b.len() == 32)
        {
            return Err(Error::Admission);
        }
        crate::OnionEndpoint::parse(&challenge.endpoint.host, challenge.endpoint.port)?;
        let bytes = serde_json::to_vec(&serde_json::json!([
            "cfrm.rendezvous.v1",
            "register",
            challenge.community_id,
            challenge.member_id,
            challenge.chat_public_key,
            challenge.endpoint.host,
            challenge.endpoint.port,
            challenge.challenge_id,
            challenge.issued_at,
            challenge.expires_at,
        ]))
        .map_err(|_| Error::Admission)?;
        let signature = self.signer.sign(&bytes).map_err(|_| Error::Admission)?;
        Ok(BASE64URL_NOPAD.encode(&signature))
    }
}
