//! Private accounting evidence. These methods neither contact an operator nor
//! mutate a balance. All inputs remain bounded and errors omit private contents.
use super::*;
use crate::{AccountingAcknowledgment, AccountingDelegation, AccountingKey, AccountingReceipt};
use serde::de::DeserializeOwned;

fn parse<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    if json.len() > 64 * 1024 {
        return Err(js_error(Error::Admission));
    }
    serde_json::from_str(json).map_err(|_| js_error(Error::Admission))
}
fn encode<T: serde::Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|_| js_error(Error::Admission))
}
fn fixed(bytes: &[u8]) -> Result<&[u8; 32], JsValue> {
    bytes.try_into().map_err(|_| js_error(Error::Admission))
}

#[wasm_bindgen]
impl BrowserMember {
    #[wasm_bindgen(js_name = authorizeAccountRequest)]
    pub fn authorize_account_request(
        &self,
        request_id: &[u8],
        circuit_digest: &[u8],
        verifying_key_digest: &[u8],
        statement_digest: &[u8],
        proof_digest: &[u8],
        issued_at: f64,
        expires_at: f64,
    ) -> Result<String, JsValue> {
        encode(
            &self
                .member
                .authorize_account_request(
                    fixed(request_id)?,
                    fixed(circuit_digest)?,
                    fixed(verifying_key_digest)?,
                    fixed(statement_digest)?,
                    fixed(proof_digest)?,
                    timestamp(issued_at)?,
                    timestamp(expires_at)?,
                )
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = delegateAccountingPublicKey)]
    pub fn delegate_accounting_public_key(
        &self,
        public_key: &[u8],
        hash_scheme: &str,
        state_secret_commitment: &[u8],
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let public = public_key
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        encode(
            &self
                .member
                .delegate_accounting_public_key(
                    public,
                    hash_scheme,
                    fixed(state_secret_commitment)?,
                    timestamp(expires_at)?,
                )
                .map_err(js_error)?,
        )
    }
}

/// Independent P-256 signer. Its secret has only an encrypted recovery export.
#[wasm_bindgen]
pub struct BrowserAccountingKey {
    key: AccountingKey,
}
#[wasm_bindgen]
impl BrowserAccountingKey {
    #[wasm_bindgen(constructor)]
    pub fn new(session: &BrowserInbox) -> Result<BrowserAccountingKey, JsValue> {
        Ok(Self {
            key: AccountingKey::new(&session.member).map_err(js_error)?,
        })
    }
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().to_vec()
    }
    #[wasm_bindgen(js_name = memberId)]
    pub fn member_id(&self) -> String {
        self.key.member_id().to_owned()
    }
    pub fn seal(&self, key: &[u8], context: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.key
            .seal(&*wrapping_key(key)?, context)
            .map_err(js_error)
    }
    pub fn restore(
        sealed: &[u8],
        key: &[u8],
        community: &str,
        member: &str,
        expected_public_key: &[u8],
        context: &[u8],
    ) -> Result<BrowserAccountingKey, JsValue> {
        let public = expected_public_key
            .try_into()
            .map_err(|_| js_error(Error::InvalidStore))?;
        Ok(Self {
            key: AccountingKey::restore(
                sealed,
                &*wrapping_key(key)?,
                community,
                member,
                public,
                context,
            )
            .map_err(js_error)?,
        })
    }
}

#[wasm_bindgen]
impl BrowserInbox {
    #[wasm_bindgen(js_name = authorizeAccountRequest)]
    pub fn authorize_account_request(
        &self,
        request_id: &[u8],
        circuit_digest: &[u8],
        verifying_key_digest: &[u8],
        statement_digest: &[u8],
        proof_digest: &[u8],
        issued_at: f64,
        expires_at: f64,
    ) -> Result<String, JsValue> {
        encode(
            &self
                .member
                .authorize_account_request(
                    fixed(request_id)?,
                    fixed(circuit_digest)?,
                    fixed(verifying_key_digest)?,
                    fixed(statement_digest)?,
                    fixed(proof_digest)?,
                    timestamp(issued_at)?,
                    timestamp(expires_at)?,
                )
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = prepareAccountingContact)]
    pub fn prepare_accounting_contact(&self, peer: &str) -> Result<String, JsValue> {
        encode(
            &self
                .inbox
                .prepare_accounting_contact(peer, &self.member)
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = delegateAccountingPublicKey)]
    pub fn delegate_accounting_public_key(
        &self,
        public_key: &[u8],
        hash_scheme: &str,
        state_secret_commitment: &[u8],
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let public = public_key
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        let commitment = state_secret_commitment
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        encode(
            &self
                .member
                .delegate_accounting_public_key(
                    public,
                    hash_scheme,
                    commitment,
                    timestamp(expires_at)?,
                )
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = prepareAccountingReceipt)]
    pub fn prepare_accounting_receipt(
        &self,
        peer: &str,
        delegation_json: &str,
    ) -> Result<String, JsValue> {
        encode(
            &self
                .inbox
                .prepare_accounting_receipt(peer, &self.member, &parse(delegation_json)?)
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = prepareAccountingAcknowledgment)]
    pub fn prepare_accounting_acknowledgment(
        &self,
        peer: &str,
        delegation_json: &str,
        answer_json: &str,
    ) -> Result<String, JsValue> {
        encode(
            &self
                .inbox
                .prepare_accounting_acknowledgment(
                    peer,
                    &self.member,
                    &parse(delegation_json)?,
                    &parse(answer_json)?,
                )
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = delegateAccounting)]
    pub fn delegate_accounting(
        &self,
        key: &BrowserAccountingKey,
        hash_scheme: &str,
        state_secret_commitment: &[u8],
        expires_at: f64,
    ) -> Result<String, JsValue> {
        let commitment = state_secret_commitment
            .try_into()
            .map_err(|_| js_error(Error::Admission))?;
        encode(
            &self
                .member
                .delegate_accounting(&key.key, hash_scheme, commitment, timestamp(expires_at)?)
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = accountingReceipt)]
    pub fn accounting_receipt(
        &self,
        peer: &str,
        key: &BrowserAccountingKey,
        delegation_json: &str,
    ) -> Result<String, JsValue> {
        let delegation: AccountingDelegation = parse(delegation_json)?;
        encode(
            &self
                .inbox
                .accounting_receipt(peer, &self.member, &key.key, &delegation)
                .map_err(js_error)?,
        )
    }
    #[wasm_bindgen(js_name = accountingAcknowledgment)]
    pub fn accounting_acknowledgment(
        &self,
        peer: &str,
        key: &BrowserAccountingKey,
        delegation_json: &str,
        answer_json: &str,
    ) -> Result<String, JsValue> {
        let delegation: AccountingDelegation = parse(delegation_json)?;
        let answer: AccountingReceipt = parse(answer_json)?;
        encode(
            &self
                .inbox
                .accounting_acknowledgment(peer, &self.member, &key.key, &delegation, &answer)
                .map_err(js_error)?,
        )
    }
}

/// Time and issuer trust are caller-owned, just as for ordinary admission.
#[wasm_bindgen(js_name = verifyAccountingDelegation)]
pub fn verify_delegation(json: &str, trust_json: &str, now: f64) -> Result<Vec<u8>, JsValue> {
    let delegation: AccountingDelegation = parse(json)?;
    crate::verify_accounting_delegation(&delegation, &parse(trust_json)?, timestamp(now)?)
        .map_err(js_error)?;
    Ok(delegation.digest().map_err(js_error)?.to_vec())
}
#[wasm_bindgen(js_name = verifyAccountingReceipt)]
pub fn verify_receipt(json: &str, trust_json: &str, now: f64) -> Result<Vec<u8>, JsValue> {
    let receipt: AccountingReceipt = parse(json)?;
    crate::verify_accounting_receipt(&receipt, &parse(trust_json)?, timestamp(now)?)
        .map_err(js_error)?;
    receipt.signing_bytes().map_err(js_error)
}
#[wasm_bindgen(js_name = verifyAccountingAcknowledgment)]
pub fn verify_ack(json: &str, trust_json: &str, now: f64) -> Result<Vec<u8>, JsValue> {
    let ack: AccountingAcknowledgment = parse(json)?;
    crate::verify_accounting_acknowledgment(&ack, &parse(trust_json)?, timestamp(now)?)
        .map_err(js_error)?;
    ack.signing_bytes().map_err(js_error)
}

#[wasm_bindgen(js_name = verifyHistoricalAccountingReceipt)]
pub fn verify_historical_receipt(
    json: &str,
    trust_json: &str,
    expected_delegation_digest: &[u8],
    now: f64,
) -> Result<Vec<u8>, JsValue> {
    let receipt: AccountingReceipt = parse(json)?;
    let expected = expected_delegation_digest
        .try_into()
        .map_err(|_| js_error(Error::Admission))?;
    crate::verify_accounting_receipt_historical(
        &receipt,
        &parse(trust_json)?,
        expected,
        timestamp(now)?,
    )
    .map_err(js_error)?;
    receipt.signing_bytes().map_err(js_error)
}
#[wasm_bindgen(js_name = verifyHistoricalAccountingAcknowledgment)]
pub fn verify_historical_ack(
    json: &str,
    trust_json: &str,
    expected_recipient_digest: &[u8],
    expected_initiator_digest: &[u8],
    now: f64,
) -> Result<Vec<u8>, JsValue> {
    let ack: AccountingAcknowledgment = parse(json)?;
    let recipient = expected_recipient_digest
        .try_into()
        .map_err(|_| js_error(Error::Admission))?;
    let initiator = expected_initiator_digest
        .try_into()
        .map_err(|_| js_error(Error::Admission))?;
    crate::verify_accounting_acknowledgment_historical(
        &ack,
        &parse(trust_json)?,
        recipient,
        initiator,
        timestamp(now)?,
    )
    .map_err(js_error)?;
    ack.signing_bytes().map_err(js_error)
}

/// Canonical bytes alone confer no authority; completed signatures still require
/// the corresponding verifier and the caller's exact obligation checks.
#[wasm_bindgen(js_name = accountingReceiptSigningBytes)]
pub fn receipt_signing_bytes(json: &str) -> Result<Vec<u8>, JsValue> {
    parse::<AccountingReceipt>(json)?
        .signing_bytes()
        .map_err(js_error)
}
#[wasm_bindgen(js_name = accountingAcknowledgmentSigningBytes)]
pub fn ack_signing_bytes(json: &str) -> Result<Vec<u8>, JsValue> {
    parse::<AccountingAcknowledgment>(json)?
        .signing_bytes()
        .map_err(js_error)
}
