//! One confirmation stamp from the wallet: the device durably begins a blind stamp request in
//! its Wallet, the person confirms once with the wallet passkey (user verification over the
//! request's confirmation challenge), the wallet answers blindly, and Wallet retains the stamp
//! only after verifying its signature. The wallet never sees the actions or the communities.
use super::{ErrorCode, Result, custody::SystemClock, foyer::Transport, passport::GlobalPassport};
use cfyr::membership::GlobalStampIssuance;
use ckmg::{Authority, Clock, Entropy};
use cvlt::Records;
use cwlt::passport::{
    self, BlindStamp, IssuanceChallenge, StampAction, StampPublicKey, StampScope,
};
use serde_json::Value;
use std::future::Future;

fn now() -> u64 {
    SystemClock.now().unwrap_or(u64::MAX)
}

fn refused() -> ErrorCode {
    ErrorCode::Unauthorized
}

/// The wallet passkey's request options over exactly `challenge`. The server's options
/// authorize nothing: they must name exactly this wallet's passkey and require user
/// verification; the challenge is always the locally computed one.
pub(crate) fn stamp_options(
    options: &Value,
    credential: &[u8],
    challenge: [u8; 32],
) -> Result<Value> {
    use data_encoding::{BASE64URL, BASE64URL_NOPAD};
    let mut options = options.clone();
    let public = options.get_mut("publicKey").ok_or_else(refused)?;
    let allowed = public
        .get("allowCredentials")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    let id = match allowed.as_slice() {
        [only] => only.get("id").and_then(Value::as_str).ok_or_else(refused)?,
        _ => return Err(refused()),
    };
    let id = BASE64URL_NOPAD
        .decode(id.as_bytes())
        .or_else(|_| BASE64URL.decode(id.as_bytes()))
        .map_err(|_| refused())?;
    if id != credential || public.get("userVerification") != Some(&Value::from("required")) {
        return Err(refused());
    }
    public["challenge"] = Value::from(BASE64URL_NOPAD.encode(&challenge));
    Ok(options)
}

/// The public signed fields of the passkey answer, as the wallet's `stamp_issue` takes them.
pub(crate) fn assertion_fields(credential: Value) -> Result<Value> {
    let public: ckyh::PublicKeyCredential =
        serde_json::from_value(credential).map_err(|_| refused())?;
    Ok(serde_json::json!({
        "credential_id": public.raw_id.to_vec(),
        "client_data_json": public.response.client_data_json.to_vec(),
        "authenticator_data": public.response.authenticator_data.to_vec(),
        "signature": public.response.signature.to_vec(),
        "user_handle": public.response.user_handle.as_ref().map(|v| v.to_vec()),
    }))
}

/// Obtain one stamp covering `actions` (at most one per community) with ONE confirmation.
///
/// `assertion` performs the one WebAuthn assertion of the wallet passkey for the options it
/// receives and returns the public credential JSON. A pending request of an earlier,
/// interrupted attempt is dropped first: its nonce was single-use. An unknown issuance outcome
/// is `Reconcile` and is never retried here.
pub async fn request_stamp<B, C, E, A, R, G, F, Fut>(
    mut issuance: GlobalStampIssuance<Transport>,
    wallet: &mut GlobalPassport<B, C, E, A, R>,
    actions: &[(StampScope, StampAction)],
    assertion: F,
    rng: &mut G,
) -> Result<()>
where
    B: cwst::backend::Backend,
    C: Clock,
    E: Entropy,
    A: Authority,
    R: Records,
    G: passport::rand::RngCore + passport::rand::CryptoRng,
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    if actions.is_empty() {
        return Err(ErrorCode::Unavailable);
    }
    wallet.same_stamp_wallet(&mut issuance).await?;
    let (key, challenge, options) = issuance
        .with_current(now, |_, _, key, challenge, options| -> Result<_> {
            Ok((
                StampPublicKey::from_bytes(key).map_err(|_| refused())?,
                IssuanceChallenge::from_bytes(challenge.try_into().map_err(|_| refused())?),
                options.clone(),
            ))
        })
        .map_err(|_| refused())??;
    wallet.cancel_stamp(rng).await?;
    let request = wallet.begin_stamp(rng, &key, &challenge, actions).await?;
    let options = stamp_options(
        &options,
        wallet.credential(),
        request.confirmation_challenge(&challenge),
    )?;
    let credential = assertion(options).await?;
    let fields = assertion_fields(credential)?;
    let answer = issuance
        .issue(request.to_bytes(), fields, now)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    wallet
        .same_stamp_wallet(&mut issuance)
        .await
        .map_err(|_| ErrorCode::Reconcile)?;
    let blind = BlindStamp::from_bytes(&answer).map_err(|_| ErrorCode::Reconcile)?;
    wallet.finish_stamp(rng, &blind).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::json;

    fn options(ids: &[&[u8]], uv: &str) -> Value {
        json!({"publicKey": {
            "challenge": BASE64URL_NOPAD.encode(&[0; 32]),
            "rpId": "wallet.example.test",
            "allowCredentials": ids.iter().map(|id| json!({"type":"public-key","id":BASE64URL_NOPAD.encode(id)})).collect::<Vec<_>>(),
            "userVerification": uv,
        }})
    }

    #[test]
    fn stamp_options_name_only_this_wallet_passkey_and_carry_the_local_challenge() {
        let ready = stamp_options(&options(&[b"cred"], "required"), b"cred", [7; 32]).unwrap();
        assert_eq!(
            ready["publicKey"]["challenge"],
            json!(BASE64URL_NOPAD.encode(&[7; 32]))
        );
        assert_eq!(ready["publicKey"]["rpId"], json!("wallet.example.test"));
        for refused in [
            options(&[b"other"], "required"),
            options(&[b"cred"], "preferred"),
            options(&[b"cred", b"cred"], "required"),
            options(&[], "required"),
            json!({}),
        ] {
            assert!(stamp_options(&refused, b"cred", [7; 32]).is_err());
        }
    }

    #[test]
    fn assertion_fields_keep_only_the_public_signed_fields() {
        assert!(assertion_fields(json!({"id": 1})).is_err());
    }
}
