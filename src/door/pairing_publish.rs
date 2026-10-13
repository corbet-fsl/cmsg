//! Lineage revision above 1: the existing device's passkey signs the exact receipt of its
//! approval (`Receipt::passkey_challenge`), producing the certified evidence that peers
//! verify. This is the same original evidence format as the genesis revision, built on an
//! ordinary member lease. Nothing here publishes or acknowledges: the caller retains the
//! prepared evidence (`Vault::retain_lineage_evidence`), publishes it to the member's own
//! lineage record slot, and only then acknowledges the receipt and approves the new key.
use super::*;
use cfyr::{membership::LiveMembership, policy::CurrentPolicy};
use foyer::Transport;

fn refused() -> ErrorCode {
    ErrorCode::Unauthorized
}

/// Build the certified lineage evidence for an approval receipt. One user-verifying
/// assertion is requested through `sign_in` (request options in, public credential
/// JSON out; the Door's trusted `passkey_assert` or a passkey client), for exactly the
/// receipt's challenge.
pub async fn prepare_pairing_evidence(
    membership: &mut LiveMembership<Transport>,
    policy: &mut CurrentPolicy<Transport>,
    sign_in: impl AsyncFnOnce(Value) -> Result<Value>,
    receipt: &ckmg::Receipt,
    clock: &mut impl ckmg::Clock,
) -> Result<cvlt::PreparedLineageEvidence> {
    // The receipt must be a device authorization whose attested lineage names its author.
    let (_, author) = receipt.attested_lineage().map_err(|_| refused())?;
    if !matches!(receipt.change, ckmg::Change::DeviceAuthorized(_)) {
        return Err(refused());
    }
    let challenge = receipt.passkey_challenge().map_err(|_| refused())?;
    let mut failed = false;
    let mut sample = || {
        clock.now().unwrap_or_else(|_| {
            failed = true;
            u64::MAX
        })
    };
    let lease = membership
        .observe_lease(&mut sample)
        .await
        .map_err(foyer::map_error)?;
    let mut certified = lease
        .passkey_certificate(policy, &mut sample)
        .await
        .map_err(foyer::map_error)?;
    let certificate = certified
        .certificate_bytes()
        .map_err(|_| refused())?
        .to_vec();
    let member = certified
        .observation()
        .map_err(|_| refused())?
        .member
        .clone();
    let now = sample();
    let options = certified
        .with_current(&mut sample, |current| {
            let certificate = current
                .passkey_certificate(&certificate, &member, now)
                .map_err(|_| refused())?;
            serde_json::to_value(certificate.request(challenge, now).map_err(|_| refused())?)
                .map_err(|_| refused())
        })
        .map_err(|_| refused())??;
    let public = sign_in(options).await.map_err(|_| refused())?;
    if serde_json::to_vec(&public).map_err(|_| refused())?.len() > cvlt::MAX_LINEAGE_EVIDENCE_BYTES
    {
        return Err(refused());
    }
    let public: ckyh::PublicKeyCredential =
        serde_json::from_value(public).map_err(|_| refused())?;
    let assertion = ckyh::lineage::Assertion {
        credential_id: public.raw_id.to_vec(),
        client_data_json: public.response.client_data_json.to_vec(),
        authenticator_data: public.response.authenticator_data.to_vec(),
        signature: public.response.signature.to_vec(),
        user_handle: public.response.user_handle.as_ref().map(|v| v.to_vec()),
    };
    let now = sample();
    let evidence = certified
        .with_current(&mut sample, |current| {
            if current.revocations().device_revoked(author.value()) {
                return Err(refused());
            }
            cvlt::LineageEvidence::prepare(current, receipt, &assertion, &certificate, &member, now)
                .map_err(|_| refused())
        })
        .map_err(|_| refused())??;
    if failed {
        return Err(ErrorCode::Clock);
    }
    Ok(evidence)
}
