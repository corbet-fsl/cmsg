//! Probe of the browser prover path for the wasm32 browser tests (feature `browser-prover-probe`,
//! never part of a product build). A test page calls these exports to run the REAL Rust path in a
//! real browser: the deployed material is fetched and checked against its pinned digests, the
//! engine derives the public inputs from the public statement itself, the Web Worker proves, and
//! the engine accepts only a reply that carries exactly those public inputs. The page then hands
//! the result to the native verifier. The probe holds no key and reads no vault.
use super::{calibrate, configure, WorkerPort};
use crate::door::browser::registration::ProverDeployment;
use ckmg::wallet_engine::browser_prover::BrowserProver;
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn deployment_of(json: &str) -> Result<ProverDeployment, JsValue> {
    serde_json::from_str(json).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str deployment",
            JsValue::from_str("deployment"),
            &__cause,
        )
    })
}

/// Prove `input` (the private witness JSON) for the statement `public_json` (its public
/// fields) on the prover a deployment lends. Resolves to `{ setup, reply }` where `reply` is
/// `{ verified, public_inputs, proof }` as the engine accepted it; rejects with a fixed word
/// when the engine refuses (for example a forecast that the window will not hold).
#[wasm_bindgen]
pub async fn probe_prove(
    deployment: &str,
    public_json: &str,
    input: &str,
) -> Result<String, JsValue> {
    let deployment = deployment_of(deployment)?;
    let config = configure(&deployment).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str configure",
            JsValue::from_str("configure"),
            &__cause,
        )
    })?;
    let prover = BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str prover",
            JsValue::from_str("prover"),
            &__cause,
        )
    })?;
    let (public_inputs, proof) = prover
        .probe_prove(public_json, Zeroizing::new(input.to_owned()))
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "JsValue::from_str refused",
                JsValue::from_str("refused"),
                &__cause,
            )
        })?;
    let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);
    let reply = serde_json::json!({
        "verified": true,
        "public_inputs": public_inputs.iter().map(|field| hex(field)).collect::<Vec<_>>(),
        "proof": hex(&proof),
    });
    Ok(serde_json::json!({ "setup": prover.setup_json(), "reply": reply }).to_string())
}

/// The public setup a deployment's prover hands its worker (circuit version id included); no proof.
#[wasm_bindgen]
pub async fn probe_setup(deployment: &str) -> Result<String, JsValue> {
    let deployment = deployment_of(deployment)?;
    let config = configure(&deployment).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str configure",
            JsValue::from_str("configure"),
            &__cause,
        )
    })?;
    let prover = BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str prover",
            JsValue::from_str("prover"),
            &__cause,
        )
    })?;
    Ok(prover.setup_json().to_owned())
}

/// The calibration a wallet frame runs when idle, on the same code (`prover::calibrate`):
/// resolves to the forecast JSON, or `null` when a real proof or a failure took the device first.
#[wasm_bindgen]
pub async fn probe_calibrate(deployment: &str) -> Result<String, JsValue> {
    let deployment = deployment_of(deployment)?;
    let forecast = calibrate(&deployment).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str calibration",
            JsValue::from_str("calibration"),
            &__cause,
        )
    })?;
    serde_json::to_string(&forecast).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "JsValue::from_str calibration",
            JsValue::from_str("calibration"),
            &__cause,
        )
    })
}

/// The peer-release member a probe call names: `wave` or `outcome`, nothing else.
fn wave_program(program: &str) -> Result<ckmg::wallet_engine::browser_prover::Program, JsValue> {
    use ckmg::wallet_engine::browser_prover::Program;
    match program {
        "wave" => Ok(Program::Wave),
        "outcome" => Ok(Program::Outcome),
        _ => Err(JsValue::from_str("program")),
    }
}

async fn wave_group(deployment: &str) -> Result<super::WaveGroup, JsValue> {
    super::WaveGroup::load(&deployment_of(deployment)?)
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "JsValue::from_str configure",
                JsValue::from_str("configure"),
                &__cause,
            )
        })
}

fn hex_of(text: &str) -> Result<Vec<u8>, JsValue> {
    data_encoding::HEXLOWER
        .decode(text.as_bytes())
        .map_err(|_| JsValue::from_str("hex"))
}

/// Prove a peer-release member (`wave` or `outcome`) of the deployment's pinned wave group in the
/// worker: the same configuration the wave stack lends (`WaveGroup::provers`); the engine derives the
/// public fields from `input` itself and accepts only a reply that carries exactly those. Resolves to
/// `{ setup, reply }` as `probe_prove` does.
#[wasm_bindgen]
pub async fn probe_wave_prove(
    deployment: &str,
    program: &str,
    input: &str,
) -> Result<String, JsValue> {
    let program = wave_program(program)?;
    let prover = wave_group(deployment)
        .await?
        .prover(program)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "JsValue::from_str prover",
                JsValue::from_str("prover"),
                &__cause,
            )
        })?;
    // The public statement is the input's public parameters: the engine reads only those.
    let (public_inputs, proof) = prover
        .probe_prove(input, Zeroizing::new(input.to_owned()))
        .await
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "JsValue::from_str refused",
                JsValue::from_str("refused"),
                &__cause,
            )
        })?;
    let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);
    let reply = serde_json::json!({
        "verified": true,
        "public_inputs": public_inputs.iter().map(|field| hex(field)).collect::<Vec<_>>(),
        "proof": hex(&proof),
    });
    Ok(serde_json::json!({ "setup": prover.setup_json(), "reply": reply }).to_string())
}

/// The counterpart's proof check of one member alone (`WorkerCheck`, bb.js in the worker under the
/// pinned key): `fields` is a JSON array of 32-byte hex fields, `proof` hex. Resolves to the verdict.
#[wasm_bindgen]
pub async fn probe_wave_check(
    deployment: &str,
    program: &str,
    fields: &str,
    proof: &str,
) -> Result<bool, JsValue> {
    use cwlt::wave::ProofCheck;
    let program = wave_program(program)?;
    let prover = wave_group(deployment)
        .await?
        .prover(program)
        .map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "JsValue::from_str prover",
                JsValue::from_str("prover"),
                &__cause,
            )
        })?;
    let fields: Vec<String> =
        serde_json::from_str(fields).map_err(|_| JsValue::from_str("fields"))?;
    let fields = fields
        .iter()
        .map(|field| {
            hex_of(field).and_then(|bytes| {
                <[u8; 32]>::try_from(bytes).map_err(|_| JsValue::from_str("fields"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(super::WorkerCheck::of(&prover)
        .check(&fields, &hex_of(proof)?)
        .await
        .is_ok())
}

/// The whole counterpart verifier of the browser wave ports (`WaveGroup::verifier_factory`, then
/// `cwlt::wave::WaveVerifier` over the worker checks) on one statement of the retained release:
/// `kind` `wave` verifies a reservation, `outcome` a settled outcome (`expected_outcome`,
/// `receipt_digest` hex). Resolves to `accepted`, or rejects with the refusal (`Unavailable` when the wave group is not loaded,
/// `Refused` for a proof or context the verifier does not accept; the policy is judged by `WaveVerifier` and never compared with the group the deployment pins).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn probe_wave_verify(
    deployment: &str,
    policy: &str,
    now: u64,
    authority_until: u64,
    kind: &str,
    statement: &str,
    proof: &str,
    expected: &str,
    expected_outcome: &str,
    receipt_digest: &str,
) -> Result<String, JsValue> {
    use crate::door::inbox_waves::{verify_outcome_with, verify_reservation_with};
    let refused = |code: crate::door::ErrorCode| JsValue::from_str(&format!("{code:?}"));
    let factory = wave_group(deployment)
        .await?
        .verifier_factory()
        .map_err(|_| JsValue::from_str("configure"))?;
    let policy = serde_json::from_str(policy).map_err(|_| JsValue::from_str("policy"))?;
    let verifier = factory(policy, now, authority_until).map_err(refused)?;
    let proof = hex_of(proof)?;
    let expected: cwlt::wave::WaveContext =
        serde_json::from_str(expected).map_err(|_| JsValue::from_str("expected"))?;
    match kind {
        "wave" => {
            let statement =
                serde_json::from_str(statement).map_err(|_| JsValue::from_str("statement"))?;
            verify_reservation_with(&verifier, &statement, &proof, &expected, now)
                .await
                .map_err(refused)?;
        }
        "outcome" => {
            let statement =
                serde_json::from_str(statement).map_err(|_| JsValue::from_str("statement"))?;
            let outcome = serde_json::from_value(serde_json::Value::from(expected_outcome))
                .map_err(|_| JsValue::from_str("outcome"))?;
            let digest: [u8; 32] = hex_of(receipt_digest)?
                .try_into()
                .map_err(|_| JsValue::from_str("receipt digest"))?;
            verify_outcome_with(
                &verifier, &statement, &proof, &expected, outcome, &digest, now,
            )
            .await
            .map_err(refused)?;
        }
        _ => return Err(JsValue::from_str("kind")),
    }
    Ok("accepted".into())
}

/// The compose-time warm-up of the browser wave stack (`BrowserWaveProver::prewarm`) on the
/// deployment's pinned material. Resolves to whether the setup is warm.
#[wasm_bindgen]
pub async fn probe_wave_prewarm(deployment: &str) -> Result<bool, JsValue> {
    let parsed = deployment_of(deployment)?;
    let provers = wave_group(deployment)
        .await?
        .provers(&parsed)
        .await
        .map_err(|_| JsValue::from_str("configure"))?;
    Ok(provers.prewarm().await)
}
