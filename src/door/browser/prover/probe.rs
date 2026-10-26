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
