//! The browser prover's Web Worker port. The Rust engine (`ckmg::wallet_engine::browser_prover`)
//! decides everything that matters: which material is trusted, which public inputs a proof must
//! carry and which setup digests are pinned. This file only reaches the frame-host glue
//! (`prover.ts`), which starts one isolated worker per proof on the wallet origin.
use super::super::{
    account::{AccountProver, RefusingProver},
    composer_core::ComposeError,
    ErrorCode, Result,
};
use super::registration::{
    ProverDeployment, PROVER_CALIBRATION_PATH, PROVER_CIRCUIT_PATH, PROVER_KEYS_PATH,
};
use ckmg::wallet_engine::{
    browser_prover::{
        calibration::{self, Forecast},
        BrowserProver, BrowserProverConfig, Program, ProofWorker, SrsLocation,
    },
    Error,
};
use js_sys::Uint8Array;
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use wasm_bindgen::prelude::*;

/// The proof window the device predicts against: the server accepts a genesis request for at most
/// this many seconds after its proof time (`cblc::accounting::GENESIS_PROOF_WINDOW_SECONDS`, landing
/// with the class-B fix of lane flaky19, value 100 until the benchmark sets it). Keep both equal;
/// once that constant is on main this becomes a re-export and nothing else here changes.
pub const GENESIS_PROOF_WINDOW_SECONDS: u64 = 100;
/// Whole timeout of one proof, setup load and worker start included.
const PROOF_TIMEOUT: Duration = Duration::from_secs(240);
/// Most threads a worker may start; it starts more than one only on a cross-origin isolated page.
const MAX_THREADS: u8 = 8;

#[wasm_bindgen(module = "/src/door/browser/prover.ts")]
extern "C" {
    #[wasm_bindgen(js_name = cancelProof)]
    fn cancel_proof();
    /// A real proof: `{ reply, millis }` (milliseconds from the setup being in the worker to its reply).
    #[wasm_bindgen(catch, js_name = provedMillis)]
    async fn proved_millis(
        setup: &str,
        input: &Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = fetchMaterial)]
    async fn fetch_material(path: &str, max_bytes: u32) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = storedMillis)]
    async fn stored_millis(circuit_id: &str) -> JsValue;
    #[wasm_bindgen(js_name = storeMillis)]
    async fn store_millis(circuit_id: &str, millis: f64);
    #[wasm_bindgen(js_name = announce)]
    fn announce(stage: &str, detail: &str);
    #[wasm_bindgen(js_name = takeSlowPermission)]
    fn take_slow_permission() -> bool;
    #[wasm_bindgen(catch, js_name = calibrateInWorker)]
    async fn calibrate_in_worker(
        setup: &str,
        circuit_id: &str,
        input: &Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
}

/// The port every browser prover answers behind: a unit value, because the one worker of a
/// proof is started and ended by the glue, never retained here.
#[derive(Clone, Copy, Default)]
pub struct WorkerPort;

/// The circuit id the engine put into the public setup (`None` for a setup without one).
fn circuit_id(setup: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Named {
        circuit_id: String,
    }
    serde_json::from_str::<Named>(setup)
        .ok()
        .map(|named| named.circuit_id)
}

fn whole_millis(value: &JsValue) -> Option<u64> {
    value
        .as_f64()
        .filter(|millis| millis.is_finite() && *millis >= 1.0 && millis.fract() == 0.0)
        .map(|millis| millis as u64)
}

/// The prediction for the stored measurement of this circuit version, announced to the frame.
async fn forecast_for(id: &str) -> Option<Forecast> {
    let millis = whole_millis(&stored_millis(id).await)?;
    let forecast = match calibration::forecast(millis, GENESIS_PROOF_WINDOW_SECONDS) {
        Ok(forecast) => forecast,
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "calibration::forecast", &__cause);
            return None;
        }
    };
    let announced = match serde_json::to_string(&forecast) {
        Ok(announced) => announced,
        Err(__cause) => {
            crate::door::cause::print(file!(), line!(), "serde_json::to_string", &__cause);
            return None;
        }
    };
    announce("forecast", &announced);
    Some(forecast)
}

/// A real proof that took longer than the window: tell the frame, with the device class, and
/// correct the stored measurement upward so the next forecast knows.
async fn window_elapsed(id: &str, forecast: Option<Forecast>, elapsed_millis: u64) {
    let class = match forecast {
        Some(forecast) => Some(forecast.class),
        None => calibration::classify(elapsed_millis, GENESIS_PROOF_WINDOW_SECONDS).ok(),
    };
    let detail = serde_json::json!({
        "class": class.map(|class| class.key()),
        "elapsed_millis": elapsed_millis,
        "window_seconds": GENESIS_PROOF_WINDOW_SECONDS,
    });
    announce("window-elapsed", &detail.to_string());
    let stored = whole_millis(&stored_millis(id).await).unwrap_or(0);
    store_millis(id, calibration::corrected(stored, elapsed_millis) as f64).await;
}

impl ProofWorker for WorkerPort {
    fn prove<'a>(
        &'a self,
        setup: &'a str,
        input: &'a str,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<String, Error>> + 'a>> {
        Box::pin(async move {
            // The forecast comes first: a proof predicted not to fit the window is not started,
            // unless the member chose to try (a one-shot permission from the frame's own UI).
            let id = circuit_id(setup);
            let forecast = match &id {
                Some(id) => forecast_for(id).await,
                None => None,
            };
            if forecast.is_some_and(|forecast| !forecast.fits) && !take_slow_permission() {
                return Err(Error::Crypto);
            }
            // A fresh copy for the transfer; the glue detaches it, the caller zeroizes `input`.
            let bytes = Uint8Array::from(input.as_bytes());
            let proved = proved_millis(setup, &bytes).await.map_err(|__cause| {
                crate::door::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
            })?;
            let reply = js_sys::Reflect::get(&proved, &JsValue::from_str("reply"))
                .ok()
                .and_then(|reply| reply.as_string())
                .ok_or(Error::Crypto)?;
            let elapsed = js_sys::Reflect::get(&proved, &JsValue::from_str("millis"))
                .ok()
                .and_then(|millis| whole_millis(&millis))
                .ok_or(Error::Crypto)?;
            if let Some(id) = &id {
                if elapsed > GENESIS_PROOF_WINDOW_SECONDS * 1_000 {
                    window_elapsed(id, forecast, elapsed).await;
                }
            }
            Ok(reply)
        })
    }

    fn cancel(&self) {
        cancel_proof();
    }
}

async fn fetch_checked(
    path: &str,
    sha256: &str,
    maximum: u32,
) -> std::result::Result<Vec<u8>, ComposeError> {
    let refused = |what: &str| ComposeError::Config(what.into());
    let bytes = fetch_material(path, maximum).await.map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "refused prover material",
            refused("prover material"),
            &__cause,
        )
    })?;
    let bytes = Uint8Array::new(&bytes).to_vec();
    if data_encoding::HEXLOWER.encode(&Sha256::digest(&bytes)) != sha256 {
        return Err(refused("prover material digest"));
    }
    Ok(bytes)
}

/// The prover configuration for these two files and this setup size: the scope is the digests of
/// the files themselves (the engine checks them again against the circuit group it opens).
fn config_of(circuit: Vec<u8>, verification_key: Vec<u8>, points: u32) -> BrowserProverConfig {
    let sha = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
    BrowserProverConfig {
        scope: czkp::ProofScope {
            circuit_digest: sha(&circuit),
            verifying_key_digest: sha(&verification_key),
        },
        program: Program::Update,
        circuit,
        verification_key,
        srs: SrsLocation {
            g1_path: format!("/prover/srs/g1-{points}.dat"),
            g2_path: "/prover/srs/g2.dat".into(),
            points,
        },
        timeout: PROOF_TIMEOUT,
        max_threads: MAX_THREADS,
    }
}

/// The prover configuration of a deployment: the circuit and key groups the wallet origin
/// serves, each checked against the digest the deployment pins (the engine checks them again
/// against the scope it derives), and the setup paths of the pinned size.
pub async fn configure(
    deployment: &ProverDeployment,
) -> std::result::Result<BrowserProverConfig, ComposeError> {
    let circuit = fetch_checked(PROVER_CIRCUIT_PATH, &deployment.circuit_sha256, 64 << 20).await?;
    let verification_key =
        fetch_checked(PROVER_KEYS_PATH, &deployment.keys_sha256, 1 << 20).await?;
    Ok(config_of(circuit, verification_key, deployment.points))
}

/// The prover a browser build lends the account actor once the wallet origin has authenticated
/// its circuit, key and setup (the engine checks them): the `BrowserProver`. Without this call
/// a browser build lends [`RefusingProver`], which refuses every proof before any vault step.
pub fn lend(config: BrowserProverConfig) -> Result<Arc<dyn AccountProver>> {
    let prover = BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    Ok(Arc::new(prover))
}

/// What the wallet frame's composer lends when the deployment ships a browser prover.
pub async fn lend_deployed(
    deployment: &ProverDeployment,
) -> std::result::Result<Arc<dyn AccountProver>, ComposeError> {
    lend(configure(deployment).await?).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ComposeError::Config browser prover into",
            ComposeError::Config("browser prover".into()),
            &__cause,
        )
    })
}

/// Calibrate this device (decided 2026-10-23): when the page is idle, prove the shipped dummy input
/// once per circuit version, keep the time in this origin only, and return the forecast it gives.
/// `None` when a real proof or a failure took the device first; the next idle time tries again.
pub async fn calibrate(
    deployment: &ProverDeployment,
) -> std::result::Result<Option<Forecast>, ComposeError> {
    let refused = |what: &str| ComposeError::Config(what.into());
    let config = configure(deployment).await?;
    let input = fetch_checked(
        PROVER_CALIBRATION_PATH,
        &deployment.calibration_sha256,
        8 << 20,
    )
    .await?;
    let prover = BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "refused browser prover",
            refused("browser prover"),
            &__cause,
        )
    })?;
    let measured = calibrate_in_worker(
        prover.setup_json(),
        prover.circuit_id(),
        &Uint8Array::from(&input[..]),
    )
    .await
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "refused calibration",
            refused("calibration"),
            &__cause,
        )
    })?;
    let Some(millis) = whole_millis(&measured) else {
        return Ok(None);
    };
    let forecast =
        calibration::forecast(millis, GENESIS_PROOF_WINDOW_SECONDS).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "refused calibration",
                refused("calibration"),
                &__cause,
            )
        })?;
    announce(
        "calibrated",
        &serde_json::to_string(&forecast).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "refused calibration",
                refused("calibration"),
                &__cause,
            )
        })?,
    );
    Ok(Some(forecast))
}

/// What a browser build lends when no prover is configured.
pub fn refusing() -> Arc<dyn AccountProver> {
    Arc::new(RefusingProver)
}

/// Test-only exports for the browser tests of this prover path (never part of a product build).
#[cfg(feature = "browser-prover-probe")]
mod probe;
