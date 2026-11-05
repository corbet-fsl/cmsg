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
    WAVE_CIRCUIT_PATH, WAVE_KEYS_PATH, WAVE_MANIFEST_PATH,
};
use crate::door::inbox_waves::{production::VerifierFactory, wallet::WaveProver};
use ckmg::wallet_engine::account::{Evidence, UpdateInput};
use ckmg::wallet_engine::{
    browser_prover::{
        calibration::{self, Forecast},
        BrowserProver, BrowserProverConfig, Program, ProofWorker, SrsLocation,
    },
    Error,
};
use cwlt::wave::{ProofCheck, PublicField, WaveVerifier};
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
    /// The verdict of the pinned key over these public fields and proof: `true` or `false`.
    #[wasm_bindgen(catch, js_name = verifyInWorker)]
    async fn verify_in_worker(
        setup: &str,
        fields: &Uint8Array,
        proof: &Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
    /// Load the pinned setup into this origin's verified cache and the proof system, prove nothing.
    #[wasm_bindgen(catch, js_name = warmInWorker)]
    async fn warm_in_worker(setup: &str) -> std::result::Result<JsValue, JsValue>;
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

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The prover configuration of one member of these two group files at this setup size: the scope
/// is the digests of the files themselves (the engine checks them again against the group it opens).
fn config_of(
    circuit: Vec<u8>,
    verification_key: Vec<u8>,
    points: u32,
    program: Program,
) -> BrowserProverConfig {
    BrowserProverConfig {
        scope: czkp::ProofScope {
            circuit_digest: sha(&circuit),
            verifying_key_digest: sha(&verification_key),
        },
        program,
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
    Ok(config_of(
        circuit,
        verification_key,
        deployment.points,
        Program::Update,
    ))
}

/// The peer-release group (`wave` and `outcome`) a deployment ships, read once and authenticated
/// exactly like the update group: each file is the one whose digest vault.json pins, and the pinned
/// release manifest names exactly these circuit and key digests. It proves on the deployment's
/// pinned setup. The community's wave policy must pin this manifest and scope before any proof of
/// the counterpart is judged (the same rule as the native verifier).
pub struct WaveGroup {
    circuit: Vec<u8>,
    keys: Vec<u8>,
    points: u32,
}

impl WaveGroup {
    /// Fetch and authenticate the group of a deployment; refused when the deployment ships none.
    pub async fn load(deployment: &ProverDeployment) -> std::result::Result<Self, ComposeError> {
        let refused = |what: &str| ComposeError::Config(what.into());
        let pins = deployment
            .wave
            .as_ref()
            .ok_or_else(|| refused("the deployment ships no wave group"))?;
        let circuit = fetch_checked(WAVE_CIRCUIT_PATH, &pins.circuit_sha256, 64 << 20).await?;
        let keys = fetch_checked(WAVE_KEYS_PATH, &pins.keys_sha256, 1 << 20).await?;
        let manifest = fetch_checked(WAVE_MANIFEST_PATH, &pins.manifest_sha256, 65_536).await?;
        Self::of(circuit, keys, &manifest, deployment.points)
    }

    fn of(
        circuit: Vec<u8>,
        keys: Vec<u8>,
        manifest: &[u8],
        points: u32,
    ) -> std::result::Result<Self, ComposeError> {
        let refused = |what: &str| ComposeError::Config(what.into());
        // The released manifest spells its keys in camelCase (as the native verifier reads it).
        #[derive(serde::Deserialize)]
        struct Manifest {
            #[serde(alias = "circuitSha256")]
            circuit_sha256: String,
            #[serde(alias = "vkSha256")]
            vk_sha256: String,
        }
        let named: Manifest = serde_json::from_slice(manifest).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "refused wave manifest",
                refused("wave manifest"),
                &__cause,
            )
        })?;
        let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(&sha(bytes));
        if named.circuit_sha256 != hex(&circuit) || named.vk_sha256 != hex(&keys) {
            return Err(refused(
                "the wave files are not the group the manifest names",
            ));
        }
        let group = Self {
            circuit,
            keys,
            points,
        };
        // Refuse a group without both members (or with a foreign ABI) now, not at the first wave.
        for program in [Program::Wave, Program::Outcome] {
            group.prover(program)?;
        }
        Ok(group)
    }

    fn prover(&self, program: Program) -> std::result::Result<BrowserProver, ComposeError> {
        let config = config_of(
            self.circuit.clone(),
            self.keys.clone(),
            self.points,
            program,
        );
        BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "refused wave prover",
                ComposeError::Config("wave prover".into()),
                &__cause,
            )
        })
    }

    /// The counterpart verifier factory of the browser wave ports: both program checks run bb.js
    /// in a Web Worker of this origin under the `wave` and `outcome` keys of the key group whose
    /// digest vault.json pins (and the pinned manifest names); trust in those keys is exactly those
    /// pins. The community's verified wave policy is judged by `cwlt::wave::WaveVerifier` itself
    /// (context, lease, issuer certificate under the policy's key ring and account-group scope). It
    /// is not compared with this group: a published policy pins the account (extension) group, never
    /// the separate peer-release group (retained release 6bb79d4d: policy scope 17aa1372/7236d034 =
    /// its extension scope, wave group 97f20af5/bad05ec4), so such a comparison refuses every real
    /// policy.
    pub fn verifier_factory(
        &self,
    ) -> std::result::Result<VerifierFactory<WorkerCheck>, ComposeError> {
        let wave = WorkerCheck::of(&self.prover(Program::Wave)?);
        let outcome = WorkerCheck::of(&self.prover(Program::Outcome)?);
        Ok(Box::new(move |policy, now, authority_until| {
            WaveVerifier::new(policy, now, authority_until, wave.clone(), outcome.clone()).map_err(
                |error| match error {
                    czkp::Error::Expired => ErrorCode::Unavailable,
                    _ => ErrorCode::Refused,
                },
            )
        }))
    }

    /// The member's provers of the wave stack: the account update of the deployment's update
    /// group, and the `wave` and `outcome` members of this group.
    pub async fn provers(
        &self,
        deployment: &ProverDeployment,
    ) -> std::result::Result<BrowserWaveProver, ComposeError> {
        let update = BrowserProver::new(configure(deployment).await?, Arc::new(WorkerPort))
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "refused update prover",
                    ComposeError::Config("update prover".into()),
                    &__cause,
                )
            })?;
        Ok(BrowserWaveProver {
            update,
            wave: self.prover(Program::Wave)?,
            outcome: self.prover(Program::Outcome)?,
        })
    }
}

/// The three provers of the browser wave stack, each bound to its own member: the browser
/// counterpart of the native `NativeWaveProver`. A proof runs in a Web Worker of this origin that
/// is handed the member's own witness input once; only a proof whose public inputs this engine
/// derived comes back.
pub struct BrowserWaveProver {
    update: BrowserProver,
    wave: BrowserProver,
    outcome: BrowserProver,
}

/// A refused witness (wrong member, an input that does not fit the ABI) is `Refused`; a failed,
/// cancelled or busy worker is `Unavailable`: the job stays recorded and is offered again.
fn proof_error(error: &Error) -> ErrorCode {
    match error {
        Error::Invalid => ErrorCode::Refused,
        _ => ErrorCode::Unavailable,
    }
}

impl WaveProver for BrowserWaveProver {
    async fn prove_update(&mut self, input: &UpdateInput) -> Result<Vec<u8>> {
        self.update.prove_update(input).await.map_err(|__cause| {
            let code = proof_error(&__cause);
            crate::door::cause::emit(file!(), line!(), "browser update proof", code, &__cause)
        })
    }
    async fn prove_evidence(&mut self, evidence: &Evidence) -> Result<Vec<u8>> {
        let prover = if evidence.is_outcome() {
            &self.outcome
        } else {
            &self.wave
        };
        prover
            .prove_wave_evidence(evidence)
            .await
            .map_err(|__cause| {
                let code = proof_error(&__cause);
                crate::door::cause::emit(file!(), line!(), "browser wave proof", code, &__cause)
            })
    }
}

impl BrowserWaveProver {
    /// Speculative sender reservation, option (b) (decided 2026-11-05): when the member starts
    /// composing, warm only what the send will need on this device. The pinned setup is loaded
    /// (from this origin's verified cache, or fetched from this origin once) and expanded, and the
    /// proof system is started and ended again. Nothing is proven, nothing is reserved, and no
    /// request leaves this origin: no Hello, no counterpart, no issuer learns of the compose.
    /// `true` once the setup is warm; `false` when the device is busy or the warm-up failed (the
    /// send then loads the setup itself).
    pub async fn prewarm(&self) -> bool {
        warm(self.wave.setup_json()).await
    }

    /// The same warm-up as the handle the embedding runtime binds for the member origin
    /// (`Door::bind_wave_prewarm`), so `inbox.wave_prewarm` reaches it at compose.
    pub fn prewarm_handle(&self) -> std::rc::Rc<dyn crate::door::inbox_waves::WavePrewarm> {
        std::rc::Rc::new(SetupWarmUp(Arc::from(self.wave.setup_json())))
    }
}

async fn warm(setup: &str) -> bool {
    matches!(warm_in_worker(setup).await, Ok(value) if value.as_bool() == Some(true))
}

/// The pinned setup of the wave stack, warmed at compose (see [`BrowserWaveProver::prewarm`]).
struct SetupWarmUp(Arc<str>);

impl crate::door::inbox_waves::WavePrewarm for SetupWarmUp {
    fn prewarm(&self) -> Pin<Box<dyn Future<Output = ()>>> {
        let setup = Arc::clone(&self.0);
        Box::pin(async move {
            warm(&setup).await;
        })
    }
}

/// The browser half of the counterpart verifier: one program's proof check, run by bb.js in a
/// Web Worker of this origin under the verification key the engine took from the pinned key group
/// (its setup JSON carries that key and the pinned setup; nothing else). Every context, policy,
/// lease and issuer-certificate check stays in `cwlt::wave::WaveVerifier`, as natively.
#[derive(Clone)]
pub struct WorkerCheck {
    setup: Arc<str>,
    publics: usize,
}

impl WorkerCheck {
    fn of(prover: &BrowserProver) -> Self {
        Self {
            setup: Arc::from(prover.setup_json()),
            publics: prover.program().publics(),
        }
    }
}

/// The native prover never emits a longer proof (the native verifier's bound).
const MAX_PROOF_BYTES: usize = 1 << 20;

impl ProofCheck for WorkerCheck {
    async fn check(
        &self,
        fields: &[PublicField],
        proof: &[u8],
    ) -> std::result::Result<(), czkp::Error> {
        if fields.len() != self.publics
            || proof.is_empty()
            || proof.len() > MAX_PROOF_BYTES
            || !proof.len().is_multiple_of(32)
        {
            return Err(czkp::Error::InvalidInput);
        }
        let flat: Vec<u8> = fields.iter().flatten().copied().collect();
        match verify_in_worker(
            &self.setup,
            &Uint8Array::from(flat.as_slice()),
            &Uint8Array::from(proof),
        )
        .await
        {
            Ok(verdict) if verdict.as_bool() == Some(true) => Ok(()),
            _ => Err(czkp::Error::CryptoProvider),
        }
    }
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
