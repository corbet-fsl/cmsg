//! The browser prover's Web Worker port. The Rust engine (`ckmg::wallet_engine::browser_prover`)
//! decides everything that matters: which material is trusted, which public inputs a proof must
//! carry and which setup digests are pinned. This file only reaches the frame-host glue
//! (`prover.ts`), which starts one isolated worker per proof on the wallet origin.
use super::super::{
    account::{AccountProver, RefusingProver},
    ErrorCode, Result,
};
use ckmg::wallet_engine::{
    browser_prover::{BrowserProver, BrowserProverConfig, ProofWorker},
    Error,
};
use js_sys::Uint8Array;
use std::{future::Future, pin::Pin, sync::Arc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/src/door/browser/prover.ts")]
extern "C" {
    #[wasm_bindgen(catch, js_name = proveInWorker)]
    async fn prove_in_worker(
        setup: &str,
        input: &Uint8Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = cancelProof)]
    fn cancel_proof();
}

/// The port every browser prover answers behind: a unit value, because the one worker of a
/// proof is started and ended by the glue, never retained here.
#[derive(Clone, Copy, Default)]
pub struct WorkerPort;

impl ProofWorker for WorkerPort {
    fn prove<'a>(
        &'a self,
        setup: &'a str,
        input: &'a str,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<String, Error>> + 'a>> {
        Box::pin(async move {
            // A fresh copy for the transfer; the glue detaches it, the caller zeroizes `input`.
            let bytes = Uint8Array::from(input.as_bytes());
            let reply = prove_in_worker(setup, &bytes)
                .await
                .map_err(|_| Error::Crypto)?;
            reply.as_string().ok_or(Error::Crypto)
        })
    }

    fn cancel(&self) {
        cancel_proof();
    }
}

/// The prover a browser build lends the account actor once the wallet origin has authenticated
/// its circuit, key and setup (the engine checks them): the `BrowserProver`. Without this call
/// a browser build lends [`RefusingProver`], which refuses every proof before any vault step.
pub fn lend(config: BrowserProverConfig) -> Result<Arc<dyn AccountProver>> {
    let prover =
        BrowserProver::new(config, Arc::new(WorkerPort)).map_err(|_| ErrorCode::Unavailable)?;
    Ok(Arc::new(prover))
}

/// What a browser build lends when no prover is configured.
pub fn refusing() -> Arc<dyn AccountProver> {
    Arc::new(RefusingProver)
}
