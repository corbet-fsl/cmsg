//! Test-only binding to the maintained profiling runtime. Never a product dependency.
#![cfg(all(target_arch = "wasm32", owned_browser_coverage))]

use wasm_bindgen::prelude::wasm_bindgen;

/// Capture the actual instrumented counters after the upstream tests finish.
#[wasm_bindgen]
pub fn __owned_test_cov_dump() -> Vec<u8> {
    let mut bytes = Vec::new();
    // SAFETY: the test driver calls once, after completion, on the sole browser
    // thread. The harness enables neither Wasm threads nor shared memory.
    unsafe { minicov::capture_coverage(&mut bytes).expect("profiling capture failed") };
    bytes
}

/// Upstream load-module identity used by its existing profile-file handler.
#[wasm_bindgen]
pub fn __owned_test_module_signature() -> u64 {
    minicov::module_signature()
}
