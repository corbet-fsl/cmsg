//! Device-local Member door: one registry and bounded dispatcher.
//! Domain authority belongs to dedicated owners, never to frontend projections.
// The wasm-bindgen glue macros expand to FFI declarations, so wasm builds can
// only deny (not forbid) unsafe code; no authored code uses it.
#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![cfg_attr(target_arch = "wasm32", deny(unsafe_code))]
pub mod door;

// Reuse the original owner fixture modules in private native unit tests.
#[cfg(all(test, not(target_arch = "wasm32")))]
extern crate self as cmsg;
