//! Device-local Member door: one registry and bounded dispatcher.
//! Domain authority belongs to dedicated owners, never to frontend projections.
pub mod door;

// Reuse the original owner fixture modules in private native unit tests.
#[cfg(all(test, not(target_arch = "wasm32")))]
extern crate self as cmsg;
