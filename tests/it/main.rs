//! All native and wasm-capable cmsg integration tests in ONE test binary (one link of the dependency
//! tree instead of eleven). Each former `tests/<name>.rs` is the module `<name>`; its feature and
//! platform gate stays the inner `#![cfg(..)]` of that file (and its wasm_bindgen_test_configure!).
//! Kept as their own targets, see Cargo.toml: foyer (leaves its router running past the test, which
//! broke the enrollment suites when both shared one process), ohttp_keys (the ohttp feature changes
//! the types every other suite compiles against), pairing_onion_tor (runs alone inside the private
//! Tor fixture) and initial_tor (the private-network fixture executes that test binary directly as
//! its Tor probe, so it must contain only that journey).

mod account_acceptance;
mod account_e2e;
mod browser_bridge;
mod door;
mod facades;
mod foyer_browser;
mod initial_enrollment;
mod native_scenario;
mod peer_lineage;
mod wallet_enrollment;

/// A tests/*.rs file that is neither a [[test]] target nor a module of tests/it/main.rs would silently
/// never run. Both directions are checked: every remaining top-level test file must be a target, and
/// every file in tests/it must be wired as a module here. Native only: it reads the source tree.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn every_test_file_is_wired() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hub = std::fs::read_to_string(dir.join("tests/it/main.rs")).expect("read the hub");
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    for entry in std::fs::read_dir(dir.join("tests")).expect("tests dir") {
        let path = entry.expect("entry").path();
        if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let stem = path
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            assert!(
                manifest.contains(&format!("path = \"tests/{stem}.rs\"")),
                "tests/{stem}.rs is not a [[test]] target and did not move under tests/it"
            );
        }
    }
    for entry in std::fs::read_dir(dir.join("tests/it")).expect("tests/it dir") {
        let path = entry.expect("entry").path();
        if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let stem = path
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            if stem == "main" {
                continue;
            }
            assert!(
                hub.contains(&format!("mod {stem};")),
                "tests/it/{stem}.rs is not a module of tests/it/main.rs"
            );
        }
    }
}
