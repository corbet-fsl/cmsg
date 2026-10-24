//! All native cmsg integration tests in ONE test binary (one link of the dependency tree instead of eight).
//! Each former `tests/<name>.rs` is the module `<name>`; its feature and platform gate stays the inner
//! `#![cfg(..)]` of that file. Wasm-capable suites (browser_bridge, door, facades, foyer_browser), ohttp_keys and foyer
//! stay their own targets, see Cargo.toml (foyer leaves its router running past the test, which broke the
//! enrollment suites when both shared one process).

#[path = "account_acceptance.rs"]
mod account_acceptance;
#[path = "account_e2e.rs"]
mod account_e2e;
#[path = "initial_enrollment.rs"]
mod initial_enrollment;
#[path = "initial_tor.rs"]
mod initial_tor;
#[path = "native_scenario.rs"]
mod native_scenario;
#[path = "peer_lineage.rs"]
mod peer_lineage;
#[path = "wallet_enrollment.rs"]
mod wallet_enrollment;

/// A tests/*.rs file that is neither a module above nor a [[test]] in Cargo.toml would silently never run.
#[test]
fn every_test_file_is_wired() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let hub = std::fs::read_to_string(dir.join("tests/cmsg.rs")).expect("read the hub");
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read Cargo.toml");
    for entry in std::fs::read_dir(dir.join("tests")).expect("tests dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let stem = path
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            let wired = hub.contains(&format!("#[path = \"{stem}.rs\"]"))
                || manifest.contains(&format!("path = \"tests/{stem}.rs\""));
            assert!(
                wired,
                "tests/{stem}.rs is neither a module of tests/cmsg.rs nor a [[test]] target"
            );
        }
    }
}
