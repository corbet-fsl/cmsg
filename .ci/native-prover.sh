#!/usr/bin/env bash
# Opt-in native prover feature: build and test only, in the original verifier owner's
# authenticated native SDK shell (the same one cwlt uses). No other CI behavior.
set -euo pipefail
exec 2>&1
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
python3 -B .ci/import-native-prover-sdk.py
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo clippy --locked --lib --features native-prover -- -D warnings; cargo test --locked --lib --features native-prover accounting::'
