#!/usr/bin/env bash
# Worker-only native qualification. Browser/coverage gates remain independent.
set -euo pipefail
mkdir -p evidence/native
rustc --version --verbose > evidence/native/rustc.txt
retain_locks() {
    if [[ -f Cargo.lock ]]; then cp Cargo.lock evidence/native/Cargo.lock; fi
    if [[ -f tests/fixture/Cargo.lock ]]; then
        cp tests/fixture/Cargo.lock evidence/native/fixture-Cargo.lock
    fi
}
trap retain_locks EXIT
python3 .ci/check-first-party.py
# Resolve once, retain even on a later failure, and reuse for every following check.
cargo update
cargo update --manifest-path tests/fixture/Cargo.toml
date -u +%FT%TZ > evidence/native/resolved-at.txt
cp Cargo.lock evidence/native/Cargo.lock
cp tests/fixture/Cargo.lock evidence/native/fixture-Cargo.lock
sha256sum Cargo.lock tests/fixture/Cargo.lock > evidence/native/locks.sha256
python3 .ci/check-first-party.py
bash .ci/prepare-foyer-fixture.sh
cp fixture-owner.json evidence/native/fixture-owner.json
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
fixture="${CARGO_TARGET_DIR:-tests/fixture/target}/debug/cmsg-foyer-fixture"
python3 .ci/with-foyer-fixture.py "$fixture" cargo test --locked --all-targets
