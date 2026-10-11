#!/usr/bin/env bash
# Separate product dependency resolution, never a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cargo update --manifest-path tests/fixture/Cargo.toml
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
cp tests/fixture/Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-fixture-Cargo.lock"
sha256sum Cargo.lock tests/fixture/Cargo.lock
