#!/usr/bin/env bash
# Separate product dependency resolution, never a validation verdict.
set -euo pipefail
exec 2>&1
# Original direct declared-check execution has no cached-check artifact variable.
# Retain this product's actual outputs on its already-declared worker mount.
if [[ -n "${ARTIFACT_ROOT:-}" ]]; then
    resolution_artifacts="$ARTIFACT_ROOT"
else
    : "${CARGO_TARGET_DIR:?Missing declared persistent product target}"
    resolution_artifacts=$(mktemp -d "$(dirname "$CARGO_TARGET_DIR")/resolution.XXXXXXXX")
fi
mkdir -p "$resolution_artifacts"
cargo update
cargo update --manifest-path tests/fixture/Cargo.toml
cp Cargo.lock "$resolution_artifacts/resolve-dependencies-Cargo.lock"
cp tests/fixture/Cargo.lock "$resolution_artifacts/resolve-dependencies-fixture-Cargo.lock"
sha256sum "$resolution_artifacts/resolve-dependencies-Cargo.lock" "$resolution_artifacts/resolve-dependencies-fixture-Cargo.lock"
