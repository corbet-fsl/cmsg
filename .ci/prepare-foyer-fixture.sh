#!/usr/bin/env bash
# Must use the same retained main snapshot as the production Foyer client.
set -euo pipefail
cargo metadata --locked --format-version 1 > runtime-metadata.json
cargo metadata --locked --manifest-path tests/fixture/Cargo.toml --format-version 1 > fixture-metadata.json
python3 .ci/copy-foyer-fixture.py
cargo build --locked --manifest-path tests/fixture/Cargo.toml
