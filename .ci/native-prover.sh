#!/usr/bin/env bash
# Opt-in native prover feature: build and test only, in the original verifier owner's
# authenticated native SDK shell (the same one cwlt uses). No other CI behavior.
set -euo pipefail
exec 2>&1
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
python3 -B .ci/import-native-prover-sdk.py
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo clippy --locked --lib --features native-prover -- -D warnings; cargo test --locked --lib --features native-prover accounting::'

# The account lifecycle against the real native operator: the assembled G5 configuration (retained cblc
# artifacts), the owned prover worker, and a dedicated fixture instance whose community runs that operator
# and loses its first account response.
cwlt_engine=$(python3 -B - <<'PY'
import json
packages = [p for p in json.load(open("dependency-metadata.json"))["packages"] if p["name"] == "cwlt-engine"]
assert len(packages) == 1, "expected exactly one cwlt-engine"
print(packages[0]["manifest_path"])
PY
)
worker_target="${CARGO_TARGET_DIR:-target}/cwlt-account-worker"
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; CARGO_TARGET_DIR="'"$worker_target"'" cargo build --locked --manifest-path "'"$cwlt_engine"'" --features native-prover --example cwlt-account-worker --message-format=json > native-prover-worker-build.json'
export CMSG_NATIVE_PROVER_WORKER="$(python3 -B - <<'PY'
import json
records = [json.loads(line) for line in open("native-prover-worker-build.json") if line.startswith("{")]
chosen = [r for r in records if r.get("reason") == "compiler-artifact" and r.get("target", {}).get("name") == "cwlt-account-worker"
          and r.get("target", {}).get("kind") == ["example"] and r.get("executable")]
assert len(chosen) == 1, "expected exactly one prover worker"
print(chosen[0]["executable"])
PY
)"
g5=$(mktemp -d)
nix-shell tests/fixture/owner/check-shell.nix --run "python3 -B tests/fixture/owner/g5-account-config.py --community omega --out '$g5' --exports" > "$g5.env"
# shellcheck disable=SC1090
source "$g5.env"
export CMSG_G5_ACCOUNT_CONFIG="$CVLD_G5_ACCOUNT_CONFIG" CMSG_G5_LOSE_FIRST_ACCOUNT_RESPONSE=1
fixture="${CARGO_TARGET_DIR:-tests/fixture/target}/debug/cmsg-foyer-fixture"
export RUST_MIN_STACK=67108864
# Build the test binary BEFORE the fixture starts (pending passkey ceremonies expire after 300 s).
nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo test --locked --features native-prover --test account_e2e --no-run'
python3 .ci/with-foyer-fixture.py "$fixture" nix-shell native-prover-owner/check-shell.nix --run 'set -euo pipefail; export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }${BB_NATIVE_RUSTFLAGS:?Missing original native loader configuration}"; cargo test --locked --features native-prover --test account_e2e -- --test-threads=1'
