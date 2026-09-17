#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
python3 --version
case "$TOR_STAGE" in client|streams|service|test-network) ;; *) exit 2 ;; esac
export TOR_NETWORK="${TOR_NETWORK:-private}"
case "$TOR_NETWORK" in public|private) ;; *) exit 2 ;; esac
export TOR_DIAGNOSTICS="${TOR_DIAGNOSTICS:-0}"
case "$TOR_DIAGNOSTICS" in 0|1) ;; *) exit 2 ;; esac
artifact_suffix="$TOR_STAGE"
if test "$TOR_NETWORK" = public; then
  test "$TOR_STAGE" = service
  artifact_suffix=public
  python3 -c 'import ast,pathlib; ast.parse(pathlib.Path("browser/upstream/public-runtime-fixture.py").read_text())'
  node --check browser/upstream/runtime-contract.mjs
  node --check browser/upstream/runtime-driver.mjs
fi
if test "$TOR_DIAGNOSTICS" = 1; then artifact_suffix="$artifact_suffix-diagnostics"; fi
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/tor-$artifact_suffix"
mkdir -p "$artifact_dir"
timeout 30 python3 browser/upstream/runtime-process.test.py \
  2>&1 | tee "$artifact_dir/process-cleanup-tests.log"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
ln -s "$TORJS_SOURCE_ARCHIVE" "$scratch/tor-js.tar"
ln -s "$ARTI_SOURCE_ARCHIVE" "$scratch/arti.tar"
printf '%s\n' "$TORJS_SOURCE_SHA256" > "$scratch/tor-js.tar.sha256"
printf '%s\n' "$ARTI_SOURCE_SHA256" > "$scratch/arti.tar.sha256"
python3 browser/upstream/apply.py --from-archives \
  "$scratch/tor-js.tar" "$scratch/arti.tar" "$scratch/source" "$TOR_STAGE" \
  | tee "$artifact_dir/source-application.json"
if test -n "${OPENSSL_INCLUDE_DIR:-}"; then
  test -d "$OPENSSL_INCLUDE_DIR/openssl"
  test -d "$OPENSSL_LIB_DIR"
  export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
  export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
if test -n "${SQLITE3_LIB_DIR:-}"; then
  test -f "$SQLITE3_LIB_DIR/libsqlite3.so"
  test -f "$SQLITE3_INCLUDE_DIR/sqlite3.h"
  export SQLITE3_LIB_DIR SQLITE3_INCLUDE_DIR
  export LD_LIBRARY_PATH="$SQLITE3_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
torjs_manifest="$scratch/source/tor-js/Cargo.toml"
arti_manifest="$scratch/source/arti/Cargo.toml"
# Public validation retains the already validated dependency graph. The source
# stage changes, but dependency versions must not drift between network runs.
if test "$TOR_NETWORK" = public; then
  cp browser/upstream/locks/tor-js-Cargo.lock "$scratch/source/tor-js/Cargo.lock"
  cp browser/upstream/locks/arti-Cargo.lock "$scratch/source/arti/Cargo.lock"
else
  cargo update --manifest-path "$torjs_manifest" --workspace
fi
cp "$scratch/source/tor-js/Cargo.lock" "$artifact_dir/tor-js-Cargo.lock"
if test "$TOR_NETWORK" = public; then
  cp browser/upstream/locks/README.md "$artifact_dir/dependency-provenance.md"
else
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
result=0
tor_features=()
if test "$TOR_STAGE" = test-network; then tor_features=(--features browser-test-network); fi
timeout 1800 cargo check --locked --manifest-path "$torjs_manifest" \
  -p tor-js --target wasm32-unknown-unknown "${tor_features[@]}" || result=$?
if test "$TOR_STAGE" = service || test "$TOR_STAGE" = test-network; then
  if test "$TOR_NETWORK" != public; then
    cargo update --manifest-path "$arti_manifest" --workspace
  fi
  cp "$scratch/source/arti/Cargo.lock" "$artifact_dir/arti-Cargo.lock"
  timeout 1800 cargo test --locked --manifest-path "$arti_manifest" \
    -p tor-persist --features state-dir state_dir_wasm_tests -- --test-threads=2 || result=$?
fi
if test "${RUN_RUNTIME:-0}" = 1 && test "$result" = 0; then
  if test "$TOR_NETWORK" = public; then
    test "$TOR_STAGE" = service
  else
    test "$TOR_STAGE" = test-network
  fi
  test -x "$WASM_LINKER"
  test -x "$BROWSER_BIN"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="$WASM_LINKER"
  export BROWSER_BIN
  # Both helpers are project dependencies; neither is installed on the host.
  if ! test -f .ci/tor-bindgen/Cargo.lock; then
    cargo generate-lockfile --manifest-path .ci/tor-bindgen/Cargo.toml
  fi
  cp .ci/tor-bindgen/Cargo.lock "$artifact_dir/tor-bindgen-Cargo.lock"
  timeout 1200 cargo build --locked --manifest-path .ci/tor-bindgen/Cargo.toml
  timeout 1200 cargo build --locked --manifest-path .ci/browser-bindgen/Cargo.toml
  export TOR_BINDGEN_BINARY="$CARGO_TARGET_DIR/debug/cmsg-tor-test-bindgen"
  export CMSG_BINDGEN_BINARY="$CARGO_TARGET_DIR/debug/cmsg-browser-test-bindgen"
  bash .ci/tor-runtime-build.sh "$scratch/source/tor-js" "$artifact_dir/runtime"
  printf '%s  %s\n' "$TOR_TOOLS_RECEIPT_SHA256" "$TOR_TOOLS_RECEIPT" | sha256sum --check --strict
  cp "$TOR_TOOLS_RECEIPT" "$artifact_dir/runtime/tools.json"
  mapfile -t fixture_tools < <(python3 - "$TOR_TOOLS_RECEIPT" <<'PY'
import json,sys
with open(sys.argv[1]) as stream:
    tools=json.load(stream)
for key in ("torBin", "torGencert", "python", "chutney"):
    value=tools[key]
    if not isinstance(value,str) or not value.startswith('/') or '\n' in value:
        raise SystemExit('invalid fixture tool path')
    print(value)
PY
  )
  test "${#fixture_tools[@]}" = 4
  export TOR_BIN="${fixture_tools[0]}" TOR_GENCERT_BIN="${fixture_tools[1]}"
  export CHUTNEY_SOURCE="${fixture_tools[3]}"
  export TOR_GATEWAY_BIN="$CARGO_TARGET_DIR/debug/tor-js-gateway"
  export TOR_NATIVE_PEER_BIN="$CARGO_TARGET_DIR/debug/examples/tor_browser_peer"
  export TORJS_DIST="$scratch/source/tor-js/dist"
  export TOR_RUNTIME_ARTIFACT="$artifact_dir/runtime"
  fixture=browser/upstream/runtime-fixture.py
  fixture_seconds=3000
  if test "$TOR_NETWORK" = public; then
    fixture=browser/upstream/public-runtime-fixture.py
    fixture_seconds=3300
  fi
  # Each fixture also enforces its own phase bounds and owns all child cleanup.
  timeout --kill-after=40 "$fixture_seconds" "${fixture_tools[2]}" "$fixture" \
    2>&1 | tee "$artifact_dir/runtime/network.log" || result=$?
  (cd "$artifact_dir/runtime" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
fi
(cd "$artifact_dir" && sha256sum source-application.json *Cargo.lock > SHA256SUMS)
printf 'Patched upstream validation status: %s\n' "$result"
exit "$result"
