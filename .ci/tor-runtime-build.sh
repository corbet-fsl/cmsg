#!/usr/bin/env bash
# Run only in the isolated CI source tree after apply.py's test-network stage.
set -euo pipefail
test "$#" = 2
torjs="$(realpath "$1")"
artifact="$(realpath -m "$2")"
: "${TOR_BINDGEN_BINARY:?matching wasm-bindgen 0.2.122 helper required}"
: "${CMSG_BINDGEN_BINARY:?matching cmsg wasm-bindgen helper required}"
: "${CARGO_TARGET_DIR:?explicit CI target cache required}"
test -x "$TOR_BINDGEN_BINARY"
test -x "$CMSG_BINDGEN_BINARY"
mkdir -p "$artifact"
timeout 1800 cargo build --locked --manifest-path "$torjs/Cargo.toml" \
  -p tor-js --features browser-test-network --target wasm32-unknown-unknown
"$TOR_BINDGEN_BINARY" "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/tor_js.wasm" \
  "$torjs/crates/tor-js-wasm/pkg" tor_js
timeout 1800 cargo build --locked --manifest-path "$torjs/Cargo.toml" -p tor-js-gateway
timeout 1800 cargo test --locked --manifest-path "$torjs/Cargo.toml" \
  -p tor-js-gateway tunnel::tests:: -- --nocapture \
  2>&1 | tee "$artifact/gateway-tunnel-tests.log"
timeout 1800 cargo build --locked --target wasm32-unknown-unknown --lib
"$CMSG_BINDGEN_BINARY" "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/cmsg.wasm" browser/pkg cmsg
timeout 1800 cargo build --locked --example tor_browser_peer
(
  cd "$torjs"
  timeout 600 npm ci --ignore-scripts --no-audit --no-fund
  timeout 120 node --test test/unit/kpsGateway.test.mjs \
    2>&1 | tee "$artifact/gateway-browser-parser-tests.log"
  # The exact upstream build includes a README gzip-size comparison against the
  # stock artifact. Preserve every code/declaration build check; omit only that
  # historical size assertion for this explicitly labelled experimental package.
  python3 - "$CI_COMMIT_SHA" <<'PY'
import json, pathlib, sys
source = pathlib.Path('build.mjs').read_text()
needle = '    verifyGzipSizes,\n'
if source.count(needle) != 1:
    raise SystemExit('upstream build layout changed')
pathlib.Path('build.cmsg-experiment.mjs').write_text(source.replace(needle,
    '    // Experimental package: stock README size assertion is inapplicable.\n'))
package = pathlib.Path('package.json')
data = json.loads(package.read_text())
data['version'] = '0.4.1-cmsg-fixture.' + sys.argv[1][:12]
package.write_text(json.dumps(data, indent=2) + '\n')
PY
  npm_config_offline=true timeout 900 node build.cmsg-experiment.mjs
  npm pack --ignore-scripts --pack-destination "$artifact" --json > "$artifact/tor-package.json"
)
cp "$torjs/Cargo.lock" "$artifact/tor-js-runtime-Cargo.lock"
cp "$torjs/package-lock.json" "$artifact/tor-js-package-lock.json"
cp "$torjs/build.cmsg-experiment.mjs" "$artifact/build.cmsg-experiment.mjs"
cp "$torjs/package.json" "$artifact/tor-js-package.json"
sha256sum "$torjs/dist/tor_js_bg.wasm" browser/pkg/cmsg_bg.wasm \
  "$CARGO_TARGET_DIR/debug/tor-js-gateway" "$CARGO_TARGET_DIR/debug/examples/tor_browser_peer" \
  > "$artifact/runtime-input-SHA256SUMS"
printf 'Runtime package built; network contract still required.\n'
