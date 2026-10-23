#!/usr/bin/env bash
# Milestone packaging on a provisioned worker, never the fast check or a deploy.
set -euo pipefail
: "${CI:?CI worker required}" "${CI_COMMIT_SHA:?}"
: "${CMSG_BROWSER_OUT:?absolute artifact directory required}"
locked="${CMSG_PACKAGE_LOCKED---locked}"  # empty in the integration workspace, whose lock file is generated
mode="${1:-ports}"
case "$mode" in ports|service|assemble) ;; *) echo 'Expected ports, service or assemble' >&2; exit 64 ;; esac
[[ "$CMSG_BROWSER_OUT" == /* && ! -L "$CMSG_BROWSER_OUT" ]]
helper="$PWD/.ci/v01-browser-host.ts"
if [[ "$mode" == service ]]; then
  ctrn=$(node "$helper" service-source "$CMSG_BROWSER_OUT")
  bash "$ctrn/.ci/browser-build.sh" service-artifact \
    "$CMSG_BROWSER_OUT/selection.json" "$CMSG_BROWSER_OUT/service"
  exit 0
fi
if [[ "$mode" == assemble ]]; then
  # Reuse the exact ports artifact; no rebuild or dependency resolution.
  export CMSG_TORJS_DIST="${CMSG_TORJS_DIST:-$CMSG_BROWSER_OUT/service/dist}"
  export CMSG_TORJS_RECEIPT="${CMSG_TORJS_RECEIPT:-$CMSG_BROWSER_OUT/service/receipt.json}"
  node "$helper" assemble "$CMSG_BROWSER_OUT"
  exit 0
fi
: "${CARGO_TARGET_DIR:?existing worker target required}"
[[ ! -e "$CMSG_BROWSER_OUT" ]]
[[ "$CARGO_TARGET_DIR" == /* ]]
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
[[ "$CARGO_BUILD_JOBS" =~ ^([1-9]|1[0-6])$ ]]
for tool in cargo rustc node wasm-bindgen esbuild; do command -v "$tool" >/dev/null; done
# Dependencies of the original generator must already be provisioned. No tool
# downloads, npm updates, rustup, cache setup or fallback executables here.
test -f tools/node_modules/typescript/bin/tsc
test -d tools/node_modules/json-schema-to-typescript
test -d tools/node_modules/ajv
# The browser prover's worker (bb.js and noir_js, exact versions in prover/package-lock.json) is built
# from provisioned dependencies as well.
test -d prover/node_modules/@aztec/bb.js
test -d prover/node_modules/@noir-lang/noir_js
mkdir "$CMSG_BROWSER_OUT"
out="$CMSG_BROWSER_OUT"
trap 'printf "Packaging stopped; partial evidence retained at %s\n" "$CMSG_BROWSER_OUT" >&2' ERR
cp Cargo.lock "$out/Cargo.lock"
cp Cargo.toml "$out/Cargo.toml"
cp tools/package-lock.json "$out/tools-package-lock.json"
{
  rustc --version
  cargo --version
  node --version
  wasm-bindgen --version
} > "$out/tool-versions.txt"

# The parent resolves/retains v01's snapshot. Never reselect first-party sources
# from an archived candidate list or a child crate's standalone lockfile.
cargo metadata $locked --format-version 1 --features browser-tor,browser-prover \
  --filter-platform wasm32-unknown-unknown > "$out/metadata.json"
node "$helper" select "$out" "$PWD"
node "$helper" bindgen "$out" "$(wasm-bindgen --version)"

cargo build --release $locked --target wasm32-unknown-unknown --lib \
  --features cmsg/browser-tor,cmsg/browser-prover -p cmsg -p ctrn -p cfry \
  --message-format=json > "$out/wasm-build.jsonl"
for port in cmsg ctrn cfry; do
  wasm=$(node "$helper" artifact "$out" "$port")
  case "$port" in
    cmsg) destination="$out/generated/wasm" ;;
    *) destination="$out/public/cmsg/vendor/$port/browser/pkg" ;;
  esac
  wasm-bindgen --target web --remove-name-section --remove-producers-section \
    --out-dir "$destination" --out-name "$port" "$wasm"
  if command -v wasm-opt >/dev/null; then
    wasm-opt -Oz --all-features "$destination/${port}_bg.wasm" -o "$destination/${port}_bg.wasm"
  fi
done

# Original registry and generator, unchanged. The native schema exporter does
# not need Tor: its browser feature only gates the target-specific owner module.
cargo run $locked --example registry > "$out/registry.json"
node tools/generate.mjs "$out/registry.json" "$out/generated"
node tools/check.mjs "$out/registry.json"
node tools/node_modules/typescript/bin/tsc --outDir "$out/public/cmsg" \
  --strict --declaration --target es2022 --lib es2022,dom,esnext.disposable --module nodenext --moduleResolution nodenext \
  "$out/generated/client.ts" "$out/generated/browser.ts"
cmp Cargo.lock "$out/Cargo.lock"
cmp Cargo.toml "$out/Cargo.toml"
cmp tools/package-lock.json "$out/tools-package-lock.json"
node "$helper" package "$out"
printf 'Browser package (%s; no runtime qualification): %s\n' "$mode" "$out"
