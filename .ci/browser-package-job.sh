#!/usr/bin/env bash
# Manual job: build the browser package with the existing milestone script and
# retain it as a deterministic tar. Nothing is uploaded and no secret is used.
set -euo pipefail
export CI="${CI:-true}"
export CI_COMMIT_SHA="${CI_COMMIT_SHA:-$(git rev-parse HEAD)}"
export CARGO_HOME="${CARGO_HOME:-/caches/cargo}"
printf 'worker: commit=%s cargo_home=%s target=%s\n' "$CI_COMMIT_SHA" "$CARGO_HOME" "${CARGO_TARGET_DIR:-unset}"
for tool in cargo rustc node wasm-bindgen esbuild; do
  command -v "$tool" >/dev/null || { printf 'worker is missing tool: %s\n' "$tool"; exit 3; }
done
base="$CARGO_HOME/ccid-artifacts/cmsg-browser"
mkdir -p "$base"
dir=$(mktemp -d "$base/$CI_COMMIT_SHA.XXXXXXXX")
export CMSG_BROWSER_OUT="$dir/build"
for mode in ports service assemble; do
  bash .ci/v01-browser-package.sh "$mode"
done
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -cf "$dir/cmsg-browser.tar" -C "$CMSG_BROWSER_OUT" public/cmsg receipt.json
digest=$(sha256sum "$dir/cmsg-browser.tar" | cut -d' ' -f1)
printf '%s  cmsg-browser.tar\n' "$digest" > "$dir/cmsg-browser.tar.sha256"
printf '%s\n' "$CI_COMMIT_SHA" > "$dir/commit"
chmod -R a-w "$dir"
printf 'BROWSER_PACKAGE sha256=%s commit=%s dir=%s\n' "$digest" "$CI_COMMIT_SHA" "$dir"
