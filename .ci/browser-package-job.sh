#!/usr/bin/env bash
# Manual job: build the browser package with the existing milestone script and
# retain it as a deterministic tar. Nothing is uploaded and no secret is used.
set -euo pipefail
export CARGO_BUILD_JOBS=2
export CI="${CI:-true}"
export CI_COMMIT_SHA="${CI_COMMIT_SHA:-$(git rev-parse HEAD)}"
export CARGO_HOME="${CARGO_HOME:-/caches/cargo}"
printf 'worker: commit=%s cargo_home=%s target=%s\n' "$CI_COMMIT_SHA" "$CARGO_HOME" "${CARGO_TARGET_DIR:-unset}"
# Provisioned tools live in the shared worker cache: the wasm-bindgen CLI whose
# version equals Cargo.lock's library, and a pinned esbuild.
want=$(awk '/^name = "wasm-bindgen"$/{getline; gsub(/[^0-9.]/,""); print; exit}' Cargo.lock)
for candidate in "$CARGO_HOME"/wasm-pack/wasm-bindgen-*/wasm-bindgen; do
  if [[ -x "$candidate" && "$("$candidate" --version)" == "wasm-bindgen $want" ]]; then
    PATH="$(dirname "$candidate"):$PATH"; break
  fi
done
for candidate in "$CARGO_HOME"/../bun/esbuild@*/bin/esbuild; do
  if [[ -x "$candidate" ]]; then PATH="$(dirname "$candidate"):$PATH"; break; fi
done
export PATH
printf 'tools: wasm-bindgen want=%s have=%s esbuild=%s\n' "$want" "$(command -v wasm-bindgen || echo none)" "$(command -v esbuild || echo none)"
for tool in cargo rustc node wasm-bindgen esbuild; do
  command -v "$tool" >/dev/null || { printf 'worker is missing tool: %s\n' "$tool"; exit 3; }
done
base="$CARGO_HOME/ccid-artifacts/cmsg-browser"
mkdir -p "$base"
dir=$(mktemp -d "$base/$CI_COMMIT_SHA.XXXXXXXX")
export CMSG_BROWSER_OUT="$dir/build"
# The milestone script needs the locked generator dependencies; install exactly the lockfile.
(cd tools && npm ci --no-audit --no-fund)
for mode in ports service assemble; do
  bash -x .ci/v01-browser-package.sh "$mode"
done
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -cf "$dir/cmsg-browser.tar" -C "$CMSG_BROWSER_OUT" public/cmsg receipt.json
digest=$(sha256sum "$dir/cmsg-browser.tar" | cut -d' ' -f1)
printf '%s  cmsg-browser.tar\n' "$digest" > "$dir/cmsg-browser.tar.sha256"
printf '%s\n' "$CI_COMMIT_SHA" > "$dir/commit"
chmod -R a-w "$dir"
printf 'BROWSER_PACKAGE sha256=%s commit=%s dir=%s\n' "$digest" "$CI_COMMIT_SHA" "$dir"
