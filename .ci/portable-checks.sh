#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/${CHECK_SUITE:-core}"
mkdir -p "$artifact_dir"
case "${CHECK_SUITE:-core}" in
  core|browser|composition) ;;
  *) printf 'Unknown check suite\n'; exit 2 ;;
esac
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo update --workspace
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
cp Cargo.lock "$artifact_dir/Cargo.lock"
result=0
if test "${CHECK_SUITE:-core}" = browser; then
  test -x "$BROWSER_BIN"
  compiler_root="$(rustc --print sysroot)"
  compiler_host="$(rustc -vV | sed -n 's/^host: //p')"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="${WASM_LINKER:-$compiler_root/lib/rustlib/$compiler_host/bin/rust-lld}"
  if ! test -x "$CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER"; then
    printf 'Preinstalled Wasm linker unavailable: %s\n' "$CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER"
    exit 1
  fi
  if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
    cargo update --manifest-path .ci/browser-bindgen/Cargo.toml --workspace
  fi
  cp .ci/browser-bindgen/Cargo.lock "$artifact_dir/browser-helper-Cargo.lock"
  timeout 1200 cargo build --locked --target wasm32-unknown-unknown --lib
  timeout 1200 cargo run --locked --manifest-path .ci/browser-bindgen/Cargo.toml -- \
    "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/cmsg.wasm" browser/pkg cmsg
  export BROWSER_BIN BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
  timeout 300 node .ci/browser-check.mjs || result=$?
  cargo fmt --all
  tar --create --file "$artifact_dir/formatted-browser-source.tar" src/browser_accounting.rs
  tar --create --file "$artifact_dir/browser-package.tar" browser/pkg browser/index.mjs browser/index.d.ts browser/package.json \
    browser/live-stream.mjs browser/live-stream.d.ts browser/indexeddb-store.mjs browser/indexeddb-store.d.ts
  (
    cd "$artifact_dir"
    sha256sum Cargo.lock browser-helper-Cargo.lock browser-package.tar formatted-browser-source.tar > SHA256SUMS
    if test -f browser-evidence.json; then sha256sum browser-evidence.json >> SHA256SUMS; fi
  )
  exit "$result"
fi
if test "${CHECK_SUITE:-core}" = composition; then
  test -n "$CFRM_SOURCE_ARCHIVE"
  test -n "$CFRM_SOURCE_SHA256"
  printf '%s  %s\n' "$CFRM_SOURCE_SHA256" "$CFRM_SOURCE_ARCHIVE" | sha256sum --check --strict
  test "$(git get-tar-commit-id < "$CFRM_SOURCE_ARCHIVE")" = 2c4fa47c59dfd8eb2fdc058ee171836ebc097d99
  mkdir -p .ci-dependencies/cfrm
  tar --extract --touch --file "$CFRM_SOURCE_ARCHIVE" --directory .ci-dependencies/cfrm --no-same-owner
  test -d "$OPENSSL_INCLUDE_DIR/openssl"
  test -d "$OPENSSL_LIB_DIR"
  export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
  export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  manifest=experiments/community-composition/Cargo.toml
  if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
    cargo update --manifest-path "$manifest" --workspace
  fi
  cp experiments/community-composition/Cargo.lock "$artifact_dir/composition-Cargo.lock"
  timeout 1200 cargo test --locked --manifest-path "$manifest" -- --test-threads=2 || result=$?
  cargo fmt --manifest-path "$manifest"
  tar --create --file "$artifact_dir/composition-source.tar" experiments/community-composition/src experiments/community-composition/tests
  printf '%s\n' "$CFRM_SOURCE_SHA256" > "$artifact_dir/cfrm-source-sha256.txt"
  (cd "$artifact_dir" && sha256sum Cargo.lock composition-Cargo.lock composition-source.tar cfrm-source-sha256.txt > SHA256SUMS)
  exit "$result"
fi
timeout 1200 cargo test --locked --all-targets -- --test-threads=2 || result=$?
wasm_libdir="$(rustc --print target-libdir --target wasm32-unknown-unknown)"
if test -d "$wasm_libdir"; then
  timeout 1200 cargo check --locked --target wasm32-unknown-unknown --lib || result=$?
else
  printf 'Browser target standard library unavailable; browser validation incomplete\n'
  result=1
fi
cp browser/package-lock.json "$artifact_dir/browser-package-lock.json"
cargo fmt --all
tar --create --file "$artifact_dir/formatted-source.tar" src/*.rs tests/*.rs tests/common/*.rs examples/*.rs
(cd "$artifact_dir" && sha256sum Cargo.lock browser-package-lock.json formatted-source.tar > SHA256SUMS)
printf 'Validation status: %s\n' "$result"
exit "$result"
