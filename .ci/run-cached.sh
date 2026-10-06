#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
# Merge stderr into stdout so the captured Crow log shows tool diagnostics.
exec 2>&1
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify" ]; then
  echo "CHECKS must be exactly 'verify', got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
ln -s "$state/moon-cache/hashes" .moon/cache/hashes
ln -s "$state/moon-cache/outputs" .moon/cache/outputs
# Tool installation is an explicit part of this job, in persistent CI storage.
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436?narHash=sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#nodejs" "$tool_source#cargo-llvm-cov" "$tool_source#wasm-pack" "$tool_source#clang" "$tool_source#chromedriver" "$tool_source#chromium")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
# minicov's build script hardcodes `clang`, so the wasm32 C build uses whatever
# `clang` resolves on PATH. Resolve the pinned unwrapped compiler here (actual
# closure path from Nix at runtime, never a hardcoded store path) and export
# it for the wasm-pack leg in verify.sh. It stays off the global PATH so
# native builds and nightly coverage keep the wrapper.
CMSG_WASM_CLANG_BIN=""
for out in $(nix build --no-link --print-out-paths "$tool_source#llvmPackages.clang-unwrapped"); do
  if [ -x "$out/bin/clang" ]; then CMSG_WASM_CLANG_BIN="$out/bin"; fi
done
test -n "$CMSG_WASM_CLANG_BIN" || { echo 'pinned unwrapped clang provides no bin/clang' >&2; exit 2; }
export CMSG_WASM_CLANG_BIN
export CMSG_WASM_CLANG="$CMSG_WASM_CLANG_BIN/clang"
"$CMSG_WASM_CLANG" --version
# requirements.txt pins exactly `selenium>=4`; supply a pinned python env with
# selenium 4.40.0 plus its transitive deps (urllib3/trio/websocket-client/
# certifi/…) and pip (probe + CI pip fallback) so the gate needs no PyPI round
# trip. A singular python3Packages.selenium site-packages dir on PYTHONPATH is
# insufficient: transitive imports would fail. Same nixpkgs revision+NAR.
python_env=$(nix build --no-link --print-out-paths --impure --expr '(builtins.getFlake "'"$tool_source"'").legacyPackages.${builtins.currentSystem}.python3.withPackages (p: [ p.selenium p.pip ])')
test -n "$python_env" || { echo 'nix python selenium env resolution failed' >&2; exit 2; }
PATH="$python_env/bin:$PATH"
python3 -c 'import selenium; print(selenium.__version__)'
export PROTO_HOME="$toolchains/proto" RUSTUP_HOME="$toolchains/rustup"
shared_cargo_home=${CARGO_HOME:-}
export CARGO_HOME="$toolchains/cargo" MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$CARGO_HOME/bin:$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
if [ -n "${GIT_CONFIG_COUNT:-}" ]; then
  echo 'GIT_CONFIG_COUNT is already set; refusing to overwrite job git config' >&2
  exit 2
fi
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0='url.https://git.corbet.ch/corbet-libs/.insteadOf'
export GIT_CONFIG_VALUE_0='https://github.com/corbet-libs/'
export GIT_CONFIG_KEY_1='url.https://git.corbet.ch/corbet-foss/.insteadOf'
export GIT_CONFIG_VALUE_1='https://github.com/corbet-foss/'
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
# wasm32 targets are covered by TOOLCHAIN_WASM_TARGETS (provisioned under
# exclusive when missing), so the unconditional `rustup target add` lines in
# verify.sh stay as idempotent no-ops.
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown nightly:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
# Per-repo helper installs: verify.sh installs wasm-bindgen-cli here (under
# the per-repo fd 9 lock already held above), never into shared CARGO_HOME.
export CARGO_INSTALL_ROOT="$state/install-bin"
export PATH="$CARGO_INSTALL_ROOT/bin:$PATH"
cargo_bin=$("$CARGO_HOME/bin/rustup" which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
"$CCID_BIN" render --repo "$PWD" --check
proto --version
moon --version
rustc -vV
cargo --version
node --version
python3 --version
python3 -m pip --version
wasm-pack --version
clang --version
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "nix chromedriver not executable at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "nix chromium not executable at $CHROME_BIN" >&2; exit 2; }
chromedriver --version
chromium --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
"$CCID_BIN" cached --repo "$PWD" --check verify
test -s ".ccid/results/verify.jsonl"
