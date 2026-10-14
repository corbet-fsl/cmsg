#!/usr/bin/env bash
# Local browser package from the checked-out sources, through the integration workspace.
# Usage: local-browser-package.sh <fresh-output-dir> <torjs-source-package.tar> [cargo-target-dir]
#
# Runs the same ports stage as v01-browser-package.sh (wasm32 release build of cmsg, ctrn and cfry,
# wasm-bindgen, the generated client) and then assembles the TorJS service stage. The service stage is
# not rebuilt here (it needs the reviewed tor-js and arti forks); it is copied from an earlier package
# (its `public/cmsg/vendor/torjs` directory). The result carries no CI receipt and is for local use only.
# Needs on PATH: cargo, node, esbuild, a wasm-bindgen CLI equal to the resolved crate, clang with the
# wasm32 target, and `npm ci` done in tools/. The output directory must not exist (nothing is deleted).
set -euo pipefail
out="${1:?fresh output directory}"
torjs_tar="${2:?package tar that supplies the TorJS service stage}"
target="${3:-${CARGO_TARGET_DIR:-$PWD/target}}"
[[ "$out" == /* && ! -e "$out" ]]
export CMSG_PACKAGE_LOCKED=""  # the integration workspace generates its own lock file
export CI=1 CI_COMMIT_SHA="${CI_COMMIT_SHA:-$(git rev-parse HEAD)}" CMSG_BROWSER_OUT="$out"
export CARGO_TARGET_DIR="$target"
export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}"
for profile in RELEASE; do
  export "CARGO_PROFILE_${profile}_OPT_LEVEL=z" "CARGO_PROFILE_${profile}_LTO=true" \
    "CARGO_PROFILE_${profile}_CODEGEN_UNITS=1" "CARGO_PROFILE_${profile}_DEBUG=0" \
    "CARGO_PROFILE_${profile}_STRIP=debuginfo" "CARGO_PROFILE_${profile}_DEBUG_ASSERTIONS=false" \
    "CARGO_PROFILE_${profile}_OVERFLOW_CHECKS=true" "CARGO_PROFILE_${profile}_INCREMENTAL=false"
done
here="$(cd "$(dirname "$0")" && pwd)"
bash "$here/v01-browser-package.sh" ports
# Local package only: no CI receipt is written, because none was produced for this service stage.
tar -xf "$torjs_tar" -C "$out" public/cmsg/vendor/torjs
printf 'Local browser package (TorJS service stage from %s; not CI-attested): %s/public/cmsg\n' "$torjs_tar" "$out"
