#!/usr/bin/env bash
# Compile check of the browser (wasm32) build; arguments are passed to cargo check.
set -euo pipefail
source .ci/wasm-tools.sh
export PATH
exec cargo check "$@"
