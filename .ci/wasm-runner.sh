#!/usr/bin/env bash
# Same upstream release/checksum process as the existing browser diagnostics.
set -euo pipefail
version=$(python3 -c 'import tomllib; p=tomllib.load(open("Cargo.lock","rb"))["package"]; v={x["version"] for x in p if x["name"]=="wasm-bindgen"}; assert len(v)==1; print(v.pop())')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir "$CI_ACCEPTANCE_ARTIFACTS/runner"
cd "$CI_ACCEPTANCE_ARTIFACTS/runner"
curl --user-agent dependency-ci --fail --location --retry 3 --remote-name "$base/$archive"
curl --user-agent dependency-ci --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
tar -xzf "$archive" --strip-components=1
test "$(./wasm-bindgen --version)" = "wasm-bindgen $version"
./wasm-bindgen-test-runner --version > runner-version.txt
sha256sum "$archive" wasm-bindgen wasm-bindgen-test-runner > runner-artifact.sha256
