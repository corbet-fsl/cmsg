#!/usr/bin/env bash
# Build current public-network transport assets without starting Tor clients.
set -euo pipefail
test "${CI:-}" = true
test -n "${ARTIFACT_ROOT:-}"
test -n "${CARGO_TARGET_DIR:-}"
[[ "${CI_COMMIT_SHA:-}" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA"
export TOR_NETWORK=public TOR_STAGE=service TOR_DIAGNOSTICS=0 TOR_RENEWAL=0 TOR_PACKAGE_ONLY=1
mkdir -p "$ARTIFACT_ROOT" .ci-dependencies
scratch="$(mktemp -d "$PWD/.ci-dependencies/tor-public-package.XXXXXX")"
capture() {
  result=$?
  trap - EXIT
  printf '%s\n' "$result" > "$ARTIFACT_ROOT/validation-status.txt"
  (cd "$ARTIFACT_ROOT"; find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  rm -rf -- "$scratch"
  exit "$result"
}
trap capture EXIT
rustc --version > "$ARTIFACT_ROOT/rustc-version.txt"
cargo --version > "$ARTIFACT_ROOT/cargo-version.txt"
node --version > "$ARTIFACT_ROOT/node-version.txt"
git archive --format=tar --output="$ARTIFACT_ROOT/cmsg-source.tar" "$CI_COMMIT_SHA"
mapfile -t pins < <(node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const manifest = JSON.parse(await readFile('browser/upstream/manifest.json', 'utf8'));
for (const key of ['torJs', 'arti']) {
  const value = manifest[key];
  assert.match(value.repository, /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+\.git$/);
  assert.match(value.revision, /^[0-9a-f]{40}$/);
  console.log(value.repository); console.log(value.revision);
}
JS
)
test "${#pins[@]}" = 4
fetch_source() {
  local directory="$1" repository="$2" revision="$3"
  mkdir "$directory"
  git -C "$directory" init --quiet
  git -C "$directory" remote add origin "$repository"
  git -C "$directory" fetch --depth=1 origin "$revision"
  git -C "$directory" -c advice.detachedHead=false checkout --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
}
fetch_source "$scratch/tor-js" "${pins[0]}" "${pins[1]}"
fetch_source "$scratch/arti" "${pins[2]}" "${pins[3]}"
python3 browser/upstream/apply.py "$scratch/tor-js" "$scratch/arti" service | tee "$ARTIFACT_ROOT/source-application.json"
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const value = JSON.parse(await readFile(process.env.ARTIFACT_ROOT + '/source-application.json', 'utf8'));
assert.equal(value.stage, 'service'); assert.equal(value.testNetworkOnly, false);
assert.equal(value.serviceDiagnostics, false); assert.equal(value.renewalDiagnostics, false);
assert(value.inputsSha256['arti-publisher-renewal.patch'], 'Current renewal fix required');
assert(!value.inputsSha256['tor-js-test-network.patch']);
JS
cp browser/upstream/locks/tor-js-Cargo.lock "$scratch/tor-js/Cargo.lock"
cp browser/upstream/locks/arti-Cargo.lock "$scratch/arti/Cargo.lock"
cp browser/upstream/locks/README.md "$ARTIFACT_ROOT/dependency-provenance.md"
cp browser/upstream/manifest.json "$ARTIFACT_ROOT/upstream-manifest.json"
cp browser/upstream/locks/arti-Cargo.lock "$ARTIFACT_ROOT/arti-Cargo.lock"
cp .ci/tor-bindgen/Cargo.lock "$ARTIFACT_ROOT/tor-bindgen-Cargo.lock"
timeout --kill-after=15 1200 cargo build --locked --manifest-path .ci/tor-bindgen/Cargo.toml
export TOR_BINDGEN_BINARY="$CARGO_TARGET_DIR/debug/cmsg-tor-test-bindgen"
bash .ci/tor-runtime-build.sh "$scratch/tor-js" "$ARTIFACT_ROOT/runtime"
cmp browser/upstream/locks/tor-js-Cargo.lock "$scratch/tor-js/Cargo.lock"
cmp browser/upstream/locks/arti-Cargo.lock "$scratch/arti/Cargo.lock"
cp "$CARGO_TARGET_DIR/debug/tor-js-gateway" "$ARTIFACT_ROOT/tor-js-gateway"
node --input-type=module <<'JS'
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join, basename } from 'node:path';
const root = process.env.ARTIFACT_ROOT;
const [packed] = JSON.parse(await readFile(join(root, 'runtime/tor-package.json'), 'utf8'));
assert.equal(packed.name, 'tor-js');
assert.equal(packed.version, '0.4.1-cmsg-experiment.' + process.env.CI_COMMIT_SHA.slice(0, 12));
assert.equal(packed.filename, basename(packed.filename));
const archive = await readFile(join(root, 'runtime', packed.filename));
assert.equal(packed.integrity, 'sha512-' + createHash('sha512').update(archive).digest('base64'));
const names = new Set(packed.files.map(file => file.path));
for (const file of ['dist/tor_js_bg.wasm', 'dist/wasm-pkg/tor_js.js', 'dist/entryPoints/wasm-file/index.js', 'dist/entryPoints/wasm-file/index.d.ts', 'LICENSE-MIT', 'LICENSE-APACHE']) assert(names.has(file), file);
const sha256 = value => createHash('sha256').update(value).digest('hex');
await writeFile(join(root, 'package-evidence.json'), JSON.stringify({ source: process.env.CI_COMMIT_SHA,
  packageBuilt: true, publicNetworkVerified: false, testNetworkFeature: false, serviceDiagnostics: false,
  renewalPatchIncluded: true, archive: 'runtime/' + packed.filename, sha256: sha256(archive), integrity: packed.integrity,
  sourceManifestSha256: sha256(await readFile(join(root, 'source-application.json'))),
  gatewaySha256: sha256(await readFile(join(root, 'tor-js-gateway'))),
  sourceArchiveSha256: sha256(await readFile(join(root, 'cmsg-source.tar'))),
  scope: 'Current public service package and gateway build; existing gateway/parser tests; no new Tor network or cmeet interoperability result'
}, null, 2) + '\n');
JS
