#!/usr/bin/env bash
# Assemble the browser prover's artifact directory from the CI retained store, every file pinned by sha256 (CI request 12; SC1).
#
#   prover-artifacts.sh DEST        DEST must not exist; on success it holds the layout CMSG_PROVER_ARTIFACTS and cmeet's CMEET_PROVER_ARTIFACTS take:
#     circuit.json keys.json           the update group  (= the retained accounting group a8a4689 artifact-conformance)
#     calibration.json                 a valid update-circuit input of a synthetic account (public test data)
#     srs/g1-524288.dat srs/g2.dat     the setup: the first 2^19 points of the wave fixture's g1.dat, and its g2.dat
#     wave/{circuit,keys,manifest}.json    the wave group   (release wave-fixtures 6bb79d4d, cblc .ci/wave-fixture.digest)
#     record/{circuit,keys,period}.json    the record_epoch group (the same accounting group a8a4689; period.json is a constant)
#   and DEST/env, the `export` lines for the consumers: CMSG_PROVER_ARTIFACTS, CMEET_PROVER_ARTIFACTS, CMSG_WAVE_FIXTURE (the retained wave fixture directory itself).
# The record_epoch witness (cwlt tests/vectors/witness/record_epoch.json) is a committed repository vector, not an artifact; CMSG_RECORD_INPUTS and CMSG_WAVE_INPUTS
# point into the cwlt checkout the caller already has.
#
# Sources are looked up by CONTENT: any $CACHE/ccid-cached/*/release-artifacts/<relative path> whose sha256 equals the pin below; a file with another
# digest is never used, a missing one stops the run. Nothing is downloaded and nothing here writes to the store.
set -euo pipefail
dest=${1:?usage: prover-artifacts.sh DEST}
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
[[ ! -e $dest ]] || { echo "refusing to overwrite $dest" >&2; exit 2; }

ACCOUNTING=release-artifacts/a8a4689889a33c8edd0186ba64f5d65bd2a47e97/artifact-conformance
WAVE_DIGEST=6bb79d4de8c1a9bc4bbcb0e8cd3ddfa3bb6877ea08ceab0a08b085c7fb2643d6
WAVE=release-artifacts/wave-fixtures/$WAVE_DIGEST
CIRCUITS_SHA=5a24a6ae074c4e02e5673543a1b6e1027d1dd4a6ee64d71d83054495276f5806
KEYS_SHA=b8f2d00902b313ef6a920cc2f50ef9ca43a6a6f6816538564659980a7dc52682
WAVE_CIRCUITS_SHA=97f20af539b6c0e6c1e03c69f9ebd3ad4b38c4f15de875c6cf4e08d90d1f930b
WAVE_KEYS_SHA=bad05ec4e71f1770395e04e9acfbdfd873adf433ce4665d95ed1c06d7443aa8e
WAVE_MANIFEST_SHA=f6e850c6360553667d00acb3b657899681e08afcf1115f9ffd7df48974214172
G1_FULL_SHA=23d5e6ef4d511367e83c0d909911b7cdd33f0b324d4106d57eefdf50fac6a59d
G1_2POW19_SHA=1d03ebeb73e1a6d426e44a2ccc88b04125ca185ab9d1679817380502a723fa80
G2_SHA=01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f
CALIBRATION_SHA=7a50e25dfdafd1520e277efefffb926a9443b551547203ee2a1886c3157f003d
PERIOD_SHA=f9ce85b52d1c52f78ccfa65128b446e9688358460dc5d1196d82347b73a9203e
CALIBRATION=release-artifacts/prover-calibration/$CALIBRATION_SHA/calibration.json

sha() { sha256sum "$1" | cut -d' ' -f1; }
# locate RELATIVE SHA : the first retained file with that relative path and that digest
locate() {
  local candidate
  for candidate in "$cache_root"/ccid-cached/*/"$1"; do
    [[ -f $candidate ]] && [[ $(sha "$candidate") = "$2" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  echo "prover-artifacts: no retained file $1 with sha256 $2" >&2
  return 1
}
# put SOURCE TARGET-IN-DEST
put() { mkdir -p "$(dirname "$dest/$2")"; cp -- "$1" "$dest/$2"; }

staging=$(mktemp -d "$(dirname "$dest")/.prover-artifacts.XXXXXX")
trap 'rm -rf -- "$staging"' EXIT
dest_final=$dest; dest=$staging

circuits=$(locate "$ACCOUNTING/circuits.json" "$CIRCUITS_SHA")
keys=$(locate "$ACCOUNTING/keys.json" "$KEYS_SHA")
put "$circuits" circuit.json;        put "$keys" keys.json
put "$circuits" record/circuit.json; put "$keys" record/keys.json
printf '{"period_key":"account.record_period"}\n' > "$staging/record/period.json"
[[ $(sha "$staging/record/period.json") = "$PERIOD_SHA" ]] || { echo 'prover-artifacts: record/period.json differs from its pin' >&2; exit 1; }
put "$(locate "$CALIBRATION" "$CALIBRATION_SHA")" calibration.json

put "$(locate "$WAVE/circuits.json" "$WAVE_CIRCUITS_SHA")" wave/circuit.json
put "$(locate "$WAVE/keys.json" "$WAVE_KEYS_SHA")" wave/keys.json
put "$(locate "$WAVE/manifest.json" "$WAVE_MANIFEST_SHA")" wave/manifest.json
g1=$(locate "$WAVE/setup/g1.dat" "$G1_FULL_SHA")
mkdir -p "$staging/srs"
head -c $((524288 * 32)) "$g1" > "$staging/srs/g1-524288.dat"
[[ $(sha "$staging/srs/g1-524288.dat") = "$G1_2POW19_SHA" ]] || { echo 'prover-artifacts: the 2^19 setup prefix differs from its pin' >&2; exit 1; }
put "$(locate "$WAVE/setup/g2.dat" "$G2_SHA")" srs/g2.dat

fixture=$(dirname "$(dirname "$g1")")
[[ $(sha "$fixture/wave-roundtrip.json") = "$WAVE_DIGEST" ]] || { echo 'prover-artifacts: the wave fixture directory is not the pinned one' >&2; exit 1; }
{
  printf 'export CMSG_PROVER_ARTIFACTS=%q\n' "$dest_final"
  printf 'export CMEET_PROVER_ARTIFACTS=%q\n' "$dest_final"
  printf 'export CMSG_WAVE_FIXTURE=%q\n' "$fixture"
} > "$staging/env"
mv -T "$staging" "$dest_final"
trap - EXIT
echo "prover-artifacts: $dest_final (wave fixture $fixture)"
