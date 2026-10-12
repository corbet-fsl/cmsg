#!/usr/bin/env bash
# Worker-only native qualification. Browser/coverage gates remain independent.
set -euo pipefail
# Keep actual compiler/test diagnostics in the retained product job stream.
exec 2>&1
mkdir -p evidence/native
rustc --version --verbose > evidence/native/rustc.txt
retain_locks() {
    if [[ -f Cargo.lock ]]; then cp Cargo.lock evidence/native/Cargo.lock; fi
    if [[ -f tests/fixture/Cargo.lock ]]; then
        cp tests/fixture/Cargo.lock evidence/native/fixture-Cargo.lock
    fi
}
trap retain_locks EXIT
python3 .ci/check-first-party.py
# The separate declared resolver retains both locks before this qualification.
# Every Cargo operation below consumes that reviewed immutable graph.
cp Cargo.lock evidence/native/Cargo.lock
cp tests/fixture/Cargo.lock evidence/native/fixture-Cargo.lock
sha256sum Cargo.lock tests/fixture/Cargo.lock > evidence/native/locks.sha256
python3 .ci/check-first-party.py
bash .ci/prepare-foyer-fixture.sh
cp fixture-owner.json evidence/native/fixture-owner.json
cargo fmt --all -- --check
# The Keyhole test server links openssl through webauthn-rs-core.
nix-shell tests/fixture/owner/check-shell.nix --run 'cargo clippy --locked --all-targets -- -D warnings'
nix-shell tests/fixture/owner/check-shell.nix --run 'bash .ci/native-prover.sh'
# Pending passkey ceremonies expire after 300 s of wall time; build every test binary BEFORE the fixture starts.
nix-shell tests/fixture/owner/check-shell.nix --run 'cargo test --locked --all-targets --no-run'
fixture="${CARGO_TARGET_DIR:-tests/fixture/target}/debug/cmsg-foyer-fixture"
export fixture
# The foyer test edits the live policy, which invalidates every passport minted by the same fixture;
# the initial-enrollment and Wallet tests each fill the fixture's bounded pending challenges.
# Each of these gets its own fixture instance.
own="foyer initial_enrollment wallet_enrollment"
others=$(for t in tests/*.rs; do n=$(basename "$t" .rs); case " $own " in *" $n "*) ;; *) printf -- '--test %s ' "$n";; esac; done)
export others
status=0
# Debug builds of the Wallet flows hold large futures on the test thread.
export RUST_MIN_STACK=67108864
nix-shell tests/fixture/owner/check-shell.nix --run 'python3 .ci/with-foyer-fixture.py "$fixture" cargo test --locked --lib --bins --examples $others --no-fail-fast' || status=1
for t in $own; do
    export t
    nix-shell tests/fixture/owner/check-shell.nix --run 'python3 .ci/with-foyer-fixture.py "$fixture" cargo test --locked --test "$t" --no-fail-fast -- --test-threads=1' || status=1
done
[ "$status" = 0 ]

# Qualify the actual maintained Tor transport separately from inert record tests.
# Existing provisioned original tools are required; this route never installs them.
python3 .ci/test-private-tor-journey.py
cargo metadata --locked --features native-tor --format-version 1 > evidence/native/tor-metadata.json
cargo test --locked --features native-tor --test initial_tor --no-run --message-format=json > evidence/native/tor-build.jsonl
python3 .ci/private-tor-journey.py
