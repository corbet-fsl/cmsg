# Coverage evidence

Stable Rust runs the native vectors and the same device vectors in actual Chrome.
Current nightly measures native and browser Rust source lines and branches with
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov#wasm). The browser test
harness uses the maintained [minicov](https://github.com/Amanieu/minicov) runtime
and wasm-bindgen's profiling upload endpoint, after actual tests finish. This
profiling helper is a test-only dependency, separate from product code.

Every emitted reachable source line and branch must be covered. The gate checks
LCOV against the same execution's raw JSON file/branch inventory and annotated
source line locations and hit states. Missing, duplicate, truncated or inconsistent
reports fail. Source counters merge generic instances; raw JSON is retained and
this metric does not claim every monomorphized instance was separately covered.
Any exception requires exact source, target, reason and evidence in the checked
manifest; a changed, exercised, missing or branch-bearing exception fails.

Native and browser artifacts remain separate. Passing local vectors cannot
establish live network, admission, restore or full integration acceptance.

These Rust composition libraries export no standalone C or JavaScript ABI. They
build as rlibs on native and Wasm; an embedding application owns its eventual
exported module. A standalone instrumented cdylib would link before the test-only
profiling runtime and is not used for the actual browser vector harness.

The resolver refreshes both Cargo and the Node tooling lock before testing.
The maintained [npm update](https://docs.npmjs.com/cli/v11/commands/npm-update)
lock-only operation respects declared ranges and disables package scripts; the
single resolved artifact carries both locks and their hashes to every job.
Generation, schema validation and actual TypeScript HTTP conformance install
that exact tooling graph with npm ci.
