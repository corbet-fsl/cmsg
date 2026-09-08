# External crate consumer

This checks the actual generated `.crate` archive from an already verified public source checkout. It runs on the existing CI worker, without installing tools, publishing a package, using provider accounts or spending money.

The root-owned package workflow first verifies the checksum and embedded commit of an immutable Git archive. It then runs:

```sh
cargo package --locked --offline --no-verify
python3 experiments/package-consumer/check.py "$CARGO_TARGET_DIR/package/cmsg-0.1.0-alpha.1.crate" --expected-commit "$CI_COMMIT_SHA"
```

The checker validates the package allowlist, matches included source and document bytes to that verified checkout, checks normalized Cargo metadata and the dependency lock, and rejects links or escaping archive paths. Cargo's optional VCS metadata must match when present; its absence in an archive-only workspace is expected. The commit argument alone does not authenticate the checkout.

The consumer is copied into a temporary directory beside the unpacked crate. Its dependency points only to that unpacked directory. The archive's exact dependency graph is retained, adding only the standalone consumer root; Cargo runs offline and locked. The consumer cannot reach private Rust modules or the repository's test helpers.

It verifies real synthetic cvld signatures, creates independently keyed MLS participants, exchanges UTF-8 text, checks authenticated participant IDs and chat keys, restores encrypted state, rejects replay and continues the conversation. Output contains aggregate success booleans and package metadata. This is a `Member` primitive consumer, with no network or cfrm redemption claim; the separate composition experiment checks the real recipient gate.

The Python checker and companion consumer sources are CI infrastructure and are excluded from the crate. This explanation is included with other experiment documentation. The generated archive, checksum and external source provenance record are staged only after the checker succeeds. Publication is a separate maintainer action.
