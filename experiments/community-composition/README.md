# Rust cmsg/cfrm composition

This crate tests the actual libraries together with synthetic member identities,
eligibility, device certificates, RSA blind permits, redemption stamps and MLS
messages. cfrm is pinned in `.ci/archives.toml`; CI verifies that exact source
archive before staging it under `.ci-dependencies/cfrm`. It sends no repository
credentials to the worker.

The tests cover signed public presence, hostile issuer/device substitution,
one allowance across devices, restart-safe exact retries, real blind issuance
through recipient admission, repeated-introduction rejection, an actual answer,
and rejection of a permit copied to another recipient. The adapter sends only
the anonymous redemption request to the authority; the recipient's opening
remains in its local encrypted checkpoint.

Run `cargo test --locked --manifest-path experiments/community-composition/Cargo.toml`
through the repository's `composition` CI workflow. The native
issuer requires an existing OpenSSL development environment. Do not run this
crate against real accounts or production signing keys.

The tests do not implement the private reciprocal budget, prove nontransferable
permits, validate Tor delivery, or count generic MLS group participation as
individually admitted first contacts. See [the boundary document](../../docs/browser-first.md).
