# cmsg

Private text messaging with encrypted local state and an explicit metadata-privacy boundary.

An experimental Rust alpha is published as [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1), requiring Rust 1.97.1. See the [verified release artifact and installation](studies/crate-alpha-release.md).

This repository contains an experimental Rust client built on OpenMLS, with encrypted local snapshots and authenticated community identities. Its tests exercise real pair and 100-member text exchanges, membership changes, tamper recovery and replay rejection. Earlier core revisions passed Android and iOS Rust target checks; later changes still need those checks, and native applications, device passkeys and background networking require integration and device testing.

The validated core at `0371e4a` passed [56 native behavioral tests and real cross-language profile signing](https://crow.corbet.ch/repos/10/pipeline/9). This includes recipient-side first-contact enforcement, encrypted local blocking/cancellation, same-identity credential renewal, recovery of the exact renewal update from an encrypted outbox, authenticated participant display and safe removal handles. The [combined component experiment](experiments/composition/README.md) also passed with the actual recipient Inbox enforcing allowance redemption.

`Member` exposes the underlying messaging primitives. Applications use `Inbox` with a trusted cfrm redemption adapter for unknown first contacts, keep their durable storage and outbox transactions local, and honor local blocks. The library does not infer delivered-message counts or sincere interaction from a permit spend.

It is not yet a deployable anonymous messenger. Onion-only transport fails closed. A real isolated Tor-network experiment passes; public-network connectivity and mobile operation remain unverified. Admission, participation rules, durable device state and transport require further integration before deployment. See the implementation study for the precise tested boundaries and remaining work.

- [Messaging contract](docs/contract.md)
- [Component boundaries](docs/components.md)
- [Reuse study](studies/messaging-components.md)
- [Implementation and security experiments](studies/implementation-experiments.md)
- [Passing 100-member and mobile-target checks](https://github.com/corbet-labs/cmsg/actions/runs/34257557064)
- [Cross-component composition experiment](experiments/composition/README.md)
- [Experiments](experiments/README.md)

License: [FSL-1.1-ALv2](LICENSE.md). Third-party dependencies retain their own licenses.
