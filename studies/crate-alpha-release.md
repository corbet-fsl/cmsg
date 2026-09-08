# Published Rust alpha

Published 2026-09-08: [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1), owned by `julian-corbet`, with the source repository under Corbet Labs. This is a useful experimental client library, not a deployable anonymous messenger or a completed mobile application.

```toml
[dependencies]
cmsg = "=0.1.0-alpha.1"
```

The alpha conservatively requires Rust 1.97.1, the compiler actually used for its native and packaged-consumer checks. Its [API and integration review](crate-alpha-release-review.md) describes the available exports and host responsibilities. Original code is covered by [FSL-1.1-ALv2](../LICENSE.md); dependencies retain their own licenses.

## Exact artifact evidence

| Field | Verified value |
|---|---|
| Release source | `4af0dad8dcb16ea04361d18c4fe6e0270426a17b` |
| Package execution | [Crow repository 10, pipeline 10](https://crow.corbet.ch/repos/10/pipeline/10) |
| Archive | `cmsg-0.1.0-alpha.1.crate` |
| SHA256 | `4b9f5e0df762b1bc3a104bd6d08323db086adbf26b611e53a0db18dde6207d49` |
| Contents | 38 files; 68,180 compressed bytes; 259,663 unpacked bytes |
| Native compiler | Rust 1.97.1; Cargo 1.97.0 |
| Independent registry verification | Anonymous version metadata, owner listing and archive download succeeded; downloaded bytes have the same SHA256 |

CI first verified the staged Git archive's checksum and embedded source commit. The package checker compared every included source/document file to that checkout, checked Cargo's normalized metadata and dependency lock, and built a separate consumer against the unpacked `.crate`. It exercised actual certified pair messaging, authenticated roster identity, encrypted restore, replay rejection and continued exchange using public exports.

The exact checked archive was uploaded through the [documented Cargo registry API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html#publish), without rebuilding or repackaging it. Publication returned success without warnings. Registry credentials were not provided to CI. The [registry version record](https://crates.io/api/v1/crates/cmsg/0.1.0-alpha.1) and [downloadable archive](https://static.crates.io/crates/cmsg/cmsg-0.1.0-alpha.1.crate) provide independent public retrieval.

The artifact contains Rust source, tests and the public synthetic admission fixture, examples, license, README, Cargo metadata/lock and selected Markdown studies. CI workflows, executable experiment infrastructure, caches and private handoffs are excluded. Cargo VCS metadata is absent because CI packages an extracted Git archive; the source verification and archive checksum above establish this release's provenance under the trusted worker boundary.

## Scope of the result

The behavior at `0371e4ad5e7e39720f9a333d70579c2b208786da` passed [56 native tests and actual cross-language profile signatures](https://crow.corbet.ch/repos/10/pipeline/9). The release changes from that revision only affect packaging metadata and documentation. The external consumer verifies the shipped library; the [separate component composition](../experiments/composition/README.md) establishes actual recipient Inbox enforcement against cfrm blind-permit redemption. Neither local harness establishes production network anonymity.

Execution uses the included dependency lock. Downstream applications resolve and retain their own lock; this result is not evidence for every future semver-compatible dependency combination. Source and package checks are not a security audit.

Earlier core revisions passed Android/iOS Rust target checks. The current worker lacks those target standard libraries, and the released revision has no current mobile compilation, native application, device passkey or background-network evidence. Native bindings, verified onion service ownership, device lifecycle handling, monotonic single-writer storage, private rules integration and independently operated eligibility providers remain integration work. Exact limits are recorded in the [release review](crate-alpha-release-review.md).
