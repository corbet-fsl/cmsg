# Crate alpha release review

[`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1) is published as a reusable Rust integration library rather than a deployable messenger. The maintainer uploaded the exact archive after its external consumer and source comparison passed; the checker itself does not publish packages. FSL-1.1-ALv2 covers this repository's code; dependencies retain their upstream licenses.

## Useful public API

| Export | Useful responsibility | Host responsibility |
|---|---|---|
| `AdmissionGrant`, `AdmissionTrust`, `verify_admission` | Verify the cvld signature, current authorization and community/member/signing-key binding | Configure issuer trust independently and obtain the grant through cvld |
| `Member` | Independently keyed pair/group MLS conversation, key packages, membership control, text, encrypted snapshots and same-key certificate renewal | Sequence epochs, deliver control messages and make local state durable; raw `join` does not spend first-contact allowance |
| `Invitation`, `Received`, `TextMessage` | Exact MLS wire objects and authenticated text with the participant's stable member ID | Route bytes only through the reviewed anonymous transport and keep text/IDs out of operator telemetry |
| `Inbox`, `Acceptance`, `Redemption` | Recipient first-contact gate, persisted private retry state, known counterparts, local invitation block/cancel | Trusted recipient-generated redemption claim, authenticated cfrm callback, atomic persistence and bounded retry |
| `Participant`, `ParticipantHandle` | Authenticated participant-local roster and safe epoch-scoped removal targeting | Refresh handles after epoch changes; this alpha rejects duplicate stable IDs within one group |
| `Clock` | Explicit trusted time for deterministic authorization and `Member` restore | Supply trusted time; this is not an untrusted peer timestamp |
| `OnionEndpoint`, `OnionTransport` | Checksum-validated onion destinations and isolated connections through a configured loopback SOCKS listener | Own/verify Tor, constrain network egress, provide the receiving onion service and handle suspension/reconnection |
| `RendezvousChallenge`, `RendezvousEndpoint`, `ProfileChallenge` | Fixed-purpose signatures under the certified chat key for cfrm registration and profile ownership | Validate peer-side signatures and current live leases; there is no generic signing oracle |
| `validate_text`, `MAX_TEXT_BYTES`, `MAX_WIRE_BYTES`, `Error` | Literal UTF-8 framing, bounded input and coarse error categories | Render text literally and avoid attachments, previews, URL fetching or logging private data |

`Member::renew_admission` provides the candidate member plus the exact outbound control bytes to its persistence callback. The host can atomically encrypt and save both the snapshot and its private outbox before success. This does not guarantee delivery or snapshot freshness. Low-level add/remove/send/receive remain host-managed transactional integration boundaries; this release does not add a general durable messaging engine. The legacy `remove(u32)` primitive uses an epoch-relative leaf index; clients should use `participants` and `remove_participant` for user-selected targets.

A callback error or panic rolls back in-memory state but cannot undo a host write that became durable before an ambiguous error. After a possibly durable write reports failure, the host must recover its canonical encrypted checkpoint/outbox before further sends. Continuing from the older in-memory copy can fork the sender state. The same host uncertainty applies to Inbox checkpoints; a callback cannot establish monotonic persistence by returning a boolean alone.

`Inbox` persistence/redemption closures are synchronous Rust interfaces. A host must supply the appropriate worker/runtime boundary for network and disk work; these are not already Swift/Kotlin asynchronous APIs. The public `Error` is a coarse enum, not yet a `std::error::Error` implementation. No private signing-key export, plaintext serialization of `Member`, operator content callback or report API is exported.

## Evidence and package contents

Crow repository 10, pipeline 7 at `b666cd7c915038796956e20544539d0394090d89` passed all 55 native tests and actual cross-runtime profile-signature verification. The roster's seven tests first failed in pipeline 6 at `6b14d6c04f18e2d2dbb5b355248350eae832f8ab`. Renewal outbox specification `8552c1c` then failed exactly its new restart assertion in pipeline 8 at `4d141953833818dced13c97cc7b9ff806a05ec80`, with the previous 55 tests still passing. Fix `0371e4a` passed all 56 tests and profile interoperability in pipeline 9 at `0371e4ad5e7e39720f9a333d70579c2b208786da`.

The package allowlist contains Rust source, tests and their public synthetic fixture, Rust examples, license, README, Cargo metadata/lock and Markdown documentation. It excludes CI workflows, Python/JavaScript runners, package-consumer infrastructure, caches, archives and private handoff files. Cargo adds its normalized manifest and may add VCS metadata. The [external consumer](../experiments/package-consumer/README.md) checks actual archive contents and uses only public exports for a real certified pair exchange, stable roster identity and encrypted restore.

[Crow repository 10, pipeline 10](https://crow.corbet.ch/repos/10/pipeline/10) passed the complete package check at `4af0dad8dcb16ea04361d18c4fe6e0270426a17b`: packaged source/document comparison to the verified checkout, normalized metadata and locked dependencies, plus certified pair exchange, stable roster identity, encrypted restore, replay rejection and continued exchange from the external consumer. The archive contains 38 files and is 68,180 bytes. Its SHA-256 is `4b9f5e0df762b1bc3a104bd6d08323db086adbf26b611e53a0db18dde6207d49`.

The maintainer published those exact bytes on 2026-09-08 and independently verified the anonymous registry version/download checksum and the `julian-corbet` registry owner. Later documentation commits do not change the published archive. The native behavioral evidence remains the 56-test run above; the package check compiles and exercises the actual distributed library, without claiming another full native suite or mobile check.

The current worker reports Rust 1.97.1 and Cargo 1.97.0. It has no rustup and neither Android arm64 nor iOS arm64 target standard library installed, as observed in pipeline 8. The alpha therefore conservatively declares `rust-version = "1.97.1"`, the tested compiler, rather than claiming the former untested minimum of 1.91. This floor can be lowered after a real older-toolchain check.

Earlier source `b4ac4f9` passed both mobile arm64 target checks in [GitHub run 34258758551](https://github.com/corbet-labs/cmsg/actions/runs/34258758551). Those checks precede Inbox, renewal and roster changes. Static review found no new OS-specific dependency in these APIs, but that is not current cross-target or device evidence. The crate does not provide a native ABI, app packaging/signing, native passkey PRF adapter, mobile Tor lifecycle or background execution design. An ordinary-browser build is not supplied.

## Release and deployment limits

The bounded crate-release checks and publication are complete for this exact alpha artifact. That establishes a usable, independently consumed package with the tested behavior above; it does not establish production readiness or expand the supported deployment boundary.

Production use additionally requires security review, verified Tor ownership/network confinement and device integration, atomic monotonic single-writer persistence, recovery and control-message delivery, and production cvld/cfrm adapters. Authentic old snapshots can still roll back or fork state. An expired credential does not erase an existing participant's group keys; removal and rekey are required for future-epoch exclusion. Signing-key rotation, issuer/policy migration and multi-device membership remain separate protocols. Text recipients can copy what they read.

The isolated real Tor experiment proves functional onion routing on its disposable test network; public-network connectivity, independent mobile devices and resistance to global traffic analysis remain unverified. Raw MLS headers carry group identifiers, so a central relay/logging service would need a separately reviewed outer envelope. The dependency audit reported the tracked unmaintained `proc-macro-error2` warning; a passing build is not an audit of security or dependency maintenance. Exact older evidence and boundaries are in [the implementation study](implementation-experiments.md).
