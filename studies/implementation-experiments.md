# Native messaging experiments

This is an experimental client library, not a deployable anonymous messenger or an audited security product. It uses released upstream implementations, with synthetic fixtures only. No phone check, payment, paid service or production credential is involved.

## Selected building blocks

| Requirement | Implementation | Boundary |
|---|---|---|
| Pair and group text encryption | OpenMLS 0.9.0 with its RustCrypto 0.6 provider; RFC 9420 MLS, X25519/ChaCha20-Poly1305/Ed25519 | The application validates membership authorization; MLS alone does not supply anonymity or quotas |
| Stable identity from community into private chats | Independently verified cvld Ed25519 grant, bound to each MLS signing key and carried as a BasicCredential | The stable member ID is intentionally visible to participants; no cross-community account linking is added |
| Local encrypted state and history | Random data key and XChaCha20-Poly1305 envelope, wrapped with caller-provided 32-byte PRF-derived material | No password, operator key, plaintext persistence or device recovery fallback |
| Network identity | Checksum-validated v3 onion endpoints through a trusted loopback Tor SOCKS listener; isolated SOCKS credentials per connection | No clearnet endpoint representation or fallback; the host application must own and verify the Tor process |
| Mobile foundation | Rust core with caller-supplied memory/key material and transport configuration | Cross-target checks are separate from native app integration and device tests |

Dependencies remain under their upstream licenses; FSL applies to this repository's own integration code. The original selection favored OpenMLS over incorporating SimpleX or libsignal: the latter introduce AGPL composition questions, and libsignal explicitly does not promise support for third-party clients. This is a reason to use the maintained MLS protocol implementation, not a claim that a smaller integration automatically has better security.

Sources: [OpenMLS](https://github.com/openmls/openmls), [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), [RustCrypto AEADs](https://github.com/RustCrypto/AEADs), [Tor onion protocol](https://spec.torproject.org/rend-spec/), [libsignal](https://github.com/signalapp/libsignal).

## Executable checks

The tests create actual independently keyed MLS participants and exercise encrypted two-member and 100-member conversations, addition/removal, past-epoch exclusion, tampering, exact framing, replay and out-of-order delivery. They also check UTF-8 byte limits, literal markup handling, hidden debug output, issuer/community/policy/key/expiry binding, and snapshots containing both history and ratchet state.

The first fail-first commit is `e4ff940`: all ten behavioral tests compiled and failed against explicit stubs. The admission test commit `a49fa02` likewise failed on accepting a real signed identity and preventing unadmitted creation. The 100-member specification was introduced at `b8dca4c` before bulk-add implementation.

A real integration defect appeared during testing: OpenMLS could reject an altered ciphertext after advancing receive-ratchet storage, making the authentic retransmission fail. The receive boundary now stages the operation in isolated memory storage and commits only fully authenticated, application-valid changes. Rejected ciphertext must not advance committed state; the test was retained rather than weakened. A second negative test (`2fcfb66`, run 34257175944) proved that an otherwise valid Welcome with an unauthorized identity could consume a pending KeyPackage before application rejection. Joining now uses the same transactional boundary, preserving a later authorized invitation.

The mocked SOCKS tests are socket-level negative tests, not proof of Tor anonymity. They observe requested onion names and per-connection isolation, use a separate clearnet trap, and verify failure replies and deceptive bind-address replies cannot cause direct connections. Receiving text with an embedded tracking URL causes zero trap connections.

`Live Tor onion experiment` is a separately dispatched workflow. It launches independent client and onion-service Tor processes on an ephemeral public runner and carries a real MLS ciphertext through an onion circuit. Its output is limited to aggregate booleans. A successful run proves this routing path works and the service sees its local Tor connection; it does not prove resistance to timing correlation, a compromised client, or a global observer. The two processes use one disposable host, not independent mobile networks. The first public-network attempt (run 34256811872) failed closed at the bootstrap deadline; it is not successful anonymity evidence. A separate `Isolated Tor onion experiment` uses pinned upstream Chutney and real Tor authorities/relays/client/onion service on the disposable runner to separate protocol integration from access to the public Tor network.

The isolated experiment succeeded in [run 34258388661](https://github.com/corbet-labs/cmsg/actions/runs/34258388661): nine real Tor processes bootstrapped in 77 seconds, carried an actual MLS ciphertext through the onion service, and returned `onion_round_trip`, `plaintext_equal` and `recipient_saw_only_local_tor` as true. This is evidence for the real protocol integration on that test network; the public-network and independent-device limits above still apply.

All builds and tests run on standard public GitHub-hosted runners with public source and synthetic data. No production secret or protected input is sent to CI. Dependency resolution is locked. The normal workflow additionally checks Android arm64 and iOS arm64 Rust targets without signing or paid accounts.

## Measured baseline

At `a48250e`, [run 34257557064](https://github.com/corbet-labs/cmsg/actions/runs/34257557064) passed twenty behavioral tests and both arm64 mobile target checks. With dependency optimization enabled and integration code still in the test/debug profile, a single synthetic process containing all 100 clients measured:

| Operation | Elapsed |
|---|---:|
| Create and join 100 members | 2.87 seconds |
| Encrypt and deliver to the other 99 clients | 1.48 seconds |
| Remove one member, process the commit and deliver to remaining clients | 4.96 seconds |
| Peak process resident memory | 49.9 MiB |

These are functional scale measurements on one hosted runner, not phone benchmarks, network latency or per-user memory. The initial unoptimized dependency run was much slower; the tests now optimize cryptographic dependencies and execute the scale case once per normal run. Neither result predicts Tor throughput.

At `b4ac4f9`, [run 34258758551](https://github.com/corbet-labs/cmsg/actions/runs/34258758551) passed 23 behavioral tests and both mobile target checks. The additional checks cover fixed-domain cfrm rendezvous signatures and byte-for-byte verification of a real JavaScript cvld issuer fixture.

The separate dependency audit [run 34258592464](https://github.com/corbet-labs/cmsg/actions/runs/34258592464) scanned 213 locked dependencies against 1,242 RustSec advisories. It completed without a vulnerability error and reported one maintenance warning: `proc-macro-error2` 2.0.1 is unmaintained, [RUSTSEC-2026-0173](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/proc-macro-error2/RUSTSEC-2026-0173.md). This is a transitive macro dependency through OpenMLS's provider dependency tree. The warning remains visible and requires tracking; a successful audit is not evidence that all dependencies are maintained or that the application is secure.

## Recipient first-contact boundary

`Member` is the low-level MLS primitive. Its `join` method authenticates the conversation but does not spend cfrm allowances. The separate `Inbox` client boundary is intended to require a permit for an unknown certified inviter, persist known counterparts privately, and allow established counterparts without another first-contact debit. Accepting a group invitation establishes only its authenticated inviter as a known counterpart; it does not grant every other group member free future invitations.

Before any external spend, `Inbox` prepares and validates the complete Welcome in isolated MLS state. The recipient's trusted cfrm adapter adds a fresh private retry claim to the sender's permit. Only these opaque redemption bytes go to the redemption callback, without member IDs or group IDs. The client must durably save the exact pending invitation and claim in an encrypted checkpoint before invoking that callback. An indeterminate result preserves the attempt for an idempotent retry; it does not create a replacement claim. A successful redemption is followed by one durable checkpoint containing both the joined ratchet and known-counterpart state before acceptance becomes visible.

The persistence callback must mean an atomic, durable local write. It cannot establish storage freshness or prevent concurrent devices from restoring the same state. The `composition` example supplies a synthetic filesystem implementation with restrictive permissions, file and directory synchronization, and atomic replacement. A production mobile adapter must supply its own equivalent persistence and monotonicity design. Retry attempts must be bounded and constrained by the cfrm epoch's validity.

Recipient-controlled cancellation and stable-ID invitation blocking have published fail-first specifications. Cancellation clears the local pending attempt without a refund or an operator request. Blocking is private and community scoped, including known inviters; existing conversation display still needs to honor that local state separately from raw `Member::receive`. Local history and cancellation should remain accessible after admission expiry, while accepting a new invitation still requires current admission.

Verification is incomplete for this newer boundary. The initial six Inbox specifications compiled and failed against explicit stubs at `3f90beb`, [run 34259403726](https://github.com/corbet-labs/cmsg/actions/runs/34259403726). Subsequent implementation, transactional persistence changes, the gated composition example and additional cancellation/blocking specifications have not completed a hosted build. As observed on 2026-09-08, new pushes produced no Actions runs and workflow dispatch returned HTTP 500 across the component repositories. No local build was substituted and no green result is claimed for those changes.

## Remaining integration and security work

- The local Tor listener is a trusted deployment boundary. A loopback address is not evidence that the process is Tor. Mobile applications need a supported embedded/local Tor lifecycle, network confinement, suspension/reconnection handling and device testing. There is no ordinary-browser implementation.
- MLS outer messages expose group identifiers to whoever receives those bytes. This prototype connects directly to member onion services; intermediary Tor relays do not receive MLS plaintext. An operator-run delivery queue would need a separately reviewed outer envelope and routing design. Do not send these raw MLS objects to a central logging relay.
- The library validates cvld admission grants and binds them to signing keys. Production issuance still depends on cvld's provider and passkey integration. The separate Inbox first-contact boundary and real cfrm redemption composition still need successful execution and review; an admission grant alone does not prove good standing or available allowance.
- Snapshots authenticate the saved state, not its freshness. A valid old snapshot can still roll state back, and simultaneous restored copies can fork a sender state. Production persistence requires atomic, monotonic commits and single-writer/device handling. No test here establishes crash consistency or rollback protection.
- Credential expiry is enforced against the client clock. Renewing a grant/key in an existing MLS group and migration of issuer trust require an explicit protocol path. Expiry is not a behavioral ban or a revocation database.
- History is client-local. Its recipient already knows the content and can copy it. The process necessarily holds plaintext while unlocked; zeroization reduces residual copies but does not establish protection against a compromised OS, crash dumps or all allocator copies.
- No offline ciphertext queues, recipient introduction service, attachment codec, URL fetcher, video call, operator telemetry pipeline or content-report endpoint is implemented. Limits bound bytes, not the semantic meaning of user-written text.
- The `composition` example is a synthetic local JSON process seam, not a network API. It receives already issued grants and synthetic PRF material, emits public chat keys, fixed-domain rendezvous signatures and boolean results, and can exchange opaque recipient redemption bytes with the actual cfrm adapter. The gated flow keeps member pairs and group IDs out of the redemption callback. Its older primitive flow remains available for isolated MLS experiments and must not be presented as recipient-enforced quota checking.

[Chutney test-network source](https://gitlab.torproject.org/tpo/core/chutney/-/tree/6cc158868d722e652975cb4efd5b278d95ff2fbb) is installed only inside the disposable test runner; its upstream license remains attached.
