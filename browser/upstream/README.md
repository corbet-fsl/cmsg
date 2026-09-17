# Browser Tor dependency boundary

The upstream source and nested Arti fork are pinned in `manifest.json`.
The stock `tor-js@0.4.1` npm artifact configures `arti-client` with
`default-features = false` and only `experimental-api`. That does not include
`onion-service-client`; browser HTTP fetch support alone is insufficient.

## Public-network runtime mode

The actual public-network contract passed [Crow run 84](https://crow.corbet.ch/repos/10/pipeline/84)
at cmsg `d39022b35ebe4a1bc2569acaa5f7ac2f206b29c3` on 2026-09-17.
Both browser-owned services reported `running`; nine checks include public
browser/browser framing and native/browser MLS exchange with replay rejection.
See the [public validation record](../../docs/public-tor-validation.md) for
the diagnostic build mode, measured timings, artifact hashes and limits.

`TOR_NETWORK=public TOR_STAGE=service RUN_RUNTIME=1` selects
`public-runtime-fixture.py` after the pinned service package build. It starts
one disposable native C Tor client and a separate KPS gateway using the public
authorities. The browser receives no `testNetwork` option or directory/path
overrides. `tor-js-full-vanguards.patch` explicitly selects full vanguards:
the pinned Arti default is Lite and does not automatically escalate for hosts.

`tor-js-gateway-bind.patch` adds a validated IP listener setting; this fixture
uses `127.0.0.1`, independently of its advertised address. The gateway starts
with empty task-owned cache/state, normal signature-verified directory sync,
and local targets forbidden. It waits for its actual bootstrap archive; the
fixture retains both gateway and native-client accepted public consensuses and
requires validity through the bounded browser run. No `--no-sync`, synthetic
authorities, network parameter overrides, host services or persistent keys
are used in public mode.

The shared browser contract checks local-target rejection with zero canary
connections, exact non-relay rejection for a documentation-range address,
two browser-owned onion services, browser/browser framing and a native C Tor
client connecting to a browser onion for root-authorized MLS binary data in
both directions. It records phase durations, rejects replay/malformed routes,
and checks service cancellation. This topology does not test a native-hosted
onion service. Public success requires the actual runtime artifact; source
preparation alone is not evidence. Private-network mode retains its existing
separate test-network stage and signed fixture authorities.

`TOR_DIAGNOSTICS=1` also permits the existing sanitized service/publisher
instrumentation with the public `service` stage. This source option does not
enable `browser-test-network`, injected authorities or network overrides; the
source receipt records `serviceDiagnostics` separately from `testNetworkOnly`.
It changes diagnostic labels only and preserves the selected service readiness
bound. The current service's IPT/publisher states are reported alongside
runtime-wide last-error/upload categories, which can describe another service.
No identifiers, addresses, keys or raw underlying error strings are included.
The shared contract performs native MLS exchange with the first service before
publishing the second, retaining that evidence if later publication fails;
overall success still requires both services and every transport assertion.

Publication has a separate explicit deadline of 1..600,000 ms. The public
contract selects 420,000 ms; the private contract retains 60,000 ms. The pinned
Arti publisher permits 300 seconds of retry per onion directory, with at least
30 seconds per attempt, and reports a period's results only after all its
uploads finish (`publish/reactor.rs:130`, `:382`, `:1672`, `:2130`). A single
recovering upload can therefore keep the service bootstrapping past 60 seconds
while other uploads succeed. The public budget allows that retry episode plus
60 seconds each for upload scheduling and startup. It guarantees no success:
the wrapper requires Arti's `is_fully_reachable()` predicate (`Running` or
`DegradedReachable`), full vanguards and subsequent peer reachability. The
listener exposes the startup state so reduced redundancy remains visible;
this snapshot does not guarantee continuing availability. Stream
connect/accept/read/write limits remain 60,000 ms.

Both supervisors terminate their owned process groups even when a leader
already exited. They retain the leader unreaped until cleanup to prevent PID
reuse from authorizing an unrelated group. `python3 browser/upstream/runtime-process.test.py` checks an
orphaned descendant that ignores SIGTERM and requires bounded SIGKILL cleanup.
Run this regression only on CI. Request interception remains tab HTTP evidence,
not whole-process network confinement or a hostile-gateway resource audit.

`tor-js-onion-client.patch` enables onion clients and vanguards, and exposes a
capability marker through the actual Wasm module. cmsg checks that marker before
creating a client. A marker proves which integration API was built; a real Tor
round-trip is still required to prove network operation.

Apply the patch to the exact TorJS revision with `git apply --check` followed by
`git apply` in an isolated CI checkout. Regenerate the dependency lock only in
that checkout, preserve it as an artifact, and build the Wasm and JS together.
The released npm artifact must not be relabeled as a patched build. Record the
patched source revision, patch hash, Cargo/npm locks and artifact hash.

`tor-js-gateway-response.patch` bounds response heads to 64 KiB and CONNECT
refusal bodies to 4 KiB, rejects ambiguous length fields, honors a declared body
length without waiting for FIN, and keeps the caller's abort active through the
refusal body. Each rejected CONNECT releases its own KPS stream. Run 64 exposed
the upstream bug: the gateway returned non-relay 403 and the canary saw zero TCP
connections, but its browser client hung waiting for EOF on the kept-open stream.
Crow run 66 at cmsg `6dfadad9af` passed all 52 browser parser tests and the
actual WebRTC/KPS non-relay 403 with zero canary connections.

## Security review boundary

The Tor protocol and circuit cryptography come from Arti. This integration does
not change those algorithms. The fork's Rust runtime, gateway adapters,
persistence, TLS backend and JavaScript bindings remain separate review scope.
In particular, `rustls-rustcrypto` is an alpha dependency; an Arti audit does not
automatically certify that backend or the browser port. No complete external
browser integration audit was verified.

Native socket emulation is a byte transport to Tor entry relays. All messaging
must still use browser-owned circuits and onion endpoints. The gateway sees
the client's network address, selected entry, timing and encrypted byte volume.
This adapter's application messages never use native browser `fetch`.

## Onion service hosting work

The inspected Arti revision's onion service runtime still requires
`StateDirectory`, file-backed introduction replay logs, and service keys. Simply
enabling `onion-service-service` fails to establish browser hosting. A browser
backend must preserve introduction replay protection for the full lifetime of
each introduction key, enforce one service owner per active state, expose
bounded cancellable streams, and stop accepting streams when closed.

The experimental service overlay uses per-session onion keys and in-memory
service state. Every restart creates fresh service/introduction keys; the wrapper
offers no independent key restore. Permanent cmsg identity remains a different
member root key. Compilation and native state tests have passed as detailed
below; browser service reachability passed the isolated runtime contract in
Crow run 68 and the public-network contract in Crow run 84.

## Raw stream stage

After the onion-client patch, `tor-js-onion-stream.patch` plus the
`onion_stream.rs` overlay expose actual Arti `DataStream` bytes. Copy the overlay
to `crates/tor-js-wasm/src/onion_stream.rs` in the isolated pinned checkout.
The client, stream and service patches applied to the exact source archives in
Crow run 45 at cmsg `755d83b1a`. Its full service stage passed the Wasm
compilation check and all three native ephemeral-state tests. Crow run 52 at
cmsg `addbe4c0f1` built the actual Wasm modules, matching generated bindings,
TorJS TypeScript/declarations, experimental npm package and native gateway/peer.
Crow run 62 at cmsg `6b494416a6` reached the actual browser and bootstrapped
both Arti clients over WebRTC/KPS on the signed isolated network. The first
onion service launched, then reached the 60-second publication deadline.
Crow run 68 at `b23221271f7170a4f665e3834f4302a4a1a33ff0` passed
actual browser onion publication, dial/accept and browser/native MLS transport
on the isolated signed network after the fixture initialization corrections.
Crow run 84 at `d39022b35ebe4a1bc2569acaa5f7ac2f206b29c3` passed
the public-network counterpart with the explicit service diagnostics build.
The stock dependency is not enabled by the cmsg production adapter.

`connectOnion(host, port, deadlineMs)` accepts only canonical checksum-valid
onions. This initial registry permits one pending outbound connection per
client and up to 64 established streams. `read(maximum, deadlineMs)` returns
at most 64 KiB and `write(bytes,
deadlineMs)` accepts at most one cmsg-sized chunk. One read and one write can
proceed concurrently; overlapping operations in the same direction fail.
`close()` aborts both outstanding operations and drops their stream halves.
The cmsg frame codec can then interoperate directly with native `FramedStream`.
The embedding factory must also enforce a whole-bootstrap deadline and client
shutdown, since the TypeScript client waits for bootstrap before entering the
Wasm connect deadline. Its scripted factory tests are separate from this actual
network runtime contract.

The service stage produces the same stream type from Arti's accepted
onion-service streams, with fresh ephemeral key/state ownership and
full-lifetime introduction replay protection. No JavaScript callback or local
echo is accepted as evidence that a browser onion service is reachable.

## Isolated source application and compilation

The `service` source stage now includes an in-memory state backend, target
gates for filesystem replay code, one-shot ephemeral introduction ownership,
and a bounded Arti service/stream API. Patch application is verified as above;
the generated package and public/private network evidence are recorded above.
The memory store keeps at most 16 MiB of service metadata per instance and
rejects replacement atomically when full. It exports neither raw directories
nor state recovery. It rejects reacquisition even after all handles drop.

Use clean isolated checkouts of both exact revisions in `manifest.json`. Run
on the existing CI workers, with the same Rust toolchain as cmsg:

```sh
python3 /cmsg/browser/upstream/apply.py /work/tor-js /work/arti service
cargo check --manifest-path /work/tor-js/Cargo.toml -p tor-js --target wasm32-unknown-unknown
cargo test --manifest-path /work/arti/Cargo.toml -p tor-persist --features state-dir state_dir_wasm_tests
```

Paths above are placeholders for the isolated CI checkout paths. The application
script validates both Git revisions and clean starting trees, checks/applies
each patch in sequence, copies overlays, then redirects every direct TorJS Arti
dependency to the same sibling source. It performs no installation or network
request. Save the script's source hash record and the resulting Cargo locks.
Use `client` or `streams` as the last argument to isolate an earlier source stage
in fresh checkouts. A failed patch application requires a new clean checkout.

CI can instead supply immutable Git archives with adjacent `.tar.sha256`
records: `apply.py --from-archives TORJS_TAR ARTI_TAR NEW_OUTPUT_DIR service`.
The script verifies each digest and embedded commit before extraction, rejects
Git control files in source archives, and creates clean isolated Git baselines
for checking/applying patches. It never treats those synthetic baseline commit
IDs as the upstream provenance; the verified archive IDs remain in its output.

The service uses a fresh ephemeral Arti keystore. `hostOnion(port,
maximumStreams, deadlineMs)` permits one launch per TorClient lifetime, waits
for Arti's fully reachable status and returns a peer onion,
a `readiness` startup snapshot and `accept(deadlineMs)`.
Only the configured virtual port is accepted. Pending rendezvous handshakes
and accepted streams are bounded, and closing a service cancels its pending
accept and accepted streams. Closing the client also closes raw streams and
the service. The private onion/introduction keys have no export/restore API.
This experimental service build rejects `hs-pow-full` at compile time because
that replay-store port is unfinished; it does not silently emulate its storage.

Browser restart must create a fresh TorClient and onion; permanent member
identity and private contact policy are recovered separately by cmsg. Arti's
readiness status and native state tests do not establish browser reachability.
That requires genuine Tor circuits between a browser service and a separate
native peer using the generated artifact and explicitly configured test gateway.

## Isolated test network stage

See [the signed private-network fixture](private-network.md) for its configuration,
shared-randomness initialization, runtime invocation and historical evidence.
See [renewal validation](../../docs/onion-renewal.md) for the extended lifetime check.
