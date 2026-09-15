# Browser Tor dependency boundary

The upstream source and nested Arti fork are pinned in `manifest.json`.
The stock `tor-js@0.4.1` npm artifact configures `arti-client` with
`default-features = false` and only `experimental-api`. That does not include
`onion-service-client`; browser HTTP fetch support alone is insufficient.

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
below; browser service reachability passed the isolated runtime contract in Crow run 68.

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
the generated package build is verified as above, while network tests remain.
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
for Arti's running status and returns a peer onion plus `accept(deadlineMs)`.
Only the configured virtual port is accepted. Pending rendezvous handshakes
and accepted streams are bounded, and closing a service cancels its pending
accept and accepted streams. Closing the client also closes raw streams and
the service. The private onion/introduction keys have no export/restore API.
This experimental service build rejects `hs-pow-full` at compile time because
that replay-store port is unfinished; it does not silently emulate its storage.

Browser restart must create a fresh TorClient and onion; permanent member
identity and private contact policy are recovered separately by cmsg. Arti's
running status and native state tests do not establish browser reachability.
That requires genuine Tor circuits between a browser service and a separate
native peer using the generated artifact and explicitly configured test gateway.

## Isolated test network stage

`test-network` adds a separate source patch after `service`. Build it with
`--features browser-test-network`; omitting that feature fails compilation.
Crow run 49 at cmsg `20a55ac815` passed this stage's Wasm compilation check
and all three native ephemeral-state tests. These checks do not run the network.
This artifact requires an explicit `testNetwork` JSON option and fresh fixture
storage in its TorJS constructor. It disables gateway bootstrap archives and
rejects missing configuration, non-loopback fallback sockets, retained public
authority upload/download/vote endpoints, or a vanguard mode other than `full`.
The ephemeral keystore is still forced after reading test configuration.
The production `service` stage has no test-network option or this module.

This stage also applies `arti-service-diagnostics.patch` and, after copying the
service overlay, `tor-js-service-diagnostics.patch`. Readiness failures retain
only fixed labels for the introduction-point manager and descriptor publisher,
plus the latest introduction-circuit error category across the fixture runtime.
The test stage also records static publisher scheduling, period-count, upload
step and per-attempt error categories. Runtime-wide labels describe the latest
observed event; they do not identify a particular service or peer.
These labels contain no error payloads, keys, onion addresses or paths. They
do not relax readiness or deadlines and are absent from the production service
stage.

Use at least four disposable directory authorities, twenty guard relays and
two exits with the fixture's own signed consensus. Full vanguards keep the
normal L2/L3 pools of four/eight. The local-only path needs subnet exclusions
disabled with `path_rules.ipv4_subnet_family_prefix = 33` and its IPv6 value
`129`; changing these is a test-network adaptation. Authority `v3idents` are
flat RSA identity strings. Fallback `rsa_identity`, unpadded standard-base64
`ed_identity` and `orports` come from the generated relay keys, not invented
fixture identities. Keep HSDir parameters consistent with the test consensus.
In particular, C Tor's `TestingTorNetwork` internally changes `hsdir_interval`
without advertising that change in the consensus parameters. The fixture now
uses `chutney.arti.config.tor_config(network)["override_net_params"]` from the
pinned source. Its 20-second voting interval derives an eight-minute onion
directory period; leaving Arti at the public-network 1440-minute default is
incompatible. The public signed consensus and this derivation are retained
before browser execution, including on later failure. Crow run 67 confirmed
the eight-minute override and 26 HSDirs, but the browser service still timed
out with its publisher bootstrapping. That run's startup consensus contained
neither shared-random generation.

The fixture now waits for a currently valid consensus in the native Tor client's
accepted cache containing both canonical 32-byte shared-random values. It
rejects duplicate fields and bounds each `num-reveals` to the four fixture
authorities; that count is not a signature quorum. Native Tor validates the
consensus signatures. Freshness is recorded separately: a consensus can remain
valid after its `fresh-until` time while the client awaits an update. The fixture
also checks that the signed values cover
Arti's current and an adjacent publication period. It retains the public
consensus and a bounded `shared-random-readiness.json` receipt, even on timeout.

In the pinned C Tor 0.4.9.12 source, `shared_random_state.c:164` selects 12
commit and 12 reveal rounds; `new_protocol_run()` at line 770 rotates values
only at the reveal-to-commit transition. `shared_random.c:766` requires
authority agreement before including a value in the consensus. An incomplete
startup cycle can therefore leave values absent. Warmup allows three complete
cycle durations plus four voting rounds (1520 seconds with the existing
20-second interval), covering an initial partial cycle and two full cycles.
The outer fixture supervisor allows 3000 seconds for this warmup, existing
bootstrap/driver limits and cleanup. Tor voting settings and the browser's
60-second service readiness deadline remain unchanged. Crow run 68 passed:
the gate opened after 484.184 seconds with both shared-random values and
Arti period offsets `[0, 1]`. The subsequent browser contract passed all seven
checks; the run also passed all 52 KPS parser and 11 native gateway tests.

Run the pinned gateway as a disposable test child using explicit configuration,
`run --no-sync`, a temporary synthetic KPS identity and
`TOR_JS_GATEWAY_ALLOW_LOCAL_TARGETS=1`. Its relay allowlist must contain only
the fixture's loopback ORPorts; this flag does not bypass the allowlist. Do not
run the gateway install/uninstall commands. Destroy the fixture and its private
keys after the run. All code, keys, relay data and gateway state belong to that
one test; existing host services are not part of the fixture.

This stage tests real Tor cryptography, circuit construction and stream
interoperability in an isolated network. An observer controlling every test
relay is inherent to the fixture, so the result is functional evidence and
cannot establish protection against that observer or public-network capacity.

### Runtime fixture invocation

The root CI workflow owns source staging and matching binding-generator builds.
After applying `test-network`, call:

```sh
bash .ci/tor-runtime-build.sh "$TORJS_CHECKOUT" "$TOR_RUNTIME_ARTIFACT"
python3 browser/upstream/runtime-fixture.py
```

The build requires explicit `CARGO_TARGET_DIR`, `TOR_BINDGEN_BINARY` matching
the upstream lock's wasm-bindgen 0.2.122, and `CMSG_BINDGEN_BINARY` matching
cmsg's 0.2.128. It runs locked builds, installs only project-local npm packages
with lifecycle scripts disabled, and builds the upstream TypeScript/declarations.
Only the stock README gzip-size assertion is omitted in a recorded copy of the
build script; the resulting package version includes `cmsg-fixture` and the cmsg
commit. Nothing is published. Artifact hashes and dependency locks are retained.

The fixture requires `CHUTNEY_SOURCE` at official commit
`6cc158868d722e652975cb4efd5b278d95ff2fbb`, with that source's Python dependencies
available in the isolated CI environment; `TOR_BIN`, `TOR_GENCERT_BIN`,
`TOR_GATEWAY_BIN`, `TOR_NATIVE_PEER_BIN`, `TORJS_DIST`, `BROWSER_BIN` and
`TOR_RUNTIME_ARTIFACT` must be explicit paths. It adds one native client to the
26-relay network. Generated authorities, KPS keys and browser profiles are
temporary; shutdown confirms the owned processes exit before deleting state.
The fixture explicitly selects the local Chutney launcher and loopback IPv4
listeners, with IPv6 disabled, regardless of inherited Chutney defaults.
Listener blocks stay outside the worker's ephemeral source-port range, read
without changing kernel settings. Bounded startup/final diagnostics retain
synthetic listener settings, process status and log tails; private keys and
control authentication files are excluded.

The contract uses the actual generated TorJS APIs and cmsg framing. It first
requires the real KPS gateway to reject a CONNECT to an owned non-relay TCP
canary with 403 while the canary records zero connections. It also requires
the actual Wasm onion API to reject IP, URL, malformed onion and injected route
inputs. The build runs the gateway's existing tunnel validation/resource tests
and browser parser tests, preserving their output. Run 66 passed the native
gateway tests, all 52 browser parser tests, the real non-relay canary assertion,
and actual Wasm rejection of the malformed route inputs. It established working
introduction circuits, then timed out with the descriptor publisher still
bootstrapping. Run 68 passed all these boundaries and the onion reachability
contract below after waiting for the signed shared-random generations.
An independent gateway assertion failure is retained in the runtime evidence
while service diagnostics continue; it still fails the overall result.

The passing run 68 contract has two browser clients publish different onions
with full vanguards and exchange byte frames. A separate native
cmsg process then connects through its test Tor SOCKS endpoint to a browser-owned
onion, exchanges MLS key-package/welcome data over that route, and authenticates
binary cmsg ciphertext in both directions, rejecting replay. Closing the
browser service also cancels pending accept. This checks the generic core and
native framing; the strict contact-policy API has its separate browser contract.
The browser's localhost control request only launches the synthetic native test
participant. It is fixture orchestration, not an application transport endpoint.

The tab's HTTP request interception does not observe every worker, WebRTC ICE,
UDP or browser background request. An empty tab request list does not establish
process-wide network silence; run 62's Chromium diagnostics included background
GCM errors. Gateway restriction and malformed-route assertions support their
specific boundaries, not a general browser anonymity claim.
The separate Crow run 65 isolation probe was denied by the worker's existing
security policy (`unshare: Operation not permitted`). It changed no host network
configuration. Process-wide network confinement remains unverified.
