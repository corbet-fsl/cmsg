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

Per-session onion keys could make in-memory service state valid, provided every
restart generates fresh service/introduction keys and old key material is never
restored independently of its replay state. Permanent cmsg identity remains a
different member root key. This is an implementation path requiring tests,
not a current hosting capability or a settled persistence policy.

## Raw stream stage

After the onion-client patch, `tor-js-onion-stream.patch` plus the
`onion_stream.rs` overlay expose actual Arti `DataStream` bytes. Copy the overlay
to `crates/tor-js-wasm/src/onion_stream.rs` in the isolated pinned checkout.
The client, stream and service patches applied to the exact source archives in
Crow run 45 at cmsg `755d83b1a`. Its full service stage also passed the Wasm
compilation check. Generated TorJS bindings and a network test remain pending.
The stock dependency is not enabled by the cmsg production adapter.

`connectOnion(host, port, deadlineMs)` accepts only canonical checksum-valid
onions. This initial registry permits one pending outbound connection per
client and up to 64 established streams. `read(maximum, deadlineMs)` returns
at most 64 KiB and `write(bytes,
deadlineMs)` accepts at most one cmsg-sized chunk. One read and one write can
proceed concurrently; overlapping operations in the same direction fail.
`close()` aborts both outstanding operations and drops their stream halves.
The cmsg frame codec can then interoperate directly with native `FramedStream`.
The embedding factory still needs a whole-bootstrap deadline and a dedicated
client shutdown policy, since the TypeScript client waits for bootstrap before
entering the Wasm connect deadline.

The service stage must produce the same stream type from Arti's accepted
onion-service streams. It additionally needs fresh ephemeral key/state ownership
and full-lifetime introduction replay protection. No JavaScript callback or
local echo is accepted as evidence that a browser onion service is reachable.

## Isolated source application and compilation

The `service` source stage now includes an in-memory state backend, target
gates for filesystem replay code, one-shot ephemeral introduction ownership,
and a bounded Arti service/stream API. Patch application is verified as above;
the new browser runtime behavior still requires generated-binding and network tests.
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
This artifact requires an explicit `testNetwork` JSON option and fresh fixture
storage in its TorJS constructor. It disables gateway bootstrap archives and
rejects missing configuration, non-loopback fallback sockets, retained public
authority upload/download/vote endpoints, or a vanguard mode other than `full`.
The ephemeral keystore is still forced after reading test configuration.
The production `service` stage has no test-network option or this module.

Use at least four disposable directory authorities, twenty guard relays and
two exits with the fixture's own signed consensus. Full vanguards keep the
normal L2/L3 pools of four/eight. The local-only path needs subnet exclusions
disabled with `path_rules.ipv4_subnet_family_prefix = 33` and its IPv6 value
`129`; changing these is a test-network adaptation. Authority `v3idents` are
flat RSA identity strings. Fallback `rsa_identity`, unpadded standard-base64
`ed_identity` and `orports` come from the generated relay keys, not invented
fixture identities. Keep HSDir parameters consistent with the test consensus.

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

The contract uses the actual generated TorJS APIs and cmsg framing. Two browser
clients publish different onions and exchange byte frames. A separate native
cmsg process then connects through its test Tor SOCKS endpoint to a browser-owned
onion, exchanges MLS key-package/welcome data over that route, and authenticates
binary cmsg ciphertext in both directions. This checks the generic core and
native framing; the strict contact-policy API has its separate browser contract.
The browser's localhost control request only launches the synthetic native test
participant. It is fixture orchestration, not an application transport endpoint.
