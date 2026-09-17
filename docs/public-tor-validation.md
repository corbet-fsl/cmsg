# Public Tor browser validation

The `tor-browser` CI workflow has an explicit public-network mode:
`TOR_NETWORK=public`, `TOR_STAGE=service`, `RUN_RUNTIME=1`.
It builds the pinned TorJS/Arti service overlay without the private-network
feature, then runs `browser/upstream/public-runtime-fixture.py`.
All test participants and payloads are synthetic.

## Required evidence

The browser owns its Arti clients, circuits and ephemeral onion services.
A disposable native Tor client supplies SOCKS transport for the separate Rust
cmsg participant. The browser's KPS gateway transports encrypted Tor bytes to
advertised relays. It is a loopback-only child of the test, with its own state;
it is not a deployed gateway.

The runtime contract requires:

- Two browser clients bootstrap using the public Tor directory authorities.
- Two distinct browser-owned onion services publish with full vanguards.
- Browser peers exchange binary cmsg frames through an onion service.
- A separate native Rust participant connects to a browser-owned onion and
  exchanges authenticated MLS binary messages in both directions.
- Replayed MLS ciphertext is rejected; closing the service cancels acceptance.
- The gateway refuses local and unadvertised non-relay targets. The owned local
  canary receives zero connections.
- Invalid onion routes fail in Wasm, and the page makes no unexpected external
  HTTP requests.

The generated bindings, Wasm modules, native binaries, source overlays and
dependency locks are recorded by digest. Public mode retains the dependency
snapshot documented in [the lock provenance](../browser/upstream/locks/README.md).
It does not perform a fresh dependency upgrade. CI artifacts distinguish
public-network results from the signed private-network fixture.

An explicit `TOR_DIAGNOSTICS=1` build adds fixed service-status/error categories
without changing public directory configuration, vanguards or Tor behavior.
Its artifacts use `tor-public-diagnostics` instead of `tor-public`.
Publication has its own explicit 420-second test budget; individual stream
operations remain limited to 60 seconds. Arti's directory-upload retry episode
can itself last 300 seconds. Both services must satisfy Arti's documented
`is_fully_reachable()` predicate (`Running` or `DegradedReachable`); every
service's startup readiness is recorded explicitly. Reduced redundancy is
visible, and no other state qualifies. Successful authenticated exchange is
still required independently of readiness. See [operational tuning](tuning.md).

## Scope

A passing run demonstrates interoperability on the public network for its
recorded source and environment. It does not measure mobile feasibility,
multiple independent physical hosts, long-running reliability, censorship
resistance, or production gateway capacity. Page request interception does not
establish process-wide browser network confinement or absence of metadata
leaks. The gateway can observe the client address and traffic timing/volume.

The native participant is an onion client in this test; the browser owns the
onion service. Native onion hosting has separate earlier experiment evidence.
The fixture does not deploy a service or publish the experimental package.

Long-running publication has a separate pinned-upstream code-review finding:
`tor-hsservice/src/publish/reactor.rs` returns from its time-period loop when
one period has no dirty directories, potentially skipping a later period
that needs reupload. This is not the initial-publication timeout observed in
these runs and is not exercised by this short exchange. It remains follow-up
work before claiming long-running service reliability.

## Result

**Passed on 2026-09-17:** [Crow run 84](https://crow.corbet.ch/repos/10/pipeline/84),
step `24771`, tested cmsg `d39022b35ebe4a1bc2569acaa5f7ac2f206b29c3`.
This was the public `service` build with `TOR_DIAGNOSTICS=1`, full vanguards
and no private-network feature. Both services reported `running` in this run;
acceptance of `degraded-reachable` is separately covered by adapter tests.

All nine live runtime checks above passed, including native/browser MLS in
both directions, replay rejection and browser/browser framing. The gateway
canary received zero connections; no unexpected page HTTP requests occurred.
The same run passed 23 Chromium contract groups, 52 KPS parser tests,
11 gateway tunnel tests, nine gateway configuration tests, three ephemeral
state tests and two process-cleanup regressions.

| Phase | Observed duration |
| --- | ---: |
| Native Tor and gateway bootstrap | 50.108 s |
| Both browser Arti clients bootstrap | 39.645 s |
| First / second onion publication | 50.222 / 41.998 s |
| Native connection / bidirectional MLS exchange | 3.742 / 1.687 s |
| Browser/browser connection and framing | 7.796 s |
| Entire public fixture, including cleanup | 211.146 s |

These are one successful run's timings, not latency guarantees. Earlier runs
exposed the private-state ancestor permission check, insufficient publication
time and the wrapper's overly strict readiness predicate; those were corrected
without changing public Tor directory configuration or stream deadlines.

Environment: Chromium `152.0.7977.64`, Node `24.19.0`, native Tor `0.4.9.12`.
Native Tor and the gateway retained the same accepted public consensus: 9,316 relays,
3,778 onion directories and nine directory signatures. Its SHA-256 is
`8ac1f3ebd9121dc012966edb5d6f2a3bdd0c02e454a8fc8e3a4e6be7991fc74b`.
The receipt records successful owned-process cleanup.

The artifact directory is
`/workspaces/component-releases/cmsg/d39022b35ebe4a1bc2569acaa5f7ac2f206b29c3/tor-public-diagnostics/`.
Downloaded runtime evidence, public consensuses, provenance, test logs and
source receipt were checked against the remote manifests; this was a partial
artifact download, not a second execution or a full package download.

- CI source archive SHA-256: `1af2a3f5abdd4fa158b3f177b67dc3cf46d9938a108e9269e6b0371e9b17f86c`.
- Runtime `SHA256SUMS`: `22ab9a9ee20f98355a75850142b8f348dd9952c84f4d2de1e67ba4c0d920a0a3`.
- `browser-tor-runtime.json`: `12a507d3fad672b1160279343469f5b2025160f8b68da57385d7bc5b23a16074`.
- `public-network-provenance.json`: `09ca6e80a7195aca2736209c31fad0b170cf4e37ddde12d0b01fc32965abdb5f`.
