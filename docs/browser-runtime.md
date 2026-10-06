# Browser runtime composition

The real fixture binary accepts `OUTPUT --https CHAIN.pem KEY.pem` to add a
loopback HTTPS listener for the original community router. `https.base` is its
only new output; existing component URLs remain HTTP. The helper retains the
original fixture owner, caps connections at 64, limits TLS handshakes to 5 seconds
and HTTP connections to 60 seconds, and awaits shutdown with a 5-second drain
before cancelling and joining remaining tasks. Call `shutdown().await` before
runtime teardown; Drop requests that same drain without waiting.

CI supplies ephemeral PEM files, a certificate with the emitted loopback IP SAN,
and browser/client CA trust. Native LiveMembership needs the original CVLD TLS
trust constructor; `SSL_CERT_FILE` alone does not configure its reqwest Rustls
WebPKI roots. No verification bypass is supported. Browser acceptance additionally
requires the parent-owned real fixture configuration and HTTPS page hosting:
public origin `https://community.<fixture base>`, RP `community.<fixture base>`,
frame and popup origin `https://vault.community.<fixture base>`, and matching
certificate SANs for all requested authorities. The existing alpha component
fixture does not establish those browser requirements. Reuse
`HttpsFixture::start(cvld::api::router(owner.door.clone()), owner, chain, key)`
with that configured owner; preserve Host, Origin and WebAuthn checks. Supplying
TLS establishes transport only, with no new member grants or A/B acceptance claim.

`cmsg-acceptance-fixture MODE FIXTURE_DIR CONFIG CHAIN KEY OUTPUT` launches one
original `Door::global` or `Door::community` (`MODE=global|community`) with
`SystemClock` and the matching original `Config::read`/`CommunityConfig::read`.
CI supplies a trusted, exclusively owned, existing ephemeral fixture directory;
all paths, including config file references, are absolute and resolve inside it.
Input files are capped at 1 MiB, paths at 4096 bytes. The database must be a local
`file:///` URL without a token; its parent already exists, and database/SQLite
sidecar symlinks are rejected. The launcher creates no directories or input
material: CI supplies original keys, TLS certificates and fresh original policy,
rulebook and trust files for the configured host/RP/vault origins. `listen` is
ignored; the reviewed HTTPS helper binds an ephemeral loopback port. Supply the
correct certificate SANs and trusted CA as above; host/origin checks stay intact.
OUTPUT must be absent. Atomic, mode-0600 publication contains only `{ "base":
"https://127.0.0.1:PORT", "mode": "global|community" }`. Startup is capped at
30 seconds; maintenance runs every 30 seconds with a 10-second deadline. CI owns
process lifetime (15-minute serving cap); Ctrl-C, SIGTERM, expiry, maintenance
failure and output failure await HTTPS cleanup with the owner retained. The
manifest remains after exit; CI must track process liveness and own cleanup.

The generated `createClient()` remains on the top-level community page. Its
MessageChannel terminates in `vault.<community>.<base>`, where `VaultHost`
checks the actual origin and direct top-level parent. The existing visible-frame
gesture, popup passkey ceremony and sealed HPKE handover remain the login path.

`VaultHost::attach_with_composer` retains a Rust `VaultComposer` in the same
actor that owns Door. The composer receives the actual client token after each
dispatch; it can consume `Door::prepare_login_custody` once, construct original
owners, and update the pending login output after durable acceptance. Refused
requests permit negative observation and cleanup only; their original errors
survive the hook. Composition failure closes the composer. Disposal drains
admitted work and closes the composer before Door shutdown. Implementations
must also close their owners on Drop, including failed host attachment.

The public `VaultHost` constructor installs the existing
`browser::restore::Composer` through `attach_with_composer` when its pinned
`browser_tor` configuration is present. An omitted or null `browser_tor` keeps
the bare partial host; a configured host without the `browser-tor` feature refuses
with `Unavailable`. Configuration never establishes custody or readiness.
First creation remains separate from this already-enrolled restore path.

`browser::deployment::Configuration` contains only explicit original transport,
Ferry, discovery, Records, application and startup budgets, optional local record
storage/inbound-watch budgets, ENV0 freshness bounds, signed bootstrap PeerInfo
wire bytes and a local IndexedDB name. The host's existing total JSON bound applies;
bootstrap count is bounded by `discovery.peers` and its aggregate bytes by
`maximum_bootstrap_bytes`. Original PeerInfo parsing and signature verification
run before attachment; original discovery revalidates signatures and Tor endpoints
when starting. Browser transport limits (64 streams, 600000 ms bootstrap, 60000 ms
operation), Ferry validation, discovery lanes/peers, Records consensus width,
inbound-watch validation and application limits retain their original checks.
All budgets are explicit; no deployment defaults confer acceptance. The onion
scope is SHA-256 of `cmsg.tor.scope.v1` followed by a zero byte and the immutable
runtime community's UTF-8 bytes; no second scope input is accepted. These public
data types support native schema generation; owner construction is gated by
both Wasm and `browser-tor`.

The factory supplies `RefuseWatches`: both watcher methods return original
`cdht::Error::WatchRefused`. No member watch signer is currently available.
Restoration is polling-only through the original forced Records reads, with
their original agreement and validation; no background polling scheduler or
client subscription is claimed. Original Records construction permits an empty
client-watch table. Optional server-side storage still serves authenticated
inbound watches and notifications through the unchanged original implementation.

`network_browser::BrowserTor::start` consumes the actual
`PreparedOpen::transport` session and retains it for the runtime lifetime. Its
CKMG browser initializer constructs the original CTRN Node and Ferry Messages.
It never switches to member Keys-derived transport identities. The fixed
JavaScript factory invokes the maintained `createTorJsBackend` with
`snowflake: true`; no gateway, loader override or caller factory is accepted.
Each start gets an original TorJS `MemoryStorage` instance for its Tor cache.
This ephemeral cache is separate from the encrypted member Store, whose browser
backend must be the original CWST IndexedDB owner.

Startup is guarded: failure or cancellation stops the Node and drops transport
custody. `close()` stops the Node, cancels an active transport authority check,
and wipes the session when its mutex becomes available. CKMG's cancellation
guard wipes custody when that check is dropped. Queued signing calls refuse
after close. Dropping the owner also stops the Node even if a Messages handle
survives. At most `MAX_CLIENTS` node operations can wait or run. The synchronous
`with_node` callback lends original signing/DH only; returned owned envelopes
can cross network awaits after the session guard is released. These calls must
be polled independently of Door while the composer awaits Records.

Start proves only Tor bootstrap. `messages().listen()` must await actual onion
publication before TorDiscovery accepts its signed advertisement. Neither that
publication nor constructor configuration proves Vault or product readiness.
The concrete browser TransportClient supplies TorNodeIdentity and Records
identity. The composer supplies TorWatcher and member-record recovery above
original CDHT Records. A second independent Mesh listener
cannot share the browser backend's one onion service.

`browser::records::Network` now claims the running BrowserTor's single listener
and retains original TorDiscovery/TorRecords plus `TorRecords::run_shared` on a local
wasm task. The parent's `Identity` capability supplies that exact transport,
advertisement signing and its originating ENV0 wall-clock/window; `TorWatcher`
remains an explicit original capability. No member credentials are constructed.
The same authenticated receiver handles original Records and AppCall/AppMessage
operations. `applications()` exposes the retained original `TorApplications`
Mesh backend built from that exact discovery owner; listening consumes its bounded
queue without publishing a second onion service. Configuration requires explicit
`application_queue` (1–1024 events) and `application_payload` (1–32768 bytes),
validated before listener claim. Original maintenance remains independent.
Startup cancellation, service exit, close and Drop stop the transport, close
application delivery/replies, mark watches lost and abort retained Ferry drivers;
`shutdown` drains tasks.
The `browser-tor` feature selects `cmsh/tor-records` and the original CDHT dependency.
This owner wiring has not been built or executed and establishes no A result.

`browser::mesh::Owner::bind` consumes that live Records network and binds original
Mesh over its retained `TorApplications`. The existing Door `BoundMesh` owns Mesh
and its one application listener; no second onion listener is published. Retain
the returned Rust guard in the composer. Guard or facade teardown closes network
custody and application replies and schedules Records/Ferry and Mesh-pump drain;
`shutdown` awaits completion. The actor first calls synchronous composer close,
then awaits its required `drain` before locking Vault/Store. Mesh lifetime wiring
is enabled for `browser-tor`. Inbox dispatch remains separate.

`browser::restore::Composer` is the trusted Rust-only, single-attempt restoration
composer for an already-enrolled pending login. It retains the actual transport,
supplied watcher, Records network, IndexedDB backend and Mesh owner; original
HTTPS/current-policy/recovery owners gate all custody. Missing records never
create a replacement Vault. Failure, cancellation, negative output and Drop close
lifetimes; `drain` awaits original shutdown before dependent Store teardown.
The actor passes the original action name for selection. After binding, only
login start/poll results pass through `complete_login_recovery`, which rechecks
the original session, bound Vault and live member/device set without caching an
acceptance. The public VaultHost factory now selects this composer when configured;
browser execution and acceptance remain unverified.

Integration requirements:

- The `v01` module and `browser-tor` feature now select the browser owner,
  `ckmg/browser-tor`, wasm CTRN without default features and
  `gloo-timers/futures`. Records composition also needs the selected CMSH
  `tor-records` and original CDHT dependencies.
- Resolve the fixed module specifiers `ctrn/browser/pkg/ctrn.js`,
  `ctrn/browser/tor-streams.js` and `tor-js/wasm-file` to the same selected
  maintained browser artifacts. Keep CTRN's relative `pkg/ctrn.js` import
  pointing at that same initialized module. Stock TorJS is insufficient.
- Retain the parent's `CustodyLifetime` with the composer and close it on lock,
  verified removal, cancellation and revocation. Close the corresponding
  BrowserTor owner; do not rely on a surviving Messages clone for custody.

The current-lineage Records bootstrap read-key sequence remains an integration
dependency. This change does not select that sequence or supply accepting
authority. No native/wasm build, browser journey, networking or coverage result
is established by these source changes.

## CI artifact preparation

Run `bash .ci/v01-browser-package.sh ports`, then `service`, then `assemble` on CI only.
Keep `CI_COMMIT_SHA` and absolute `CMSG_BROWSER_OUT` unchanged across phases; `ports` requires a new output directory.
The parent supplies the root `v01` lock, Git redirects, worker resource admission and target locking.
Source IDs may retain GitHub spellings; metadata, not URL spelling, selects CMSG/CTRN/Ferry.
`ports` needs existing `CARGO_TARGET_DIR`, matching wasm-bindgen and original `tools/node_modules` dependencies.
It builds the three ports in the root graph and runs the original API generator and schema/TypeScript checks.
Node runs `.ci/v01-browser-host.ts` natively. Provisioned `esbuild` compiles the
`src/door/browser/tor.ts` Wasm snippet into the CMSG entry and selected CTRN
`browser/tor-streams.ts` into the import-mapped `tor-streams.js`; no JS output is checked in.
CTRN fixture build steps emit `tor-streams.mjs` to preserve their existing runtime URLs.
`service` invokes the resolved CTRN `.ci/browser-build.sh service-artifact` entry without rebuilding ports.
Provide isolated clean `TORJS_SOURCE` and `ARTI_SOURCE` checkouts at the original upstream manifest revisions.
TorJS must contain its original provisioned `node_modules` and have no previous `dist`.
Also provide existing `TORJS_TARGET_DIR` and optionally `TORJS_BINDGEN` (defaults to `wasm-bindgen`).
The helper checks bindgen against the pinned TorJS lock, applies the original service patches/locks, and builds offline.
Only local Arti lock edges may change; missing tools/dependencies refuse without installation or downloads.
It retains patch evidence and final locks, producing `service/dist` and `service/receipt.json`; no `GITHUB_ENV` is used.
The receipt binds `ctrn_package_id`, `stage: service`, `upstream_inputs` and `dist_files` SHA-256 maps.
`assemble` verifies that receipt and the existing ports before copying the complete dist; it does not rebuild.
Serve `public/cmsg/` intact; load its import map before Vault/popup modules, with `.wasm` served as `application/wasm`.
`member.js` aliases generated `createConfiguredVaultClient` as `createClient`; `vault.js` and `popup.js` retain original entries.
Member `/cmsg/member.json`, isolated Vault `/cmsg/vault.json`, and the top-level Vault-origin popup remain distinct.
No entry starts automatically. The isolated Vault configuration selects the real
composer through `browser_tor`; constructor wiring alone does not prove the A journey.
