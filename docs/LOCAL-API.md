# Member local API

`cmsg::door` owns the action/version, typed body/result, event, authority,
effect and bounded errors. HTTP, MCP tools, CLI command descriptions and
TypeScript are projections of this registry, not separate definitions.

Local lifecycle actions include `runtime.status`, `runtime.describe`, and
`client.revoke`. `login.start`, `login.poll` and `login.cancel` share owner Rust
lifecycle types and require the actual passkey bootstrap. Launch URLs, callback
capabilities, assertions and PRF secrets are never login response fields.

Trusted embedding binds actual Board, Vault and Mesh values through
`bind_board`, `bind_vault` and `bind_mesh`. Each is fixed to a configured member
origin. Vault binding derives Inbox's member binding only after the actual
Keys owner accepts `lineage`; subsequent Inbox reads recheck it and load from
that Vault's authenticated Store. `inbox.history`, `inbox.relation` and
`inbox.delivery_status` return the original Threads, Contacts and Delivery DTOs.
No separate snapshot/store or caller-supplied pseudonym authorizes a read.
Every Inbox read checks Foyer's current signed minimum runtime version before
and after the owner await, with the same grant expiry and a nonregressing clock.
An updated requirement can withhold a completed read. Lifecycle and login
actions remain available so the client can refresh, lock or close its owners.

`board.status` and `board.disconnect` return the actual Board Status.
`vault.lock` consumes and locks the actual Vault before emitting VaultLocked.
`mesh.disconnect` closes the retained actual Mesh listener before emitting
MeshDisconnected. The embedding still owns backend node shutdown. These actions
do not fabricate attendance, delivery acceptance or network health. Missing
facades refuse; runtime preload is `unavailable` until the embedder reports the network up (`Door::set_preload_ready`: Tor bootstrap and onion publication done, then `ready`) while live end-to-end
bindings are incomplete. Groups types come from cbrd, without a copied DTO.

Create one `Door` per community with exact permitted origins for each role.
`pair_client` is an embedding control, called only after trusted local pairing;
it is absent from the public action registry. Capabilities are random, bounded,
expiring and revocable. They authorize an explicit local action set, not remote
service authority. Admin, root and member origins are separate. Remote role
sessions are supplied through `bind_foyer(origin, role, Sessions)` by trusted
embedding code. This control is absent from every callable projection. The role
selects the local portal surface; cvld checks actual membership rights. An admin
or root signs into the member portal as an ordinary member. The Vault ceremony
origin is `vault.<community>.<base>` under the pinned community RP; the global
passport uses `wallet.<base>` separately.

The shared invocation is `{action, version, body}`. `Door::dispatch` takes its
bytes, the transport's origin/capability, and trusted current time, and must be
awaited. `surface::invoke` is asynchronous as well. Requests
cannot select another role or community. Responses are `{status:"ok", result,
events}` or `{status:"error", error}`. Errors contain no member values or
dependency details. Key and PRF values have no API path.

CLI adapters use the owner's `ErrorCode::exit_code()`: 64 for malformed or
unsupported requests, 77 for denied authority, 69 for unavailable integration,
and 75 for capacity, clock or reconciliation refusals. Success is zero.
Keep incoming request bytes intact until `Door::dispatch`; parsing them into a
generic JSON value first would erase duplicate fields before the typed decoder.

Native `door::native::router` projects POST `/v1/<action>` with a typed JSON
body. Require an exact Host, Origin, application/json and bearer local client
capability. Bind the router to a local listener; do not install request/body
logging middleware. Every handled response is no-store. The native and Wasm
dispatchers use the same implementation and test vectors.

The native adapter constructs the Door and child facades on a dedicated thread
with a current-thread Tokio runtime. `router(factory, hosts, clock).await` accepts
an initialization factory whose future and resulting Door need not be Send;
only that factory crosses threads. `router_with(factory, hosts, clock).await`
can also return one protected, in-process startup value, such as a paired local
token for a trusted test host. It never serializes that value. HTTP holds a
bounded sender. Admission permits
bound authentication, body wait and invocation together. Authentication runs
before body consumption and again after the channel wait with fresh trusted time.
Once queued, the owner retains each invocation and its permit through completion,
even when the HTTP waiter disconnects. A panic during execution returns Reconcile
and permanently fences the runtime. An authentication panic returns Unavailable
and fences it. No arbitrary partially-mutated state is reused.

`native::Embedded::start(factory, Pairing, clock).await` binds a literal loopback
listener, pairs its Client inside the owner and exposes only `client()`. Pairing
contains the configured origin, portal role, allowed actions and bounded lifetime;
it does not supply remote authority. `shutdown().await` first closes HTTP and
then closes and drains the owner queue and joins its thread. HTTP drain alone
would miss work belonging to disappeared HTTP waiters. Dropping an Embedded
signals graceful listener shutdown; callers that need confirmation await shutdown.

Foyer operations are projected directly from `cfyr::contract()` under `foyer.`.
Only positive `x-client-access=forward` metadata is exposed. The original owner
role, scope, effect and request/result schemas remain attached; missing/unknown
metadata refuses projection. Configured independent service sessions select the
owner scope; JSON cannot choose a transport or authority. Raw duplicate object
keys are rejected recursively before Value conversion. Check effects are not
labelled read-only: some owner checks mutate ephemeral state. Token-bearing
trusted authentication remains inside Foyer.

After a dispatched Foyer operation, a damaged, oversized or uncertain result
returns Reconcile and fences further forwarding through that binding. Dropping
an in-flight borrowed browser future leaves that same uncertainty latch. Local
status remains usable. There is no automatic retry or synthetic effect cache.

`door::surface::{bundle,openapi,mcp_tools,cli_commands}` exports the generated
views. The `registry` example exports the bundle in CI. `tools/generate.mjs`
uses maintained `json-schema-to-typescript` to emit `client.ts`:

```typescript
const client = createCmsgClient(pairedLocalTransport);
const status = await client.call('runtime.status', {});
// Preserve the complete owner envelope and events for effectful operations.
const outcome = await client.invoke('client.revoke', {});
```

`invoke` preserves the typed result, events and owner refusal envelope. `call`
returns the result or throws CmsgError. Both deliver successful completion events
to `subscribe(listener)`; it returns an unsubscribe function. Observer exceptions
cannot convert a committed action into an action failure. Neither operation adds
retries or domain logic.

The transport sends the invocation to the embedded local door; it does not
implement domain behavior. Generated artifacts include the exact Rust registry
snapshot. Schemars derives schemas from Serde types; Axum supplies native HTTP,
getrandom creates local capabilities, and SHA-256 indexes their digests. None
of those primitives is implemented here.

Remaining integration includes actual login/Vault custody, additional owner
operations, Mesh readiness, bounded event delivery, and combined encrypted checkpoint/output
publication. The local API foundation is not end-to-end product acceptance.

Native applications use the owner's `door::native::Client::new(base, origin,
ClientToken) -> Result<Client, ErrorCode>` and
`Client::invoke_bytes(&[u8]) -> Result<Output, ErrorCode>` (async). The constructor
consumes a capability delivered by trusted host pairing; there is no frontend
mint endpoint or token command-line/file convention. The client uses literal
loopback HTTP only, no proxy/cookies/redirects, a total timeout, sensitive auth
headers and a bounded streaming decoder. Transport errors use Result; action
refusals preserve Output and its existing process exit taxonomy.

POST `/invoke` accepts the original `{action, version, body}` bytes through the
same authorization and dispatcher as per-action routes. CLI/MCP/TUI transport
adapters must preserve these bytes so duplicate fields remain detectable.
The integration test starts a real Axum loopback Door, pairs actual owner
capabilities in trusted test setup, and invokes status/description/revocation
and refusal paths through reqwest. This proves local transport, not production
pairing bootstrap, member authority or the full network demonstration.

A separate native process can receive the opaque capability through an inherited
private pipe/socket, then call
`ClientToken::from_protected_transport(Zeroizing<Vec<u8>>)`. Import checks only
fixed canonical encoding; the Door still authorizes the digest, origin, expiry
and explicit action set. Imported random bytes grant nothing. The frontend
adapter owns bounded pipe reads; tokens must not enter argv, environment values,
logs or raw files. This is transport plumbing, not a production pairing bootstrap.

Native invocation never retries or follows redirects. Once sending begins, a
transport timeout, missing/invalid headers, truncated/oversized body, invalid
Output or mismatched status returns `Reconcile`: the action may already have
committed. Valid owner Output is preserved exactly. Local pre-send request size
refusal remains `Capacity`. A caller must reconcile through owner state, never
blindly retry a mutation. This uses the maintained [reqwest never-retry policy](https://docs.rs/reqwest/latest/reqwest/retry/fn.never.html).

The generated TypeScript client also runs against an actual native Door in CI.
A test-only host transfers its local capability over an inherited private pipe;
the client checks status/discovery, unavailable Board, strict duplicate decoding,
origin refusal, revocation events and subsequent denial over real loopback HTTP.
This establishes local generated-client parity, not production bootstrap or remote
member workflows. The host requires the non-default `conformance` feature.

The same generation emits `browser.ts`, exporting
`createBrowserClient(configuration: BrowserConfiguration)`. Its Wasm module is
built from the same Rust source/lock snapshot. The configuration is public pinned
deployment data: community, exact page origin, portal role, primary Foyer scope,
and one or two original service addresses. It contains no local capability,
remote bearer, PRF or secret. Rust verifies the actual window origin and creates
the local capability internally. No global injection is used.

The returned client has the same registry-typed `call`, `invoke` and `subscribe`
methods plus `dispose(): Promise<void>`. Browser disposal stops admission, waits
for admitted operations even when their JavaScript promises were abandoned, then
closes bound Mesh listeners. The member-page runtime rejects any Door holding
Vault custody; the separate per-community vault-origin iframe/worker bridge must
own decrypted keys and profile state. Native custom transports may supply
their corresponding drain in createCmsgClient's optional lifecycle parameter;
without that parameter disposal closes only the generated client wrapper.

The default browser constructor binds actual unauthenticated Foyer transports
and optionally the real configured Forum transport/Link/Board. Board initially
reports Disconnected. Configured login uses the original sealed popup and retained
public server authentication, but custody and Mesh require their real initializers.
This is an explicit partial runtime, with no
ready event or preload transition. Trusted Rust can attach an already-composed
Door through BrowserRuntime::attach without exposing its sessions or capability.
The actual browser regression and generated-module smoke test retain these
refusals. Native, browser and strict coverage execution are required before
acceptance.

Native hosts may use `Embedded::configured(native::DeviceConfiguration,
lifetime_seconds, clock).await` for the same public deployment configuration.
Foyer/Board constructors run inside the owner thread, and the returned Client
remains privately paired to literal loopback. The optional `forum` configuration
supplies original Forum origin and explicit response/timeout/search-cache bounds.
Construction creates no attendance, passkey authority or readiness.

`board.heartbeat` and `board.depart` accept an empty body. The Door constructs
the original owner request, asks Board for its immutable Prepared transcript,
and signs only that transcript through actual Vault Keys. Sessions, nonces,
signatures and arbitrary signing bytes are absent from local request/output
schemas. The actual authority's intent-admission half must be supplied through
trusted `bind_vault_with_intent`; the guard remains owned through remote
completion. Original request/session/nonce/signature remain private after an
uncertain response; further mutation is fenced and never retried automatically.
A signed departure emits BoardDisconnected only after the child completes.

`board.attend` loads the committed Profile through the retained Vault owner.
`board.search` accepts only `cursor` and `page_size`; `board.watch` accepts only
the opaque `cursor` returned in the preceding page's `watch` field. Watch updates
that exact held search window through Board's original delta operation. Both
return the owner's `DiscoveryPage`, including the next watch cursor.
`board.discovery` rechecks the held view before returning display entries.
`board.groups` takes an empty body and returns one `GroupView` per group in the
committed Groups checkpoint, under the policy projected from the current signed
Rulebook settings (`groups.*`, `seats.*`, `waves.*`). It is local and read-only:
no Forum request, consent or membership decision. It refuses unless the retained
Vault owner and the current Foyer Charter are available.
`board.group_act` takes `{"intent": {...}, "accept_profile_visibility": bool}` where
`intent` is one of `create`, `fork`, `join`, `leave` or `describe` (tagged by
`"intent"`), and returns the group views after the change. The caller never names
the acting member and never supplies a signature, command or policy: the retained
owner supplies the local member and signs consents with the device key, Groups
decides, and nothing changes unless the whole transaction publishes. Joining or
opening a room requires `accept_profile_visibility: true` (members of the group
may see your private profile); without it Groups refuses. The action refuses with
`unavailable` until the retained owner provides the group integration.

Commands that need other members (`create`, `fork`, `join` with vouches) run in
three door actions over the members' direct conversations; nobody is ever added,
removed or consented for by someone else, and groups stay immutable (a change is
always a fork the members consent to; there are no admins):

- `board.group_propose {intent, accept_profile_visibility}` signs only the local
  member's own consent and returns `{operation, invitations: [{member, text}],
  committed}`. Send each `text` unchanged in the direct conversation with that
  contact. A command that needs nobody else commits at once (`committed` set).
- `board.group_message {from, text}` takes a text received in the conversation
  with `from` (`from` comes from the authenticated conversation, never from the
  text). An invitation is only stored and returned as `state: "invitation"` for
  the member to decide; it is refused unless `from` is the acting member and an
  established contact, the local member is a consenting party, the request is
  fresh and the policy epoch is current. A consent or decline from an invited
  member is admitted only for that member, that operation and that exact command
  digest; the group is prepared and published (Groups re-checks contacts,
  devices, standing and policy) only when every consent is present. A decline
  ends the proposal. Pending proposals and invitations live in memory only and
  expire with the consent window (one hour); a restart means proposing again.
- `board.group_answer {operation, accept, accept_profile_visibility}` is the
  member's own decision on a stored invitation; it returns `{actor, text}` to
  send back in the conversation with the actor.

`board.profile_publish` takes `{"profile": {...}, "rules": [...], "reachability": [...]}`
and publishes the member's own answers and rules as one signed bundle. The caller
never supplies a revision, key, signature, credential or block rule: the next
revision follows the committed publication, Envelope generates a fresh profile
key, the credential-authorized device signs both projections, Guard admits them
against the current Charter, and the Vault commits profile, key and publication
in one atomic transaction. Block rules come from Contacts only. A restricted-field
change needs a fresh credential and is refused until admission supplies one. The
action releases no profile key to anyone and ends the current Forum presence, so
the member attends again with the committed publication. It refuses with
`unavailable` until the retained owner provides the profile integration.

Search and watch retain the original signed request through the network wait.
Before disclosure, they reload the committed Profile under the same Vault and
rebuild verification from Foyer's current signed Charter, including the published
minimum client version. Cancellation or failed current verification clears the
held view. Uncertain network completion requires reconciliation; it never triggers
an automatic retry. Restricted contact-detail fields remain refused when their
required detector is unavailable. Full admission/accounting and successful
native/browser end-to-end discovery qualification remain outstanding.


### Browser passkey login ownership

The existing `login.start/poll/cancel` registry rows are shared by native and
browser owners. The vault host alone installs the private frame gesture slot;
page-only BrowserRuntime construction cannot do so. Start fetches the original
Foyer discoverable challenge, prepares CPKY and returns Pending. The visible
vault document calls `VaultHost.continue_login` synchronously on its own real
click; it never routes activation through the member MessagePort. The popup
consumes its public launch before loading the generated CMSG owner and calls
`PopupLogin` for its own Continue and sealed handover. No secret or credential is
projected through the generated client.

Door retains the original wait and server-finish futures. Only the public
assertion enters Foyer; opaque custody stays with the Rust session owner. Old
completion/cancellation cannot mutate a newer frame gesture generation. An unsent
ceremony expires at its reported deadline, discards even a queued callback, and
permits a fresh attempt. An already-started server finish keeps its uncertainty
fence until the original result or reconciliation; expiry cannot roll it back. Owner
shutdown drains an admitted login_finish before clearing grants. Unknown
post-send effects remain fenced and are never retried as a new login. Current
success is `authenticated_pending_custody`, never Complete or network readiness.

The real HTTPS fixture seeds a pending registration through the original
passport/server path, enrolls a real browser test credential, then exercises
generated login, actual frame and popup clicks, original HPKE, verified Foyer
session, authenticated lobby and unavailable custody. Native shared-lifecycle
regressions remain in place. Compilation/execution, generated equality and full
coverage are required; adding fixture source does not qualify a browser.


### Trusted login custody handover

`Door::prepare_login_custody(origin, &ClientToken, now)` is a trusted Rust
composition method, absent from the action registry and every generated wire
projection. The shared native/browser login owner consumes the original opaque
Passkeys result directly into `cvlt::PreparedOpen` once. It requires the matching
local origin and live grant with `login.start`, a Member portal with Community as
its primary service, an unambiguous Foyer, and the same successfully installed
original session before its exclusive deadline. Foyer correlates the session with
a weak opaque generation stamp; equal public user/role/deadline values are not
session equality. Reauthentication or logout invalidates an earlier stamp.

No Store is opened and no root, Wallet or authority is created by this handover.
A missing PRF or initializer refusal consumes the attempt; repeating it cannot
recover the original secret. Cancelling before handover drops the retained result.
After handover, the preparation belongs to the trusted composer, which must drop
it on cancellation and recheck current authority before binding custody. The
login remains `authenticated_pending_custody`; cancellation after taking the
preparation does not pretend to revoke its independent ownership. Complete and
runtime readiness still require the original accepted owners and checkpoint.

The added shared Rust fixture uses original owner-generated challenges, an actual
maintained software PRF authenticator and real server session acceptance on native
and Wasm targets. It covers one-use transfer, exact local scope/origin, original
session replacement/logout/expiry, grant expiry, cancellation, clock regression,
uncertainty and initializer refusal. Its software gesture is not a platform or
popup qualification. The separate actual HTTPS popup/HPKE fixture, native/Wasm
compilation, full coverage and successful Authority/Wallet composition remain
required; no execution claim accompanies this source change.
