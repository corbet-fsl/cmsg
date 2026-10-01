# Member local API

`cmsg::door` owns the action/version, typed body/result, event, authority,
effect and bounded errors. HTTP, MCP tools, CLI command descriptions and
TypeScript are projections of this registry, not separate definitions.

The current implemented actions are `runtime.status`, `runtime.describe`, and
`client.revoke`. `board.status` projects the real `cbrd::Status` result schema
and returns `Unavailable` until the Board runtime is bound. The generated
`GroupView` type is the owner cgrp type reexported by cbrd, not a copied DTO.
Domain owner ports are still being integrated. Runtime status
reports every missing facade as unavailable and blocks preload. No membership,
balance, transport, profile or group success is fabricated.

Create one `Door` per community with exact permitted origins for each role.
`pair_client` is an embedding control, called only after trusted local pairing;
it is absent from the public action registry. Capabilities are random, bounded,
expiring and revocable. They authorize an explicit local action set, not remote
service authority. Admin, root and member origins are separate. Remote role
sessions will be supplied by Foyer; no copied cvld metadata or frontend bypass.

The shared invocation is `{action, version, body}`. `Door::dispatch` takes its
bytes, the transport's origin/capability, and trusted current time. Requests
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
is a result-only convenience for reads; consumers needing effect events use
`invoke`. Neither operation adds retries or domain logic.

The transport sends the invocation to the embedded local door; it does not
implement domain behavior. Generated artifacts include the exact Rust registry
snapshot. Schemars derives schemas from Serde types; Axum supplies native HTTP,
getrandom creates local capabilities, and SHA-256 indexes their digests. None
of those primitives is implemented here.

Remaining integration includes real owner schemas/operations, Foyer projections,
Mesh readiness, bounded event delivery, and combined encrypted checkpoint/output
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
