# cmsg browser bindings

The browser package runs the same Rust MLS core and wire format as native cmsg.
It accepts opaque binary messages and offers a text convenience method.

```js
import { init, BrowserIdentity, BrowserMember, BrowserInbox } from '@corbet-labs/cmsg';

await init();
const member = new BrowserMember();
const identity = new BrowserIdentity(communityId);
const publicKey = member.chatPublicKey();
const deviceAuthorization = identity.authorizeDevice(publicKey, issuedAt, expiresAt);
// Obtain issuer eligibility for identity.memberId() and this device public key.
member.bindDeviceAdmission(JSON.stringify(grant), JSON.stringify(trustedIssuer), deviceAuthorization);
const inbox = new BrowserInbox(member); // Consumes the low-level member.
```

`BrowserIdentity` owns the permanent community identity root and authorizes
independently generated device keys. Issuer eligibility alone cannot enroll a
device under somebody else's identity. Identity recovery exports only sealed
ciphertext, bound to the expected community and member ID.

`BrowserMember` exposes low-level group creation, invitations, joining, binary/text
encryption, authenticated receive, participant removal and encrypted snapshots.
Application conversations use `BrowserInbox` to enforce first-contact acceptance,
stable-identity exclusions and asynchronous durable state transitions.
`sendBytes(Uint8Array)` preserves arbitrary bytes, including invalid UTF-8;
`sendText(string)` has the core text size limit. A received object exposes
`kind`, `memberId`, `bytes`, and optional `text`. Display text literally.

Trust configuration uses the Rust `AdmissionTrust` JSON field names:
`community_id`, `policy_digest`, `issuer_public_key` (32 numbers).
An admission grant uses its existing camelCase wire fields. Issuer trust is
application configuration; do not accept it from a conversation peer.

Call `free()` on Wasm-owned objects when finished. Erase JavaScript's own key
and plaintext copies. Rust memory is accessible to code in the same JavaScript
context. The host must supply secure code distribution, passkey wrapping
material, and atomic durable storage for sealed state. Restoring old valid
snapshots does not detect rollback or merge concurrent device state.

## Durable browser sessions

`BrowserInbox` owns both contact policy and the MLS session. Its mutating methods
take a wrapping key, context bytes and an async persistence function:

```js
async function persist(checkpoint, outboundFrames) {
  await storage.commitCheckpointAndOutbox(checkpoint, outboundFrames);
  return true;
}
await inbox.createGroup(wrappingKey, context, persist);
// After authenticating the unique peer, both endpoints register the same nonce
// and bounds, with roles "initiator" and "recipient" respectively.
await inbox.beginFirstContact(peerMemberId, introductionId, role,
  responseDeadline, maxIntroductionBytes, wrappingKey, context, persist);
const wire = await inbox.sendBytes(payload, wrappingKey, context, persist);
```

The storage function must atomically write the encrypted checkpoint and every
outbound frame, and resolve `true` only after the write is durable. IndexedDB
applications wait for transaction completion, not an individual request's
success event. Storage is application supplied. cmsg never treats a synchronous
return, a missing return, or a rejected Promise as successful persistence.
Failed writes leave the published session unchanged. Store and retry exact
outbound ciphertext; generating another send advances the ratchet again.

`accept(welcome, recipientRedemption, key, context, persist, redeem)` returns
`joined`, `rejected`, `pending`, `needsPermit`, `busy` or `blocked`. The recipient's
trusted policy adapter prepares `recipientRedemption` using
`invitationSender(welcome)`, which authenticates the invitation signer.
The `redeem(opaqueBytes)` callback resolves `accepted`, `rejected` or `pending`.
It runs only after pending intent is durably stored. Ambiguous results keep the
same pending claim for recovery; a final write precedes publishing a joined
session. The callback must use the configured anonymous policy-service route.

The primary API requires a strict first-contact record for the unique
authenticated peer. Omitting it fails closed. The application supplies an
absolute response deadline and introduction byte limit; cmsg invents neither.
The initiator can send one introduction until an authenticated answer arrives.
The recipient can answer after receiving it or call `closeContact` to commit and
send an encrypted member-owned block. The received `kind` is `contactClosed`.
Its default lasts until the blocking member explicitly starts a new contact.
The blocked member cannot clear it. `closeContactUntil(until, ...)` takes an
optional absolute expiry; expiry permits a fresh initiative but does not revive
old messages or answer an old introduction.
`sendBytes`, `sendText` and `receive` apply deadlines durably before further
traffic; hosts also call `applyDeadlines` when updating idle session state.
This policy currently supports pairs. Multi-member MLS remains a low-level
`BrowserMember` capability until a group first-contact policy is defined.

`blockMemberUntil(peer, until, ...)` saves a member-owned block locally for
private device sync. `setBlocked`, `cancelPending` and `mergeContactSync` also
await durability. Clearing a temporary flag cannot clear a member-owned block.
`initiateContact(freshNonce, responseDeadline, maxIntroBytes, ...)` sends a signed
encrypted fresh initiative and starts another one-introduction gate. Only the
member who blocked can initiate while their block remains active. If both
members blocked, the other must explicitly `consentContact` too. Receiving
either policy transition reports `contactPolicyChanged`. Old queued messages
are bound to their old introduction and cannot answer the new one.
`exportContactSync` returns private contact data: carry it only inside an
encrypted channel authenticated to another root-authorized device of the same
member. `renewDeviceAdmission` saves its new credential and outbound MLS commit
together. `restore` restores the combined encrypted inbox and session.

`awaitingPeerResolution` distinguishes an unresolved remote obligation from
local conversation closure. Private inbound/outbound receipt accessors retain
the signed result for recovery. After device-certificate renewal,
`refreshOutboundResolution` can renew an expired stored decision without
changing its pair, nonce or outcome; `closeContact` can then send a fresh
encrypted close. Raw receipt bytes contain contact identities, are not MLS wire
frames or anonymous proofs, and must never be sent to board logs or telemetry.

`signPresence`, `signDisconnect` and `authorizeAllocation` expose only typed
board statements. There is no generic device-signing or private-key export API.

## Tor transport

### Experimental raw onion node

The `/tor-streams` entrypoint uses the separate pinned `service` build described
in `upstream/`. Its source provides browser-owned onion publication and raw
Arti streams. Patch application, compilation and a real browser/native Tor
round trip remain required evidence; the stock npm TorJS package is rejected.

```js
import { createTorJsOnionNode } from '@corbet-labs/cmsg/tor-streams';
const node = await createTorJsOnionNode({
  gateway: configuredGateway,
  bootstrapDeadlineMs: 180000,
  operationDeadlineMs: 45000,
});
const listener = await node.listen({ port: 4242, maximumStreams: 8, deadlineMs: 60000 });
// Sign/publish listener.host and listener.port with this device's live lease.
const stream = await listener.accept();
const incomingWire = await stream.receive();
const incoming = await inbox.receive(incomingWire, wrappingKey, context, persist);
```

`node.connect(peerOnion, peerPort)` returns the same framed stream. Its wire
format matches native `FramedStream` directly; it requires no HTTP payload
server. `send` and `receive` each allow one pending operation, can proceed in
opposite directions concurrently, and close on framing/transport failure.
Closing a node closes its listener and streams. Each node can launch one onion
service; restarting creates fresh onion keys. Permanent member identity and
contact policy remain separately encrypted cmsg state. A terminated or
suspended browser cannot promise continuous reachability.

### HTTP client bridge

The optional `@corbet-labs/cmsg/tor-js` entrypoint requires the pinned onion-enabled
build of `tor-js@0.4.1` described in `upstream/`. The stock npm artifact omits
Arti's `onion-service-client` feature and is rejected before network bootstrap.
The patch and its generated artifact still require compile and network evidence.
The adapter requires an explicitly configured TorJS gateway and a whole-request
deadline. No gateway, billing account, CDN fallback or direct-IP message route
is supplied. Bundle and serve TorJS' `wasm-file` asset with the application.

```js
import { createTorJsOnionTransport } from '@corbet-labs/cmsg/tor-js';

const transport = await createTorJsOnionTransport({
  gateway: configuredGateway,
  deadlineMs: 45000,
});
const replyWire = await transport.exchange(peerOnion, peerPort, encryptedWire);
const reply = await inbox.receive(replyWire, wrappingKey, context, persist);
```

This adapter performs one request/reply exchange against a peer-owned onion
HTTP listener. It does not publish a browser onion service, provide an inbox
server, queue offline messages, or make a suspended browser reachable.
TorJS 0.4.1 exposes client HTTP fetch, not a public onion-service hosting API.
Transport connectivity and hosting need separate end-to-end evidence; codec
tests and browser crypto tests do not establish either.

The browser constructs Tor circuits. Its gateway forwards encrypted bytes and
can observe client IP, timing, volume, and the entry relay. The gateway is part
of the bandwidth path for the entire session. The adapter suppresses its TorJS
logger, sends a fixed generic User-Agent, accepts only checksum-valid v3 onion
destinations, rejects redirects, and applies strict response bounds. A deadline
closes the dedicated TorJS client and rejects the operation; upstream in-flight
connection cancellation is limited by TorJS' own implementation.

### Peer HTTP wire contract

- Request: `POST /cmsg/v1/exchange`.
- Content-Type and Accept: `application/vnd.cmsg.frame`.
- Body: one nonempty frame, encoded as uint32 big-endian length plus bytes.
- Response: status 200, the same Content-Type, and an exact Content-Length.
- Response body: exactly one frame, at most `MAX_WIRE_BYTES` payload bytes.
- Redirects, compression, chunked responses and multiple response frames fail.

Applications supply MLS ciphertext as frame payloads. This HTTP wrapper does
not identify members, attest a gateway, or enforce first-contact admission.
Do not replace TorJS fetch with browser fetch or a cleartext onion gateway.

## Build and evidence

Build the Rust library for `wasm32-unknown-unknown`, then generate the Web
bindings with a `wasm-bindgen` CLI matching the resolved crate version, output
name `cmsg`, into `browser/pkg/`. Copy the repository license into the package
before packing. The checked-in package excludes generated artifacts.

`tests/browser.rs` runs in a real browser using `wasm-bindgen-test` and covers
binary/text MLS round-trips, authentication failures, replay rejection,
encrypted restore, and the portable route/framing bindings.

The generated-JavaScript ABI contract is `browser/contract.mjs`. Serve the
repository root after generating `browser/pkg`, then run in a real browser:
`await import('/browser/contract.mjs').then(m => m.runBrowserContract())`.
It returns `{ evidence, passed }` or throws on failure. It exercises real
WebCrypto, Wasm and IndexedDB transactions, plus separately labeled scripted
transport failure cases; it does not claim live Tor connectivity.
