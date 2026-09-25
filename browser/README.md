# cmsg browser bindings

The browser package runs the same Rust MLS core and wire format as native cmsg.
It accepts opaque binary messages and offers a text convenience method.

cmsg owns reusable transport, cryptographic and storage logic. Product screens,
DOM rendering, styles, navigation and user flows belong in cmeet. This
package contains headless browser bindings and validation fixtures, with
no product UI.

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
import { openIndexedDbInboxStore } from '@corbet-labs/cmsg';
const storage = await openIndexedDbInboxStore('my-cmsg-inboxes');
// Reuse this stable local ID for the same Inbox across reloads and tabs.
const persist = storage.persist(localInboxId);
await inbox.createGroup(wrappingKey, context, persist);
// After authenticating the unique peer, both endpoints register the same nonce
// and bounds, with roles "initiator" and "recipient" respectively.
await inbox.beginFirstContact(peerMemberId, introductionId, role,
  responseDeadline, maxIntroductionBytes, wrappingKey, context, persist);
// Complete the authenticated live handshake before sending application data.
```

The supplied IndexedDB adapter commits the encrypted checkpoint and outbound
records in one transaction with strict durability, resolving `true` only after
transaction completion. The third persistence argument contains native-generated
`expectedVersion`, `nextVersion`, device identity and live outbox metadata. A
write succeeds only if the stored version matches; competing tabs cannot both
publish successors. On conflict, reload the stored checkpoint before retrying.
A missing row accepts only version zero: deleting storage cannot silently import
an older nonzero chain. `read(localInboxId)` returns the stored record, and
`close()` closes the database without deleting its contents.
The stored `outbound` array belongs to that latest publication; it is not an
accumulating queue. Send returned frames while their live session permits it,
and use the Inbox's retained control journal for control recovery. An embedding
that adds a separate queue must atomically apply cancellation metadata too.

Alternative hosts must implement the same atomic version check and commit
contract. cmsg never treats a synchronous return, missing return or rejected
Promise as successful persistence. Failed writes leave the published session
unchanged. The adapter serializes local tabs sharing one database; independent
devices and rollback of all storage require separate recovery guarantees.
Persisted application ciphertext is eligible only for its still-live session.
Restoring or losing that session cancels pending delivery; it must not be blindly
retransmitted from the outbox. Control and accepted-history recovery are separate.

`LiveInboxStream.open` also accepts an optional `schedule(category, operation)`
storage callback. It lets an embedding serialize cmsg's asynchronous mutation
and its synchronous Wasm getters with the application's own Inbox queue. The
category is `send`, `receive`, or `control`; the operation includes any control
wires generated while processing the current frame. The callback must not wait
for peer input. Read the transport before scheduling `receive`; bounded writes
of the generated live/control wire may complete inside the callback so the
release check remains adjacent to the write. Pass the raw `BrowserInbox` to the
stream when using this hook so a second proxy queue is not nested around cmsg's
own queue.

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

After group-state loss, `initiateReplacement` starts an owner-authorized fresh
group using a separately prepared, root-authorized `BrowserMember` and the peer's
fresh KeyPackage. The returned `BrowserReopeningInvitation` contains `welcome`
and encrypted `control`; both frames enter the durable outbox together. The
existing contact journal stays in force, including either member's block.
Before preparing that recipient claim, `previewReplacement` authenticates the
complete welcome/control bundle without consuming the replacement member. Its
private JSON result contains `inviter`, `introductionId`, `groupId`, and `policy`
with `response_deadline` and `max_intro_bytes`. Prepare admission from these
authenticated fields; keep the identifying context at the endpoint.
`acceptReplacement` always needs a fresh recipient-prepared admission claim,
including for a known contact. It saves the exact pending bundle before external
redemption. `retryPendingReplacement` resumes that same intent and claim after
ambiguity or encrypted checkpoint recovery. `pendingReplacementControl` pairs
with `pendingWelcome` for local recovery; neither goes to the policy operator.

The replacement handle is borrowed during each operation. A failed initial write
leaves it usable for retry. After the first successful durable checkpoint, the
Inbox owns that member's state and the external handle becomes a fresh, unbound
member. This transfer also occurs for durable pending acceptance. Reopening gets
one new introduction; a reply or explicit block is still required.

`awaitingPeerResolution` distinguishes an unresolved remote obligation from
local conversation closure. Private inbound/outbound receipt accessors retain
the signed result for recovery. `applyResolution(receiptJson, key, context,
persist)` verifies a privately delivered peer receipt and saves its encrypted
checkpoint before returning whether it resolved a previously unresolved
introduction. Receipts for archived introductions cannot change the current
contact gate. No raw receipt enters the transport outbox. After device-certificate renewal,
`refreshOutboundResolution` can renew an expired stored decision without
changing its pair, nonce or outcome; `closeContact` can then send a fresh
encrypted close. Raw receipt bytes contain contact identities, are not MLS wire
frames or anonymous proofs, and must never be sent to board logs or telemetry.

`signPresence`, `signDisconnect` and `authorizeAllocation` expose only typed
board statements. There is no generic device-signing or private-key export API.
`signProfileStatement` on both `BrowserMember` and `BrowserInbox` accepts cfrm's
eight supported canonical profile/discovery signing transcripts, using this
same root-authorized device key. It can be supplied directly as cfrm's
`identity.sign` callback; see the [schema and authority boundary](https://github.com/corbet-libs/cmsg/blob/main/docs/profile-signing.md).

## Transport and packaging references

The browser package exposes experimental raw Tor onion streams and an optional
HTTP client bridge. The embedding supplies the configured gateway, deadlines,
and live peer endpoints. Permanent identity and encrypted contact state remain
separate from ephemeral onion-service keys.

- [Tor adapter setup, lifecycle and peer HTTP wire contract](https://github.com/corbet-libs/cmsg/blob/main/docs/browser-transport.md)
- [Building bindings, packing the npm archive and browser validation](https://github.com/corbet-libs/cmsg/blob/main/docs/browser-package.md)
- [Pinned upstream TorJS source and patches](https://github.com/corbet-libs/cmsg/blob/main/browser/upstream/README.md)
- [Public-network validation](https://github.com/corbet-libs/cmsg/blob/main/docs/public-tor-validation.md) and [onion renewal evidence](https://github.com/corbet-libs/cmsg/blob/main/docs/onion-renewal.md)
