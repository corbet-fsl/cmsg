# Browser-first library and cfrm boundary

The current source develops one Rust core for browser Wasm and native hosts.
The published `0.1.0-alpha.1` artifact predates this work. These changes have not
been published as a new release or audited as a complete anonymous messenger.

## What each component owns

| Component | Owns | Does not establish |
|---|---|---|
| `MemberIdentity` | A community-scoped member root; independent device authorization; sealed root recovery | Eligibility, device revocation distribution, or protection from malicious application code |
| `Member` | MLS encryption, authenticated participants, independent device leaves, bounded text/binary payloads, encrypted local state | First-contact policy when called directly |
| `Inbox` | Recipient permit admission, owner-controlled contact restrictions, signed sibling contact sync, live first-contact transitions and an optional mandatory reservation-proof gate | A proof verifier supplied by cmsg itself or fresh state after every replica is rolled back |
| `BrowserInbox` | The same Rust policy and live flow, asynchronous publication and an IndexedDB version comparison across tabs | Browser background availability or trustworthy storage callbacks supplied by hostile JavaScript |
| cfrm public board | Member-signed short-lived onion presence and a common full roster | A truthful omission-free roster from a malicious host or confidential public membership |
| cfrm aggregate permits | Blinded allowance withdrawal and authoritative one-use redemption | Nontransferable credits or the full private reciprocal budget |
| cfrm experimental account ledger | Verified hidden-state transitions, shared incoming/outgoing capacity, replay protection and private Active presentations | Production activation, simultaneous settlement of both accounts or mobile proving suitability |
| Eligibility adapter | A currently valid external eligibility signature | Authority to add a device under an existing member root |

The public board has no selected-recipient lookup parameter. A client downloads
the common roster and selects locally. This removes a recipient-specific request
from that API. It does not conceal public membership, presence timing, or a
client's other network behavior.

## Identity and device lifecycle

`MemberIdentity` derives the stable member ID from the community and its public
root key. Each `Member` generates its own device signing key and MLS state. A
device requires both eligibility for that exact key and a root-signed
`DeviceAuthorization`. The browser exposes the joint admission path.

Pairing authorizes a fresh device; copying an MLS ratchet snapshot does not
create a second independent participant. Existing members add device key
packages through normal MLS membership changes. Devices can synchronize ordered
controls and authenticated accepted history privately. New application delivery
requires a fresh live session; an offline recipient has no queued application
delivery. Newly enrolled devices do not automatically receive earlier history.
An unresolved [accounted introduction](reservation-release.md) retains its
original two-device roster until establishment or a fresh admitted introduction.

`renew_device_admission` renews eligibility and root authorization together
without changing the member identity or device key. Expiration and MLS removal
are implemented; a complete community-wide device revocation service is not.

## One introduction, then answer or close

The strict pair flow requires an explicit `FirstContactPolicy` containing an
absolute response deadline and maximum introduction size. There are no chosen
product defaults for these values or the operator's credit budget.

1. Authenticate the invitation and obtain its actual signer with
   `Member::invitation_sender`. Bind the shared introduction identifier to the
   private peer handshake.
2. Register the same identifier and policy at each endpoint, with the correct
   initiator/recipient role. Recipient acceptance verifies the first-contact
   permit through the trusted cfrm adapter.
3. The initiator may send one bounded introduction. The recipient independently
   rejects repeated introduction data even if the initiator bypasses its local
   guard.
4. The recipient sends an actual answer or an encrypted owner-controlled close
   decision. A separately signed claim of answering does not open the strict
   data path by itself.
5. A configured deadline closes the pair locally when the client next runs the
   deadline transition. A suspended browser cannot execute a timer or notify an
   offline peer. Local sender cancellation does not count as a peer response.

A restriction belongs to its blocker and covers the pair across device keys.
Only the blocker may initiate reopening while that restriction applies. The
initial default has no expiry; applications can offer a blocker-selected expiry.
Expiry permits a fresh contact request, never delivery of old buffered messages.
No one-year duration or second-block escalation is hard-coded.

Each owner signs a chained directive covering both parties, the previous control
state, and any expiry. Fresh initiatives bind a new introduction identifier,
policy and MLS group. When both parties have blocked, one cannot erase the
other's restriction. Authenticated sibling synchronization retains the history;
devices must receive it before they can enforce the latest decision. Conflicting
owner histories fail closed. The current native and browser checks cover these
directional rules, including signed attempts to substitute consent fields and
sender cancellation followed by another introduction.

This is a private contact restriction, not an operator-wide behavioral ban.

Strict introduction data currently requires exactly one distinct peer identity
in the conversation. Generic `Member` still supports groups, including the
100-participant tests. Group admission must account for every unfamiliar pair;
the pair adapter does not claim to implement that policy.

## Reopening after group loss

Ordinary reconnects and enrolled-device catchup retain their existing MLS group
and require no new admission callback. Owner reopening can instead establish a
replacement group when the original group state is unavailable. This requires
the preserved contact journal or authenticated sibling history; the identity key
alone cannot reconstruct forgotten blocks or unpaid obligations.

`initiate_replacement` creates a Welcome plus an encrypted fresh directive using
a new device authorized by the same member root. The initial replacement group
contains exactly two currently authorized device leaves. The recipient calls
`preview_replacement` to authenticate the actual inviter, nonce, group and policy
before constructing its private cfrm claim. `accept_replacement` requires a fresh
redemption even for a known contact. A block owned by the recipient still requires
its exact consent before data can pass. Additional devices use normal enrollment.

Replacement state and both outbound frames become visible only after durable
persistence. A pending recipient checkpoint retains the original Welcome,
control and private claim across recovery. Retry and post-redemption acceptance
recheck current credentials and policy. A delayed receipt updates only its exact
archived introduction; old-group ciphertext cannot carry the new nonce. Current
stored receipts can be refreshed after renewal; an archived outbound receipt
has no automatic refresh API.

## Storage and failure ordering

`Inbox::accept` saves the exact pending redemption before spending and saves
the resulting joined/rejected state before exposing it. Ambiguous results retain
the same pending claim for an idempotent retry. A failed final write does not
authorize another spend.

Replacement acceptance uses the same ordering. Restore authenticates the complete
saved bundle at its sealed, locally recorded validation time; incoming requests
cannot choose historical authorization. Network retries use the live clock.
An expired pending request remains available for cancellation without a refund.

Strict data methods stage MLS state, then require atomic persistence of the
encrypted checkpoint and exact outgoing ciphertext before returning output.
The browser wrapper awaits a Promise resolving to `true` only after that local
transaction commits. Incoming plaintext is released after its receive checkpoint
commits. The supplied IndexedDB adapter compares sealed publication versions in
the same transaction, so competing tabs sharing a row cannot publish both
successors. The browser contract exercises two actual database connections.

Authenticated encrypted storage rejects tampering, wrong wrapping keys and wrong
contexts. It cannot identify an old authentic snapshot when every freshness
anchor is also old. Same-root device sync merges closures and first-contact
progress monotonically; conflicting simultaneous introductions require explicit
reconciliation. Siblings cannot independently replay the registered initial
writer's introduction through the strict API.

## Actual permit composition and its limits

The [executable composition](../experiments/community-composition/README.md)
uses actual cmsg device signatures and cfrm verification, issuance and redemption:

1. A member authorizes a blinded request against its pinned allocation policy.
2. The authority atomically debits its durable member allowance and stores the
   blind signature response. Independent devices share that allowance.
3. The client unblinds a common-epoch permit. At acceptance the recipient adds
   private randomness binding the permit to the authenticated pair and exact
   introduction. Only the anonymous request crosses the operator boundary.
4. The authority spends the serial once and signs the commitment. The recipient
   verifies that stamp against its private claim before cmsg joins.

The current composition also exercises owner-initiated replacement groups. It
uses the authenticated replacement preview to prepare the claim and rejects
reuse of the initial permit for the replacement admission.

This is an aggregate bearer gate: permits can be transferred, and an authority
holding the signing keys can issue outside its ledger. Common pinned epochs,
authoritative shared spent state, and separation of issuance from anonymous
redemption are required. Timing and small anonymity sets can still correlate
actions. The relevant constructions are [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474.html)
and the unlinkability analysis in [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html).

The separate experimental [private account ledger](https://github.com/corbet-libs/cfrm/blob/main/docs/account-ledger.md)
now binds hidden state, the debited member, both roles, the exact introduction
and authenticated resolution evidence. Its [v2 policy](https://github.com/corbet-libs/cfrm/blob/main/docs/reciprocity-policy.md)
implements shared capacity, nonrefundable admission turns, Prepared cancellation,
outgoing expiry and bounded refill. Answer refunds both reservations when each
owner's required evidence is accepted; recipient Close refunds the recipient
while the sender's cost remains spent. It does not promise atomic two-account
settlement. cmsg's [protected release](reservation-release.md) requires matching
Active presentations, recipient consent and a trusted current-own-state check.
Local booleans, generic membership proofs and bearer permits do not substitute
for those proofs. The older allocation API's `resolve_private` remains closed;
it is a separate path from this experimental ledger.

The [private accounting review](https://github.com/corbet-libs/cfrm/blob/main/docs/private-accounting.md)
retains the earlier backend comparison and links the current implementation.
An account's latest hiding state commitment can be public without revealing
its contact map. Public markers shared by two named accounts would reconnect
those accounts, so event markers must be owner-specific and peer proofs stay
private. The experimental proof backend is not enabled in production.

## Tor and browser evidence

The core's native transport accepts checksum-valid v3 onion endpoints and fails
closed without its configured Tor listener. The portable frame codec bounds
messages and rejects malformed/truncated streams. It does not hide frame sizes.

The [browser adapter](../browser/README.md) includes pinned source patches for
TorJS/Arti. The stock TorJS package omits the onion-client feature and exposes no
browser onion hosting API; it is not silently accepted as a working onion
transport. Raw-stream and ephemeral-service patches require separate build and
network verification. No production gateway or free bandwidth claim is made.

A browser Tor gateway sees the client IP and encrypted-traffic timing/volume.
Peers should see onion identities. Tor does not establish resistance to every
global traffic-correlation attack. Browser code delivery remains part of the
trust model: JavaScript in the same execution context can access Wasm memory.

## Evidence as of the current development work

See [the browser and composition evidence record](browser-evidence.md) for exact
source revisions, CI results and coverage limits. Public Tor evidence has its
[own validation record](public-tor-validation.md).
