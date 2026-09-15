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

The separate experimental [private account ledger](https://github.com/corbet-labs/cfrm/blob/main/docs/account-ledger.md)
now binds hidden state, the debited member, both roles, the exact introduction
and authenticated resolution evidence. Its [v2 policy](https://github.com/corbet-labs/cfrm/blob/main/docs/reciprocity-policy.md)
implements shared capacity, nonrefundable admission turns, Prepared cancellation,
outgoing expiry and bounded refill. Answer refunds both reservations when each
owner's required evidence is accepted; recipient Close refunds the recipient
while the sender's cost remains spent. It does not promise atomic two-account
settlement. cmsg's [protected release](reservation-release.md) requires matching
Active presentations, recipient consent and a trusted current-own-state check.
Local booleans, generic membership proofs and bearer permits do not substitute
for those proofs. The older allocation API's `resolve_private` remains closed;
it is a separate path from this experimental ledger.

The [private accounting review](https://github.com/corbet-labs/cfrm/blob/main/docs/private-accounting.md)
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

- cmsg `80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`: [161 native tests and Wasm checking](https://crow.corbet.ch/repos/10/pipeline/76), plus [21 Chromium contract groups](https://crow.corbet.ch/repos/10/pipeline/77), cover live delivery, reservation-gate boundaries, IndexedDB competing writers and recovery. Scripted transport cases and verifier doubles remain separately labeled.
- cfrm `eddc92835b2e2b08bc431852c8ff3332203198eb`: [the v2 Answer and Close composition](https://crow.corbet.ch/repos/9/pipeline/58) passed with actual browser-generated account/peer proofs, the Rust ledger and cmsg protected release. This experimental composition is separate from the older isolated Tor run below; it does not establish production or mobile operation.

Earlier evidence, with its original source and scope:

- cmsg `1e70a802b54c04ba4815c7f124390ce4a2aeaf7a`: [138 native tests and the Wasm target check](https://crow.corbet.ch/repos/10/pipeline/59), step `23959`. The total is the sum of the passing test-result lines across 24 nonempty executables. It includes 16 directional-contact tests, authenticated replacement preview, both-owner consent, pending recovery/expiry, archived receipts, malicious sender cancellation, old-group rejection and the 100-member group test. Rust `1.97.1`, Cargo `1.97.0`.
- The same cmsg revision: [actual Chromium/Wasm contract](https://crow.corbet.ch/repos/10/pipeline/60), step `23961`, on Chrome `152.0.7977.64` and Node `24.19.0`. Its 12 named contract groups cover generated bindings, real MLS cryptography, identity/recovery, IndexedDB checkpoint/outbox durability, replacement-handle transfer and restored pending retries. Transport cases are explicitly scripted. The harness observed no unexpected tab requests; this is neither a host packet capture nor live Tor evidence.
- The same cmsg revision with cfrm `2c4fa47c59dfd8eb2fdc058ee171836ebc097d99`: [four actual library-composition tests](https://crow.corbet.ch/repos/10/pipeline/61), step `23963`. Real member/device signatures, blind issuance and verified redemption gate initial and replacement groups; exact retries and independent devices cannot multiply the member allowance. This does not implement the private reciprocal budget.
- cfrm `3bc89d0`: [21 Rust tests, 55 historical JavaScript tests, and portable permit Wasm checking](https://crow.corbet.ch/repos/9/pipeline/33), plus [63 actual Chromium checks](https://crow.corbet.ch/repos/9/pipeline/32) for the signed public roster, blind-permit flow, encrypted checkpoints and tampering.
- cmsg `755d83b`: [pinned TorJS/Arti service Wasm compilation and three ephemeral-state tests](https://crow.corbet.ch/repos/10/pipeline/45). The separate private-test-network artifact [passed these checks](https://crow.corbet.ch/repos/10/pipeline/49) at `20a55ac8`. Generated-binding and network behavior require separate runtime evidence.
- cmsg `b23221271f7170a4f665e3834f4302a4a1a33ff0`: [actual browser Tor runtime](https://crow.corbet.ch/repos/10/pipeline/68), step `24021`, passed seven checks on the 27-node signed private Tor network. Two browser-owned onion services published with full vanguards; browser/browser framing and browser/native root-authorized MLS binary traffic worked both ways, with replay rejection and pending-accept cancellation. The real gateway refused the non-relay canary with 403 and zero connections; Wasm rejected malformed routes. The same run passed 52 KPS parser and 11 native gateway tests. Chromium `152.0.7977.64`, Node `24.19.0`, C Tor `0.4.9.12`. The [overlay record](../browser/upstream/README.md) explains the test-only configuration and required signed-randomness initialization. This is isolated-network evidence, not a public-network deployment check.

GHA is the primary executor; Crow supplies the same core/browser scripts as a
fallback. The results above were produced on Crow while GHA was unavailable.

These checks establish their named behavior. They are not a proof of no leaks,
a cryptographic audit, mobile-background testing, or process-wide network confinement.
