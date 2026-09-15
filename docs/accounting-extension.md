# Accounting signature extension v1

Status: implemented source awaiting its first CI validation. This is a private
evidence interface, not a production private-accounting backend or a credit rule.
Existing Ed25519 member roots, root-signed device certificates, MLS keys and
`ContactResolution` signatures remain unchanged. A device may additionally
delegate a P-256 accounting key, including a key held by WebCrypto.

## Authority and state

`Member::delegate_accounting` delegates a sealed-recoverable `AccountingKey`.
`delegate_accounting_public_key` delegates an externally held uncompressed P-256
public key (X || Y, 64 bytes). The latter demonstrates authorization, not secret
possession. Proofs/signatures must establish any needed possession separately.
The state-secret commitment is an opaque canonical lowercase hex bytes32 value;
the selected proof scheme must additionally enforce its field/secret relation.

`Inbox::prepare_accounting_contact` returns the original strict introduction's
nonce, actual MLS group, role, policy and current signed history tips. Applications
use that context for reservation. It does not itself prove or authorize a debit.
Strict records now retain their group ID. Older snapshots remain readable but
records without this binding cannot export accounting evidence. Sync rejects
conflicting group bindings, including a missing-versus-present binding; it does
not reconstruct missing history from an arbitrary current group.

`Inbox::accounting_receipt` derives a P-256 witness from a persisted recipient
Answer or Close. Answer requires the actual strict send/receive flags; sender
self-cancellation cannot produce a recipient receipt. `accounting_acknowledgment`
additionally requires the original sender's own persisted receipt of the MLS
answer, and binds its signature to the exact recipient Answer object. Preparing
either object with an external delegated signer leaves its P-256 signature empty;
the corresponding verifier rejects it until signed.

These methods currently derive **current introduction** evidence. They do not
invent missing archived group context or migrate an expired delegation to a new
one. Already exported receipts remain independently verifiable as described below.
Local endpoint checks describe honest library behavior. A modified client can sign
claims directly; a private proof must constrain role, pair, nonce, group, policy,
delegation and receipt/acknowledgment fields to its accepted obligation. A signed
history hash does not prove the history's contents or the Inbox transitions.

## Canonical encodings

JSON is compact UTF-8 as produced by the declared Rust serde structs. IDs and
Ed25519 keys/signatures use canonical unpadded base64url. P-256 public keys and
state-secret commitments use canonical lowercase hex. P-256 signatures are
64-byte P1363 r || s, with low-S required. ECDSA hashes the complete message with
SHA-256. Integers below use unsigned big-endian encoding. Times are whole seconds
in 1..=2^53-1; delegation intervals are `[issuedAt, expiresAt)`.

The `AccountingDelegation` Ed25519 signing array is:

```
["cmsg.accounting-delegation.v1", 1, hashScheme,
 communityId, memberId, devicePublicKey, accountPublicKey,
 stateSecretCommitment, issuedAt, expiresAt,
 b64url(SHA256(serde_json(admission))),
 b64url(SHA256(serde_json(authorization)))]
```

It includes the complete issuer grant and root-device authorization by digest.
Their serialization follows their Rust struct field order, not a general JSON
canonicalization algorithm. Verify the original objects with the Rust adapter;
do not accept a peer's independently asserted delegation digest. The digest is:

```
SHA256("cmsg.accounting-delegation-digest.v1\0" ||
       transcript_length_u32 || transcript || Ed25519_signature64)
```

Every authority is checked at delegation issuance and current acceptance time;
delegation expiry cannot exceed either parent credential's expiry. The proof
enrollment leaf must bind the verified member, key, state-secret commitment,
delegation digest and interval. The comparison circuit's scheme identifier is
`poseidon2-bn254-fixed-128-v1`; cmsg's generic library does not select that policy.

### Recipient receipt: 357 bytes

```
"cmsg.accounting-receipt.v1\0"          // 27 bytes
community_digest32                    // SHA256(raw community UTF-8)
responder_member_id32
peer_member_id32
initiator_member_id32
introduction_nonce32
group_binding32
delegation_digest32
contact_policy_digest32
history_digest32
ed25519_resolution_digest32
kind_u8                               // 1 Answered, 2 ClosedForever
recipient_role_u8                     // exactly 1
accounting_issued_at_u64
```

The responder is always the original recipient, distinct from the peer, and
initiator must equal peer. `ClosedForever` retains the existing enum/wire spelling;
the actual block's owner/expiry/reopening history remains directional.
`accounting_issued_at` is the accounting-signature time. The original Ed25519
resolution has its own signed timestamp, which cannot be later. A fresh accounting
signature never rewrites the original receipt's time or decision.

Derived fields:

```
group_binding = SHA256("cmsg.accounting-group.v1\0" || group_length_u16 || group)
policy_digest = SHA256("cmsg.accounting-contact-policy.v1\0" ||
                       response_deadline_u64 || max_intro_bytes_u32)
history_digest = SHA256("cmsg.accounting-contact-history.v1\0" ||
                        responder_history_tip32 || peer_history_tip32)
resolution_digest = SHA256("cmsg.accounting-resolution-digest.v1\0" ||
                           original_transcript_length_u32 ||
                           original_Ed25519_transcript || original_signature64)
receipt_digest = SHA256("cmsg.accounting-receipt-digest.v1\0" ||
                        receipt_message357 || P256_signature64)
```

The group is nonempty and at most 256 bytes. Policy uses the existing
`FirstContactPolicy` serde fields `response_deadline` and `max_intro_bytes`.
History tips are the verified local chains' directional tips, oriented as
recipient then initiator; absent history uses zero tips. Merely constraining
`history_digest` in a circuit is not verification of those chains.

### Original sender acknowledgment: 255 bytes

```
"cmsg.accounting-ack.v1\0"              // 23 bytes
community_digest32
initiator_member_id32
recipient_member_id32
introduction_nonce32
group_binding32
exact_answer_receipt_digest32
initiator_delegation_digest32
acknowledgment_issued_at_u64
```

The object contains the completed recipient Answer receipt and the original
sender's delegation. It requires Answered, matching hash schemes, an original
sender signer, and acknowledgment time at least the accounting Answer time.
An incoming Answer credit relation must verify both signatures and bind both
delegation leaves, not simply accept the hash of a supplied Answer object.
Neither this acknowledgment nor a recipient receipt establishes reading,
sincerity, fairness, or an operator balance change.

## Current and historical verification

`verify_accounting_receipt` and `verify_accounting_acknowledgment` accept new
network evidence only with currently valid signer authority. The embedded
Ed25519 resolution also remains verified at its own issuance time. An expired
original resolution needs the existing durable resolution refresh before a new
current receipt can be issued; that refresh does not reopen the conversation.

The explicit `*_historical` APIs additionally require the **exact delegation
digest(s) retained in an accepted reservation**. They verify signatures and
authority at signed times and reject a verifier clock earlier than the evidence.
Copying the expected anchor from the arriving object would defeat that boundary.
They permit later use of valid archived evidence after signer expiry. An incoming
recipient Close needs no renewed eligibility or signature from its silent peer.
Changing delegation/key/scheme/checkpoint requires an authenticated continuity
protocol outside this extension; an unrelated fresh enrollment is not a refill.

## Named cfrm request authorization

`Member::authorize_account_request` signs only this fixed Ed25519 transcript:

```
"cfrm.account.request.v1\0" || request_id32 || circuit_digest32 ||
verifying_key_digest32 || device_public_key32 || issued_at_u64 ||
expires_at_u64 || statement_digest32 || proof_digest32
```

The request ID must be nonzero and its interval must fit the current admission
and root-device authorization. cfrm must recompute the canonical statement and
exact proof hashes, check owner/device binding and consume its request/state
transaction atomically. This helper does not inspect a proof or supply credit.

## Native and browser fixture interface

`examples/accounting_fixture.rs --serve` is a **synthetic**, bounded JSON-line
fixture. Responses are `{ "ok": ... }` or `{ "error": "fixed label" }`.
It accepts no private P-256 keys and keeps newly generated root/device identities
for the lifetime of one process. No production identity determinism is implied.

- `enroll`: `keys` (2..16 `{accountKey, secretHash}` entries), optional
  `peerExpires` (default 10000). It creates actual root/device delegations at time
  100 and returns normalized original objects, trusted fixture issuer, and the
  real nonce/group/policy/roles before any introduction is sent. Owner index 0 is
  the initiator; owner 1 is the recipient. The two participant roots remain held.
- `answer`: performs the actual MLS introduction, persisted Answer and sender
  receipt, returning `{receipt, signingBytes}` with an unsigned P-256 receipt.
- `advance`: changes the monotonic synthetic clock to 300 or 600 after an
  Answer or Close. The enrollment response declares the host's fixed
  `acceptedTimes: [100, 300, 600]` and community SHA-256 hex digest; these are
  fixture scope, not production time policy.
- `ack`: accepts `answer` completed by the browser's P-256 signer, validates it,
  and returns `{acknowledgment, signingBytes}` derived from the actual sender Inbox.
- `close`: takes `now` and creates a persisted recipient Close after an actual
  introduction. A fresh process with peer expiry 200 and Close time 300 exercises
  the silent-peer expiry boundary.
  The Close scenario does not require outgoing Close settlement: cfrm may keep
  that sender reservation until its original deadline. A subsequent current
  sender refund request must still use an eligible device/delegation; choose
  `peerExpires: 10000` for that fixture scenario and keep `peerExpires: 200` for
  separate historical-authority tests. No expired authority is revived.
- `verify`: accepts the complete original `delegations` list. It checks retained
  root/digest identity plus actual cmsg authority, returning normalized entries.
- `verifyReceipt` / `verifyAcknowledgment`: take the completed named object and
  `now`. `verifyHistoricalReceipt` / `verifyHistoricalAcknowledgment` additionally
  use delegation anchors from the process's retained originals, never request pins.
- `authorize`: takes `owner` (0 or 1), hex32 `requestId`, `circuitDigest`,
  `verifyingKeyDigest`, `statementDigest`, `proofDigest`, plus `issuedAt` and
  `expiresAt`; returns the signed request fields and original admission/device
  authorization. `now` is the fixture scenario's current clock.

The Wasm exports provide these operations through `BrowserAccountingKey`,
`BrowserMember`, `BrowserInbox` and bounded JSON verifier functions. They perform no operator I/O.

The native suite passed 148 tests plus Wasm checking at `90dfb3a77070a3f14bc2283834fa0d3188aab68c`
(Crow 10/69). The actual Chromium contract passed 19 groups at
`e8bac3ec17abafce942e85584e3e468068c616f4` (Crow 10/70), including Rust/Wasm
signatures verified independently by WebCrypto, externally delegated browser
keys, request authorization before a conversation exists, receipt/acknowledgment
authority and encrypted P-256 recovery. Scripted transport groups remain separate.
The fixture's known issuer and synthetic
admission are test infrastructure, not a proof of production enrollment,
reservation admission, global continuity, or anonymous settlement.
