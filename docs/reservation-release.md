# Protected reservation release

`Inbox::new_accounted` / `BrowserInbox.newAccounted` combine live delivery with a
mandatory private reservation gate. Existing generic Member and unaccounted
Inbox constructors remain separate integration choices. Blind introduction
permits are a separate admission path and never stand in for reservation proofs.

Before an application payload, `require_active_reservations` durably records the
actual introduction, permanent pair/roles, MLS group binding, contact policy,
current block-history context, shared openedAt/expiresAt, pinned stable state policy
and fresh peer challenges. Each side adopts only the challenge for its own
presentation. The recipient explicitly calls `authorize_incoming_reservation`
after the outgoing **Active** presentation verifies. This records permission to
reserve incoming capacity, not a ledger debit. `bind_active_reservations` then
requires both matching Active proofs and a trusted current-own-state check.
Prepared proofs, unacknowledged persistence, missing consent and changed context
cannot release application data. Control, receipt and recovery traffic continue
without a new application allowance.

The selected accounting rule returns the sender's reserved capacity at the
original fixed reservation deadline after Close or silence. Only a confirmed
Answer can release it earlier; the recipient's explicit Close clears its own
incoming reservation immediately. These are cfrm settlement rules, not effects
of cmsg transport delivery or local cancellation. A refund never restores an
admission turn, clears an unresolved introduction or removes a member block.
Changing `openedAt`, restoring a checkpoint or choosing a new message/nonce
cannot extend or restart an existing cmsg reservation. New owner-authorized
contact/replacement still requires fresh admission and matched reservations.

The trusted `ReservationVerifier` verifies actual proof bytes under locally
pinned circuits/verification keys, exact public statement and signed accounting
acceptance. `verify_current_local` additionally checks the embedding's accepted
own state. Browser bindings await a host verifier returning a typed verified
statement; a peer's boolean has no authority. The test fixture invokes a fixed
Node verifier executable and trusted paths from process configuration, which
verifies actual BB proofs and cfrm Rust certificates/current-own state. No peer
proof or pair transcript is sent to the named operator.

A pending accounted introduction belongs to its original two device MLS roster.
Its peer proof exposes the reservation's ownerAuthority only to the peer; the
trusted verifier binds that leaf to the original verified delegation/device.
Another authorized sibling cannot bind or release that pending introduction.
Roster expansion waits until the contact is established. Moving a pending first
contact to another device requires closure and a fresh admitted introduction;
recovery does not silently transfer first-payload authority. Established devices
can still exchange and synchronize authenticated accepted history.

A device needs one durable writer. Browser persistence includes expectedVersion
and nextVersion for an atomic IndexedDB comparison; concurrent restored copies
must fail the comparison. Native hosts provide equivalent serialization.
Restored/synchronized gates retain evidence and restrictions, but require fresh
trusted binding before application release. The host invalidates a gate before
publishing an accepted own accounting state that removes its obligation.

A remote Active acceptance proves a past accepted state, not non-supersession.
A fresh challenge does not change that fact. Local contact/closure, exact nonce,
lease, current-own state and one-introduction rules remain mandatory. There is
no claim that both remote budgets remain locked at one instantaneous global
time. Full rollback of every copy or deliberate device-key cloning remains
outside local journal guarantees.

At `80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`, Crow10/76 passed
161 native tests and Wasm checking, including four reservation-gate tests;
Crow10/77 passed 21 Chromium contract groups. Native verifier doubles exercise
authorization/storage boundaries, not proof validity. The separate cfrm
account-state experiment records actual proof-composition results and their
source pins.

Verification runs remote proof work first, refreshes the trusted contact context,
and queries current own state last. A verifier also returns `validUntil` as
trusted metadata, separate from the proof statement. It bounds the common
policy expiry, reservation lease and original reserved device delegation expiry.
The accepted accounting request's commit horizon is not the Active state's
lifetime. Binding and first-payload release independently require time strictly
before both verification bounds. Browser cached verdicts match the complete
device, role, tuple, evidence digest and verification mode, permit forward time
within that bound, and reject clock rollback.

Current-own verification is a snapshot, not a lock across verification, network
I/O and persistence. The embedding serializes own accounting updates and Inbox
publication and invalidates the gate when the accepted own obligation changes.
The fixture's actual Close checkpoint is read back and restored before it emits
accounting evidence; signatures cannot substitute for durable local history.

The additional native regressions `original_reservation_expiry_and_capacity_release_never_restart_the_contact`
and `waiting_default_changes_apply_only_to_new_gates_and_expiry_is_verified`
check these boundaries for both silence and explicit recipient Close, including
restore, attempted deadline extension, new nonce/reopen and queued ciphertext.
They model host authorization/storage boundaries, not accounting settlement
proofs. Crow10/78 at `ef1483c0a709e86975c44f6f8c84e833e7aa6ac4`
passed all 163 native tests including these two regressions and portable Wasm
checking. Crow10/79 at that source passed 21 actual Chromium contract groups;
scripted transport cases remain labeled separately. Revised cfrm account/peer
proof integration has its own source pin and validation.

The peer reservation schema is version 3: it uses `statePolicyDigest` and an
explicit `expiresAt`. The stable digest excludes only the prospective waiting
period; the signed named accounting request still binds its complete current
policy separately. cmsg derives the original expiry once from the gate's
`opened_at + abandon_after`, then requires both verified roles to bind that
exact expiry. An incoming reservation matches the already authenticated
outgoing deadline even if the current default changed. A different default can
apply to a future introduction, never to an existing gate. Older experiment
proof/checkpoint schemas are not silently reinterpreted as version 3.
