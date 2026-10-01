# Monolith retirement and regression handoff

cmsg 0.2 is the device-local Member door. The previous package combined messaging,
identity, profile, browser storage and Tor implementations. Those authorities now
belong to dedicated owners; exporting the old implementation from the new door
would leave two competing authorities.

The final source before retirement is preserved at
[`0958c30fc030edb7c60c8de41a389afad6c4ee89`](https://github.com/corbet-libs/cmsg/tree/0958c30fc030edb7c60c8de41a389afad6c4ee89).
The leaf extraction baseline is
[`c809cca308f48aaff373c66853f626412534bd58`](https://github.com/corbet-libs/cmsg/tree/c809cca308f48aaff373c66853f626412534bd58).
[retired-manifest.json](retired-manifest.json) records every retired path and its
SHA-256 at the final source commit. Neither commit is rewritten. Source, tests,
experiments, browser patches and historical CI configurations remain recoverable.

## Owner and regression map

Paths below refer to the immutable final source tree. This is an extraction map,
not a claim that each successor has completed or passed the associated tests.

| Historical source and tests | Current owner | Required regression evidence |
| --- | --- | --- |
| `src/member.rs`, `src/roster.rs`, `tests/roster.rs`, `tests/payloads.rs`, `tests/security.rs` | Threads `cthr` | Real OpenMLS commits, Welcome, epoch/replay/authentication failures, encrypted checkpoint and cancellation |
| `src/release.rs`, `src/inbox_policy.rs`, `tests/contact_directives.rs`, `tests/directional_contact.rs`, `tests/first_contact.rs`, `tests/closure.rs`, `tests/resolution.rs` | Contacts `ctcs`, Waves `cwvs`, Inbox `cnbx` | Signed private contact history, both owners' blocks, close/reopen, stale resolution and first-contact lifetime rules |
| `src/live.rs`, `src/inbox_live.rs`, `tests/live_delivery.rs` | Delivery `cdlv` | Sender/receiver state, authenticated ACK, timeout/cancel, unknown-after-write and durable outbox retries |
| `src/inbox.rs`, `src/inbox_replacement.rs`, `src/inbox_reservation*`, `tests/inbox.rs`, `tests/reservation_gate.rs` | Inbox `cnbx` composing dedicated owners | One combined candidate/checkpoint before output, replacement restoration and refusal on missing current authority |
| `src/accounting.rs`, `src/reservation.rs`, `src/inbox_accounting.rs`, `tests/accounting.rs`, `tests/accounted_admission.rs`, `experiments/community-composition`, `experiments/first-contact-release` | Wallet `cwlt`, Balance `cblc`, corresponding facades | Actual current proofs and private settlement; old verifier callbacks never establish G2/G5 |
| `src/identity.rs`, `src/enrollment.rs`, `src/admission.rs`, `tests/identity.rs`, `tests/devices.rs`, `tests/device_attacks.rs`, `tests/device_renewal.rs`, `tests/enrollment_signing.rs`, `tests/admission.rs` | Keys `ckmg`, device Passkeys `cpky`, server Keyhole `ckyh`, membership owners | PRF-derived identity, WebAuthn separation, current device authority, revocation and same-passkey restore |
| `src/profile.rs`, `src/profile_statements.rs`, `src/board.rs`, `tests/profile.rs`, `tests/profile_statements.rs`, `tests/release_signing.rs` | Profile `cpfl`, Envelope `cnvl`, Search `csrh`, Exchange `cxch`, Board `cbrd` | Current signed public/full Guard validation, scoped read-key custody, authenticated give-first exchange |
| `src/vault.rs`, `src/browser*.rs`, `browser/indexeddb-store*`, `tests/browser.rs` | Waist `cwst`, Vault `cvlt`, dedicated facade adapters | Real encrypted IndexedDB/CAS, cross-tab conflict, shared checkpoint, durable unknown and reopen |
| `src/framing.rs`, `src/transport.rs`, `src/rendezvous.rs`, `tests/frame_codec.rs`, `tests/framing.rs`, `tests/transport.rs`, `tests/rendezvous.rs`, `tests/renewal.rs`, Tor examples and experiments, `browser/upstream`, `browser/tor-*`, `browser/live-stream*` | Mesh `cmsh`, Tor `ctrn`, Ferry `cfry`, backend owners | Bounded messages/partial reads/backpressure, actual browser/native networking, renewal, deadlines and process isolation |
| `browser/peer-channel*`, browser contracts, `.ci`, `.crow`, `studies`, historical docs, `tests/scale.rs` | Corresponding owners and product integration | Preserve original fixture limits and artifact hashes; expensive scale/churn stays on owned CI |

Groups `cgrp` and Attend `ctnd` supply the current group/room authority rather than
old generic MLS membership. Profile exchange may not reuse historical synthetic
eligibility or transport callbacks as production authorization. Every other test
and support file is included in the exact hash inventory.

## Evidence boundary

The old native suite passed in
[run 36899003376](https://github.com/corbet-libs/cmsg/actions/runs/36899003376),
which remained red because legacy native Tor examples failed Wasm compilation.
Historical browser/Tor success and limitations remain in that source tree's
`README.md`, `docs/browser-evidence.md` and `docs/browser-first.md`.

Current door CI measures only current door code. Retiring these tests does not
satisfy or waive their successor regressions, real network integration, active
member restoration, anonymous settlement, group scenarios or product acceptance.
Unavailable domain operations remain failures and preload remains unavailable.
