# Credential renewal: review findings and proposed checks

This records the source-review findings, implemented renewal boundary and remaining recovery limits. The lifecycle checks and encrypted renewal outbox recovery now pass as part of the 56-test native suite at `0371e4ad5e7e39720f9a333d70579c2b208786da`, Crow repository 10, pipeline 9. The cvld admission verifier remains strict. Detailed runtime evidence is recorded in [the implementation study](implementation-experiments.md).

## Behavior found before the renewal change

`Member::send` requires the local member's current cvld certificate. `Member::receive` requires both the recipient's current certificate and the actual message sender's current certificate. An unrelated inactive member with an expired certificate does not stop ordinary text between two still-authorized members.

Membership changes have a different failure: after merging a candidate commit in isolated state, `receive` validates every remaining roster certificate against the current clock. An expired, unchanged member can therefore prevent peers from accepting an unrelated addition or removal, even though the committer has already advanced its own MLS state. Joining an existing group also rejects an expired inactive roster entry. `bind_admission` permits only the first binding, so there is no renewal path.

The local history snapshot can be decrypted after expiry. However, the current receive entry check also prevents an expired member from processing control messages needed to catch up after an offline period. Adding a renewal method alone would not resolve that case.

## Authorization boundary

| Operation or role | Required validation |
|---|---|
| Send or expose newly received application text | Current local admission, and current admission for the authenticated sender |
| New first contact | Current inviter and recipient admission plus the recipient's applicable Inbox/cfrm gate |
| Add a new MLS member or change a credential | Current issuer-authorized credential, bound to the actual MLS leaf signing key |
| Unchanged existing roster entry | Valid historical issuer signature and stable community/member/key binding; expiry alone does not invalidate a different member's action |
| Process ordinary membership control | Current authorization of the authenticated committer; validate additions and changes before committing state |
| Recover an expired local member's epoch | A separate control-only boundary may use the historical local binding; it must not return application text |
| Same-key credential renewal | Current replacement certificate for the same community, stable member ID and signing key, authenticated by an MLS self-update |

The historical check must still verify the issuer signature, community, policy and signing-key binding. It cannot mean accepting arbitrary expired certificate fields. Issuer or policy migration and signing-key replacement remain separate protocols.

An expired old certificate may authorize a renewal message only through a narrow recovery exception: the MLS message proves possession of its existing signing key, the candidate own leaf carries an independently verified current certificate for that same identity/key, and the commit contains no unrelated proposals or membership changes. An expired sender's text, additions, removals or unrelated commits remain rejected. Validation and persistence must be transactional, preserving legitimate retransmission after a rejected renewal.

OpenMLS already supports credential changes through `MlsGroup::self_update` and `LeafNodeParameters::with_credential_with_key`; this should use that maintained protocol path. Sources: [OpenMLS 0.9 updates](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/group/mls_group/updates.rs), [leaf parameter builder](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/treesync/node/leaf_node.rs).

The convenience `self_update` method consumes queued proposals. Our bounded renewal should instead use `CommitBuilder::consume_proposal_store(false)` with the replacement leaf parameters and no additional proposals. On receipt, `StagedCommit::queued_proposals()` and `update_path_leaf_node()` expose the exact checks needed before merging: no proposals in an expired-sender recovery, and a current same-identity/key credential in the authenticated update path. Sources: [commit builder](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/group/mls_group/commit_builder.rs), [staged commit inspection](https://raw.githubusercontent.com/openmls/openmls/openmls-v0.9.0/openmls/src/group/mls_group/staged_commit.rs).

Expiry remains an application admission check. An existing member already holds group keys and a modified client can bypass local expiry checks. Excluding that member from future cryptographic epochs requires an MLS removal and rekey. Neither certificate expiry nor this proposed renewal procedure erases previously delivered keys or plaintext.

## Required fail-first experiments

Use a trusted injectable clock for deterministic tests; do not sleep until certificates expire or make tests depend on a global mutable clock. Restoring a snapshot must explicitly reconnect its trusted time source. Production convenience methods can use the system clock; tests can advance independently held synthetic clocks.

1. Three members join while valid. One becomes inactive and its certificate expires. The other two can still exchange text, accept a new eligible member and process a removal. The inactive entry must not break their epoch agreement.
2. Expired actual senders and locally expired recipients still cannot send or expose new application text. Historical signature validity must not become a general expiry bypass.
3. A member renews its certificate using the same key and stable ID, before and after old-certificate expiry. Peers authenticate the renewal and preserve that visible ID and their local known-counterpart/block state.
4. Reject renewal with another member ID, community, policy, issuer or signing key, an invalid signature, a not-yet-valid certificate or an expired replacement. Reject a recovery commit bundled with any unrelated proposal or roster change.
5. Rejection, failed durable writes and replay leave ratchet state unchanged; a subsequent legitimate renewal succeeds. A restored authentic old snapshot still has the documented rollback limitation.
6. An expired member can catch up on authenticated control messages without exposing application text, obtain its current credential through cvld and complete renewal at the current MLS epoch.
7. A new first contact after renewal still goes through Inbox. A certified same-ID counterpart remains known or locally blocked, rather than receiving a new identity through certificate rotation.

Existing membership concurrency, missed-control delivery and durable multi-device state remain separate integration work. This review does not establish a production-ready renewal state machine.

In particular, a long offline backlog may contain control messages whose senders' certificates have since expired. The proposed strict current-sender rule cannot traverse an arbitrary such backlog. The bounded catch-up test keeps the committer current. A fresh introduction/Welcome from an eligible member, through Inbox, may be required for later recovery; accepting every historical control message is not an implicit fallback.

## Prepared API specifications

`26add9a` adds seven fail-first lifecycle tests and explicit stubs. All seven compiled and failed at the clock constructor in Crow repository 10, pipeline 1, running public commit `10f20212c93dc18deaf4819504b7c0af705542b8`. Implementation `7e2d407` follows that red evidence. A future-issued-history regression subsequently failed before fix `cfe9498`; the full native suite passed in pipeline 4 at `8ede4f139e452f37733ac7cfe6e3ca32f8d3d30f`. The API is `Clock::now()`, `Member::new_with_clock`, `Member::restore_with_clock`, `Member::renew_admission` and `Member::receive_control`. Existing constructors keep their system-clock behavior. The injected clock is trusted caller-owned process state and is not serialized into a snapshot.

`renew_admission` targets an already joined group and returns its MLS commit only after a caller-supplied durable persistence callback succeeds. That callback receives both the candidate member and exact outbound commit bytes, allowing an atomic encrypted snapshot/outbox checkpoint using the client's own wrapping material. Both a returned persistence error and a panic must restore the original in-memory certificate and ratchet. `receive_control` returns no application text. Neither new method bypasses Inbox for a new invitation.

The hostile-peer specifications construct actual upstream OpenMLS messages, including a renewed certificate bundled with an addition and a valid certificate for a different stable identity under the existing signing key. The passing checks demonstrate rejection without consuming state needed for a subsequent legitimate renewal, within the bounded cases above.

The outbox specification at `8552c1c` failed in Crow pipeline 8 at `4d141953833818dced13c97cc7b9ff806a05ec80`: the new callback received an empty commit even though candidate state was available. The other 55 tests still passed. Fix `0371e4a` passes the exact commit; all 56 tests and profile interoperability passed in pipeline 9 at `0371e4ad5e7e39720f9a333d70579c2b208786da`.

The recovery experiment writes an actual encrypted file containing both the candidate snapshot and outbound commit, synchronizes the file and directory, drops the original sender and in-memory commit copies, and restores from the encrypted file. The saved commit legitimately advances the peer exactly once, and the restored sender can continue messaging. This is a simulated sender restart with real filesystem I/O, not a process-kill, power-loss or monotonic-storage test. Durable outbox capability is distinct from guaranteeing network delivery, peer availability or arbitrary offline recovery. Low-level add/remove continue to require host-managed persistence and delivery.

The rollback guard restores memory; it cannot undo an external write that became durable before the callback reported an error or panicked. After an ambiguous host-write result, recover the canonical encrypted checkpoint and outbox before sending again. Continuing from an older in-memory state risks a fork. Correct error classification, atomic replacement and monotonic single-writer recovery remain host responsibilities.
