# Messaging contract

## Required behavior

Messages are end-to-end encrypted between two or more participants. Groups must support at least 100 participants with configurable practical limits. Each participant can authenticate the same stable pseudonymous identity shown in the forum; a self-asserted display name is insufficient. The universal library carries bounded opaque bytes and offers a UTF-8 text API. The community application selects text-only payloads: no attachments, pictures, video, embedded HTML, automatic link previews or remote assets. Text can encode arbitrary information; the protocol cannot prove that plaintext is semantically human prose.

The operator holds no content keys or plaintext message store. Local history and private credentials are encrypted. Passkey-based local key wrapping is a candidate; the passkey signing key is not itself a database encryption key. Device recovery and PRF support need validation.

Admission requires external eligibility, member-root device authorization and cfrm's applicable rules capability. First contact requires an answer or a member-owned block, with an explicitly configured response deadline. A block applies to that member across their devices within the community. The blocking member may explicitly start a fresh contact; the blocked member cannot clear the block. An optional expiry permits a later fresh initiative, and expiry alone never revives queued messages. If both members blocked, both must consent. A fresh initiative starts another one-introduction limit with a new nonce. Established conversations reconnect privately. Clients must not be trusted to self-report counts honestly. Aggregate blind-permit issuance/redemption is implemented; private member-bound reciprocal accounting remains unfinished. See the [exact capability and evidence boundaries](browser-first.md).

Owner reopening can use a retained group or a replacement group with fresh root-authorized devices. Replacement admission requires a new recipient-prepared redemption and preserves both owners' journal history. The recipient authenticates the invitation's nonce, group and policy before preparing its claim. Lost message ratchets do not authorize forgetting blocks or pending obligations, and old-group ciphertext cannot satisfy a replacement introduction. Ordinary established-group reconnects do not invoke this new-admission flow.

## Network identity boundary

A malicious participant must not learn another participant's IP by discovering a profile, establishing a conversation, choosing a relay or sending content. This applies to the discovery layer as well as messaging.

All relevant connections require validated Tor transport. There is no silent direct fallback. Loading a profile or receiving a message must never cause sender-selected URLs, previews, images or other external resources to be fetched. Opening an external link is a separate boundary and must not happen automatically.

Peers hold and exchange application state. Tor relays carry encrypted traffic; the application operator has no message relay, queue or archive. Offline catch-up relies on client-owned peer retention. The all-devices-offline case and retention duration remain open.

No design can prevent a recipient from copying deliberately shared content or identify every correlation attack. Resistance to a global timing observer is a separate threat-model question, not an automatic consequence of encryption or Tor.

## Portability

The primary client runs in an ordinary browser using Rust/Wasm. Native Android and iOS reuse the same portable core. Browser and mobile compatibility require executable build/integration evidence for cryptographic bindings, protected local keys and Tor transport; desktop success alone is insufficient. App suspension and reconnection must preserve identity and cryptographic state without a direct-network fallback.

## Accounting and telemetry

Operational telemetry should consist of aggregate success/failure counts and coarse latency buckets, with a privacy budget and release threshold to be defined. Do not attach account, recipient, group or conversation IDs to events. Even apparently anonymous timing can correlate activity.

cfrm must validate permitted resource use without receiving the private contact graph. Candidate mechanisms include anonymous one-use capabilities and private state transitions. Neither conventional E2EE nor a messaging library supplies this automatically. Persistent spent-token or state-commitment records may be necessary; they must be scoped and retained only as required.

Rules control participation in this protocol. They cannot prevent consenting people from communicating through a modified client or unrelated channel outside it.

## Acceptance specifications

These define deployment acceptance, not a claim that every item has passed.
The [evidence record](browser-first.md#evidence-as-of-the-current-development-work)
separates current core/browser checks from outstanding Tor runtime, protected-key,
telemetry and production private-accounting validation.

1. A malicious contact-selected endpoint cannot observe the participant's source IP.
2. An unavailable anonymity route produces failure and zero direct fallback traffic.
3. Profile and message payloads containing URLs, markup or image syntax cause zero external fetches.
4. The universal byte API enforces its binary bound; the community text endpoint rejects non-text, invalid UTF-8 and oversized text.
5. Altered ciphertext fails authentication; replay and out-of-order handling follow the selected protocol.
6. Group membership changes preserve the chosen forward-secrecy and recovery properties.
7. A copied local store is unreadable without an authorized local key; unavailable PRF support never causes plaintext fallback.
8. Duplicate or concurrent spending of the same first-contact capability cannot increase reach.
9. Reconnection does not replenish allowance or erase outstanding rules state.
10. Telemetry and error transcripts contain no plaintext, account-pair mapping or private keys.
11. No trusted server-side hosted client holds the user's decryption keys.
12. A blocked member and their other devices cannot reopen; the blocking member can explicitly initiate a fresh contact, subject to any block the peer also owns.
13. Old queued messages, device synchronization and expiry cannot turn an old introduction into an answer to a fresh one.
