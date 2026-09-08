# Messaging contract

## Required behavior

Messages are end-to-end encrypted between two or more participants. Groups must support at least 100 participants with configurable practical limits. Each participant can authenticate the same stable pseudonymous identity shown in the forum; a self-asserted display name is insufficient. The application payload is bounded UTF-8 text. There are no attachments, pictures, video, embedded HTML, automatic link previews or remote assets. Text can encode arbitrary information; the protocol cannot prove that plaintext is semantically human prose.

The operator holds no content keys or plaintext message store. Local history and private credentials are encrypted. Passkey-based local key wrapping is a candidate; the passkey signing key is not itself a database encryption key. Device recovery and PRF support need validation.

Admission requires cvld eligibility and cfrm's applicable rules capability. Limits concern first contacts under an explicit policy; ordinary replies and existing conversations require separately specified rules. Clients must not be trusted to self-report counts honestly. Cryptographically authenticated accounting and double-spend prevention remain unsolved integration work.

## Network identity boundary

A malicious participant must not learn another participant's IP by discovering a profile, establishing a conversation, choosing a relay or sending content. This applies to the discovery layer as well as messaging.

All relevant connections require a validated anonymity transport. There is no silent direct fallback. Loading a profile or receiving a message must never cause sender-selected URLs, previews, images or other external resources to be fetched. Opening an external link is a separate boundary and must not happen automatically.

Peers hold and exchange application state, but direct network sockets between them are not required. Anonymity relays may carry encrypted traffic. Exact queue lifetime and offline private-message behavior remain open; online-only profile discovery does not settle offline message delivery.

No design can prevent a recipient from copying deliberately shared content or identify every correlation attack. Resistance to a global timing observer is a separate threat-model question, not an automatic consequence of encryption or Tor.

## Portability

The library must support future native Android and iOS applications. Server runtimes need not run on the device. Mobile compatibility requires executable build/integration evidence for cryptographic bindings, protected local keys and anonymous transport; desktop success alone is insufficient. App suspension and reconnection must preserve identity and cryptographic state without a direct-network fallback.

## Accounting and telemetry

Operational telemetry should consist of aggregate success/failure counts and coarse latency buckets, with a privacy budget and release threshold to be defined. Do not attach account, recipient, group or conversation IDs to events. Even apparently anonymous timing can correlate activity.

cfrm must validate permitted resource use without receiving the private contact graph. Candidate mechanisms include anonymous one-use capabilities and private state transitions. Neither conventional E2EE nor a messaging library supplies this automatically. Persistent spent-token or state-commitment records may be necessary; they must be scoped and retained only as required.

Rules control participation in this protocol. They cannot prevent consenting people from communicating through a modified client or unrelated channel outside it.

## Acceptance specifications

These are tests to implement, not reported passing checks:

1. A malicious contact-selected endpoint cannot observe the participant's source IP.
2. An unavailable anonymity route produces failure and zero direct fallback traffic.
3. Profile and message payloads containing URLs, markup or image syntax cause zero external fetches.
4. Non-text application payloads and invalid or oversized UTF-8 are rejected at the endpoint boundary.
5. Altered ciphertext fails authentication; replay and out-of-order handling follow the selected protocol.
6. Group membership changes preserve the chosen forward-secrecy and recovery properties.
7. A copied local store is unreadable without an authorized local key; unavailable PRF support never causes plaintext fallback.
8. Duplicate or concurrent spending of the same first-contact capability cannot increase reach.
9. Reconnection does not replenish allowance or erase outstanding rules state.
10. Telemetry and error transcripts contain no plaintext, account-pair mapping or private keys.
11. No trusted server-side hosted client holds the user's decryption keys.
