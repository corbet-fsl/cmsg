# Community components

Any community can compose these three repositories. They are general-purpose reusable software components. A community supplies its own participation policy and presentation above the shared components.

A member has one authenticated pseudonymous identity that visibly persists from the forum into their chats within a deployment. That identity is intentionally visible to counterparts; private conversation relationships are not disclosed to operator accounting. Community identities and rule histories must not be automatically joined across deployments. Reusing eligibility infrastructure does not authorize a global member directory or a shared cross-community tracking identifier.

| Component | Responsibility | State boundary |
|---|---|---|
| cvld | Passkey authentication, local credential unlocking and admission eligibility | Client private keys; protected factor/duplicate-use state at the gate; public authentication/verification material; no behavioral sanctions |
| cfrm | Entire public sphere: live discovery, rendezvous, quotas, reciprocity, standing and optional epoch votes | Short-lived presence leases; member-held profiles; minimal durable rule state to prevent allowance resets and double spending |
| cmsg | Private text conversations and encrypted local history | Client-held content and keys; bounded encrypted relay state if selected |

These are three repository boundaries: cvld, cfrm and cmsg. cvld encapsulates both passkeys and eligibility; cfrm encapsulates the public sphere and its rules. There are no separate clgn or crls repositories. Deployment boundaries are an implementation choice. Authentication should not become a global tracking endpoint. Admission credentials should be presented locally to relying services where possible instead of calling cvld for each message.

A presence lease expires after disconnect or missed heartbeats; a network partition is not instantly detectable. Peers may retain information they have already received. Rules state must survive disconnect or a malicious client can reset allowances. Within cfrm, separate the transient live roster from the minimum durable rule state; retaining the latter does not require storing profiles or a contact graph.

No component accepts content reports, maintains a moderator queue or asks an operator to arbitrate private conversations. Conduct rules operate on protocol-valid numerical events and local recipient choices.

Engineering work must select and test gate trust/expiry mechanisms, client execution and private accounting. Surface material functional tradeoffs such as offline private-message delivery, group-introduction costs or required additional metadata; do not ask the user to choose libraries or implementation mechanics.
