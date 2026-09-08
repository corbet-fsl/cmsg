# Reusable messaging components

Research snapshot: 2026-09-08. Candidates are not adopted dependencies or audited integrations.

| Candidate | Reusable functionality | Gap |
|---|---|---|
| [SimpleX](https://github.com/simplex-chat/simplex-chat) | Native messaging core, pairwise queues, groups, ratchets, encrypted local database, Tor support; AGPL | Requires enforced anonymous routing, passkey adaptation, explicit relay retention and private admission/quota integration |
| [OpenMLS](https://github.com/openmls/openmls) | MIT Rust implementation of MLS group encryption | Discovery, transport anonymity, storage and private accounting remain separate; browser support requires validation |
| [libsignal](https://github.com/signalapp/libsignal) | Signal protocol and native bindings; AGPL | Upstream explicitly does not support use outside Signal and may change APIs |
| [Briar](https://briarproject.org/how-it-works/) | Tor-based synchronization and member-held data | Its replicated forums retain offline content; this is not the proposed live-only discovery model |

Initial research direction: evaluate a local native SimpleX integration with mandatory anonymity routing. Its TypeScript SDK talks to a native CLI; hosting that CLI on the operator's server would expose plaintext and keys there and violate the boundary. This is not an approved browser architecture.

[SimpleX relay defaults](https://simplex.chat/privacy/) include persistent undelivered ciphertext; do not inherit them without choosing the retention policy. [MLS metadata considerations](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.4) show why encryption alone does not hide a graph. [Tor limitations](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/) require explicit treatment of timing correlation.

An ordinary direct [WebRTC connection](https://www.rfc-editor.org/rfc/rfc8828.html) can reveal network addresses. It does not meet the peer-IP requirement.

No candidate implements the complete private reciprocity/quota protocol. License compatibility must be resolved before incorporating upstream code; repository documentation licensing is not an assertion that AGPL code can be relicensed under FSL.
