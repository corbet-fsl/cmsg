# cmsg

Browser-first Rust/Wasm messaging with end-to-end encryption, bounded opaque bytes, text convenience APIs and encrypted local state.

The published [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1) requires Rust 1.97.1 and predates the browser-first implementation described here. See the [release artifact and installation](studies/crate-alpha-release.md).

The shared OpenMLS core authenticates stable community identities through member-owned roots and separately authorized device keys. `Member` provides the generic messaging primitives, including groups. `Inbox` adds local admission and contact policy; `BrowserInbox` enforces the strict pair flow and waits for asynchronous checkpoint/outbox persistence before exposing results.

Strict first contact allows one bounded introduction, followed by an actual answer or owner-controlled closure. Only the blocker can initiate reopening while their block applies. Applications can offer blocker-selected expiry; expiry permits a fresh request, never old queued messages. Response deadlines and introduction limits are configurable. Signed contact history synchronizes privately between independent devices. Sender cancellation does not count as a peer response or restore allowance.

An already enrolled device can reconnect through ordered group catchup and private contact-history sync. Owner reopening can also create a replacement pair group using fresh root-authorized devices, the preserved contact journal, and a new recipient-prepared admission redemption. Both owners' blocks still require consent; losing every copy of the journal cannot be repaired by possession of the identity key alone. Delayed resolution receipts update their exact archived introduction without changing the current contact gate, and still require current signer authorization when delivered.

At cmsg `1e70a802`, [138 native tests and the Wasm target check](https://crow.corbet.ch/repos/10/pipeline/59) passed, including the 100-member group test and 16 directional-contact tests. The [actual Chromium contract](https://crow.corbet.ch/repos/10/pipeline/60) passed identity, messaging, IndexedDB durability, replacement-group recovery and separately labeled scripted transport cases. The [browser-first evidence](docs/browser-first.md) records the exact scope. Earlier Android/iOS target checks do not establish current mobile operation.

The [cfrm composition](experiments/community-composition/README.md) uses actual blind-permit issuance and redemption for first-contact admission. [Four composition tests passed](https://crow.corbet.ch/repos/10/pipeline/61) with cfrm `2c4fa47c`, including initial and replacement groups without permit reuse. Full private, member-bound reciprocal accounting remains unimplemented and fails closed. A spent permit or signed receipt does not prove sincere interaction or the complete hidden accounting transition.

Browser Tor support includes experimental pinned TorJS/Arti overlays for onion streams and ephemeral onion hosting. The stock package is insufficient; compilation and real browser Tor-network evidence are required separately from core tests. Earlier native isolated-network evidence does not establish browser connectivity. This work is not a deployable anonymous messenger or a proof of no leaks: malicious application code, traffic correlation, rollback of all replicas, and browser suspension remain explicit boundaries.

- [Messaging contract](docs/contract.md)
- [Browser-first architecture and current evidence](docs/browser-first.md)
- [Browser bindings and experimental Tor adapters](browser/README.md)
- [Component boundaries](docs/components.md)
- [Reuse study](studies/messaging-components.md)
- [Implementation and security experiments](studies/implementation-experiments.md)
- [Passing 100-member and mobile-target checks](https://github.com/corbet-labs/cmsg/actions/runs/34257557064)
- [Current cmsg/cfrm composition experiment](experiments/community-composition/README.md)
- [Experiments](experiments/README.md)

License: [FSL-1.1-ALv2](LICENSE.md). Third-party dependencies retain their own licenses.
