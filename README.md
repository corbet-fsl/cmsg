# cmsg

Browser-first Rust/Wasm messaging with end-to-end encryption, bounded opaque bytes, text convenience APIs and encrypted local state.

The published [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1) requires Rust 1.97.1 and predates the browser-first implementation described here. See the [release artifact and installation](studies/crate-alpha-release.md).

The shared OpenMLS core authenticates stable community identities through member-owned roots and separately authorized device keys. `Member` provides the generic messaging primitives, including groups. `Inbox` adds local admission and contact policy; `BrowserInbox` enforces the strict pair flow and waits for asynchronous checkpoint/outbox persistence before exposing results.

Strict first contact allows one bounded introduction, followed by an actual answer or owner-controlled closure. Only the blocker can initiate reopening while their block applies. Applications can offer blocker-selected expiry; expiry permits a fresh request, never old queued messages. Response deadlines and introduction limits are configurable. Signed contact history synchronizes privately between independent devices. Sender cancellation does not count as a peer response or restore allowance.

[Live delivery](docs/live-delivery.md) binds application messages to authenticated device sessions. Disconnect, restore and timeout cancel pending delivery without fabricating an Answer, Close or refund. A receiver acknowledgment distinguishes accepted history from an unconfirmed send. The supplied IndexedDB adapter checks publication versions across browser tabs. [Accounted introductions](docs/reservation-release.md) additionally require matching accepted Active reservations and bind the pending contact to its original devices.

An already enrolled device can reconnect through ordered group catchup and private contact-history sync. Owner reopening can also create a replacement pair group using fresh root-authorized devices, the preserved contact journal, and a new recipient-prepared admission redemption. Both owners' blocks still require consent; losing every copy of the journal cannot be repaired by possession of the identity key alone. Delayed resolution receipts update their exact archived introduction without changing the current contact gate, and still require current signer authorization when delivered.

At `80bbcf30e777b56a9ce6f8ea4a261f440c349eb0`, [161 native tests and the Wasm target check](https://crow.corbet.ch/repos/10/pipeline/76) passed. The same source passed [21 Chromium contract groups](https://crow.corbet.ch/repos/10/pipeline/77), including actual Rust/Wasm and WebCrypto signatures, IndexedDB concurrent-writer rejection, live cancellation/ACK/history, replacement recovery and separately labeled scripted transport cases. Native reservation-verifier doubles test gate boundaries; real proof validity requires the separate cfrm composition. The [browser-first evidence](docs/browser-first.md) records earlier transport evidence. Earlier Android/iOS target checks do not establish current mobile operation.

The earlier [cfrm composition](experiments/community-composition/README.md) uses actual blind-permit issuance and redemption for first-contact admission. [Four composition tests passed](https://crow.corbet.ch/repos/10/pipeline/61) with cfrm `2c4fa47c`, including initial and replacement groups without permit reuse. The separate protected reservation gate consumes a trusted private-account verifier; it has no successful default. A spent permit or signed receipt does not prove sincere interaction or the complete hidden accounting transition.

Browser Tor support includes experimental pinned TorJS/Arti overlays for onion streams and ephemeral onion hosting. The [actual browser Tor contract](https://crow.corbet.ch/repos/10/pipeline/68) passed at `b23221271f71`: browser-owned onion publication, browser/browser framing and browser/native encrypted MLS traffic in both directions with replay rejection. This uses a 27-node signed private Tor network and the patched experimental package; the stock package is insufficient. Public-network deployment, mobile behavior and process-wide network confinement remain unvalidated. This work is not a deployable anonymous messenger or a proof of no leaks: malicious application code, traffic correlation, rollback of all replicas, and browser suspension remain explicit boundaries.

- [Messaging contract](docs/contract.md)
- [Browser-first architecture and current evidence](docs/browser-first.md)
- [Accounting delegation, receipt and sender acknowledgment extension](docs/accounting-extension.md)
- [Browser bindings and experimental Tor adapters](browser/README.md)
- [Component boundaries](docs/components.md)
- [Reuse study](studies/messaging-components.md)
- [Implementation and security experiments](studies/implementation-experiments.md)
- [Passing 100-member and mobile-target checks](https://github.com/corbet-labs/cmsg/actions/runs/34257557064)
- [Current cmsg/cfrm composition experiment](experiments/community-composition/README.md)
- [Experiments](experiments/README.md)

License: [FSL-1.1-ALv2](LICENSE.md). Third-party dependencies retain their own licenses.
