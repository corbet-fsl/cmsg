# cmsg

Browser-first Rust/Wasm messaging with end-to-end encryption, bounded opaque bytes, text convenience APIs and encrypted local state.

The published [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1) requires Rust 1.97.1 and predates the browser-first implementation described here. See the [release artifact and installation](studies/crate-alpha-release.md).

The shared OpenMLS core authenticates stable community identities through member-owned roots and separately authorized device keys. `Member` provides the generic messaging primitives, including groups. `Inbox` adds local admission and contact policy; `BrowserInbox` enforces the strict pair flow and waits for asynchronous checkpoint/outbox persistence before exposing results.

Strict first contact allows one bounded introduction, followed by an actual answer or owner-controlled closure. Only the blocker can initiate reopening while their block applies. Applications can offer blocker-selected expiry; expiry permits a fresh request, never old queued messages. Response deadlines and introduction limits are configurable. Signed contact history synchronizes privately between independent devices. Sender cancellation does not count as a peer response or restore allowance.

[Live delivery](docs/live-delivery.md) binds application messages to authenticated device sessions. Disconnect, restore and timeout cancel pending delivery without fabricating an Answer, Close or refund. A receiver acknowledgment distinguishes accepted history from an unconfirmed send. The supplied IndexedDB adapter checks publication versions across browser tabs. [Accounted introductions](docs/reservation-release.md) additionally require matching accepted Active reservations and bind the pending contact to its original devices.

An already enrolled device can reconnect through ordered group catchup and private contact-history sync. Owner reopening can also create a replacement pair group using fresh root-authorized devices, the preserved contact journal, and a new recipient-prepared admission redemption. Both owners' blocks still require consent; losing every copy of the journal cannot be repaired by possession of the identity key alone. Delayed resolution receipts update their exact archived introduction without changing the current contact gate, and still require current signer authorization when delivered.

At `eda36aef1af375c396e0d1d7e0e4dbe0f2626f63`, [167 native tests, the Wasm target check and formatting](https://github.com/cmtymeet/cmsg/actions/runs/35732596527/job/106761664175), [four cfrm composition tests](https://github.com/cmtymeet/cmsg/actions/runs/35732596311), and [Android/iOS target type checks](https://github.com/cmtymeet/cmsg/actions/runs/35732596464) passed. Target type checks do not establish mobile operation. Native reservation-verifier doubles test gate boundaries; real private-account proof validity requires the separate cfrm proof composition.

At `4e5b57a92d53c2bcfe1d9c933cdaf1c1459437bf`, [25 Chromium contract groups and npm package validation](https://github.com/cmtymeet/cmsg/actions/runs/35736650915) passed. The browser contract completed in 14.621 seconds using release Wasm, including all eight scoped cfrm profile signing domains, owner/holder key release and decryption, IndexedDB concurrent-writer rejection, live cancellation/ACK/history, replacement recovery and failed-ACK payload cleanup. The same Wasm binary was packed into the checked npm archive, with its contents, import closure, license and hashes verified. Profile eligibility callbacks and ticket requests are synthetic, and profile transport is in memory; this run adds no live Tor evidence. The [browser-first evidence](docs/browser-first.md) records earlier transport checks.

The [cfrm composition](experiments/community-composition/README.md) uses actual blind-permit issuance and redemption for first-contact admission. Its four passing tests use cfrm `2c4fa47c59dfd8eb2fdc058ee171836ebc097d99`, including initial and replacement groups without permit reuse. The separate protected reservation gate consumes a trusted private-account verifier; it has no successful default. A spent permit or signed receipt does not prove sincere interaction or the complete hidden accounting transition.

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
