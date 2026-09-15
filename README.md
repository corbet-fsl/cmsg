# cmsg

Browser-first Rust/Wasm messaging with end-to-end encryption, bounded opaque bytes, text convenience APIs and encrypted local state.

The published [`cmsg 0.1.0-alpha.1`](https://crates.io/crates/cmsg/0.1.0-alpha.1) requires Rust 1.97.1 and predates the browser-first implementation described here. See the [release artifact and installation](studies/crate-alpha-release.md).

The shared OpenMLS core authenticates stable community identities through member-owned roots and separately authorized device keys. `Member` provides the generic messaging primitives, including groups. `Inbox` adds local admission and contact policy; `BrowserInbox` enforces the strict pair flow and waits for asynchronous checkpoint/outbox persistence before exposing results.

Strict first contact allows one bounded introduction, followed by an actual answer or owner-controlled closure. Only the blocker can initiate reopening while their block applies. Applications can offer blocker-selected expiry; expiry permits a fresh request, never old queued messages. Response deadlines and introduction limits are configurable. Signed contact history synchronizes privately between independent devices. Sender cancellation does not count as a peer response or restore allowance.

The [browser-first design and evidence](docs/browser-first.md) records the exact tested revisions and limitations. Native behavioral tests and Wasm target checks cover the shared core; browser contracts and Tor overlays have separate validation. Tests exercise encrypted payloads, replay and tamper rejection, independent devices, persistent closure, renewal and failure ordering. Earlier revisions also passed 100-member and Android/iOS target checks; these do not establish current mobile operation.

The [cfrm composition](experiments/community-composition/README.md) uses actual blind-permit issuance and redemption for first-contact admission. Full private, member-bound reciprocal accounting remains unimplemented and fails closed. A spent permit or signed receipt does not prove sincere interaction or the complete hidden accounting transition.

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
