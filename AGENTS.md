# cmsg engineering contract

cmsg owns the device-local action registry and thin composition of Vault, Mesh,
Foyer, Board and Inbox. It owns no leaf policy, crypto, roster or balance ledger.
All frontends use the same generated API; admin/root traffic goes through Foyer.
No raw member keys, PRF output, profile plaintext or identifiers belong in logs.
Cross-facade effects require one encrypted checkpoint before publication.

First-party Git dependencies follow main; keep reproducible lockfiles with one
revision per crate. CI resolves one fresh snapshot and shares it across checks.
Require real native and executed wasm tests and exact 100% reachable line and
branch coverage. Do not lower gates, substitute mocks or claim compilation as
coverage. Document justified unreachable exclusions for review.

Use free public CI for suitable inputs, bounded concurrency and reusable caches.
No workstation Cargo commands. Heavy load/churn tests run on owned CI. Never
publish packages or put secrets in repositories. Commit explicit paths with
plain English messages and no attribution trailers. Every backend change needs
independent review before acceptance.
