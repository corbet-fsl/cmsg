# Member door contract

The Member door is the sole frontend boundary for one device/community runtime.
One Rust registry owns action, version, typed body/result/event, authority, effect
and coarse error metadata. HTTP/OpenAPI/MCP/CLI/TypeScript are generated views.
The same bounded dispatcher checks every local capability, exact origin, action
set, expiry, revocation and fixed runtime scope. Requests cannot select a role
or community. Root/admin origins and sessions remain separate from members.

The registry includes local lifecycle actions and original owner views for
Board, Mesh and Inbox. Trusted Rust composition binds actual facade instances;
unbound owners refuse. Inbox reads revalidate Keys after acquiring the original
Vault checkpoint guard. GroupView and Mesh BackendView use original owner types.
Production login/custody and messaging initialization remain incomplete.
Preload starts unavailable and only a completed network bind releases it
(`Door::network_bound` after Tor bootstrap and onion publication; the trusted
embedding control `set_preload_ready` sets it directly), and nothing callable
clears it. No network health report, compile test, transport ACK or fixture can
create readiness.
Native paired clients use the owned original-byte Client and loopback HTTP;
capability import from protected inherited transport grants no authority itself.

Vault/Mesh/Foyer/Board/Inbox operations must use their real owner ports. Every
accepted cross-facade effect requires one combined encrypted candidate/checkpoint
before an external result, event or output escapes. Contacts and Wallet stay at
their owners. Admin/root projections must preserve the actual cvld registry via
Foyer; there is no frontend-to-cvld bypass or copied administrative action table.

No member keys or PRF appear in API data, errors or logs. A local paired-client
capability is distinct from passkeys, remote sessions and member authority.
Original request bytes reach typed decoding intact; unknown/duplicate fields and
oversized requests fail. Every HTTP response, including routing errors, is
noncacheable. The implementation uses maintained Schemars/Axum/reqwest and
upstream cryptographic primitives rather than custom protocols or primitives.

Historical monolithic messaging sources remain in immutable Git history, indexed
by the retirement map for their dedicated owners. Their old callback/fixture authorities do not satisfy current
admission, accounting, key custody, room, transport or restore acceptance.
Native and actual Wasm parity, full reachable line/branch coverage, real local
HTTP invocation, shared-checkpoint failure/replay tests, live owner integration
and independent review are required; passing one subset never implies the rest.

The generated browser module constructs a Rust owner task from public deployment
configuration, with an exact actual-page origin check. Local pairing and remote
sessions stay in Rust. Its bounded admission queue retains child completion when
a JavaScript waiter disappears. Disposal closes admission, drains accepted work,
then closes actual bound listeners. This member-page actor refuses a Door with
Vault custody; decrypted state belongs in the separate vault-origin runtime. A lost accepted reply is Reconcile.
The generated subscriber receives only dispatcher completion events; observer
failures cannot change an accepted action result.
