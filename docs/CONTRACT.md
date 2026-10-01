# Member door contract

The Member door is the sole frontend boundary for one device/community runtime.
One Rust registry owns action, version, typed body/result/event, authority, effect
and coarse error metadata. HTTP/OpenAPI/MCP/CLI/TypeScript are generated views.
The same bounded dispatcher checks every local capability, exact origin, action
set, expiry, revocation and fixed runtime scope. Requests cannot select a role
or community. Root/admin origins and sessions remain separate from members.

Current local actions are runtime.status, runtime.describe and client.revoke.
All domain owners remain unavailable, so preload remains blocked. No network
reachability flag, compile test, transport ACK or fixture can create readiness.
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

Historical monolithic messaging sources are retained while dedicated owners
extract them. Their old callback/fixture authorities do not satisfy current
admission, accounting, key custody, room, transport or restore acceptance.
Native and actual Wasm parity, full reachable line/branch coverage, real local
HTTP invocation, shared-checkpoint failure/replay tests, live owner integration
and independent review are required; passing one subset never implies the rest.
