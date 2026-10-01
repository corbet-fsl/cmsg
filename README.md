# cmsg

The device-local Member door for cmtymeet. `cmsg::door` owns one action registry
and dispatcher, with generated HTTP/OpenAPI/MCP/CLI/TypeScript projections.
Current local actions provide unavailable-runtime status, schema discovery and
client revocation, guarded by bounded origin-bound capabilities. The native
client forwards original bytes to the same dispatcher.

[Local API and native client](docs/LOCAL-API.md) · [Door contract](docs/CONTRACT.md)

Domain facades, production pairing, current admission and combined checkpoint
integration remain incomplete. No local status or historical fixture establishes
member readiness or full network acceptance.

## Historical implementation

The former monolith is preserved in immutable Git history. Its source, tests,
transport overlays and evidence are indexed in the [retirement map](docs/RETIREMENT.md).
Dedicated leaf owners carry the outstanding regression and integration obligations.

License: [FSL-1.1-ALv2](LICENSE.md).

## Scope

The member backend on the device exposes one versioned local action registry and
dispatcher through generated HTTP/OpenAPI, MCP, CLI and TypeScript views. Every
frontend uses the same capability, origin, role and community checks. Local client
capabilities are bounded and revocable; they are separate from passkeys and service
sessions. Vault, Mesh, Foyer, Board and Inbox retain their domain authority.

The door owns runtime lifecycle and cross-facade orchestration. An accepted effect
must be included in one combined encrypted owner checkpoint before any result,
event or output escapes. Groups decides membership and Threads executes it; the
door coordinates their checkpoint. Admin and root operations use Foyer's generated
`cvld` projections and separate sessions/origins. The trusted origin policy
includes the configured vault origin; WebAuthn RP policy belongs to its owners.
Preload remains blocked until Mesh actually reports ready, and an unsupported
published minimum version must refuse runtime use.

The door never exports member keys or PRF material, records member traces, lets a
caller choose another community or role, or gives official clients extra privilege.
It has no policy engine, roster, wallet, retry machine or alternate remote door.
Runtime states derive from the children: starting, locked/ready, and stopping.

Validation must cover every projection's authorization and typed parity, bounded
strict decoding, revocation and origin isolation, crash/cancellation at every
checkpoint boundary, reconciliation of uncertain sends, restore/offline delivery,
GroupView and consent, real Mesh readiness, minimum versions, and third-party use
of the unchanged door. Missing owner operations return typed failures. The current
implementation boundary is documented in [the contract](docs/CONTRACT.md).
