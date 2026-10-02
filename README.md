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

### Purpose

cmsg is the member's backend on their own device, offering one versioned local API with generated HTTP/OpenAPI, MCP, CLI, and TypeScript views, composed from Vault, Mesh, Foyer, Board, and Inbox.

### Owns

| Area | Responsibility |
|---|---|
| Local API | One action registry and dispatcher; all projections share identical authorization and semantics |
| Clients | Bounded, revocable, origin-bound local capabilities, separate from passkeys and service sessions; third parties embed cmsg unchanged |
| Orchestration | Routes cross-facade operations and includes every accepted effect in one combined encrypted checkpoint before any result, event, or output escapes; coordinates the Groups and Threads checkpoint |
| Administration | Forwards admin and root actions through Foyer with separate sessions and origins |
| Runtime | Lifecycle management, readiness reporting with use blocked until Mesh reports ready, refusal to run below the published minimum version, and the member MCP server on the member's machine |

### Never

| cmsg does not |
|---|
| Keep domain workflows; those stay in the specialist libraries and facades |
| Export member keys or PRF material through APIs, errors, logs, or remote access |
| Grant extra privilege to any frontend, or let a caller switch community or role |
| Let a frontend bypass it to reach backend services directly |
| Keep legacy or parallel code paths, protocol libraries, policy engines, rosters, wallets, or retry machines |
| Record member traces |

### States

Starting, then Locked or Ready, then Stopping. Action progress is derived from the committed checkpoints of the child facades, and the door is not usable before Mesh readiness is reported.

### Test obligations

| Area | Requirement |
|---|---|
| Parity | Every action behaves identically across HTTP, MCP, CLI, and TypeScript views, including administration and group views |
| Authorization | Wrong origins, expired or revoked capabilities, wrong action sets, cross-community calls, and wrong roles are refused |
| Decoding | Oversized, duplicate-field, and unknown-field requests are refused before typed decoding, within bounded resource limits |
| Atomicity | Crashes or cancellations at every checkpoint boundary leave no output before the combined checkpoint; restarts replay to exactly one effect, and uncertain sends reconcile without blind retry |
| Flows | Group consent, offline delivery, restore, readiness gating, minimum-version refusal, and unchanged third-party embedding work end to end |
| Hygiene | No secrets, PRF material, plaintext, identifiers, or cross-community keys appear in traces, errors, or debug output |
| Common | Native and Wasm builds share identical test vectors; state machines declare states, inputs, outputs, and failures with injected clock, randomness, storage, and network; coverage is full line and branch with real round trips and injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts; each community keeps independent keys, identities, locators, sessions, and stores; maintained third-party code is reused and no own cryptography is shipped |
