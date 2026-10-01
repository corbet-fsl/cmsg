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
