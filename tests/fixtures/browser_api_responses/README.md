# Browser API response fixtures (proposed inputs/oracles)

Proposed `createCmsgClient`/vault-bridge **response decoding** vectors for the real
owner constructor harness. This directory is data only: no test runner, no client,
no validator, no harness. Nothing here has been executed locally.

## Decoder under test (exact sources)

- Bridge `receive()` (pinned rev): `tools/browser.ts:L187-L209` — enforces
  `isTrusted`/no-ports/string/`maximum_reply_bytes` (`L188-L189`), `JSON.parse`
  (`L191`), `reply.output.status` is `ok` or `error` (`L197`), 32-hex `challenge`
  (`L198`), pending-id match and `ack` (`L195-L200`). `fail()` (`L178-L186`)
  resolves every pending waiter with `failure('reconcile')` (`L12`), clears the
  map, and begins close — so a refused payload still settles the pending call
  with typed reconcile, never silence. It does **not** check
  `result`/`events`/`error` presence, event shape, per-action result type, or the
  error literal set.
- Generated client, pinned rev: `tools/generate.mjs:L42-L69` — `transport(...) as
  ActionOutput` cast (`L44`), `ok` event fan-out (`L45-L50`), `call()` throws
  `CmsgError` on `error` else returns `result` (`L64-L68`). No status whitelist,
  no shape or literal checks, no size check.
- Generated client, current base: `tools/generate.mjs:L37-L49` — even thinner:
  cast (`L39`), `error` throws else return `result` (`L45-L46`). No event loop.
- Envelope truth (both revs): `src/door/mod.rs:L152-L157` (`Output`),
  `L26-L37` (closed `ErrorCode` literals), `L159-L163` (`Event`),
  `L175-L181` (`RuntimeStatus`), `L20-L21` (byte bounds).
- Bridge contract (pinned rev): `src/door/browser.rs:L80-L110`
  (`BRIDGE_MAX_REPLY`, `VaultBridgeReply`, `bridge_contract()`).
- Desired-only references (not received-response decoder behavior):
  `tools/check.mjs:L16-L24` is a build/conformance validator, not runtime
  enforcement; per-action specialization in `src/door/surface.rs:L7-L19` is
  server-side only. The actual runtime-enforced contrast is the strict native
  response parsing in `src/door/native.rs:L256-L272`.

## Pinned immutable sources

- [tools/browser.ts @ fb534f48](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts) — `receive()` response decoder.
- [tools/generate.mjs @ fb534f48](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/generate.mjs) — pinned client template.
- [src/door/browser.rs @ fb534f48](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs) — bridge contract and reply shape.
- Current-base files: [tools/generate.mjs](../../../tools/generate.mjs),
  [src/door/mod.rs](../../../src/door/mod.rs),
  [src/door/surface.rs](../../../src/door/surface.rs),
  [src/door/native.rs](../../../src/door/native.rs),
  [tools/check.mjs](../../../tools/check.mjs),
  [tools/client-conformance.mjs](../../../tools/client-conformance.mjs).

Base `c3989b2` has no `tools/browser.ts` and no `src/door/browser/`; every
bridge oracle below cites pinned rev `fb534f48` read from git objects.
Source-described APIs on other candidate branches are not current main.

Related docs: [local API](../../../docs/LOCAL-API.md),
[contract](../../../docs/CONTRACT.md), [coverage](../../../docs/COVERAGE.md).

## Preconditions (every case)

Each case assumes a fresh vault bridge channel: connected, not closing, exactly
one pending invoke with id 1. Every Output reply in `cases.json` uses id 1 with
the fixed 32 lower-hex challenge, so each reply matches the pending call with no
pending-map mutation and no fake client. Wire data is a UTF-8 string; the byte
guard measures `TextEncoder` byteLength against `maximum_reply_bytes`. A bridge
refusal (`fail()`) resolves the pending id-1 call with typed
`{status:error,error:reconcile}` and begins close: the malicious payload is
never delivered, but the pending call still settles.

## Oracle reading

Each case in `cases.json` carries `bridge_expect` (pinned `receive()` oracle) and
`client_expect` (generated `createCmsgClient` oracle). `*_gap_*` means the shape
is **accepted today**; the note names the desired validation that does not exist.
The harness must assert the gap (pass-through), never invent a rejection.

| id | oracle |
|---|---|
| `valid_runtime_status_ok` | bridge accepts; `call()` returns the `RuntimeStatus` result |
| `valid_typed_error_unavailable` | bridge accepts; `call()` throws `CmsgError('unavailable')` |
| `malformed_non_json` | bridge `fail('reconcile')` on `JSON.parse`; pending call settles with typed reconcile, `call()` throws `CmsgError('reconcile')` |
| `unknown_status` | bridge `fail('reconcile')` (`pending` status); pending call settles with typed reconcile (a bare cast without the bridge would pass it through) |
| `missing_result` | gap: bridge accepts, `call()` yields `undefined` |
| `missing_events` | gap: bridge accepts; pinned client throws untyped `TypeError`, current client returns result |
| `missing_error` | gap: bridge accepts, `CmsgError(undefined)` |
| `wrong_event_shape` | gap: unknown `{event:made_up}` returned; emission asserted only with a subscriber registered before the call |
| `action_result_mismatch` | gap: `runtime.status` returning `{revoked:true}` accepted (cast only) |
| `unknown_error_literal` | gap: `made_up_error` accepted and thrown as `CmsgError` |
| `oversized_reply` | bridge `fail('reconcile')` on byte length; pending call settles with typed reconcile; harness appends ASCII whitespace to exactly 6295553 UTF-8 bytes (`BRIDGE_MAX_REPLY` 6295552 + 1), isolating the byte guard; the literal reply is the shape template only |

## Owner review items (gaps; no production fix here)

- G1 `missing_result`: no required-`result` check in bridge/client.
- G2 `missing_events`: no required-`events` check; pinned failure mode is untyped.
- G3 `missing_error`: no required-`error` check on `error` status.
- G4 `wrong_event_shape`: the Rust door emits typed `Output`, but the
  received-response boundary (bridge/generated client) performs no event
  validation, so the unknown event is emitted and returned.
- G5 `action_result_mismatch`: `ActionOutput` is a compile-time cast, not a runtime check.
- G6 `unknown_error_literal`: literal-set refusal exists in the build validator
  and the strict native decoder only, not in bridge/received client.
- G7 general: oversized enforcement lives only in the bridge byte guard, not in the generated client.

These are observations for owner review, not a directive to change decoder
policy; any new validation is the owner's decision.

## Boundaries

- Response decoding only. Request shape, handshake, origins, config loading, and
  lifecycle/disposal corpora belong to sibling packages; nothing here duplicates them.
- Synthetic reserved `.example`-style data only (`fixture-community`); no tokens,
  secrets, or real identifiers.
- `cases.json` stays under 8 KiB and copies no schema; the oversized length
  recipe (`wire_utf8_bytes`, `wire_recipe`) sits outside the reply payload: the
  harness appends ASCII whitespace to valid serialized JSON to exactly 6295553
  UTF-8 bytes, and the literal reply is the shape template only.
- Configured, not executed: static source/data review plus `git diff --check` only.
  No local builds, tests, typechecks, or dependency installs were run.
