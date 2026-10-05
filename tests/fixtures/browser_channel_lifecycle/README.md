# Browser channel lifecycle fixtures

Proposed input/oracle data for the owner real browser harness.
Not an executed test, not a production API definition, no harness code here.

## Source

Immutable published owner revision: `fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1`.

Read with `git show <rev>:<path>`; nothing was copied into this branch:

- [`tools/browser.ts` @ `fb534f48`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts) —
  `createVaultClient` / `startVaultHost` channel owner
  (`next` at line 161, `beginClose` 170-177, `fail` 178-186,
  `receive` 187-209, invoke/dispose guard 241-254).
- [`src/door/browser.rs` @ `fb534f48`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs) —
  bridge constants and contract (lines 80-84, 108-111).
- [`src/door/browser/bridge/host.rs` @ `fb534f48`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge/host.rs) —
  vault-frame sequence gate, invoke bound, ack validation,
  retain/complete (lines 44-57, 60-80, 82-95, 99-138).
- [`src/door/mod.rs` @ `fb534f48`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/mod.rs) —
  `MAX_BODY_BYTES`, `MAX_RESULT_BYTES`, `MAX_CLIENTS` (lines 26-28).
- [`src/door/registry.rs` @ `fb534f48`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/registry.rs) —
  original action `runtime.status` (Read, Local).

## Branch fact

Base `c3989b2` (current `origin/main`) has no `tools/browser.ts`
and no `src/door/browser/` directory. The channel exists only at the
owner revision above. These fixtures describe that published behavior
for `createVaultClient` / `startVaultHost` with `runtime.status`
as the nonmutating positive control.

## Data

- [`cases.json`](cases.json) — 12 bounded declarative cases within the 8 KiB budget.
  Correlation ids are small synthetic integers (1, 2, 3, 9, N);
  challenge shape is cited as 32-lowercase-hex without a value.
  Origins in real runs are deployment values such as
  `https://member.example` and `https://vault.member.example`;
  no credentials, payloads, or identifiers appear here.
- Schedules are logical event steps. No timers, no `MessagePort`
  construction, no client implementation, no retry logic.

## Configured vs executed

Configured here: oracle bounds (`maximum_body_bytes` 65536,
`maximum_pending` 64, `maximum_request_bytes` 393472,
`maximum_reply_bytes` 6295552, `acknowledgement_millis` 30000)
and per-case `expect` (published consequence) vs `required`
(owner-harness proof still to execute, e.g. the late-reply execution).
Executed later: the owner real
browser harness performs actual `createVaultClient` / `startVaultHost`
round trips, timeouts, and disposal checks. No success is
claimed until that harness runs.
