# browser-channel-origin fixtures

Proposed input/oracle data for the published `createVaultClient` /
`startVaultHost` channel establishment and its exact origin/source checks.
See [cases.json](./cases.json). Existing tests (for example
[tests/door.rs](../../door.rs)) cover the configured native door, a
different subject; they are not bridge coverage.

## Pinned source (read-only, never copied here)

Revision `fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1`; short cites in
`cases.json` resolve against these immutable links:

- [`tools/browser.ts` guards](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts#L130-L141) —
  `createVaultClient` pre-frame guard, URL parse, pair check
- [`tools/browser.ts` hello](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts#L210-L225) —
  READY echo and CONNECT accept branches
- [`tools/browser.ts` loaded/timer](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts#L226-L233) —
  second load fails, `readyTimer` gives `unavailable`
- [`tools/browser.ts` configured entries](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts#L63-L79) —
  top-level and direct-child preconditions
- [`src/door/browser.rs` vault_pair](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs#L114-L130)
- [`src/door/browser.rs` bridge config](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs#L42-L69)
- [`src/door/browser/bridge.rs` same_source](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge.rs#L37-L43)
- [`src/door/browser/bridge/host.rs` attach](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge/host.rs#L160-L178)
- [`src/door/browser/bridge/host.rs` hello](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge/host.rs#L205-L251)

Same content offline via
`git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:<path>`.

Current `origin/main` (base `c3989b2`) has no `tools/browser.ts` and no
`src/door/browser/`; that absence is preserved and nothing was copied.

## Port note

`MessagePort` data itself carries no authenticated origin. `receive()`
checks only trust, ports, string shape and size; origin and source are
checked when the real port is transferred and bound (`hello()` /
`same_source()`). Post-bind traffic is sequenced and challenged, not
origin-checked.

## Configured vs executed

`cases.json` is proposed oracle data, not an executed test and not a
production API definition. No executed-success claim is made; owner
real-browser integration is pending.

## Current vs required

Oracles record pinned-rev behavior; each case names its exact boundary and
precedence in `at`. Where behavior is two-phase, the immediate event oracle
(`exp`) and the eventual setup outcome (`then`) are separate fields:

- `wildcard_origin`: direct `createVaultClient` hits the first
  `location.origin !== member` guard, so `unauthorized`, not
  `invalid_request`.
- `opaque_origin`, `foreign_page_redirect`: the foreign event is ignored
  (extra ports closed); only the later `readyTimer` yields `unavailable`.
  `iframe.src` is plain navigation, not the `configured()` fetch, so there
  is no immediate redirect-policy refusal.
- `duplicate_handshake`: split into `duplicate_ready_connect` (ignored) and
  `second_iframe_load` (`fail_reconcile`).
- `community_protocol_version`: field absence is current shape only. JS
  extra fields and Rust `deny_unknown_fields` are distinct paths; no
  outcome is asserted and no policy is proposed.

All values are synthetic under reserved `.example` origins. No credentials,
keys, or real identifiers appear.
