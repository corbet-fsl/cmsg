# Browser config byte fixtures (proposed, not executed)

12 declarative boundary/adversary recipes for the **actual published**
`configured()` browser loader. Input/oracle data only: no harness, exporter,
runtime, or API is defined here, and nothing has been executed. The owner
consumes these later with real browser execution.

## Immutable published source

All expectations cite revision `fb534f4` (`Start configured browser owners
through the generated API`), read with:

```sh
git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:tools/browser.ts
git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:src/door/browser.rs
git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:src/door/browser/runtime.rs
git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:src/door/browser/bridge/host.rs
git show fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1:src/door/mod.rs
```

Immutable links to the same revision (read-only; this branch holds no copy):

- [`tools/browser.ts` @ `fb534f4`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts) — `configured()` loader (`#L21-L60`), member entry (`#L63-L69`), `createVaultClient` (`#L129-L132`)
- [`src/door/browser.rs` @ `fb534f4`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs) — `VaultBridgeConfiguration` shape (`#L43-L50`), `BRIDGE_ACK_MILLIS` (`#L84`)
- [`src/door/browser/runtime.rs` @ `fb534f4`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/runtime.rs) — `BrowserRuntime::configured` guard (`#L166-L176`)
- [`src/door/browser/bridge/host.rs` @ `fb534f4`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge/host.rs) — `VaultHost::new` guard (`#L330-L335`)
- [`src/door/mod.rs` @ `fb534f4`](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/mod.rs) — `MAX_BODY_BYTES` (`#L26`), `ErrorCode` (`#L34-L44`)

No owner file was copied into this branch.

## Current-branch fact

Current `origin/main` (this branch base) has **no** browser implementation:
`tools/browser.ts` is absent (see [tools/](../../../tools/)) and
`src/door/` holds only `mod.rs`, `native.rs`, `registry.rs`, `surface.rs`
(see [src/door/mod.rs](../../../src/door/mod.rs)). The limits below come from
the published revision, not from current-branch code.

## Loader oracle (`tools/browser.ts:21-60`)

`configured()` stages and their observable mapping. The outer
`catch { throw new CmsgError('unavailable'); }` (`tools/browser.ts:59`)
maps **every** inner failure — including inner `capacity`
(`tools/browser.ts:43`), `TextDecoder`/`JSON.parse` throws
(`tools/browser.ts:50`), and constructor rejections — to outer
`unavailable`.

| Stage | Source | Inner signal | Outer observed |
|---|---|---|---|
| Fetch + `ok`/body gate | `tools/browser.ts:31-33` | `unavailable` | `unavailable` |
| Chunked read, `length > 65536` | `tools/browser.ts:38-44` | `capacity` (after `reader.cancel()`) | `unavailable` |
| Concat + fatal UTF-8 decode + `JSON.parse` | `tools/browser.ts:47-50` | throw (`decode` or `parse`) | `unavailable` |
| `construct(configuration)` | `tools/browser.ts:54` | constructor error | `unavailable` |
| Late owner (`closed` set) | `tools/browser.ts:55` | dispose requested fire-and-forget, not awaited | `unavailable` |
| Deadline / `pagehide` / platform failure | `tools/browser.ts:22-29` | `stop()` rejects `unavailable` | `unavailable` |

## Loader failures vs constructor validation

Reaching `construct` is a loader success; what the constructor then decides
is separate. Through the TS `configured()` loader every constructor outcome
— success aside — surfaces as outer `unavailable` (`tools/browser.ts:59`).
That mapping is loader-specific: the direct unconfigured API guards keep their
own errors, e.g. `BrowserRuntime.configured` returns `Capacity` over
`MAX_BODY_BYTES` (`src/door/mod.rs:26`) and `InvalidRequest` on bad JSON/shape
(`src/door/browser/runtime.rs:166-176`), and `VaultHost::new` likewise
(`src/door/browser/bridge/host.rs:330-335`). Cases `valid-*` therefore assert
only "loader reaches construct". On the configured member path
(`createConfiguredVaultClient`, `tools/browser.ts:64-68`) the JS constructor
`createVaultClient` destructures the four known fields and ignores extras
(`tools/browser.ts:131`); Rust `VaultBridgeConfiguration::validate` is not
called there (its only call sites are `tests/browser_bridge.rs`), so
`split-multibyte` asserts decode+parse success with an owner-determined final
outcome, not an unknown-field rejection.

## Byte-count vs codepoint

The loader accumulates `value.byteLength` (`tools/browser.ts:42`) and decodes
concatenated bytes once (`tools/browser.ts:47-50`); the 65536 boundary counts
UTF-8 bytes, not JS string length or codepoints. `split-multibyte` splits raw
bytes `C3 A9` across chunks to prove concat-before-decode; `exact-65536` /
`over-65537` pad with ASCII `0x20` so bytes equal codepoints there.

## Configuration-fetch deadline vs later port lifecycle

The 10 s `setupMillis` timer (`tools/browser.ts:14,28`), `AbortController`,
and `pagehide` stop (`tools/browser.ts:22-29`) bound only the
fetch/read/construct window. (The `AbortController` itself is private to
`configured()` — `tools/browser.ts:22` — so cancellation is triggered only via
the public deadline, the `pagehide` event, or an external platform fetch/stream
failure.) They are distinct from the later vault-port
lifecycle: `timeout_millis` in `VaultBridgeConfiguration`
(`src/door/browser.rs:45-50`) and the bridge acknowledgement window
(`BRIDGE_ACK_MILLIS`, `src/door/browser.rs:84`). `fetch-lifecycle-cancel` covers
the former; it asserts nothing about port timeouts.

## Cases (`cases.json`)

| # | id | Covers |
|---|---|---|
| 1 | `valid-single-chunk` | One-chunk valid config reaches construct |
| 2 | `valid-multi-chunk` | Multi-chunk reassembly before decode |
| 3 | `split-multibyte` | Split `C3 A9` still decodes; JS ignores extra field, outcome owner-determined |
| 4 | `invalid-utf8` | Lone `0xFB` fails fatal decode |
| 5 | `empty-body` | Zero bytes fail `JSON.parse` |
| 6 | `malformed-truncated` | Cut mid-string fails `JSON.parse` |
| 7 | `concatenated-json` | Doubled document fails `JSON.parse` |
| 8 | `exact-65536` | Exactly 65536 bytes accumulate |
| 9 | `over-65537` | 65537 bytes: inner `capacity`, outer `unavailable` |
| 10 | `http-refusal` | `ok:false` and missing body, no reader |
| 11 | `fetch-lifecycle-cancel` | 10 s deadline, `pagehide`, platform fetch/stream failure |
| 12 | `late-owner-disposal` | Post-close owner dispose-requested (not awaited), never returned |

Boundary sizes are byte/chunk-length recipes against the canonical template
serialization (source field order, no whitespace: 162 UTF-8 bytes, 139 without
`timeout_millis`); no 64 KiB blobs are embedded.

## Data hygiene

All origins, URLs, and payloads are synthetic reserved `.example` values
(`https://member.example`, `https://vault.member.example`). No credentials,
keys, or real identifiers appear. Current behavior and required acceptance are
kept separate in each case oracle; no fix is invented or implied.
