# Browser embedding entrypoints (published candidate, not current API)

Status: evidence map of owner candidate
`fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1`, inspected from git objects only.
Current `origin/main` (`c3989b2cb1ec0535b6dc09de5fb3c51faf16e0e7`) has no
`src/door/browser*` and no `tools/browser.ts` (only `mod/native/registry/surface`);
it exposes no browser entrypoint. Nothing below is a released current API,
and nothing here was executed locally; source eligibility is not execution.

Candidate blobs (immutable):

- [tools/browser.ts](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/tools/browser.ts)
- [src/door/browser.rs](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser.rs)
- [src/door/browser/runtime.rs](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/runtime.rs)
- [src/door/browser/bridge.rs](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge.rs)
- [src/door/browser/bridge/host.rs](https://github.com/corbet-libs/cmsg/blob/fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1/src/door/browser/bridge/host.rs)

Architecture stays in [LOCAL-API](LOCAL-API.md) and [CONTRACT](CONTRACT.md);
this map only names the published constructors and their fixed wiring.

## Configured entries (fixed paths)

- `createConfiguredVaultClient()` fetches `/cmsg/member.json` as
  `VaultBridgeConfiguration`, then calls `createVaultClient`.
- `startConfiguredVaultHost()` fetches `/cmsg/vault.json` as
  `VaultHostConfiguration`, then calls `startVaultHost` (`VaultHost::new`).
- Paths are fixed; action bodies, query strings and the member channel
  cannot override them. Example origins only: `https://member.example`,
  vault `https://vault.member.example` (same port, `https:`).

## Constructors and accepted frame/origin

- `createConfiguredVaultClient`: top-level window only
  (`window.top === window`), `https:`; else `unauthorized`.
- `createVaultClient(config)`: top-level window only (`parent === window`,
  consistent with `createConfiguredVaultClient`); embedded children are
  rejected. Requires `location.origin === member_origin`, `vault` host exactly
  `vault.<member-host>`, same port, page URL on the vault origin with no
  userinfo/query/fragment; else `unauthorized` / `invalid_request`.
- `startConfiguredVaultHost`: non-top frame whose parent is top
  (`parent !== window && parent === top`), `https:`; else `unauthorized`.
- `VaultHost::new` / `attach`: actual origin must equal `vault_origin`;
  parent must be the top member window; member/vault pair rule as above.
- `createBrowserClient(config)` (`BrowserRuntime::new`): partial non-custody
  page runtime; requires config origin to equal the actual page origin and
  forbids vault custody in this runtime; else `unauthorized`.
- `prepareCliLogin(config, launch)`: native CLI callback page; the trusted
  caller consumes the fragment before invoking it (before custody Wasm is
  imported). It exposes progress and handover only, never a
  launch/callback capability.
- Popup/passkey sealing is owner code and is not detailed here.

## Fetch, lifetimes, limits, disposal

- Config fetch: `cache: no-store`, `credentials: omit`, `redirect: error`,
  `referrerPolicy: no-referrer`, abort on `pagehide`; 10 s setup cap and
  65,536-byte config cap. The outer catch maps every config-loading
  failure, including over-cap reads, to `unavailable`.
- Channel lifetime is separate from config fetch: one owner per
  constructor, one `dispose()` each. `configured()` disposes a late owner
  fire-and-forget (`void`/`catch`) without awaiting its drain, while
  `createVaultClient`'s `dispose()` returns the done promise that awaits
  the acknowledged close. Frame removal happens only on the
  owner-acknowledged close; none is promised after errors.
- Bounds: request body 65,536 B, outer request envelope 393,472 B, reply
  6,295,552 B, at most 64 pending requests/admissions
  (`maximum_pending`), `u32` sequence ids, 30 s acknowledgement window
  (`BRIDGE_ACK_MILLIS`). Refusals differ by layer: an oversized member
  request body, a full pending map, or an exhausted id sequence returns a
  per-request bounded refusal; an oversized or malformed incoming reply
  fails the channel and settles pending calls as `reconcile`; host-side
  request, admission, or retained-reply overflow closes the channel
  without a per-request refusal.
- Actual errors observed: `unavailable`, `unauthorized`, `invalid_request`,
  `capacity`, `reconcile` (plus `clock` in runtime paths). Unknown outcomes
  reconcile and are never blindly retried; the custody frame is never
  removed except on the owner-acknowledged close; no secret-transfer promise.

## Placement and acceptance prerequisites

- Placement: member page embeds the isolated vault frame (`iframe` titled
  `Account security`, sandboxed, `publickey-credentials` disabled,
  `no-referrer`); custody Wasm loads only in the vault frame, never on the
  member path. No screens or stand-in flows are described here.
- Prerequisites: Tor is the browser path that must work; member use waits
  for Mesh readiness / preload gate and the published minimum version
  (see CONTRACT). No executed round trip is claimed; the map above is
  source-described only.
