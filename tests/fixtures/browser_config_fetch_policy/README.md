# Browser configured-fetch policy fixtures

Declarative fixtures for the actual configured member/vault HTTP fetch
policy. Data only: `cases.json` (8 fixtures). No code, no client, no fetch
stub. Execution is pending owner HTTPS browser harness; nothing here ran.

## Pinned source (read-only, do not copy)

- Owner commit `fb534f483bb2ec0670237ac3c8fa2e25ae17c9f1`
- Blob `454f679edfaca59436f8dfa85e457f07c2749751` (`tools/browser.ts`)
- Fixed paths: `tools/browser.ts:18-19,64-68` (member) and `:72-78` (vault)
- Fetch options: `tools/browser.ts:31-33`
- After-fetch mapping: `tools/browser.ts:33,59` (`unavailable`; `capacity` on over-limit)

Base `main` (`c3989b2`) has no implementation of this path. These fixtures
declare what the owner harness must observe; they implement nothing.

## What is pinned

- Member entry `createConfiguredVaultClient` fetches exactly
  `/cmsg/member.json` from the embedding page's own origin.
- Vault entry `startConfiguredVaultHost` fetches exactly
  `/cmsg/vault.json` from the embedding page's own origin.
- Query strings, action bodies, and the member channel cannot override
  the paths (`tools/browser.ts:18-19`).
- Fetch specifies `cache: 'no-store'`, `credentials: 'omit'`,
  `redirect: 'error'`, `referrerPolicy: 'no-referrer'` (`:31-32`).
- Precondition: member needs top-level `https:` page (`:65`); vault needs
  direct-child `https:` frame (`:73-74`). Wrong context rejects with
  `unauthorized` before any fetch. Failures after fetch map to
  `unavailable` (`:33,59`).

## Configured vs executed

`cases.json` records the *specified* fetch option from source plus the
*per-request network observation* the harness must make. The observation
(pass/fail on one real request) is the execution proof. Fixtures claim no
universal browser-cache behavior, which Fetch semantics do not support.

## Harness recipe (owner runs later)

1. Serve synthetic hosts only: `https://member.example/`,
   `https://vault.example/`. Fixed `.example` data, no personal data.
2. Call only the real public entrypoint in a real HTTPS page
   (`createConfiguredVaultClient` / `startConfiguredVaultHost`).
3. Observe the actual test HTTPS server log: exact path, query absence,
   `Cookie`/`Referer` absence, 302 with no follow-up, fresh bytes.
4. Never stub `fetch`, clients, or Wasm; never touch private functions.
5. Distinct from byte/chunk/lifetime fixtures; no keys, passkeys, crypto,
   UI, CI, production, or owner files.

## Status

- `cases.json`: 8 fixtures, 6165 bytes.
- Static review only (`git diff --check`). No builds, tests, or browser
  runs here. Owner HTTPS browser execution needed; no acceptance or
  correctness claimed beyond the pinned source.
