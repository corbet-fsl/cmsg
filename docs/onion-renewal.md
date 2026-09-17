# Onion publication renewal

An onion service publishes descriptors for more than one directory period.
The pinned Arti publisher returned from its entire upload loop when the first
period had no dirty directories. That could skip a later period needing a new
descriptor. The fix skips the clean period and continues processing the rest.
It does not change Tor's publication intervals, keys or directory selection.

## Regression

The upstream publisher test uses the real reactor with its existing mock
runtime and HTTP transport. It checks clean/dirty period orderings and counts
the directory uploads, including no uploads for already clean periods.

CI runs the publisher suite against the fix, then temporarily restores the
original early return in its isolated checkout. The targeted regression must
fail at the expected upload-count assertion. CI restores the exact fixed source
before building the Wasm artifact and records that source's digest. A compiler
failure or timeout does not satisfy this negative control.

## Live check

`TOR_RENEWAL=1 TOR_NETWORK=private TOR_STAGE=test-network RUN_RUNTIME=1`
selects an extended run on the signed private Tor fixture. It retains that
fixture's existing eight-minute directory periods and full vanguards.
The production/public-network timing configuration is unchanged.

Diagnostic builds report per-service successful publication batches and public
period numbers. The test waits for a later period and a successful publication
for that period while retaining the original onion addresses. It checks an
established browser stream across the transition, then fresh browser traffic
and a fresh native/browser authenticated MLS exchange with replay rejection.
Elapsed time alone is insufficient evidence of renewal.

This exercises real directory-period transition and descriptor publication.
The separate ordinary 60–120-minute reupload timer remains at its upstream
duration; the focused publisher tests cover scheduling without requiring that
wall-clock wait. This bounded check does not establish indefinite availability.

The fixture uses an explicit 900-second renewal wait, a 2,000-second browser
contract limit, a 2,100-second driver supervisor, and a 4,300-second outer
fixture limit including signed-randomness warmup, with 80 seconds for forced
cleanup. These are test budgets, not
product defaults. It retains the documented upstream dependency snapshot;
the tested cmsg revision advances to the current source.

## Evidence

The focused [Crow run 85](https://crow.corbet.ch/repos/10/pipeline/85), step
`24782`, passed at cmsg `70db23dacf1b64b619ae6e2232604b69020a4fbf`:
13 publisher tests, the expected failure with the original early return,
three ephemeral-state tests, two process-cleanup regressions and the service
Wasm check. The exact fixed source was restored before completion.

The source archive SHA-256 is
`a806394f58162994a071affb8266d8e867ad1ef99f1b7e3501fa41b73e1168f4`.
The artifact manifest SHA-256 is
`fe02c1de9a623569437e9a18d76dc399982ddcd3f84aa097d0d4905ec89b0aba`.
Downloaded test logs, source receipt and negative-control receipt were checked
against that manifest; this is a partial artifact download.

### Live renewal passed

[Crow run 86](https://crow.corbet.ch/repos/10/pipeline/86), step `24784`,
passed on 2026-09-17 at cmsg `b63a1941ac286c9313e1bb9340e28af30bb40b54`.
It passed all 12 live contract checks on the signed 27-node private network.
Both services initially reported `running` and retained their onion addresses.

For **each service**, the snapshot changed as follows:

| Evidence | Before | After |
| --- | ---: | ---: |
| Current directory period | 3728439 | 3728440 |
| Latest successfully published period | 3728440 | 3728441 |
| Accepted batches containing successful uploads | 2 | 3 |

The observed transition wait was **537.232 seconds**. The retained stream
completed **37 authenticated MLS request/reply round trips**, including traffic
before, during and after renewal. A fresh browser Arti client with empty storage
then bootstrapped, connected and exchanged authenticated MLS in both directions
in 1.213 seconds. A second native connection and MLS exchange took 0.437 seconds
and rejected replay. The native Tor client was reused; its descriptor cache
was not cleared. Both native invocations exited successfully.

This run also passed 13 publisher tests, the negative control, one diagnostic
isolation/late-batch test, three ephemeral-state tests, two process-cleanup
regressions, 52 KPS parser tests, 11 gateway tunnel tests and nine gateway
configuration tests. The gateway canary received zero connections and there
were no unexpected page HTTP requests. All owned-process cleanup succeeded.

Signed-randomness warmup took 804.360 seconds. The fixture retained its native
client's accepted initial and final consensuses, spanning 13:20:00–13:29:00 UTC,
with distinct current/previous shared-random values. Environment: Chromium
`152.0.7977.64`, Node `24.19.0`, native Tor `0.4.9.12`.

Artifacts are under
`/workspaces/component-releases/cmsg/b63a1941ac286c9313e1bb9340e28af30bb40b54/tor-test-network-diagnostics-renewal/`.
Downloaded source/test receipts, runtime evidence, test logs and signed fixture
consensuses were verified against the manifests; the download is partial.

- Source archive SHA-256: `b1a8ec7b9f6d22106fff67bc01f37274c783513f461dff001ffacb46f2760cc0`.
- Root artifact manifest: `1d53dbb1d47045d306c5c73c8ab1b228a56a38aaea98788063334dfa2daf5eaa`.
- Runtime artifact manifest: `ad8535a5017b3f60f81771bc231b56219e57d66c47cb8143e04614802079c498`.
- Runtime evidence: `29e8f3d9682bf3ddc6e9978d57d701ab82739c743ce3652110175862509f689a`.

This closes the identified skipped-period defect and demonstrates continuity
across the tested renewal. Public-network exchange has [separate evidence](public-tor-validation.md).
Public-network renewal over ordinary wall-clock intervals, mobile behavior,
process-wide browser confinement and indefinite availability remain unverified.
