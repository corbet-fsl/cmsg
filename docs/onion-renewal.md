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

The live renewal check is pending. The earlier successful
[public Tor exchange](public-tor-validation.md) is separate evidence.
