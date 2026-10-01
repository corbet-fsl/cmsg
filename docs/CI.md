# Validation

`ci.yml` resolves a fresh root lockfile once, then tests exactly that snapshot on
stable Rust natively and in a real headless browser. A separate nightly compiler
is needed for LLVM branch instrumentation. Both integer line and branch counts
must be fully covered. The single line-only exclusion is documented below.

The retired monolith and its evidence remain in immutable Git history, indexed
in RETIREMENT.md. The new door gate covers only current cmsg production sources.
It neither replaces leaf regression obligations nor proves current membership,
accounting, Tor networking or full-system acceptance.
Automatic validation is serialized. Expensive scale/churn belongs on owned CI.

Dependabot covers every tracked manifest. Auto-merge uses only trusted workflow
code and GitHub metadata; it requires protected main, administrator enforcement,
all substantive jobs and every exact-head check/status green. No PR checkout or
artifact is executed under the merge token.

References: [LLVM coverage](https://github.com/taiki-e/cargo-llvm-cov),
[workflow security](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).

The strict gate uses every source line and branch emitted by upstream LLVM LCOV
from the same execution as the retained JSON diagnostic. Both counts must be
exactly complete after the single documented unreachable line below. This is source coverage, not
coverage of each separate generic instantiation. Fixture sources under tests/
are excluded from the production report and are still executed normally.

## Narrow initialization boundary

`.ci/coverage-exclusions.json` records the exact source and line of the defensive
reqwest ClientBuilder initialization-error conversion. The fixed constructor has
TLS/default features disabled, the default GAI resolver and no caller-selected
builder settings. Upstream documents builder failures at TLS/resolver setup; no
supported input to this constructor can induce that callback. It is retained for
upstream changes/feature unification and returns Unavailable before any request.

The gate requires the exact source, a rationale, primary evidence and a zero
count; a moved, absent or newly exercised line fails pending review. No branch,
authorization, body, mutation, timeout, retry or response path is excluded. Raw
LCOV/JSON always retain the missed line. The exception requires independent
review and does not assert that upstream initialization cannot ever fail.
