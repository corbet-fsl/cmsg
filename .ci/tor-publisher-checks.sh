#!/usr/bin/env bash
# Run only against the task-owned patched Arti checkout on CI.
set -euo pipefail
test "$#" = 2
arti_manifest="$(realpath "$1")"
artifact="$(realpath "$2")"
reactor="$(dirname "$arti_manifest")/crates/tor-hsservice/src/publish/reactor.rs"
features=tor-rtcompat/tokio,tor-rtcompat/native-tls
regression=publish::test::upload_all_skips_clean_periods_without_skipping_dirty_periods

timeout 1800 cargo test --locked --manifest-path "$arti_manifest" \
  -p tor-hsservice --features "$features" publish:: -- --test-threads=2 \
  2>&1 | tee "$artifact/publisher-tests.log"
if test "${TOR_RENEWAL:-0}" = 1; then
  timeout 1800 cargo test --locked --manifest-path "$arti_manifest" \
    -p tor-hsservice --features "$features" fixture_renewal_tests -- --test-threads=2 \
    2>&1 | tee "$artifact/publisher-renewal-diagnostics-tests.log"
fi

# Demonstrate that the regression detects the original defect. Keep all other
# source bytes fixed, and restore the tested implementation before any build.
fixed_source="$(mktemp)"
cp "$reactor" "$fixed_source"
trap 'cp "$fixed_source" "$reactor"; rm -f -- "$fixed_source"' EXIT
python3 - "$reactor" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
source = p.read_text()
fixed = ('trace!("the descriptor is clean for all HSDirs. Nothing to do");\n'
         '                // Other time periods may still have dirty HSDirs to upload to.\n'
         '                continue;')
if source.count(fixed) != 1:
    raise SystemExit("publisher regression control source no longer matches")
p.write_text(source.replace(fixed, fixed.replace("continue;", "return Ok(());")))
PY
control_status=0
timeout 1800 cargo test --locked --manifest-path "$arti_manifest" \
  -p tor-hsservice --features "$features" "$regression" -- --exact \
  > "$artifact/publisher-regression-unfixed.log" 2>&1 || control_status=$?
test "$control_status" = 101
python3 - "$artifact/publisher-regression-unfixed.log" <<'PY'
from pathlib import Path
import sys
log = Path(sys.argv[1]).read_text()
required = [
    'test publish::test::upload_all_skips_clean_periods_without_skipping_dirty_periods ... FAILED',
    'dirty period upload was skipped or a clean period was uploaded',
    'test result: FAILED. 0 passed; 1 failed;',
]
if not all(value in log for value in required):
    raise SystemExit("unfixed control did not fail at the expected regression assertion")
PY
cp "$fixed_source" "$reactor"
cmp "$fixed_source" "$reactor"
python3 - "$reactor" "$artifact/publisher-regression-control.json" <<'PY'
from pathlib import Path
import hashlib, json, sys
source = Path(sys.argv[1]).read_bytes()
Path(sys.argv[2]).write_text(json.dumps({
    "fixedPublisherSuitePassed": True,
    "originalEarlyReturnRejectedByRegression": True,
    "testedSourceRestored": True,
    "restoredReactorSha256": hashlib.sha256(source).hexdigest(),
}, indent=2) + "\n")
PY
printf 'Publisher suite passed; regression rejected original early return; fixed source restored.\n'
