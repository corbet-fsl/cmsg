#!/usr/bin/env bash
# Original generated-package regressions on provisioned worker tools only.
set -euo pipefail
: "${CI:?CI only}" "${CARGO_HOME:?}" "${CI_COMMIT_SHA:?}"
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$CARGO_HOME/ccid-artifacts/cmsg-browser-package"
export CI_ACCEPTANCE_ARTIFACTS
CI_ACCEPTANCE_ARTIFACTS=$(mktemp -d "$CARGO_HOME/ccid-artifacts/cmsg-browser-package/$CI_COMMIT_SHA.XXXXXXXX")
printf 'Browser package artifacts: %s\n' "$CI_ACCEPTANCE_ARTIFACTS"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/cmsg-browser.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export CMEET_BROWSER_CACHE="$scratch/browser-cache"
mkdir "$CMEET_BROWSER_CACHE"
browser_setup=/nix/store/21z7gs8b28i9mrgcn0bkmyghv8919p4h-cmty-browser-tools/share/cmty-browser-tools/setup.sh
printf '%s  %s\n' 4b4687d368b60df48b6c598b947c3a4715adcb7a1d23eca8b2e080fbb0f1866b "$browser_setup" | sha256sum --check --strict
printf '%s  %s\n' 4b4687d368b60df48b6c598b947c3a4715adcb7a1d23eca8b2e080fbb0f1866b "$browser_setup" > "$CI_ACCEPTANCE_ARTIFACTS/browser-setup.sha256"
. "$browser_setup"
set -euo pipefail
if [[ "$CHECKS" == browser-package-candidates ]]; then
  # The parent survives the timed candidate child to retain failure evidence.
  # Original fixture bearer files also stay inside the parent's EXIT cleanup.
  export TMPDIR="$scratch"
  result=0
  timeout --signal=TERM --kill-after=30s 1800s python3 .ci/browser-package.py || result=$?
  export CMSG_BROWSER_EXIT="$result"
  python3 - <<'PY'
import hashlib, json, os, pathlib, shutil
root = pathlib.Path(os.environ['CI_ACCEPTANCE_ARTIFACTS'])
locks = {}
for name in ['Cargo.lock', 'tests/fixture/Cargo.lock', 'tools/package-lock.json']:
    path = pathlib.Path(name)
    if path.is_file():
        target = root / 'final' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        locks[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    else:
        locks[name] = None
receipt = {'selector': 'browser-package-candidates', 'exit_code': int(os.environ['CMSG_BROWSER_EXIT']),
           'source_commit': os.environ['CI_COMMIT_SHA'], 'source_sha256': os.environ['SOURCE_SHA256'],
           'final_locks': locks, 'product_acceptance': False}
(root / 'candidate-execution.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
PY
  exit "$result"
fi
python3 .ci/browser-package.py
