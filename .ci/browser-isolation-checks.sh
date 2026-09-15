#!/usr/bin/env bash
# Existing CI worker only. No installs, capability changes or host network edits.
set -euo pipefail
: "${ARTIFACT_ROOT:?artifact root required}"
: "${CI_COMMIT_SHA:?verified source revision required}"
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/browser-isolation"
mkdir -p "$artifact_dir"
result=0
python3 - "$artifact_dir/isolation.json" <<'PY' || result=$?
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

record = {
    "source": os.environ["CI_COMMIT_SHA"],
    "status": "unsupported",
    "scope": "disposable user/network namespace capability; browser runtime not executed",
    "kernel": platform.release(),
    "python": platform.python_version(),
    "parentNetworkNamespace": os.readlink('/proc/self/ns/net'),
    "hostNetworkChanged": False,
}
exit_code = 2
try:
    search = '/nix/var/nix/profiles/system/sw/bin:/shared:' + os.environ.get('PATH', '')
    tools = {}
    for name in ('unshare', 'ip'):
        found = shutil.which(name, path=search)
        if not found:
            raise RuntimeError('required existing namespace tool unavailable')
        tools[name] = os.path.realpath(found)
    record['tools'] = {
        name: {'path': path, 'sha256': hashlib.file_digest(open(path, 'rb'), 'sha256').hexdigest()}
        for name, path in tools.items()
    }
    # The child verifies namespace separation BEFORE bringing up its own lo.
    # --kill-child terminates it if the bounded unshare supervisor is killed.
    child = r'''
import json, os, subprocess, sys
ip, parent_namespace = sys.argv[1:]
namespace = os.readlink('/proc/self/ns/net')
if namespace == parent_namespace or os.getuid() != 0:
    raise RuntimeError('new mapped user and network namespace required')
def run(*args):
    return subprocess.run([ip, *args], check=True, capture_output=True, text=True, timeout=3).stdout
links = json.loads(run('-j', 'link', 'show'))
if [link['ifname'] for link in links] != ['lo']:
    raise RuntimeError('namespace contains an unexpected network interface')
run('link', 'set', 'dev', 'lo', 'up')
links = json.loads(run('-j', 'link', 'show'))
if 'UP' not in links[0]['flags']:
    raise RuntimeError('isolated loopback did not become active')
routes = {family: json.loads(run('-j', family, 'route', 'show', 'table', 'all'))
          for family in ('-4', '-6')}
if any(route.get('dst') == 'default' or route.get('dev') not in (None, 'lo')
       for entries in routes.values() for route in entries):
    raise RuntimeError('namespace contains an external or default route')
print(json.dumps({'networkNamespace': namespace, 'mappedUid': os.getuid(),
                  'interfaces': ['lo'], 'loopbackUp': True,
                  'ipv4DefaultRoutes': 0, 'ipv6DefaultRoutes': 0,
                  'routes': routes}))
'''
    command = [tools['unshare'], '--user', '--map-root-user', '--net', '--fork', '--kill-child',
               sys.executable, '-c', child, tools['ip'], record['parentNetworkNamespace']]
    outcome = subprocess.run(command, capture_output=True, text=True, timeout=20)
    record['exitCode'] = outcome.returncode
    record['stderr'] = outcome.stderr[-4096:]
    if outcome.returncode == 0:
        record['isolated'] = json.loads(outcome.stdout)
        record['status'] = 'passed'
        exit_code = 0
    else:
        record['reason'] = 'existing worker cannot complete the bounded unprivileged namespace probe'
except subprocess.TimeoutExpired:
    record['reason'] = 'namespace probe exceeded its fixed 20-second limit'
except Exception as error:
    record['reason'] = str(error)[:1024]
Path(sys.argv[1]).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
raise SystemExit(exit_code)
PY
(cd "$artifact_dir" && sha256sum isolation.json > SHA256SUMS)
exit "$result"
