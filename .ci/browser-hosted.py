"""Explicit public hosted transport and supervisor; never a main qualification."""
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

import source_archive
import source_closure

ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
CONTRACT = HERE / 'browser-hosted-sources.json'
CANDIDATES = HERE / 'browser-candidate-sources.json'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def git(repo, *args):
    env = source_closure.clean_env()
    result = subprocess.run(['git', '--no-lazy-fetch', '-C', str(repo),
                             '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
                             *args], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=90)
    return result.stdout.decode().strip()


def package_tar(path, members):
    with tarfile.open(path, 'w', format=tarfile.PAX_FORMAT) as output:
        for name, data in sorted(members.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o644
            output.addfile(entry, io.BytesIO(data))


def prepare():
    report = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    contract, candidates = json.loads(CONTRACT.read_text()), json.loads(CANDIDATES.read_text())
    require(sha(HERE / 'source_archive.py') == contract['archive_helper_sha256']
            and sha(HERE / 'source_closure.py') == contract['consumer_sha256']
            and sha(CANDIDATES) == contract['candidate_contract_sha256'], 'transport source differs')
    require(contract['schema'] == 1 and len(contract['repositories']) == 60
            and len(contract['consumers']) == 25 and len(candidates['candidates']) == 26,
            'fixed source cardinality differs')
    commit = os.environ['CI_COMMIT_SHA']
    require(git(ROOT, 'rev-parse', 'HEAD') == commit and not git(ROOT, 'status', '--porcelain'),
            'checkout must be the exact clean dispatched source')
    work = report.parent / 'transport'
    work.mkdir()
    sources = {}
    for row in contract['repositories']:
        require(source_closure.canonical(row['url']) == row['url'] and row['url'] not in sources,
                'noncanonical or duplicate source')
        require(row['main'] in row['commits'], 'missing original main object')
        sources[row['url']] = dict(row['commits'])
    for row in candidates['candidates'].values():
        require(row['repository'] in sources, 'candidate owner absent from original closure')
        sources[row['repository']][row['commit']] = row['tree']
    mini = candidates['minicov']
    require(mini['url'] == 'https://github.com/Amanieu/minicov', 'unexpected supplemental owner')
    sources[mini['url']] = dict(mini['commits'])
    repositories = {}
    for index, (url, commits) in enumerate(sorted(sources.items())):
        require(all(re.fullmatch('[0-9a-f]{40}', oid) and re.fullmatch('[0-9a-f]{40}', tree)
                    for oid, tree in commits.items()), 'non-exact source object')
        bare = work / f'{index}.git'
        bare.mkdir()
        git(bare, 'init', '--bare', '--template=', '--quiet')
        git(bare, 'fetch', '--no-tags', '--no-write-fetch-head', url, *sorted(commits))
        for oid, tree in commits.items():
            require(git(bare, 'rev-parse', oid + '^{commit}') == oid
                    and git(bare, 'rev-parse', oid + '^{tree}') == tree, 'source object differs')
        git(bare, 'fsck', '--full', '--strict', '--no-reflogs')
        repositories[url] = bare
    environment, archive_receipts = {}, {}
    for name, row in sorted(candidates['candidates'].items()):
        require(re.fullmatch('[a-z][a-z0-9]+', name), 'invalid candidate name')
        bare = repositories[row['repository']]
        require(not source_archive.submodules(bare, row['commit']), 'unapproved source submodule')
        archive = work / (name + '.tar')
        stats = source_archive.create(bare, row['commit'], archive)
        require(not stats['submodules'] and stats['lfs_objects'] == 0
                and sha(archive) == row['archive_sha256'], 'candidate archive reconstruction differs')
        environment['CMSG_' + name.upper() + '_SOURCE_ARCHIVE'] = str(archive)
        environment['CMSG_' + name.upper() + '_SOURCE_SHA256'] = row['archive_sha256']
        archive_receipts[name] = {'commit': row['commit'], 'tree': row['tree'],
                                  'sha256': sha(archive), 'bytes': archive.stat().st_size}
    root_archive = work / 'cmsg.tar'
    stats = source_archive.create(ROOT, commit, root_archive)
    require(not stats['submodules'] and stats['lfs_objects'] == 0
            and sha(root_archive) == os.environ['SOURCE_SHA256'], 'dispatched root archive differs')
    root_payload = source_closure.read_tar(root_archive, os.environ['SOURCE_SHA256'])
    for path, digest in contract['root']['metadata_sha256'].items():
        require(path in root_payload and hashlib.sha256(root_payload[path]).hexdigest() == digest,
                'original root metadata changed')
    root = {**contract['root'], 'commit': commit, 'tree': git(ROOT, 'rev-parse', commit + '^{tree}'),
            'source_sha256': sha(root_archive)}
    for consumer in contract['consumers']:
        matches = [r for r in candidates['candidates'].values() if r['commit'] == consumer['commit']
                   and r['repository'] == consumer['url'] and r['tree'] == consumer['tree']
                   and r['archive_sha256'] == consumer['source_sha256']]
        require(len(matches) == 1, 'original consumer identity differs')
        name = next(n for n, r in candidates['candidates'].items() if r == matches[0])
        payload = source_closure.read_tar(work / (name + '.tar'), consumer['source_sha256'])
        require(all(p in payload and hashlib.sha256(payload[p]).hexdigest() == h
                    for p, h in consumer['metadata_sha256'].items()), 'original consumer metadata differs')
    members = {'closure.py': (HERE / 'source_closure.py').read_bytes()}
    rebuilt = []
    for row in contract['repositories']:
        bare = repositories[row['url']]
        refs = {'refs/heads/main': row['main'], **{'refs/closure/' + o: o for o in row['commits']}}
        for ref, oid in refs.items():
            git(bare, 'update-ref', ref, oid)
        bundle = work / (Path(row['bundle']).name)
        git(bare, '-c', 'pack.threads=1', 'bundle', 'create', '--version=2', str(bundle), *sorted(refs))
        check = work / (bundle.stem + '-verify.git')
        check.mkdir()
        source_closure.verify_bundle(bundle, check, row['main'], row['commits'])
        members[row['bundle']] = bundle.read_bytes()
        rebuilt.append({**row, 'sha256': sha(bundle)})
    manifest = {'schema': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
                'freshness': 'main-observed', 'registry_resolution': 'not-performed',
                'reconstruction': 'Original historical observations retained; no fresh main selection',
                'baseline_closure_sha256': contract['baseline_closure_sha256'],
                'consumer_sha256': contract['consumer_sha256'],
                'consumers': [root, *contract['consumers']], 'repositories': rebuilt}
    require([{k: v for k, v in r.items() if k != 'sha256'} for r in rebuilt]
            == contract['repositories'], 'original owner semantic identities changed')
    members['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    closure_archive = work / 'closure.tar'
    package_tar(closure_archive, members)
    bare = repositories[mini['url']]
    for ref, oid in mini['advertised_refs'].items():
        git(bare, 'update-ref', ref, oid)
    mini_bundle = work / 'minicov.bundle'
    git(bare, '-c', 'pack.threads=1', 'bundle', 'create', '--version=2', str(mini_bundle),
        *sorted(mini['advertised_refs']))
    refs = dict(line.split(' ', 1)[::-1] for line in
                git(bare, 'bundle', 'list-heads', str(mini_bundle)).splitlines())
    require(refs == mini['advertised_refs'], 'supplemental bundle refs differ')
    git(bare, 'bundle', 'verify', str(mini_bundle))
    environment.update(CMSG_MINICOV_BUNDLE=str(mini_bundle), CMSG_MINICOV_SHA256=sha(mini_bundle))
    write(report / 'hosted-transport.json', {
        'hosted_contract_sha256': sha(CONTRACT), 'candidate_contract_sha256': sha(CANDIDATES),
        'root': root, 'candidate_archives': archive_receipts,
        'baseline_closure_sha256': contract['baseline_closure_sha256'],
        'closure_sha256': sha(closure_archive), 'semantic_owner_equality': True,
        'consumer_sha256': contract['consumer_sha256'],
        'minicov': {'identity': mini, 'sha256': sha(mini_bundle), 'bytes': mini_bundle.stat().st_size},
        'foyer_is_producer_consumer': False, 'product_acceptance': False})
    write(report / 'hosted-environment.json', environment)
    write(report / 'hosted-closure.json', manifest)
    write(report / 'hosted-command.json', ['python3', '.ci/source_closure.py', 'consume',
          '--archive', str(closure_archive), '--sha256', sha(closure_archive),
          '--source-archive', str(root_archive), '--source-sha256', sha(root_archive),
          '--commit', commit, '--repository', root['url'], '--scratch', str(work),
          '--', 'python3', '.ci/browser-package.py'])


def supervised(command, seconds, report, label, environment):
    row = {'command': command, 'limit_seconds': seconds, 'status': 'failed'}
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        with (report / (label + '.log')).open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=environment, start_new_session=True,
                                       preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, blocked))
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                blocked = None
                code = process.wait(timeout=seconds)
                row.update(exit_code=code, status='passed' if code == 0 else 'failed')
                return code
            except BaseException as error:
                row['error'] = type(error).__name__
                raise
            finally:
                # Original fixture cleanup is preserved. Hosted VM teardown also
                # bounds descendants which independently change process groups.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                write(report / (label + '-execution.json'), row)
    finally:
        if blocked is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


def export(report):
    # Only newly created public CI evidence; never bearer fixture/profile data.
    names = set("""hosted-resources.json hosted-resources-prebuild.json hosted-refusal.json hosted-execution.json
hosted-prepare.log hosted-prepare-execution.json hosted-transport.json hosted-environment.json
hosted-closure.json hosted-command.json hosted-browser.log hosted-browser-execution.json
hosted-tools.json hosted-network-preflight.log observed-main-closure.json selenium-version.json
source-inputs.json runtime-resolved-at.json resolved-at.json resolved-locks.json metadata-inputs.json
fixture-owner.json fixture-owner-files.json compiled-artifacts.json generated-inputs.json
browser-package.json candidate-sources.json candidate-source-files.json candidate-git-environment.json
candidate-graph-scope.json candidate-patch-phases.jsonl minicov-source.json minicov-transport.log
initial-policy.log resolve-runtime.log resolve-fixture.log resolve-tools.log resolved-policy.log
copy-fixture.log npm-ci.log registry.json generate.log generated-policy.log fixture-build.jsonl
wasm-build.jsonl runner-acquisition.log wasm-bindgen.log typescript.log browser-package.log
wasm-stdlib.txt runner/runner-version.txt runner/runner-artifact.sha256""".split())
    for label in ['runtime', 'fixture']:
        names.update({f'{label}-metadata.json', f'{label}-metadata-patches.json',
                      f'{label}-candidate-lock.json', f'{label}-compiled-scope.json',
                      f'candidate-patches-{label}.toml'})
    for tool in ['rustc', 'cargo', 'node', 'npm', 'google-chrome', 'chromedriver', 'caddy', 'openssl', 'python3']:
        names.add(tool + '-version.txt')
    names.update({'rustc-actual-path.txt', 'cargo-actual-path.txt', 'rustc-actual-version.txt',
                  'cargo-actual-version.txt', 'google-chrome-actual-version.txt'})
    names.update({name + '.stderr' for name in names if '/' not in name})
    for prefix in ['baseline', 'resolved', 'final']:
        names.update(prefix + '/' + name for name in
                     ['Cargo.lock', 'tests/fixture/Cargo.lock', 'tools/package-lock.json'])
    selected = {}
    for name in sorted(names):
        path = report / name
        if path.exists():
            require(path.is_file() and not path.is_symlink()
                    and path.resolve().is_relative_to(report)
                    and path.stat().st_size <= 32 * 1024**2, 'unsafe or oversized public evidence')
            selected[name] = path.read_bytes()
    require(sum(map(len, selected.values())) <= 128 * 1024**2, 'evidence total exceeds bound')
    selected['evidence-index.json'] = (json.dumps({n: hashlib.sha256(d).hexdigest()
                                      for n, d in selected.items()}, sort_keys=True) + '\n').encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as output:
        for name, data in sorted(selected.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o644
            output.addfile(entry, io.BytesIO(data))
    data = gzip.compress(buffer.getvalue(), mtime=0)
    require(len(data) <= 20 * 1024**2, 'compressed evidence exceeds bound; no partial export')
    encoded = base64.b64encode(data).decode()
    print('CMSG_EVIDENCE_BEGIN ' + json.dumps({'sha256': hashlib.sha256(data).hexdigest(),
          'bytes': len(data), 'files': len(selected), 'chunk_characters': 4096}), flush=True)
    for index in range(0, len(encoded), 4096):
        print(f'CMSG_EVIDENCE_CHUNK {index // 4096} {encoded[index:index+4096]}', flush=True)
    print('CMSG_EVIDENCE_END', flush=True)


def main():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == 'corbet-libs/cmsg'
            and os.environ.get('CMSG_HOSTED_RUNNER') == 'ubuntu-latest'
            and os.environ.get('CMSG_HOSTED_PUBLIC') == 'true', 'explicit public hosted job required')
    require(os.environ.get('GITHUB_SHA') == os.environ.get('CMSG_EXPECTED_COMMIT')
            and re.fullmatch('[0-9a-f]{40}', os.environ['GITHUB_SHA'])
            and re.fullmatch('[0-9a-f]{64}', os.environ.get('CMSG_EXPECTED_SOURCE_SHA256', '')),
            'exact dispatched source identity required')
    scratch = Path(tempfile.mkdtemp(prefix='cmsg-hosted-', dir=os.environ['RUNNER_TEMP']))
    report = scratch / 'report'
    report.mkdir()
    environment = dict(os.environ, CI='github-actions', CI_COMMIT_SHA=os.environ['GITHUB_SHA'],
                       CI_REPOSITORY_URL='https://github.com/corbet-libs/cmsg',
                       SOURCE_SHA256=os.environ['CMSG_EXPECTED_SOURCE_SHA256'],
                       CHECKS='browser-package-candidates', CI_JOBS='2', CI_MEMORY_MB='16384',
                       CARGO_BUILD_JOBS='2', RUST_TEST_THREADS='2', PYTHONDONTWRITEBYTECODE='1',
                       CI_ACCEPTANCE_ARTIFACTS=str(report), TMPDIR=str(scratch))
    code = 1
    def terminate(_number, _frame):
        raise InterruptedError('hosted job cancelled')
    previous = {number: signal.signal(number, terminate) for number in [signal.SIGTERM, signal.SIGINT]}
    try:
        def admit_resources(name, phase):
            memory = {line.split(':', 1)[0]: int(line.split()[1])
                      for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith(('MemTotal:', 'MemAvailable:'))}
            resources = {'phase': phase, 'utc': datetime.now(timezone.utc).isoformat(),
                         'free_disk_bytes': shutil.disk_usage(scratch).free,
                         'mem_total_kib': memory['MemTotal'], 'mem_available_kib': memory['MemAvailable'],
                         'required_free_disk_bytes': 10 * 1024**3,
                         'required_available_memory_kib': 12 * 1024**2}
            write(report / name, resources)
            require(resources['free_disk_bytes'] >= resources['required_free_disk_bytes'],
                    'insufficient hosted disk admission')
            require(resources['mem_available_kib'] >= resources['required_available_memory_kib'],
                    'insufficient hosted available memory for the bounded two-job build')
        admit_resources('hosted-resources.json', 'after-tools-before-source')
        started = int(os.environ['CMSG_HOSTED_STARTED'])
        remaining = int(600 - (time.time() - started))
        require(0 < remaining <= 600, 'hosted source/tool preparation budget exhausted')
        code = supervised(['python3', '.ci/browser-hosted.py', 'prepare'], remaining, report, 'hosted-prepare', environment)
        if code == 0:
            environment.update(json.loads((report / 'hosted-environment.json').read_text()))
            admit_resources('hosted-resources-prebuild.json', 'after-source-before-browser-build')
            code = supervised(json.loads((report / 'hosted-command.json').read_text()), 1800,
                              report, 'hosted-browser', environment)
    except Exception as error:
        write(report / 'hosted-refusal.json', {'type': type(error).__name__, 'message': str(error)})
        code = 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        for lock in ['Cargo.lock', 'tests/fixture/Cargo.lock', 'tools/package-lock.json']:
            path = ROOT / lock
            if path.is_file():
                destination = report / 'final' / lock
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
        write(report / 'hosted-execution.json', {'exit_code': code, 'commit': environment['CI_COMMIT_SHA'],
              'source_sha256': environment['SOURCE_SHA256'], 'product_acceptance': False,
              'full_suite': False, 'scope': 'generated-browser-package-only',
              'binary_artifacts_exported': False, 'evidence_export': 'explicit public metadata/log/lock whitelist'})
        try:
            export(report)
        finally:
            shutil.rmtree(scratch)
    return code


if __name__ == '__main__':
    if sys.argv[1:] == ['prepare']:
        prepare()
    else:
        require(not sys.argv[1:], 'unknown hosted action')
        raise SystemExit(main())
