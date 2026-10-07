"""Qualify the original generated browser package against one main source closure."""
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tomllib

ROOT = Path.cwd().resolve()
REPORT = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
LOCKS = ['Cargo.lock', 'tests/fixture/Cargo.lock', 'tools/package-lock.json']
FIRST_PARTY = re.compile(r'git\+https://git\.corbet\.ch/(corbet-foss|corbet-labs|corbet-libs|cmtymeet)/')
MAIN = re.compile(r'git\+https://git\.corbet\.ch/(corbet-foss|corbet-labs|corbet-libs|cmtymeet)/'
                  r'([A-Za-z0-9][A-Za-z0-9_.-]*)\?branch=main#([0-9a-f]{40})')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(name, value):
    (REPORT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def retain(path, prefix=''):
    path = Path(path)
    if path.is_file():
        destination = REPORT / prefix / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)


def run(argv, name):
    if os.environ.get('CI') == 'github-actions':
        require(shutil.disk_usage(REPORT).free >= 1024**3, 'hosted disk reserve exhausted')
    print(json.dumps({'command': argv, 'log': name}), flush=True)
    with (REPORT / name).open('w') as output, (REPORT / (name + '.stderr')).open('w') as errors:
        subprocess.run(argv, stdout=output, stderr=errors, check=True)


def verify_graphs(composition=None):
    closure = json.loads((REPORT / 'observed-main-closure.json').read_text())
    require(closure['freshness'] == 'main-observed', 'observed main closure required')
    observed = {}
    for entry in closure['repositories']:
        require(entry['url'] not in observed and re.fullmatch('[0-9a-f]{40}', entry['main']),
                'ambiguous observed source')
        observed[entry['url']] = entry['main']

    def bound(source):
        match = MAIN.fullmatch(source)
        require(match is not None, 'noncanonical first-party source')
        org, name, commit = match.groups()
        url = f'https://github.com/{org}/{name.removesuffix(".git")}'
        require(observed.get(url) == commit, 'source absent from observed main closure')
        return f'git+{url}?branch=main#{commit}'

    graphs = {label: json.loads((REPORT / f'{label}-metadata.json').read_text())
              for label in ['runtime', 'fixture']}
    locks = {label: tomllib.loads(Path(path).read_text())['package']
             for label, path in zip(graphs, LOCKS[:2])}
    names = {p['name'] for graph in graphs.values() for p in graph['packages']
             if FIRST_PARTY.match(p.get('source') or '')}
    names.update(dependency['name'] for graph in graphs.values() for package in graph['packages']
                 for dependency in package['dependencies']
                 if FIRST_PARTY.match(dependency.get('source') or ''))
    names.update(p['name'] for packages in locks.values() for p in packages
                 if FIRST_PARTY.match(p.get('source') or ''))
    if composition:
        names.update(name for label in graphs for name in composition.packages(label))
    identities = {}
    for label, graph in graphs.items():
        expected = ROOT / ('Cargo.toml' if label == 'runtime' else 'tests/fixture/Cargo.toml')
        selected = [p for p in graph['packages'] if Path(p['manifest_path']).resolve() == expected]
        require(len(selected) == 1 and selected[0]['name'] ==
                ('cmsg' if label == 'runtime' else 'cmsg-foyer-fixture'), 'unexpected graph root')
        require(graph['resolve']['root'] == selected[0]['id'] and
                graph['workspace_default_members'] == [selected[0]['id']], 'unexpected selected workspace')
        allowed_local = {expected, ROOT / '.ci/coverage-runtime/Cargo.toml'}
        candidates = composition.packages(label) if composition else {}
        allowed_local.update(Path(p['manifest_path']) for p in candidates.values())
        require(all(Path(p['manifest_path']).resolve() in allowed_local
                    for p in graph['packages'] if p['source'] is None), 'unexpected local dependency')
        identities[label] = {}
        for name in sorted(names):
            for packages in [graph['packages'], locks[label]]:
                matches = [p for p in packages if p['name'] == name]
                if not matches:
                    continue
                require(len(matches) == 1, 'duplicate first-party package')
                package = matches[0]
                if name in candidates:
                    identity = candidates[name]
                    require(package.get('source') is None and package['version'] == identity['version'],
                            'candidate package identity differs')
                    if 'manifest_path' in package:
                        require(Path(package['manifest_path']).resolve() == Path(identity['manifest_path']),
                                'candidate package manifest differs')
                else:
                    identity = {'version': package['version'], 'source': bound(package.get('source') or '')}
                require(name not in identities[label] or identities[label][name] == identity,
                        'metadata and lock disagree on first-party identity')
                identities[label][name] = identity
        if label == 'runtime':
            cvld = {p['id'] for p in graph['packages'] if p['name'] == 'cvld'}
            require(all('development-gate' not in n['features'] for n in graph['resolve']['nodes']
                        if n['id'] in cvld), 'development gate entered production runtime graph')
    for name in identities['runtime'].keys() & identities['fixture'].keys():
        require(identities['runtime'][name] == identities['fixture'][name],
                'runtime and fixture resolved different first-party identities')
    write('graph-identities.json', {'graphs': identities, 'observed_main_sources': observed})
    if composition:
        composition.verify(graphs, locks)
    return graphs


def artifact(log, graph, name, wasm=False):
    package_ids = {p['id'] for p in graph['packages'] if p['name'] == name}
    require(len(package_ids) == 1, 'ambiguous artifact owner')
    paths = []
    for line in (REPORT / log).read_text().splitlines():
        row = json.loads(line)
        if row.get('reason') != 'compiler-artifact' or row['package_id'] not in package_ids:
            continue
        paths.extend([p for p in row['filenames'] if p.endswith('.wasm')] if wasm
                     else [row['executable']] if row.get('executable') else [])
    require(len(paths) == 1 and Path(paths[0]).is_file(), 'expected one current build artifact')
    return paths[0]


def main():
    hosted = os.environ.get('CI') == 'github-actions'
    require((hosted and os.environ.get('CHECKS') == 'browser-package-candidates'
             and os.environ.get('CMSG_HOSTED_RUNNER') == 'ubuntu-latest') or
            (os.environ.get('CI') == 'crow' and os.environ.get('CHECKS') in
             {'browser-package', 'browser-package-candidates'}),
            'exact admitted browser-package selector required')
    require(os.environ.get('CI_REPOSITORY_URL', '').removesuffix('.git') ==
            'https://git.corbet.ch/corbet-libs/cmsg', 'canonical source identity required')
    for name, length in [('CI_COMMIT_SHA', 40), ('SOURCE_SHA256', 64),
                         ('DEPENDENCY_CLOSURE_SHA256', 64)]:
        require(re.fullmatch(f'[0-9a-f]{{{length}}}', os.environ.get(name, '')),
                f'missing exact {name}')
    require(not REPORT.is_relative_to(ROOT), 'persistent external artifacts required')
    require(os.environ.get('CI_JOBS') in {'1', '2'} and
            os.environ.get('CARGO_BUILD_JOBS') in {'1', '2'} and
            os.environ.get('RUST_TEST_THREADS') in {'1', '2'} and
            0 < int(os.environ['CI_MEMORY_MB']) <= 16384, 'resource envelope exceeded')
    require(not os.environ.get('RUSTC_BOOTSTRAP'), 'stable compiler required')
    require(not Path('generated').exists() and not Path('generated').is_symlink(),
            'generated output must start fresh')
    hosted_tools = {}
    for tool, args in [('rustc', ['-Vv']), ('cargo', ['-V']), ('node', ['--version']),
                       ('npm', ['--version']), ('google-chrome' if hosted else 'chromium', ['--version']),
                       ('chromedriver', ['--version']), ('caddy', ['version']),
                       ('openssl', ['version']), ('python3', ['--version'])]:
        require(shutil.which(tool), f'provisioned {tool} is missing')
        run([tool, *args], tool + '-version.txt')
        if hosted:
            binary = Path(shutil.which(tool)).resolve(strict=True)
            hosted_tools[tool] = {'path': str(binary), 'sha256': sha(binary)}
    if hosted:
        for tool, args in [('rustc', ['-Vv']), ('cargo', ['-V'])]:
            run(['rustup', 'which', tool], tool + '-actual-path.txt')
            actual = Path((REPORT / (tool + '-actual-path.txt')).read_text().strip())
            require(actual.is_absolute() and actual.is_file() and os.access(actual, os.X_OK),
                    'actual hosted Rust executable missing')
            actual = actual.resolve(strict=True)
            run([str(actual), *args], tool + '-actual-version.txt')
            require((REPORT / (tool + '-actual-version.txt')).read_bytes()
                    == (REPORT / (tool + '-version.txt')).read_bytes(),
                    'Rust launcher and selected executable disagree')
            hosted_tools[tool + '-actual'] = {'path': str(actual), 'sha256': sha(actual)}
        launcher = Path(hosted_tools['google-chrome']['path'])
        with launcher.open('rb') as stream:
            launcher_is_elf = stream.read(4) == b'\x7fELF'
        actual_chrome = launcher if launcher_is_elf else launcher.parent / 'chrome'
        require(actual_chrome.is_file() and os.access(actual_chrome, os.X_OK),
                'actual hosted Chrome executable missing')
        actual_chrome = actual_chrome.resolve(strict=True)
        with actual_chrome.open('rb') as stream:
            require(stream.read(4) == b'\x7fELF', 'actual hosted Chrome must be an ELF executable')
        run([str(actual_chrome), '--version'], 'google-chrome-actual-version.txt')
        require((REPORT / 'google-chrome-actual-version.txt').read_bytes()
                == (REPORT / 'google-chrome-version.txt').read_bytes(),
                'Chrome launcher and actual executable disagree')
        hosted_tools['google-chrome-actual'] = {'path': str(actual_chrome), 'sha256': sha(actual_chrome)}
    compiler = (REPORT / 'rustc-version.txt').read_text()
    require('-nightly' not in compiler and '-beta' not in compiler, 'provisioned stable required')
    run(['rustc', '--print', 'target-libdir', '--target', 'wasm32-unknown-unknown'], 'wasm-stdlib.txt')
    require(list(Path((REPORT / 'wasm-stdlib.txt').read_text().strip()).glob('libstd-*.rlib')),
            'provisioned Wasm standard library missing')
    import selenium
    write('selenium-version.json', {'version': selenium.__version__})
    candidate = os.environ['CHECKS'] == 'browser-package-candidates'
    network_tools = {}
    network_wrapper = None
    if candidate and not hosted:
        network_wrapper = {'path': '.ci/browser-network.py', 'sha256': sha('.ci/browser-network.py')}
        for tool in ['unshare', 'ip']:
            path = (Path('/nix/var/nix/profiles/system/sw/bin') / tool).resolve(strict=True)
            require(path.is_file() and os.access(path, os.X_OK), f'provisioned {tool} is missing')
            require(path.is_relative_to('/nix/store'), 'immutable provisioned namespace tool required')
            network_tools[tool] = {'path': str(path), 'sha256': sha(path)}
            run([str(path), '--version' if tool == 'unshare' else '-Version'], tool + '-version.txt')
        write('network-tools.json', {'tools': network_tools, 'wrapper': network_wrapper})

    def browser_network(command, phase, name):
        require(all(sha(row['path']) == row['sha256'] for row in network_tools.values()),
                'provisioned namespace tool changed')
        require(sha(network_wrapper['path']) == network_wrapper['sha256'],
                'namespace wrapper source changed')
        argv = [network_tools['unshare']['path'], '--user', '--map-root-user', '--net', '--pid',
                '--fork', '--kill-child=KILL', 'python3', '.ci/browser-network.py', phase,
                os.readlink('/proc/self/ns/user'), os.readlink('/proc/self/ns/net'),
                os.readlink('/proc/self/ns/pid'), network_wrapper['sha256'],
                network_tools['ip']['path'], *command]
        result = {'phase': phase, 'status': 'failed', 'tools': network_tools,
                  'wrapper': network_wrapper}
        def terminated(_number, _frame):
            raise InterruptedError('namespace execution terminated')
        previous = signal.signal(signal.SIGTERM, terminated)
        blocked = None
        try:
            print(json.dumps({'command': argv, 'log': name}), flush=True)
            with (REPORT / name).open('w') as output, (REPORT / (name + '.stderr')).open('w') as errors:
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
                with subprocess.Popen(argv, stdout=output, stderr=errors) as process:
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                        blocked = None
                        code = process.wait(timeout=15 if phase == 'preflight' else None)
                        if code:
                            raise subprocess.CalledProcessError(code, argv)
                    except BaseException:
                        # Killing unshare kills its PID-namespace init; the kernel
                        # then removes every descendant, including separate groups.
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=5)
                        raise
            result.update(status='passed', exit_code=0)
        except subprocess.CalledProcessError as error:
            result['exit_code'] = error.returncode
            raise
        except Exception as error:
            result['error'] = str(error)
            raise
        finally:
            signal.signal(signal.SIGTERM, previous)
            if blocked is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            write(f'network-{phase}-execution.json', result)

    if hosted:
        write('hosted-tools.json', hosted_tools)
        run(['python3', '.ci/browser-hosted-network.py'], 'hosted-network-preflight.log')
    elif candidate:
        browser_network([], 'preflight', 'network-preflight.log')
    else:
        with ExitStack() as stack:
            for port in [443, 4443]:
                listener = stack.enter_context(socket.socket())
                listener.bind(('127.0.0.1', port))

    closure_path = Path(os.environ['DEPENDENCY_CLOSURE_MANIFEST'])
    shutil.copyfile(closure_path, REPORT / 'observed-main-closure.json')
    composition = None
    if os.environ['CHECKS'] == 'browser-package-candidates':
        from browser_candidates import Composition
        composition = Composition(ROOT, REPORT)
        composition.prepare()

    def cargo(label, argv, name):
        if composition:
            composition.select(label, name)
        run(['cargo', *argv], name)
        if composition:
            composition.unchanged(label)
            if argv[0] == 'metadata':
                composition.record_metadata(label)
    inputs = [Path('Cargo.toml')]
    for directory in ['src', 'tests', 'tools', '.ci']:
        inputs.extend(p for p in Path(directory).rglob('*') if p.is_file() and
                      'node_modules' not in p.parts and p.name != 'Cargo.lock' and
                      p.name != 'package-lock.json')
    source_hashes = {str(p): sha(p) for p in inputs}
    write('source-inputs.json', source_hashes)
    for path in LOCKS:
        retain(path, 'baseline')
    run(['python3', '.ci/check-first-party.py'], 'initial-policy.log')
    cargo('runtime', ['update'], 'resolve-runtime.log')
    root_lock = sha('Cargo.lock')
    retain('Cargo.lock', 'resolved')
    write('runtime-resolved-at.json', {'utc': datetime.now(timezone.utc).isoformat(),
                                      'lock_sha256': root_lock})
    if composition:
        composition.check_lock('runtime')
    cargo('fixture', ['update', '--manifest-path', 'tests/fixture/Cargo.toml'], 'resolve-fixture.log')
    require(sha('Cargo.lock') == root_lock, 'fixture resolution changed runtime lock')
    run(['npm', 'update', '--prefix', 'tools', '--package-lock-only', '--ignore-scripts',
         '--no-audit', '--no-fund'], 'resolve-tools.log')
    write('resolved-at.json', {'utc': datetime.now(timezone.utc).isoformat()})
    frozen = {path: sha(path) for path in LOCKS}
    write('resolved-locks.json', frozen)
    for path in LOCKS:
        retain(path, 'resolved')
    if composition:
        composition.check_lock('fixture')
    run(['python3', '.ci/check-first-party.py'], 'resolved-policy.log')
    cargo('runtime', ['metadata', '--locked', '--format-version', '1'], 'runtime-metadata.json')
    cargo('fixture', ['metadata', '--locked', '--manifest-path', 'tests/fixture/Cargo.toml',
                     '--format-version', '1'], 'fixture-metadata.json')
    graphs = verify_graphs(composition)
    graph_hashes = {label: sha(REPORT / f'{label}-metadata.json') for label in graphs}
    copied_metadata, compiled_inputs = {}, {}
    write('metadata-inputs.json', graph_hashes)

    def unchanged():
        require(all(sha(row['path']) == row['sha256'] for row in hosted_tools.values()),
                'hosted executable changed')
        require({path: sha(path) for path in LOCKS} == frozen, 'resolved lock changed')
        require({path: sha(path) for path in source_hashes} == source_hashes, 'source input changed')
        require(sha(closure_path) == sha(REPORT / 'observed-main-closure.json'), 'source closure changed')
        require({label: sha(REPORT / f'{label}-metadata.json') for label in graphs} == graph_hashes,
                'verified metadata changed')
        require(all(sha(path) == digest for path, digest in copied_metadata.items()),
                'fixture importer metadata changed')
        require(all(sha(path) == digest for path, digest in compiled_inputs.items()),
                'current compiler artifact changed')
        if composition:
            composition.unchanged()

    unchanged()
    # Expand the original preparation command only to retain current compiler artifacts.
    for label in graphs:
        shutil.copyfile(REPORT / f'{label}-metadata.json', f'{label}-metadata.json')
        copied_metadata[f'{label}-metadata.json'] = graph_hashes[label]
    unchanged()
    run(['python3', '.ci/copy-foyer-fixture.py'], 'copy-fixture.log')
    retain('fixture-owner.json')
    write('fixture-owner-files.json', {str(p): sha(p) for p in Path('tests/fixture/owner').glob('*.rs')})
    unchanged()
    cargo('fixture', ['build', '--locked', '--manifest-path', 'tests/fixture/Cargo.toml',
                      '--message-format=json'], 'fixture-build.jsonl')
    if composition:
        composition.compiled('fixture', 'fixture-build.jsonl', graphs['fixture'])
    fixture = artifact('fixture-build.jsonl', graphs['fixture'], 'cmsg-foyer-fixture')
    compiled_inputs[fixture] = sha(fixture)
    cargo('runtime', ['run', '--locked', '--example', 'registry'], 'registry.json')
    run(['npm', 'ci', '--prefix', 'tools', '--ignore-scripts', '--no-audit', '--no-fund'], 'npm-ci.log')
    run(['node', 'tools/generate.mjs', str(REPORT / 'registry.json'), 'generated'], 'generate.log')
    run(['node', 'tools/check.mjs', str(REPORT / 'registry.json')], 'generated-policy.log')
    cargo('runtime', ['build', '--locked', '--target', 'wasm32-unknown-unknown', '--lib',
                      '--message-format=json'], 'wasm-build.jsonl')
    if composition:
        composition.compiled('runtime', 'wasm-build.jsonl', graphs['runtime'])
    wasm = artifact('wasm-build.jsonl', graphs['runtime'], 'cmsg', wasm=True)
    compiled_inputs[wasm] = sha(wasm)
    write('compiled-artifacts.json', {'fixture': {'path': fixture, 'sha256': sha(fixture)},
                                      'wasm': {'path': wasm, 'sha256': sha(wasm)}})
    run(['bash', '.ci/wasm-runner.sh'], 'runner-acquisition.log')
    run([str(REPORT / 'runner/wasm-bindgen'), '--target', 'web', '--out-dir', 'generated/wasm', wasm],
        'wasm-bindgen.log')
    run(['tools/node_modules/.bin/tsc', '--outDir', 'generated/runtime', '--strict', '--target',
         'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext',
         'generated/client.ts', 'generated/browser.ts'], 'typescript.log')
    shutil.copytree('generated/wasm', 'generated/runtime/wasm')
    shutil.copytree('generated', REPORT / 'generated')
    generated_hashes = {str(p): sha(p) for p in Path('generated').rglob('*') if p.is_file()}
    write('generated-inputs.json', generated_hashes)
    unchanged()
    browser_command = ['python3', '.ci/with-foyer-fixture.py', fixture,
                       'python3', '.ci/test-browser-package.py']
    if candidate and not hosted:
        browser_network(browser_command, 'browser', 'browser-package.log')
    else:
        run(browser_command, 'browser-package.log')
    unchanged()
    require({str(p): sha(p) for p in Path('generated').rglob('*') if p.is_file()} == generated_hashes,
            'generated browser package changed during execution')


if __name__ == '__main__':
    status, code = 'failed', 1
    try:
        main()
        status, code = 'passed', 0
    except subprocess.CalledProcessError as error:
        code = error.returncode if error.returncode > 0 else 1
        print(f'Browser package command failed; inspect retained logs (exit {code})', file=sys.stderr)
    except Exception as error:
        print(f'Browser package refused: {error}', file=sys.stderr)
    finally:
        for path in LOCKS:
            retain(path, 'final')
        write('browser-package.json', {
            'schema': 1, 'scope': 'generated-browser-package-regressions', 'status': status,
            'candidate_composition': os.environ.get('CHECKS') == 'browser-package-candidates',
            'execution_provider': os.environ.get('CI'),
            'exit_code': code, 'source_commit': os.environ.get('CI_COMMIT_SHA'),
            'source_archive_sha256': os.environ.get('SOURCE_SHA256'),
            'dependency_closure_sha256': os.environ.get('DEPENDENCY_CLOSURE_SHA256'),
            'product_acceptance': False, 'coverage_acceptance': False,
            'actual_https_browser_passed': status == 'passed',
            'artifacts': {str(p.relative_to(REPORT)): sha(p) for p in REPORT.rglob('*') if p.is_file()}})
        print(json.dumps({'browser_package_receipt': str(REPORT / 'browser-package.json'),
                          'status': status}), flush=True)
    raise SystemExit(code)
