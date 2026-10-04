"""Exact original source composition for the explicit browser diagnostic only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tomllib

SELECTOR = 'browser-package-candidates'
CONTRACT = Path(__file__).with_name('browser-candidate-sources.json')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'invalid candidate inventory root')
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'linked candidate source')
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path)
        else:
            require(path.is_dir(), 'nonregular candidate source')
    return result


def candidate_door(owner, clients):
    """Called by the original importer; never treat two null sources as identity."""
    require(os.environ.get('CHECKS') == SELECTOR, 'explicit candidate selector required')
    contract = json.loads(CONTRACT.read_text())
    expected = Path.cwd().resolve() / '.browser-candidates/cvld/Cargo.toml'
    require(len(clients) == 1, 'ambiguous candidate client Door')
    for package in [owner, clients[0]]:
        require(package['source'] is None and package['name'] == 'cvld'
                and Path(package['manifest_path']).resolve(strict=True) == expected
                and package['version'] == contract['candidates']['cvld']['version'],
                'Door must be the exact candidate in both graphs')
    require(clients[0]['id'] == owner['id'], 'candidate Door package IDs differ')
    for name, digest in contract['door']['required_fixture_files'].items():
        path = expected.parent / name
        require(path.resolve(strict=True).is_relative_to(expected.parent)
                and not path.is_symlink() and sha(path) == digest,
                'original candidate Door fixture identity differs')
    return contract['door']


class Composition:
    def __init__(self, root, report):
        self.root, self.report = root, report
        self.contract = json.loads(CONTRACT.read_text())
        self.sources = self.contract['candidates']
        self.directory = root / '.browser-candidates'
        self.config = root / '.cargo/config.toml'
        self.frozen = None
        self.git_environment = None
        self.hosted_transport_sha256 = None

    def write(self, name, value):
        (self.report / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    def packages(self, label):
        packages = {}
        for row in self.contract['patches'][label]:
            path = self.directory / row['owner'] / row['manifest']
            package = tomllib.loads(path.read_text())['package']
            require(package['name'] == row['package'] and row['package'] not in packages,
                    'ambiguous candidate patch package')
            packages[row['package']] = {
                'version': package['version'], 'source': None,
                'candidate_commit': self.sources[row['owner']]['commit'],
                'manifest_path': str(path),
            }
        return packages

    def patch_bytes(self, label):
        sections = {}
        for row in self.contract['patches'][label]:
            url = self.sources[row['owner']]['repository']
            path = self.directory / row['owner'] / row['manifest']
            sections.setdefault(url, []).append(
                f'{row["package"]} = {{ path = {json.dumps(str(path.parent))} }}')
        return ('\n'.join(f'[patch.{json.dumps(url)}]\n' + '\n'.join(rows) + '\n'
                          for url, rows in sorted(sections.items()))).encode()

    def unchanged(self, label=None):
        if self.hosted_transport_sha256 is not None:
            require(sha(self.report / 'hosted-transport.json') == self.hosted_transport_sha256,
                    'hosted transport binding changed')
        require(not self.config.is_symlink() and not self.config.parent.is_symlink()
                and self.directory.resolve(strict=True) == self.directory,
                'candidate source/config path changed')
        require(inventory(self.directory) == self.frozen, 'candidate source changed')
        require(self.environment() == self.git_environment, 'Git transport environment changed')
        for workspace in ['runtime', 'fixture']:
            require((self.report / f'candidate-patches-{workspace}.toml').read_bytes()
                    == self.patch_bytes(workspace), 'candidate patch snapshot changed')
        active = self.config.read_bytes()
        matches = [name for name in ['runtime', 'fixture'] if active == self.patch_bytes(name)]
        require(len(matches) == 1 and (label is None or matches == [label]),
                'wrong active candidate workspace patches')
        require(not (self.root / '.cargo/config').exists()
                and not (self.root / 'tests/fixture/.cargo').exists(),
                'unexpected workspace Cargo configuration')
        copied = self.root / 'tests/fixture/owner'
        if copied.exists():
            expected = {Path(name).name: digest for name, digest
                        in self.contract['door']['required_fixture_files'].items()
                        if name.startswith('tests/support/')}
            require(inventory(copied) == expected, 'copied original Door fixture changed')
        return matches[0]

    def select(self, label, phase):
        previous = self.unchanged()
        require(label in {'runtime', 'fixture'}, 'unknown candidate workspace')
        pending = self.config.with_name('browser-next.toml')
        with pending.open('xb') as stream:
            stream.write(self.patch_bytes(label))
        pending.replace(self.config)
        self.unchanged(label)
        with (self.report / 'candidate-patch-phases.jsonl').open('a') as stream:
            stream.write(json.dumps({'workspace': label, 'phase': phase, 'previous': previous,
                                     'patch_sha256': sha(self.config)}, sort_keys=True) + '\n')

    def record_metadata(self, label):
        self.unchanged(label)
        self.write(f'{label}-metadata-patches.json', {
            'metadata_sha256': sha(self.report / f'{label}-metadata.json'),
            'patch_sha256': sha(self.config), 'workspace': label,
        })

    def check_lock(self, label):
        path = self.root / ('Cargo.lock' if label == 'runtime' else 'tests/fixture/Cargo.lock')
        unused = tomllib.loads(path.read_text()).get('patch', {}).get('unused', [])
        self.write(f'{label}-candidate-lock.json', {
            'lock_sha256': sha(path), 'unused_patches': unused,
            'patch_sha256': hashlib.sha256(self.patch_bytes(label)).hexdigest(),
        })
        require(not unused, 'unexpected unused candidate patch')

    @staticmethod
    def environment():
        return {key: value for key, value in os.environ.items()
                if key.startswith('GIT_CONFIG_') or key in {
                    'GIT_ALLOW_PROTOCOL', 'CARGO_NET_GIT_FETCH_WITH_CLI'}}

    def minicov(self):
        expected = self.contract['minicov']
        source = Path(os.environ['CMSG_MINICOV_BUNDLE'])
        bundle_sha, bundle_bytes = expected['bundle_sha256'], expected['bundle_bytes']
        if os.environ.get('CI') == 'github-actions':
            require(os.environ.get('CMSG_HOSTED_RUNNER') == 'ubuntu-latest', 'hosted runner differs')
            receipt = self.report / 'hosted-transport.json'
            transport = json.loads(receipt.read_text())
            require(transport['candidate_contract_sha256'] == sha(CONTRACT)
                    and transport['hosted_contract_sha256'] == sha(CONTRACT.with_name('browser-hosted-sources.json'))
                    and transport['closure_sha256'] == os.environ['DEPENDENCY_CLOSURE_SHA256']
                    and transport['root']['commit'] == os.environ['CI_COMMIT_SHA']
                    and transport['root']['source_sha256'] == os.environ['SOURCE_SHA256']
                    and transport['minicov']['identity'] == expected,
                    'hosted transport does not bind the exact original source identities')
            # Fresh transport bytes are admitted only here; the fixed original
            # ref/OID/tree verifier below remains mandatory for both providers.
            bundle_sha, bundle_bytes = transport['minicov']['sha256'], transport['minicov']['bytes']
            self.hosted_transport_sha256 = sha(receipt)
        require(os.environ['CMSG_MINICOV_SHA256'] == bundle_sha
                and source.stat().st_size == bundle_bytes and sha(source) == bundle_sha,
                'minicov bundle identity differs')
        bundle = self.report / 'minicov.bundle'
        shutil.copyfile(source, bundle)
        require(sha(bundle) == bundle_sha, 'copied minicov bundle differs')
        repo = self.report / 'minicov.git'
        require(not repo.exists(), 'minicov repository must be fresh')
        os.environ['GIT_ALLOW_PROTOCOL'] = 'file'

        def git(*args):
            command = ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
                       '-c', 'protocol.file.allow=always', *args]
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False)
            with (self.report / 'minicov-transport.log').open('a') as log:
                log.write(json.dumps(command) + '\n' + result.stdout + result.stderr)
            result.check_returncode()
            return result.stdout.strip()

        git('init', '--bare', str(repo))
        git('-C', str(repo), 'bundle', 'verify', str(bundle))
        refs = dict(line.split(' ', 1)[::-1] for line in
                    git('-C', str(repo), 'bundle', 'list-heads', str(bundle)).splitlines())
        require(refs == expected['advertised_refs'], 'unexpected minicov refs')
        git('-C', str(repo), 'fetch', '--no-tags', str(bundle),
            '+refs/heads/master:refs/heads/master', '+refs/closure/*:refs/closure/*')
        git('-C', str(repo), 'fsck', '--full', '--strict', '--no-reflogs')
        git('-C', str(repo), 'symbolic-ref', 'HEAD', 'refs/heads/master')
        require(git('-C', str(repo), 'rev-parse', 'HEAD') == expected['observed_head'],
                'minicov observed master differs')
        for oid, tree in expected['commits'].items():
            require(git('-C', str(repo), 'rev-parse', oid + '^{commit}') == oid
                    and git('-C', str(repo), 'rev-parse', oid + '^{tree}') == tree,
                    'minicov commit/tree differs')
        # Extend the original consumer's canonical rewrites; never replace them.
        count = int(os.environ['GIT_CONFIG_COUNT'])
        require(count > 0 and os.environ.get('CARGO_NET_GIT_FETCH_WITH_CLI') == 'true',
                'original source-closure Git environment required')
        for prefix in ['https://github.com/', 'ssh://git@github.com/', 'git@github.com:']:
            for suffix in ['', '.git']:
                os.environ[f'GIT_CONFIG_KEY_{count}'] = f'url.{repo.as_uri()}.insteadOf'
                os.environ[f'GIT_CONFIG_VALUE_{count}'] = prefix + 'Amanieu/minicov' + suffix
                count += 1
        os.environ['GIT_CONFIG_COUNT'] = str(count)
        self.write('minicov-source.json', expected)

    def prepare(self):
        require(os.environ.get('CHECKS') == SELECTOR, 'explicit candidate selector required')
        require(not self.directory.exists() and not self.config.exists()
                and not self.config.parent.is_symlink()
                and not (self.root / '.cargo/config').exists()
                and not (self.root / 'tests/fixture/.cargo').exists()
                and not (self.root / 'tests/fixture/owner').exists(),
                'candidate source/config must start fresh')
        closure = json.loads((self.report / 'observed-main-closure.json').read_text())
        records = []
        for name, expected in self.sources.items():
            prefix = 'CMSG_' + name.upper() + '_SOURCE_'
            archive = Path(os.environ[prefix + 'ARCHIVE'])
            require(os.environ[prefix + 'SHA256'] == expected['archive_sha256'],
                    'candidate digest differs from fixed contract')
            target = self.directory / name
            with archive.open('rb') as stream:
                require(archive.stat().st_size <= 32 * 1024 * 1024
                        and hashlib.file_digest(stream, 'sha256').hexdigest()
                        == expected['archive_sha256'], 'candidate archive identity/bound')
                stream.seek(0)
                commit = subprocess.check_output(['git', 'get-tar-commit-id'],
                                                 stdin=stream, text=True).strip()
                require(commit == expected['commit'], 'candidate archive commit differs')
                stream.seek(0)
                with tarfile.open(fileobj=stream, mode='r:') as package:
                    members = package.getmembers()
                    require(len(members) <= 10000 and sum(m.size for m in members)
                            <= 32 * 1024 * 1024, 'candidate archive member bound')
                    seen = set()
                    for member in members:
                        path = PurePosixPath(member.name)
                        require(not path.is_absolute() and '..' not in path.parts
                                and path.as_posix() == member.name.rstrip('/')
                                and path.parts and '.git' not in path.parts
                                and 'node_modules' not in path.parts
                                and (member.isfile() or member.isdir())
                                and path.as_posix() not in seen, 'unsafe candidate archive member')
                        seen.add(path.as_posix())
                    target.mkdir(parents=True)
                    package.extractall(target, members=members, filter='data')
            manifest = tomllib.loads((target / 'Cargo.toml').read_text())['package']
            require(manifest['name'] == name and manifest['version'] == expected['version']
                    and manifest['repository'] == expected['repository'], 'candidate owner differs')
            matches = [entry for entry in closure['consumers']
                       if entry['url'].removesuffix('.git') == expected['repository']]
            if name == 'cfyr':
                require(not matches and not list(target.rglob('Cargo.lock'))
                        and not list(target.rglob('package-lock.json')),
                        'Foyer must retain explicit separate lockless source provenance')
            else:
                require(len(matches) == 1 and all(matches[0][key] == expected[value]
                        for key, value in [('commit', 'commit'), ('tree', 'tree'),
                                           ('source_sha256', 'archive_sha256')]),
                        'candidate differs from producer-validated consumer')
            records.append(dict(owner=name, **expected, path=str(target),
                                producer_validated_consumer=name != 'cfyr',
                                identity='explicit original candidate, not dependency main'))
        self.frozen = inventory(self.directory)
        self.minicov()
        self.git_environment = self.environment()
        self.config.parent.mkdir(exist_ok=True)
        for label in ['runtime', 'fixture']:
            with (self.report / f'candidate-patches-{label}.toml').open('xb') as stream:
                stream.write(self.patch_bytes(label))
        self.config.write_bytes(self.patch_bytes('runtime'))
        self.write('candidate-sources.json', records)
        self.write('candidate-source-files.json', self.frozen)
        self.write('candidate-git-environment.json', self.git_environment)
        self.unchanged('runtime')

    def verify(self, graphs, locks):
        self.unchanged()
        identities = {}
        for label, graph in graphs.items():
            receipt = json.loads((self.report / f'{label}-metadata-patches.json').read_text())
            require(receipt == {'metadata_sha256': sha(self.report / f'{label}-metadata.json'),
                                'patch_sha256': hashlib.sha256(self.patch_bytes(label)).hexdigest(),
                                'workspace': label}, 'metadata patch phase differs')
            path = self.root / ('Cargo.lock' if label == 'runtime' else 'tests/fixture/Cargo.lock')
            require(not tomllib.loads(path.read_text()).get('patch', {}).get('unused'),
                    'unexpected unused candidate patch')
            expected = self.packages(label)
            required = {'cbrd', 'cfyr', 'ckmg', 'cnbx', 'cvlt', 'cwst', 'cvld'} \
                if label == 'runtime' else {'cvld'}
            for name, identity in expected.items():
                for kind, packages in [('metadata', graph['packages']), ('lock', locks[label])]:
                    matches = [p for p in packages if p['name'] == name]
                    # Optional dependencies can be lock-only. Their immutable
                    # patch remains bound without claiming selected execution.
                    if not matches and kind == 'metadata' and name not in required:
                        continue
                    require(len(matches) == 1 and matches[0].get('source') is None
                            and matches[0]['version'] == identity['version'],
                            'candidate missing, duplicated or substituted')
                    if kind == 'metadata':
                        require(Path(matches[0]['manifest_path']).resolve(strict=True)
                                == Path(identity['manifest_path']), 'candidate manifest differs')
            allowed = set(expected) | {'cmsg' if label == 'runtime' else 'cmsg-foyer-fixture'}
            if label == 'runtime':
                allowed.add('browser-coverage-runtime')
            for package in locks[label]:
                require(package.get('source') is not None or package['name'] in allowed,
                        'unexpected local lock package')
            third_party = 'git+' + self.contract['minicov']['url'] + '?branch=master#' + \
                self.contract['minicov']['observed_head']
            for package in graph['packages'] + locks[label]:
                source = package.get('source') or ''
                if source.startswith('git+') and not any('/' + org + '/' in source
                        for org in ['corbet-foss', 'corbet-libs', 'corbet-labs', 'cmtymeet']):
                    require(package['name'] == 'minicov' and source == third_party,
                            'unexpected third-party Git source')
            packages = {p['id']: p for p in graph['packages']}
            nodes = {n['id']: n for n in graph['resolve']['nodes']}
            pending, reached = [graph['resolve']['root']], set()
            while pending:
                identity = pending.pop()
                if identity in reached:
                    continue
                self.scope(packages[identity]['name'], nodes[identity]['features'], label)
                reached.add(identity)
                pending.extend(d['pkg'] for d in nodes[identity]['deps'])
            identities[label] = {'packages': expected, 'reachable_package_ids': sorted(reached),
                                 'unused_patches': [], 'lock_sha256': sha(path)}
        door = next(p for p in graphs['fixture']['packages'] if p['name'] == 'cvld')
        candidate_door(door, [p for p in graphs['runtime']['packages'] if p['name'] == 'cvld'])
        self.write('candidate-graph-scope.json', identities)

    @staticmethod
    def scope(name, features, label):
        forbidden = {'ckmg': {'passport', 'wallet-engine', 'native-records'},
                     'cvlt': {'native-records'}, 'cmsh': {'veilid'}}
        require(not set(features).intersection(forbidden.get(name, set())),
                'unqualified candidate feature activated')
        require(not (label == 'runtime' and name == 'cvld' and 'development-gate' in features),
                'development gate entered production runtime')

    def compiled(self, label, log, graph):
        self.unchanged(label)
        packages = {p['id']: p for p in graph['packages']}
        compiled = set()
        for line in (self.report / log).read_text().splitlines():
            row = json.loads(line)
            if row.get('reason') not in {'compiler-artifact', 'build-script-executed'}:
                continue
            require(row['package_id'] in packages, 'unmapped compiler package')
            self.scope(packages[row['package_id']]['name'], row.get('features', []), label)
            compiled.add(row['package_id'])
        self.write(f'{label}-compiled-scope.json', {'package_ids': sorted(compiled),
                                                  'metadata_sha256': sha(self.report / f'{label}-metadata.json')})
