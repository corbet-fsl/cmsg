#!/usr/bin/env python3
"""Require canonical shared/original owners and one first-party package identity."""
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https?://(?:github\.com/(?:corbet-(?:libre|fsl)|cmtymeet)|git\.corbet\.ch/(?:corbet-(?:libre|fsl)|cmty(?:meet|mt)))/")
CANONICAL = re.compile(r"^https://git\.corbet\.ch/(corbet-(?:libre|fsl))/([a-z][a-z0-9-]*)(\.git)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SIBLINGS = {'cprz-blob': 'cprz', 'cprz-pad': 'cprz', 'cwlt-engine': 'cwlt', 'cvld-client': 'cvld'}


def owner_branch(repo, package):
    matched = CANONICAL.fullmatch(repo)
    if not matched:
        raise ValueError('First-party source must use its canonical HTTPS owner URL')
    group, slug, suffix = matched.groups()
    if SIBLINGS.get(package, package) != slug:
        raise ValueError(f'Package {package} differs from its original repository owner')
    if suffix not in (None, '.git'):
        raise ValueError(f'Incorrect canonical owner URL for {package}')
    return 'main'


def check_lock(packages):
    names = {p['name'] for p in packages if FIRST_PARTY.match(p.get('source', ''))}
    for name in names:
        entries = [p for p in packages if p['name'] == name]
        if len(entries) != 1:
            raise ValueError(f'Duplicate first-party crate: {name}')
        raw = entries[0]['source']
        if not raw.startswith('git+'):
            raise ValueError(f'Invalid first-party source for {name}')
        source = urlsplit(raw.removeprefix('git+'))
        repo = source._replace(query='', fragment='').geturl()
        branch = owner_branch(repo, name)
        query = parse_qs(source.query, keep_blank_values=True)
        if not SHA.fullmatch(source.fragment):
            raise ValueError(f'Missing resolved revision for {name}')
        if query != {'branch': [branch]} or source.query != 'branch=' + branch:
            raise ValueError(f'Invalid first-party source selector for {name}')


def check_manifest(value, alias=None):
    if isinstance(value, dict):
        if FIRST_PARTY.match(value.get('git', '')):
            branch = owner_branch(value['git'], value.get('package', alias))
            if value.get('branch') != branch or {'rev', 'tag', 'path'}.intersection(value):
                raise ValueError(f'First-party dependency must declare its original branch {branch}')
        for key, item in value.items():
            check_manifest(item, key)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


def rejects(function, value):
    try:
        function(value)
    except ValueError:
        return
    raise AssertionError(f'Invalid input accepted: {value!r}')


def self_test():
    shared = 'https://git.corbet.ch/corbet-libre/csgn'
    original = 'https://git.corbet.ch/corbet-libre/cdht.git'
    def package(name, repo, branch):
        return {'name': name, 'source': 'git+' + repo + '?branch=' + branch + '#' + 'a' * 40}
    main = package('csgn', shared, 'main')
    retained = package('cdht', original, 'main')
    check_lock([main, retained, {'name': 'local'}])
    for record in [main, retained]:
        name, source = record['name'], record['source']
        branch = 'main'
        for packages in ([record, record], [record, {'name': name}],
                         [record, dict(record, source=source[:-1] + 'b')],
                         [dict(record, source=source.replace('branch=' + branch, 'branch=other'))],
                         [dict(record, source=source.replace('branch=' + branch, 'tag=v1'))],
                         [dict(record, source=source.replace('#' + 'a' * 40, '#short'))],
                         [dict(record, source=source.replace('branch=' + branch, 'branch=' + branch + '&branch=' + branch))]):
            rejects(check_lock, packages)
    rejects(check_lock, [package('csgn', shared + '.git', 'v01')])
    rejects(check_lock, [package('cdht', original.replace('git.corbet.ch', 'github.com'), 'main')])
    rejects(check_lock, [package('csgn', 'https://github.com/corbet-libre/csgn', 'main')])
    rejects(check_lock, [package('alias', shared, 'main')])
    rejects(check_lock, [package('cwlt-engine', 'https://git.corbet.ch/corbet-libre/ckmg.git', 'v01')])
    check_lock([package('cwlt-engine', 'https://git.corbet.ch/corbet-libre/cwlt', 'main'),
                package('cprz-pad', 'https://git.corbet.ch/corbet-libre/cprz.git', 'main')])
    for declaration in ({'git': shared}, {'git': shared, 'rev': 'a' * 40},
                        {'git': shared, 'branch': 'other'},
                        {'git': shared, 'branch': 'main', 'rev': 'a' * 40},
                        {'git': shared, 'branch': 'main', 'tag': 'v1'},
                        {'git': shared, 'branch': 'main', 'path': '.'}):
        rejects(check_manifest, {'target': {'cfg(wasm)': {'dependencies': {'csgn': declaration}}}})
    check_manifest({'workspace': {'dependencies': {'alias': {'git': shared, 'package': 'csgn', 'branch': 'main'}}}})
    check_manifest({'dependencies': {'cdht': {'git': original, 'branch': 'main'}}})
    rejects(check_manifest, {'dependencies': {'alias': {'git': shared, 'branch': 'main'}}})


def check_first_party_orgs():
    """Every current owner resolves on the canonical forge; github.com keeps its former owners."""
    for owner in ('corbet-libre', 'corbet-fsl',
                  'cmtymeet', 'cmtymt'):
        url = f'https://git.corbet.ch/{owner}/example'
        if not FIRST_PARTY.match(url):
            raise AssertionError(f'First-party owner rejected: {url}')
    for url in ('https://git.corbet.ch.evil.test/corbet-libre/example',
                'https://user@git.corbet.ch/corbet-libre/example',
                'https://git.corbet.ch:443/corbet-libre/example',
                'https://git.corbet.ch/corbet-libre.evil/example',
                'https://github.com/cmtymt/example'):
        if FIRST_PARTY.match(url):
            raise AssertionError(f'Invalid first-party owner accepted: {url}')

if __name__ == '__main__':
    check_first_party_orgs()
    self_test()
    if '--self-test' not in sys.argv:
        if Path('.git').exists():
            paths = subprocess.check_output(['git', 'ls-files', '-z'], text=True).split('\0')
        else:
            # ccid extracts a SHA-bound committed source archive without .git.
            # Build/generated output cannot introduce a second dependency graph.
            paths = [str(path) for pattern in ('Cargo.toml', 'Cargo.lock')
                     for path in Path('.').rglob(pattern)
                     if not {'target', 'node_modules', 'generated', 'evidence', 'owner'}.intersection(path.parts)]
        for name in paths:
            path = Path(name)
            if path.name == 'Cargo.toml':
                check_manifest(tomllib.loads(path.read_text()))
            elif path.name == 'Cargo.lock':
                check_lock(tomllib.loads(path.read_text())['package'])
        print('First-party declarations follow canonical shared/original owners; locked identities are unique')
