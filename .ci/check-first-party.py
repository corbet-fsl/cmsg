#!/usr/bin/env python3
"""Require canonical shared/original owners and one first-party package identity."""
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

FIRST_PARTY = re.compile(r"^(?:git\+)?https?://(?:git\.corbet\.ch|github\.com)/(?:corbet-(?:foss|libs)|cmtymeet)/")
CANONICAL = re.compile(r"^https://git\.corbet\.ch/(corbet-(?:foss|libs))/([a-z][a-z0-9-]*)(\.git)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")
# These retained original owners are deliberately v01. Shared owners use main;
# accepting another branch or URL spelling is not an integration repair.
ORIGINAL = {
    'corbet-foss': frozenset({
        'cchr', 'cdht', 'cdlv', 'cfry', 'cgrp', 'ckmg', 'clnk',
        'cmbl', 'cmmr', 'cnvl', 'cnvy', 'cpfl', 'cpky', 'cprz', 'csrh',
        'csrn', 'cswb', 'ctcs', 'cthr', 'ctnd', 'ctrn', 'cwst', 'cxch',
    }),
    'corbet-libs': frozenset({'cbrd', 'cfrm', 'cfyr', 'cgth', 'cmsh', 'cnbx', 'cvlt'}),
}
# Only this already-approved main owner retains its original suffix.
MAIN_SUFFIX = frozenset({('corbet-libs', 'cgbl')})
SIBLINGS = {'cprz-blob': 'cprz', 'cprz-pad': 'cprz', 'cwlt-engine': 'cwlt'}


def owner_branch(repo, package):
    matched = CANONICAL.fullmatch(repo)
    if not matched:
        raise ValueError('First-party source must use its canonical HTTPS owner URL')
    group, slug, suffix = matched.groups()
    if SIBLINGS.get(package, package) != slug:
        raise ValueError(f'Package {package} differs from its original repository owner')
    original = slug in ORIGINAL[group]
    expected_suffix = original or (group, slug) in MAIN_SUFFIX
    if bool(suffix) != expected_suffix:
        raise ValueError(f'Incorrect canonical owner URL for {package}')
    return 'v01' if original else 'main'


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
    shared = 'https://git.corbet.ch/corbet-foss/csgn'
    original = 'https://git.corbet.ch/corbet-foss/cdht.git'
    def package(name, repo, branch):
        return {'name': name, 'source': 'git+' + repo + '?branch=' + branch + '#' + 'a' * 40}
    main = package('csgn', shared, 'main')
    retained = package('cdht', original, 'v01')
    check_lock([main, retained, {'name': 'local'}])
    for record in [main, retained]:
        name, source = record['name'], record['source']
        branch = 'main' if name == 'csgn' else 'v01'
        for packages in ([record, record], [record, {'name': name}],
                         [record, dict(record, source=source[:-1] + 'b')],
                         [dict(record, source=source.replace('branch=' + branch, 'branch=other'))],
                         [dict(record, source=source.replace('branch=' + branch, 'tag=v1'))],
                         [dict(record, source=source.replace('#' + 'a' * 40, '#short'))],
                         [dict(record, source=source.replace('branch=' + branch, 'branch=' + branch + '&branch=' + branch))]):
            rejects(check_lock, packages)
    rejects(check_lock, [package('csgn', shared + '.git', 'v01')])
    rejects(check_lock, [package('cdht', original.removesuffix('.git'), 'main')])
    rejects(check_lock, [package('csgn', 'https://github.com/corbet-foss/csgn', 'main')])
    rejects(check_lock, [package('alias', shared, 'main')])
    rejects(check_lock, [package('cwlt-engine', 'https://git.corbet.ch/corbet-foss/ckmg.git', 'v01')])
    check_lock([package('cwlt-engine', 'https://git.corbet.ch/corbet-foss/cwlt', 'main'),
                package('cprz-pad', 'https://git.corbet.ch/corbet-foss/cprz.git', 'v01')])
    for declaration in ({'git': shared}, {'git': shared, 'rev': 'a' * 40},
                        {'git': shared, 'branch': 'other'},
                        {'git': shared, 'branch': 'main', 'rev': 'a' * 40},
                        {'git': shared, 'branch': 'main', 'tag': 'v1'},
                        {'git': shared, 'branch': 'main', 'path': '.'}):
        rejects(check_manifest, {'target': {'cfg(wasm)': {'dependencies': {'csgn': declaration}}}})
    check_manifest({'workspace': {'dependencies': {'alias': {'git': shared, 'package': 'csgn', 'branch': 'main'}}}})
    check_manifest({'dependencies': {'cdht': {'git': original, 'branch': 'v01'}}})
    rejects(check_manifest, {'dependencies': {'alias': {'git': shared, 'branch': 'main'}}})


if __name__ == '__main__':
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
