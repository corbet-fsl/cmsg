#!/usr/bin/env python3
"""Require every reachable LLVM source line and every emitted branch.

LCOV is exported from the same execution as the retained JSON diagnostic. This
measures source coverage, not separate coverage of every generic instantiation.
"""
import sys
import json
from pathlib import Path


def check(text):
    source = None
    lines, branches = {}, {}
    allowed, seen = {}, set()
    exclusions = Path('.ci/coverage-exclusions.json')
    for entry in json.loads(exclusions.read_text()) if exclusions.exists() else []:
        key = (entry['file'], entry['line'])
        if not entry['reason'] or not entry['evidence'] or key in allowed:
            raise ValueError('Exclusion requires unique source, reason and evidence')
        if Path(entry['file']).read_text().splitlines()[entry['line'] - 1].strip() != entry['source']:
            raise ValueError('Excluded source changed; review the rationale')
        allowed[key] = entry
    for record in text.splitlines():
        if record.startswith('SF:'):
            source = record[3:]
            if '/src/' in source:
                source = 'src/' + source.split('/src/', 1)[1]
            if not source:
                raise ValueError('Missing source filename')
        elif record.startswith('DA:'):
            line, count = map(int, record[3:].split(',')[:2])
            key = (source, line)
            if not source or line <= 0 or count < 0 or key in lines:
                raise ValueError('Invalid or duplicated source line')
            if key in allowed:
                if count != 0:
                    raise ValueError('Excluded line now exercised; remove its exclusion')
                seen.add(key)
                print('Excluded line:', key, allowed[key]['reason'])
            else:
                lines[key] = count
        elif record.startswith('BRDA:'):
            line, block, branch, count = record[5:].split(',')
            key = (source, int(line), block, branch)
            count = 0 if count == '-' else int(count)
            if not source or int(line) <= 0 or count < 0 or key in branches:
                raise ValueError('Invalid or duplicated source branch')
            branches[key] = count
        elif record == 'end_of_record':
            source = None
    if seen != allowed.keys():
        raise ValueError('Exclusion absent from LLVM report; review it')
    if not lines:
        raise ValueError('Empty coverage cannot pass')
    misses = [str(key) for rows in (lines, branches) for key, count in rows.items() if count == 0]
    print(f'lines: {sum(n > 0 for n in lines.values())}/{len(lines)}')
    print(f'branches: {sum(n > 0 for n in branches.values())}/{len(branches)}')
    if misses:
        raise ValueError('Uncovered: ' + '; '.join(misses))


if __name__ == '__main__':
    try:
        check(Path(sys.argv[1]).read_text())
    except (ValueError, IndexError, OSError) as error:
        sys.exit(f'Coverage gate: {error}')
