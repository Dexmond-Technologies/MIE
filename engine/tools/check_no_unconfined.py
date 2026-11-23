#!/usr/bin/env python3
"""No shipped program may start a child without confinement (reviewer, board note on run
45130479336: RunOptions::confine=false stays in the library because nothing outside a
program can set it; a search must show that no shipped program sets it).

Searches engine/src and engine/include for any assignment to a member named `confine`.
Only the test programs listed below may contain one. Exit 0: none elsewhere. 1: found.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(HERE)
# Test programs: never installed, never packaged.
ALLOWED = {
    os.path.join('src', 'sandbox', 'testparent.cpp'): 'test parent of the confinement cases',
    os.path.join('src', 'worker', 'worker_run.cpp'): 'mie-worker-run, the test runner (its --unconfined switch)',
}
# A member written through an object: `x.confine = ...`, `x->confine = ...`, or a designated
# initialiser `.confine = ...`. (A positional brace initialiser of RunOptions would not be seen:
# the struct's first members are not `confine`, and none exists in the sources today.)
ASSIGNMENT = re.compile(r'(?:\.|->)\s*confine\s*=(?!=)')


def main():
    found, allowed_hits = [], []
    for folder in ('src', 'include'):
        for root, _, names in os.walk(os.path.join(ENGINE, folder)):
            for name in sorted(names):
                if not name.endswith(('.cpp', '.hpp', '.h', '.inc')):
                    continue
                path = os.path.join(root, name)
                relative = os.path.relpath(path, ENGINE)
                with open(path, encoding='utf-8', errors='replace') as f:
                    for number, line in enumerate(f, 1):
                        code = line.split('//', 1)[0]
                        if not ASSIGNMENT.search(code):
                            continue
                        (allowed_hits if relative in ALLOWED else found).append(f'{relative}:{number}: {line.strip()}')
    for hit in allowed_hits:
        print('test program  ', hit)
    for hit in found:
        print('NOT ALLOWED   ', hit)
    print(f'check_no_unconfined: {len(allowed_hits)} assignments in test programs {sorted(ALLOWED)}, '
          f'{len(found)} elsewhere: {"FAIL" if found else "PASS"}')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
