#!/usr/bin/env python3
"""CI test: the C++ scorer gives the Python reference scorer's answer on every scoring vector.

Usage: scoring_vectors_test.py <path to mie-scoring-check> <repository root>

Step 1 runs engine/tools/parity/scoring_vectors.py, which builds the lists of findings from
the scoring table and asks the PYTHON reference scorer (dexmond_mie/scoring.py of this
checkout) for score, verdict and family scores of each.
Step 2 gives the same lists to the C++ scorer through mie-scoring-check and compares all three.
Step 3 proves the comparison can fail: one expected score is changed on a copy and the check
must then report exactly one difference.
"""
import json
import os
import subprocess
import sys
import tempfile

CHECK, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
TOOL = os.path.join(REPO, 'engine', 'tools', 'parity', 'scoring_vectors.py')
TABLE = os.path.join(REPO, 'engine', 'data', 'scoring.reference.json')

with tempfile.TemporaryDirectory(prefix='mie-vectors-') as tmp:
    vectors = os.path.join(tmp, 'vectors.json')
    made = subprocess.run([sys.executable, TOOL, '--out', vectors], capture_output=True, text=True, timeout=600)
    print(made.stdout.strip()[:600])
    if made.returncode != 0:
        print('FAIL  the reference vectors could not be built:', made.stderr.strip())
        sys.exit(1)

    ran = subprocess.run([CHECK, TABLE, vectors], capture_output=True, text=True, timeout=600)
    print(ran.stdout.strip())
    ok = ran.returncode == 0 and ', 0 different' in ran.stdout
    print(('PASS' if ok else 'FAIL') + '  C++ scorer equals the Python reference scorer on every vector')

    with open(vectors, encoding='utf-8') as f:
        document = json.load(f)
    victim = next(v for v in document['vectors'] if v['expected']['score'] == 30)
    victim['expected']['score'] = 31
    broken = os.path.join(tmp, 'broken.json')
    with open(broken, 'w', encoding='utf-8') as f:
        json.dump(document, f)
    again = subprocess.run([CHECK, TABLE, broken], capture_output=True, text=True, timeout=600)
    caught = again.returncode == 1 and ', 1 different' in again.stdout
    print(('PASS' if caught else 'FAIL') + '  one deliberately wrong expected score is reported as exactly one difference: '
          + again.stdout.strip().splitlines()[-1])

sys.exit(0 if (ok and caught) else 1)
