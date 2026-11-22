#!/usr/bin/env python3
"""Parity harness, reference side: runs the PYTHON reference engine of this checkout over
a folder of files and writes one JSON line per file.

    run_reference.py --corpus DIR --out FILE.jsonl [--no-reputation]
    run_reference.py --describe          (prints the header record only: versions, rule hashes)

Output format (also the format the C++ engine will write for the comparison):
  line 1: {"record":"header", ...}   what produced the file: commit, Python, YARA version,
                                     SHA-256 of every rule file, options
  then one line per file, sorted by relative path:
          {"record":"file","path":<relative path with />,"sha256":...,"size":...,
           "score":<int or null>,"verdict":<text or null>,"categories":[sorted finding categories],
           "error":<text or null>}

Rules of the harness:
  - The engine works on a COPY of rules/ and data/reputation.json in a temp folder, so a
    scan never writes into the repository (same rule as tests/conftest.py).
  - Files are visited in sorted order; links and special files are listed with
    error "not a regular file" and are not opened by the harness.
  - sha256 and size are computed by the harness itself, so they exist for error results too.
  - No network. No file content is ever executed.

r-01 condition M-12: the YARA library version is part of the header. `--describe` prints it.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def git_commit():
    try:
        out = subprocess.run(['git', '-C', REPO, 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def header(rules_dir, options):
    record = {
        'record': 'header',
        'producer': 'python-reference',
        'commit': git_commit(),
        'python': platform.python_version(),
        'platform': sys.platform,
        'options': options,
        'rules': {},
        'yara_python': None,
        'yara_library': None,
        'pefile': None,
    }
    for name in sorted(os.listdir(rules_dir)):
        full = os.path.join(rules_dir, name)
        if os.path.isfile(full) and name.endswith(('.yar', '.yara')):
            record['rules'][name] = sha256_of(full)
    try:
        import yara
        record['yara_python'] = getattr(yara, '__version__', None)
        # yara-python exposes the version of the YARA library it was built with
        record['yara_library'] = getattr(yara, 'YARA_VERSION', None)
    except ImportError:
        pass
    try:
        import pefile
        record['pefile'] = getattr(pefile, '__version__', None)
    except ImportError:
        pass
    return record


def scan_corpus(corpus, out_path, use_reputation):
    sys.path.insert(0, REPO)
    from dexmond_mie.core import Engine  # imported late: --describe must work without it

    with tempfile.TemporaryDirectory(prefix='mie-parity-ref-') as work:
        rules_copy = os.path.join(work, 'rules')
        shutil.copytree(os.path.join(REPO, 'rules'), rules_copy)
        rep_copy = os.path.join(work, 'reputation.json')
        shutil.copy(os.path.join(REPO, 'data', 'reputation.json'), rep_copy)
        engine = Engine(rules_dir=rules_copy, reputation_db=rep_copy, use_reputation=use_reputation,
                        auto_evolution=False)

        files = []
        for root, dirs, names in os.walk(corpus):
            dirs.sort()
            for name in sorted(names):
                files.append(os.path.join(root, name))
        files.sort(key=lambda p: os.path.relpath(p, corpus).replace(os.sep, '/'))

        with open(out_path, 'w', encoding='utf-8', newline='\n') as out:
            head = header(rules_copy, {'use_reputation': use_reputation})
            head['yara_status'] = getattr(engine.yara_engine, 'status', None)
            out.write(json.dumps(head, sort_keys=True) + '\n')
            for path in files:
                rel = os.path.relpath(path, corpus).replace(os.sep, '/')
                record = {'record': 'file', 'path': rel, 'sha256': None, 'size': None,
                          'score': None, 'verdict': None, 'categories': [], 'error': None}
                st = os.lstat(path)
                if not stat.S_ISREG(st.st_mode):
                    record['error'] = 'not a regular file'
                    out.write(json.dumps(record, sort_keys=True) + '\n')
                    continue
                record['sha256'] = sha256_of(path)
                record['size'] = st.st_size
                result = engine.scan_file(path)
                if 'error' in result:
                    record['error'] = str(result['error'])
                else:
                    record['score'] = result.get('score')
                    record['verdict'] = result.get('verdict')
                    record['categories'] = sorted(f.get('category', '') for f in result.get('findings', []))
                out.write(json.dumps(record, sort_keys=True) + '\n')
    return len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--corpus')
    parser.add_argument('--out')
    parser.add_argument('--no-reputation', action='store_true',
                        help='do not consult the known-hash list (the reference\'s measuring mode)')
    parser.add_argument('--describe', action='store_true', help='print the header record and stop')
    args = parser.parse_args()

    if args.describe:
        print(json.dumps(header(os.path.join(REPO, 'rules'), {}), sort_keys=True, indent=2))
        return 0
    if not args.corpus or not args.out:
        parser.error('--corpus and --out are required')
    count = scan_corpus(os.path.abspath(args.corpus), args.out, not args.no_reputation)
    print(f'run_reference: {count} files, results in {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
