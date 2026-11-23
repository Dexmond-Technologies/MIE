#!/usr/bin/env python3
"""Gate 2 (CI only): parity set S through the whole C++ engine, compared with the Python reference.

Usage: set_s_parity.py <path to mie-parity-run> <repository root>

Steps:
  1. generate set S, INCLUDING the large files (engine/tools/parity/make_set_s.py);
  2. run the Python reference over it with the set's own reputation list
     (engine/tools/parity/run_reference.py, as the CI job set-s does);
  3. run the C++ engine over the same folder with the same list (mie-parity-run), twice;
  4. compare the two result tables with engine/tools/parity/compare.py (the reviewer's pass
     line for A-1: SHA-256, score, verdict, sorted finding categories and error class per
     file; no explained differences are offered here, so any difference fails);
  5. require the two C++ runs to be identical (compare.py --identical).
Printed: both header records, compare.py's full output, and for every file that differs the
findings of both sides in full.
Exit code: 0 PASS; 1 a difference or a failed step; 3 the comparison STOPPED because a side
holds error-class entries (set S must have none).

All inputs are generated, harmless files. No malware, no EICAR file. The set's folder is a
temporary folder and is removed at the end; nine of its files score 70 or more by
construction, so the folder must not be watched by any real scanner while this runs.
"""
import json
import os
import hashlib
import shutil
import subprocess
import sys
import tempfile

RUNNER, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
PARITY = os.path.join(REPO, 'engine', 'tools', 'parity')
PY = sys.executable


def run(args, timeout=1500):
    done = subprocess.run(args, capture_output=True, timeout=timeout)
    return done.returncode, done.stdout.decode('utf-8', 'replace'), done.stderr.decode('utf-8', 'replace')


def lines_by_path(path):
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, 'rb') as f:
        for raw in f.read().split(b'\n'):
            if raw.strip():
                record = json.loads(raw.decode('utf-8', 'replace'))
                if 'path' in record:
                    out[record['path']] = record
    return out


def header_of(path):
    with open(path, 'rb') as f:
        for raw in f.read().split(b'\n'):
            if raw.strip():
                record = json.loads(raw.decode('utf-8', 'replace'))
                if record.get('record') == 'header':
                    return record
    return None


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def manifest_check(cpp, cpp2):
    """Windows only, when the reference could not run: the C++ table against the committed
    manifest of set S (made by the reference on Linux)."""
    with open(os.path.join(PARITY, 'set_s.manifest.json'), encoding='utf-8') as f:
        expected = {e['path']: e for e in json.load(f)['files']}
    got = lines_by_path(cpp)
    print('C++ header:      ', json.dumps(header_of(cpp), sort_keys=True))
    different = 0
    for path in sorted(set(expected) | set(got)):
        a, b = expected.get(path), got.get(path)
        if a is None or b is None:
            different += 1
            print(f'DIFF  {path}: present on one side only')
            continue
        for key in ('sha256', 'size', 'score', 'verdict', 'categories', 'error_class'):
            if a.get(key) != b.get(key):
                different += 1
                print(f'DIFF  {path}: {key}: C++ {b.get(key)!r}, manifest {a.get(key)!r}')
    code, out, _ = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', cpp, cpp2])
    print('--- two C++ runs ---')
    print(out.strip())
    print(f'extra check against the committed manifest (not the gate): {len(expected)} files in the '
          f'manifest, {len(got)} in the C++ table, {different} differences, two C++ runs identical: {code == 0}')
    return 1 if (different or code != 0) else 0


def main():
    failed = False
    with tempfile.TemporaryDirectory(prefix='mie-gate2-') as tmp:
        set_dir = os.path.join(tmp, 'set_s')
        code, out, err = run([PY, os.path.join(PARITY, 'make_set_s.py'), '--out', set_dir])
        print(out.strip())
        if code != 0:
            print('FAIL  set S could not be generated:', err.strip())
            return 1
        files = os.path.join(set_dir, 'files')
        reputation = os.path.join(set_dir, 'set_s.reputation.json')
        ref, ref_details = os.path.join(tmp, 'reference.jsonl'), os.path.join(tmp, 'reference.details.jsonl')
        cpp, cpp_details = os.path.join(tmp, 'cpp.jsonl'), os.path.join(tmp, 'cpp.details.jsonl')
        cpp2 = os.path.join(tmp, 'cpp.second.jsonl')

        code, out, err = run([PY, os.path.join(PARITY, 'run_reference.py'), '--corpus', files, '--out', ref,
                              '--details', ref_details, '--reputation', reputation])
        print(out.strip())
        reference_failed = code != 0
        if reference_failed:
            print('the Python reference run failed:', err.strip()[-2000:])
            if os.name != 'nt':
                print('FAIL  no reference table')
                return 1
            # On Windows the reference itself stops on set S: WinError 32 when it removes its own
            # temporary folder while an unpacked executable is still open (a defect of the
            # reference; that its own parser holds the handle is the builder's inference).
            # Reviewer's ruling B-3627: the Windows C++ table is compared, with the full comparer
            # and the same pass lines, against the reference table made on Linux in the same CI
            # run (job set-s, passed as an artifact; MIE_SET_S_REFERENCE names the folder). The
            # comparison with the committed manifest is an extra, not the gate.
            linux_dir = os.environ.get('MIE_SET_S_REFERENCE', '')
            linux_ref = os.path.join(linux_dir, 'reference.jsonl')
            if not linux_dir or not os.path.exists(linux_ref):
                print('FAIL  the reference failed here and no reference table from Linux was given')
                return 1
            shutil.copyfile(linux_ref, ref)
            if os.path.exists(os.path.join(linux_dir, 'reference.details.jsonl')):
                shutil.copyfile(os.path.join(linux_dir, 'reference.details.jsonl'), ref_details)
            print('REFERENCE FAILED ON WINDOWS: using the reference table made on Linux in this run')
            # The set's generator packs some zip files with the zlib of the Python that runs it;
            # another Python packs the same content into other bytes. A file whose hash is not the
            # manifest's is replaced by the Linux job's copy, and the hash is checked again.
            with open(os.path.join(PARITY, 'set_s.manifest.json'), encoding='utf-8') as f:
                wanted = {e['path']: e['sha256'] for e in json.load(f)['files'] if e.get('sha256')}
            replaced, wrong = [], []
            for name, digest in sorted(wanted.items()):
                local = os.path.join(files, name)
                if not os.path.isfile(local) or file_sha256(local) == digest:
                    continue
                linux_copy = os.path.join(linux_dir, 'files', name)
                if os.path.isfile(linux_copy) and file_sha256(linux_copy) == digest:
                    shutil.copyfile(linux_copy, local)
                    replaced.append(name)
                else:
                    wrong.append(name)
            print(f'files generated with other bytes here and replaced by the Linux copy: {len(replaced)} {replaced}')
            if wrong:
                print(f'FAIL  files whose bytes are not the manifest\'s and for which no Linux copy came: {wrong}')
                return 1

        engine_args = [RUNNER, '--corpus', files, '--rules', os.path.join(REPO, 'rules'), '--reputation', reputation,
                       '--scoring', os.path.join(REPO, 'engine', 'data', 'scoring.reference.json')]
        for target, extra in ((cpp, ['--details', cpp_details]), (cpp2, [])):
            code, out, err = run(engine_args + ['--out', target] + extra)
            print(out.strip())
            if code != 0:
                print(f'FAIL  the C++ engine run failed (exit {code}):', err.strip()[-2000:])
                return 1

        if reference_failed and manifest_check(cpp, cpp2) != 0:
            failed = True

        print('reference header:', json.dumps(header_of(ref), sort_keys=True))
        print('C++ header:      ', json.dumps(header_of(cpp), sort_keys=True))

        code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), ref, cpp])
        print('--- compare.py (reference against C++) ---')
        print(out.strip())
        if err.strip():
            print(err.strip())
        compare_code = code

        _, report_text, _ = run([PY, os.path.join(PARITY, 'compare.py'), ref, cpp, '--json', '--allow-error-classes'])
        try:
            report = json.loads(report_text[:report_text.rindex('}') + 1])
        except ValueError:
            report = {}
        differing = sorted({entry['path'] for entry in report.get('unexplained', [])})
        if differing:
            ref_lines, cpp_lines = lines_by_path(ref_details), lines_by_path(cpp_details)
            ref_records, cpp_records = lines_by_path(ref), lines_by_path(cpp)
            print(f'--- the {len(differing)} files that differ, both sides in full ---')
            for path in differing:
                print(path)
                print('  reference record  :', json.dumps(ref_records.get(path), sort_keys=True))
                print('  C++ record        :', json.dumps(cpp_records.get(path), sort_keys=True))
                print('  reference findings:', json.dumps(ref_lines.get(path), sort_keys=True))
                print('  C++ findings      :', json.dumps(cpp_lines.get(path), sort_keys=True))

        code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', cpp, cpp2])
        print('--- two C++ runs ---')
        print(out.strip())
        if code != 0:
            print('FAIL  two runs of the C++ engine gave different result tables')
            failed = True

        counted = len(lines_by_path(ref))
        print(f'set_s_parity: {counted} files in the reference table, {report.get("identical")} identical, '
              f'{len(differing)} different, compare.py exit code {compare_code}')
        if compare_code != 0:
            return compare_code
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
