#!/usr/bin/env python3
"""CI test of the REAL worker: every scan in a confined worker process (one per file).

    worker_cases.py <mie-worker-run> <mie-worker> <mie-worker-testhooks> <mie-parity-run> <repo root>

Parts:
  A. Set S (harmless generated files) through mie-worker-run with the SHIPPED worker,
     compared with mie-parity-run's table by compare.py --identical: the confined path gives
     the same table, header included; the details tables are byte-equal too. From the
     worker log: every job was answered by a worker that ended by itself, the parent's and
     the worker's confinement texts are there and say nothing weaker, and no two jobs had
     the same worker (one process per file: a worker is "recycled" after every file).
  B. A worker that hangs, dies or exhausts its memory is a RESULT (reviewer's condition
     M-9): that file is NOT FULLY SCANNED with the reason, never CLEAN, and the files before
     and after it get the results they get without the fault. The faults are switches of
     the test-hooks worker only.
  C. The shipped worker has no test hooks: a job that carries a fault is refused, and that
     file is NOT FULLY SCANNED.
  D. No silent weaker run: started without confinement, the shipped worker refuses (by hand
     and through mie-worker-run); the test-hooks worker runs and SAYS it is weaker.

A case that cannot run prints NOT RUN with the reason and fails the test.
No malware and no EICAR file: set S and three small text files made here.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

RUNNER, WORKER, WORKER_HOOKS, PARITY_RUNNER = (os.path.abspath(p) for p in sys.argv[1:5])
REPO = os.path.abspath(sys.argv[5])
PARITY = os.path.join(REPO, 'engine', 'tools', 'parity')
PY = sys.executable
WINDOWS = os.name == 'nt'
LINUX = sys.platform.startswith('linux')
NOT_FULLY = 'NOT FULLY SCANNED'

RESULTS = {'passed': 0, 'failed': 0}


def check(ok, text):
    RESULTS['passed' if ok else 'failed'] += 1
    print(('PASS    ' if ok else 'FAIL    ') + text, flush=True)
    return ok


def run(args, timeout=2400, stdin=None):
    done = subprocess.run(args, capture_output=True, timeout=timeout, input=stdin)
    return done.returncode, done.stdout.decode('utf-8', 'replace'), done.stderr.decode('utf-8', 'replace')


def records(path):
    """The lines of a table or log, split on line feeds only."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'rb') as f:
        for raw in f.read().split(b'\n'):
            if raw.strip():
                out.append(json.loads(raw.decode('utf-8', 'replace')))
    return out


def by_path(items):
    return {r['path']: r for r in items if 'path' in r}


def grant_container_access():
    """Windows: the worker's AppContainer must be able to read the program folder (the
    worker program and the libraries beside it). The installer does this for the product;
    the test does it for the build folder, and prints what it did."""
    code, out, err = run([RUNNER, '--sid'], timeout=60)
    sid = ''
    try:
        sid = json.loads(out.strip().split('\n')[0]).get('sid', '')
    except (ValueError, IndexError):
        pass
    print('setup: AppContainer SID %r (exit %d, %r)' % (sid, code, (out + err)[:300]), flush=True)
    folders = sorted({os.path.dirname(p) for p in (WORKER, WORKER_HOOKS)})
    for folder in folders:
        for who in (sid, 'S-1-15-2-1'):
            if not who:
                continue
            granted = subprocess.run(['icacls', folder, '/grant', '*%s:(OI)(CI)(RX)' % who],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            print('setup: icacls %s grant %s read+execute: exit %d, %s' % (
                folder, who, granted.returncode, granted.stdout.decode('ascii', 'replace').strip()[-200:]), flush=True)


def worker_run(worker, corpus, out, common, extra=(), timeout=2400):
    args = [RUNNER, '--worker', worker, '--corpus', corpus, '--out', out] + common + list(extra)
    return run(args, timeout=timeout)


def main():
    if WINDOWS:
        grant_container_access()
    with tempfile.TemporaryDirectory(prefix='mie-worker-') as tmp:
        # ---------------------------------------------------------------- part A
        set_dir = os.path.join(tmp, 'set_s')
        code, out, err = run([PY, os.path.join(PARITY, 'make_set_s.py'), '--out', set_dir])
        print(out.strip(), flush=True)
        if code != 0:
            print('NOT RUN set S could not be generated:', err.strip()[-800:])
            return 1
        files = os.path.join(set_dir, 'files')
        common = ['--rules', os.path.join(REPO, 'rules'), '--reputation', os.path.join(set_dir, 'set_s.reputation.json'),
                  '--scoring', os.path.join(REPO, 'engine', 'data', 'scoring.reference.json')]
        direct, direct_details = os.path.join(tmp, 'direct.jsonl'), os.path.join(tmp, 'direct.details.jsonl')
        confined, confined_details = os.path.join(tmp, 'confined.jsonl'), os.path.join(tmp, 'confined.details.jsonl')
        log = os.path.join(tmp, 'confined.log.jsonl')

        # --times: the unconfined runner's time per file, to put beside the confined worker's.
        direct_times = os.path.join(tmp, 'direct.times.jsonl')
        direct_started = time.perf_counter()
        code, out, err = run([PARITY_RUNNER, '--corpus', files, '--out', direct, '--details', direct_details,
                              '--times', direct_times] + common)
        if code == 2:  # a runner without --times
            direct_times = ''
            direct_started = time.perf_counter()
            code, out, err = run([PARITY_RUNNER, '--corpus', files, '--out', direct, '--details', direct_details] + common)
        direct_wall = time.perf_counter() - direct_started
        print(out.strip(), flush=True)
        if code != 0:
            print('NOT RUN mie-parity-run failed (exit %d): %s' % (code, err.strip()[-800:]))
            return 1

        # The wall limit is raised for this part only: under a sanitizer build the large files
        # of the set take longer than the product's 60 seconds. The product's limit is tested
        # in part B.
        confined_started = time.perf_counter()
        code, out, err = worker_run(WORKER, files, confined, common,
                                    ['--details', confined_details, '--log', log, '--wall', '900'])
        confined_wall = time.perf_counter() - confined_started
        print(out.strip(), flush=True)
        if err.strip():
            print(err.strip()[-1500:], flush=True)
        check(code == 0, 'A: mie-worker-run with the shipped worker over set S ends normally (exit %d)' % code)

        code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', direct, confined])
        print('--- compare.py --identical (unconfined test runner against confined workers) ---')
        print(out.strip(), flush=True)
        same = code == 0
        if not same:
            a, b = by_path(records(direct)), by_path(records(confined))
            shown = 0
            for path in sorted(set(a) | set(b)):
                if a.get(path) != b.get(path) and shown < 20:
                    shown += 1
                    print('  DIFF %s\n    direct:   %s\n    confined: %s' % (
                        path, json.dumps(a.get(path), sort_keys=True), json.dumps(b.get(path), sort_keys=True)))
            ha = [r for r in records(direct) if r.get('record') == 'header']
            hb = [r for r in records(confined) if r.get('record') == 'header']
            if ha != hb:
                print('  DIFF header\n    direct:   %s\n    confined: %s' % (
                    json.dumps(ha, sort_keys=True)[:3000], json.dumps(hb, sort_keys=True)[:3000]))
        check(same, 'A: the table from confined workers is identical to the unconfined test runner\'s, header included '
                    '(%d file records)' % len(by_path(records(confined))))
        with open(direct_details, 'rb') as f1, open(confined_details, 'rb') as f2:
            check(f1.read() == f2.read(), 'A: the details tables (every finding, weight, family, state, reason) are byte-equal')

        entries = records(log)
        describe = [r for r in entries if r.get('record') == 'describe']
        jobs = [r for r in entries if r.get('record') == 'job']
        if describe:
            print('worker: %s' % json.dumps(describe[0], sort_keys=True)[:1500], flush=True)
        scanned = [j for j in jobs if j.get('state') != 'not_scanned' or j.get('answered')]
        check(len(jobs) > 0 and all(j.get('answered') and j.get('end') == 'exited' and j.get('exit_code') == 0 for j in scanned),
              'A: every job was answered by a worker that ended by itself (%d jobs, %d answered)' % (
                  len(jobs), sum(1 for j in jobs if j.get('answered'))))
        confinements = sorted({j.get('confinement', '') for j in scanned})
        worker_says = sorted({j.get('worker_confinement', '') for j in scanned})
        print('confinement applied by the parent: %s' % confinements, flush=True)
        print('confinement as the worker reports it: %s' % worker_says, flush=True)
        check(all(c and 'WEAKER' not in c.upper() for c in confinements) and
              all(c and 'WEAKER' not in c.upper() for c in worker_says),
              'A: parent and worker both name the confinement, and neither says WEAKER')
        if LINUX:
            check(all('seccomp' in c for c in worker_says), 'A (Linux): the worker reports the system-call filter')
        if WINDOWS:
            check(all('appcontainer' in c.lower() for c in confinements + worker_says),
                  'A (Windows): parent and worker report the AppContainer')
        pids = [j.get('worker_pid') for j in scanned]
        check(len(pids) > 1 and all(pids) and len(set(pids)) == len(pids) or
              (len(set(pids)) >= max(2, len(pids) // 2) and all(pids)),
              'A: one worker process per file: %d jobs, %d different worker process ids (the system may reuse a number)' % (
                  len(pids), len(set(pids))))
        memory = max([j.get('peak_memory_bytes', 0) for j in scanned] or [0])

        def spread(values):
            values = sorted(values)
            if not values:
                return 'no values'
            p95 = values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))]
            return 'median %.1f, 95th percentile %.1f, max %.1f' % (values[len(values) // 2], p95, values[-1])

        print('MEASURED per file, %d files, milliseconds (parent = the program that starts the workers):' % len(scanned))
        for label, key in (('total in the parent (hash, start, worker, answer checked)', 'total_ms'),
                           ('  parent: its own hash of the file', 'hash_ms'),
                           ('  parent: from the start call to the worker\'s end', 'worker_run_ms'),
                           ('    process start, confinement and end (worker run minus worker alive)', 'start_overhead_ms'),
                           ('    worker alive: first line of main to its answer', 'worker_alive_ms'),
                           ('      worker: table, RULES COMPILED, engine built', 'setup_ms'),
                           ('      worker: the scan', 'scan_ms')):
            print('  %-72s %s' % (label, spread([j.get(key, 0.0) for j in scanned])), flush=True)
        print('  highest peak memory of a worker: %d bytes' % memory, flush=True)
        if direct_times:
            unconfined = [r.get('total_ms', 0.0) for r in records(direct_times)]
            print('  %-72s %s' % ('UNCONFINED test runner, Engine::scan_file per file (%d files)' % len(unconfined),
                                  spread(unconfined)), flush=True)
            both = by_path(records(direct_times))
            ratios = sorted((j.get('total_ms', 0.0) / max(both[j['path']]['total_ms'], 0.001), j['path'])
                            for j in scanned if j.get('path') in both)
            if ratios:
                print('  confined total / unconfined total per file: median %.1f, max %.1f (%s)' % (
                    ratios[len(ratios) // 2][0], ratios[-1][0], ratios[-1][1]), flush=True)
        else:
            print('  UNCONFINED test runner per file: NOT MEASURED (this mie-parity-run has no --times)', flush=True)
        print('  (the unconfined runner compiles the rules once for all files; a worker compiles them for its one file)',
              flush=True)

        # The PYTHON REFERENCE's time per file on the same set (reviewer's line A-8: "not worse
        # than the Python reference at the median and the 95th percentile"). Linux only: the
        # reference stops on Windows on an archive that holds an executable. PRINTED, NEVER
        # ASSERTED: set S is 58 generated files, not the corpus, and a CI runner is not the
        # reference machine.
        sanitized = bool(describe and describe[0].get('sanitizer_build'))
        if not LINUX:
            print('A-8 on set S: NOT MEASURED here (the Python reference is run on Linux only)', flush=True)
        else:
            reference_times = os.path.join(tmp, 'reference.times.jsonl')
            code, out, err = run([PY, os.path.join(PARITY, 'run_reference.py'), '--corpus', files,
                                  '--out', os.path.join(tmp, 'reference.jsonl'), '--times', reference_times,
                                  '--reputation', os.path.join(set_dir, 'set_s.reputation.json')])
            reference = {r['path']: r['seconds'] * 1000.0 for r in records(reference_times)
                         if 'seconds' in r and 'path' in r}
            engine_built = [r['seconds'] for r in records(reference_times) if r.get('record') == 'engine_built']
            confined_ms = {j['path']: j.get('total_ms', 0.0) for j in scanned if j.get('answered')}
            common_paths = sorted(set(reference) & set(confined_ms))
            if code != 0 or not common_paths:
                print('A-8 on set S: NOT MEASURED (the reference run gave no times: exit %d, %s)' % (
                    code, err.strip()[-300:]), flush=True)
            else:
                def at(values, share):
                    values = sorted(values)
                    return values[min(len(values) - 1, int(round(share * (len(values) - 1))))]

                ref = [reference[p] for p in common_paths]
                cpp = [confined_ms[p] for p in common_paths]
                print('A-8 on set S, %d files, milliseconds per file, measured on this CI runner%s:' % (
                    len(common_paths), ' (SANITIZER BUILD of the C++ side: its times are not the product\'s)' if sanitized else ''))
                print('  Python reference, Engine.scan_file, engine built once:   median %.1f, 95th percentile %.1f, max %.1f' % (
                    at(ref, 0.5), at(ref, 0.95), max(ref)))
                print('  C++ through a confined worker, total in the parent:      median %.1f, 95th percentile %.1f, max %.1f' % (
                    at(cpp, 0.5), at(cpp, 0.95), max(cpp)))
                print('  ratio C++ / reference: at the median %.2f, at the 95th percentile %.2f' % (
                    at(cpp, 0.5) / max(at(ref, 0.5), 0.001), at(cpp, 0.95) / max(at(ref, 0.95), 0.001)))
                # Totals over the same files (reviewer, B-3631), seconds.
                unconfined_all = {r['path']: r.get('total_ms', 0.0) for r in records(direct_times)} if direct_times else {}
                unconfined_sum = sum(unconfined_all.get(p, 0.0) for p in common_paths) / 1000.0
                print('  TOTAL over these %d files, seconds:' % len(common_paths))
                print('    Python reference: scan_file calls %.3f; building the Engine once (not in that sum) %s' % (
                    sum(ref) / 1000.0, '%.3f' % engine_built[0] if engine_built else 'NOT MEASURED'))
                print('    C++ through confined workers: sum of the parent\'s per-file totals %.3f; wall time of the whole '
                      'mie-worker-run (one describing worker, listing and writing included) %.3f' % (
                          sum(cpp) / 1000.0, confined_wall))
                if direct_times:
                    print('    C++ unconfined test runner: sum per file %.3f; its one-time set-up and writing (whole '
                          'mie-parity-run %.3f minus that sum; rules compiled once in it) %.3f' % (
                              unconfined_sum, direct_wall, max(direct_wall - sum(unconfined_all.values()) / 1000.0, 0.0)))
                else:
                    print('    C++ unconfined test runner: per file NOT MEASURED; whole mie-parity-run %.3f' % direct_wall)
                print('A-8 on set S: confined C++ %s slower than the reference at the median; %s slower at the 95th '
                      'percentile. (A statement of these numbers only: 58 generated files, not the corpus; a CI runner, '
                      'not the reference machine; nothing is asserted on it.)' % (
                          'IS' if at(cpp, 0.5) > at(ref, 0.5) else 'is not',
                          'IS' if at(cpp, 0.95) > at(ref, 0.95) else 'is not'), flush=True)

        # ---------------------------------------------------------------- part B
        small = os.path.join(tmp, 'small')
        os.mkdir(small)
        for name, text in (('a.txt', 'first file, plain text\n'), ('b.txt', 'second file, plain text\n'),
                           ('c.txt', 'third file, plain text\n')):
            with open(os.path.join(small, name), 'w', encoding='ascii', newline='\n') as f:
                f.write(text * 20)
        clean_table = os.path.join(tmp, 'small.jsonl')
        code, out, err = worker_run(WORKER_HOOKS, small, clean_table, common, ['--wall', '120'])
        base = by_path(records(clean_table))
        check(code == 0 and len(base) == 3 and all(r.get('verdict') not in (None, NOT_FULLY) for r in base.values()),
              'B: without a fault the three small files are scanned by the test-hooks worker: %s' % (
                  {p: r.get('verdict') for p, r in sorted(base.items())}))

        def fault_case(kind, words, wall, timeout):
            table = os.path.join(tmp, 'fault-%s.jsonl' % kind)
            details = os.path.join(tmp, 'fault-%s.details.jsonl' % kind)
            fault_log = os.path.join(tmp, 'fault-%s.log.jsonl' % kind)
            code, out, err = worker_run(WORKER_HOOKS, small, table, common,
                                        ['--details', details, '--log', fault_log, '--wall', str(wall),
                                         '--test-fault', 'b.txt=%s' % kind], timeout=timeout)
            got = by_path(records(table))
            reason = by_path(records(details)).get('b.txt', {})
            job = by_path([r for r in records(fault_log) if r.get('record') == 'job']).get('b.txt', {})
            b = got.get('b.txt', {})
            ok = (code == 0 and b.get('verdict') == NOT_FULLY and b.get('score') == 0 and b.get('categories') == [] and
                  reason.get('state') == 'not_fully_scanned' and any(w in reason.get('reason', '') for w in words) and
                  got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'))
            check(ok, 'B: a worker that %s: b.txt is %r with reason %r (worker end %r); a.txt and c.txt are as without '
                      'the fault: %s; the parent ended normally (exit %d)' % (
                          {'spin': 'never ends', 'crash': 'dies', 'allocate': 'exhausts its memory',
                           'answer-none': 'exits 0 having written NOTHING',
                           'answer-half': 'exits 0 having written HALF of its answer frame',
                           'answer-extra': 'exits 0 having written a whole frame FOLLOWED BY EXTRA BYTES',
                           'answer-wrong-file': 'exits 0 with a well-formed answer about ANOTHER FILE (other hash)'}[kind],
                          b.get('verdict'), reason.get('reason'), job.get('end'),
                          got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'), code))

        fault_case('spin', ['time limit'], 5, 600)
        # (under a sanitizer build a crash may be an ordinary exit of the sanitizer's own)
        fault_case('crash', ['crashed', 'ended without an answer'], 60, 600)
        fault_case('allocate', ['memory limit'], 300, 1200)
        # "Exit code 0 with an answer that is not exactly one whole frame about the handed-over file"
        # is a failed worker (reviewer, B-3631): each form has its own case and its own reason.
        fault_case('answer-none', ['the answer is cut short (0 bytes received'], 60, 600)
        fault_case('answer-half', ['the answer is cut short ('], 60, 600)
        fault_case('answer-extra', ['bytes follow the answer'], 60, 600)
        fault_case('answer-wrong-file', ['the file changed during the scan'], 60, 600)

        # Reviewer's question SB-2: the worker's handle shares its read position with the parent's.
        # A worker that MOVES that position (a plain read / SetFilePointerEx on the handed-over
        # handle) and then answers normally must change nothing: the parent's hash and size
        # check passes and all three results are those without the switch. Both sides read by
        # position only; this case fails if either stops doing so.
        table = os.path.join(tmp, 'move-position.jsonl')
        move_log = os.path.join(tmp, 'move-position.log.jsonl')
        code, out, err = worker_run(WORKER_HOOKS, small, table, common,
                                    ['--log', move_log, '--wall', '120', '--test-fault', 'b.txt=move-position'])
        got = by_path(records(table))
        job = by_path([r for r in records(move_log) if r.get('record') == 'job']).get('b.txt', {})
        said = job.get('detail', '')
        check(code == 0 and got == base and job.get('answered') is True and 'moved the shared read position' in said,
              'B (SB-2): a worker that moves the shared read position of the handed-over file changes nothing: all three '
              'results as without it: %s; b.txt answered: %s; the worker says: %r' % (
                  got == base, job.get('answered'), said[-200:]))

        # A file that CHANGES while it is scanned (reviewer's ruling: files stay shared for reading,
        # writing and deleting; the protection is the parent's hash before the worker against the
        # hash of what the worker read). The test-hooks worker pauses 3 seconds before its first
        # read; the test waits for the runner's "start" line of b.txt (written before the parent
        # opens and hashes the file), then 0.7 s, then acts.
        def during_scan(label, action):
            folder = os.path.join(tmp, 'changing-' + label)
            os.mkdir(folder)
            for name in ('a.txt', 'b.txt', 'c.txt'):
                shutil.copyfile(os.path.join(small, name), os.path.join(folder, name))
            table = os.path.join(tmp, 'changing-%s.jsonl' % label)
            details = os.path.join(tmp, 'changing-%s.details.jsonl' % label)
            change_log = os.path.join(tmp, 'changing-%s.log.jsonl' % label)
            process = subprocess.Popen([RUNNER, '--worker', WORKER_HOOKS, '--corpus', folder, '--out', table,
                                        '--details', details, '--log', change_log, '--wall', '120',
                                        '--test-fault', 'b.txt=pause-before-read'] + common,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            acted = 'the start line of b.txt never appeared'
            deadline = time.time() + 300
            while time.time() < deadline and process.poll() is None:
                try:
                    started = any(r.get('record') == 'start' and r.get('path') == 'b.txt' for r in records(change_log))
                except ValueError:
                    started = False  # a line half written
                if started:
                    time.sleep(0.7)
                    try:
                        acted = action(os.path.join(folder, 'b.txt'))
                    except OSError as problem:
                        acted = 'REFUSED BY THE SYSTEM: %r' % (problem,)
                    break
                time.sleep(0.05)
            try:
                process.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            return (process.returncode, by_path(records(table)), by_path(records(details)),
                    by_path([r for r in records(change_log) if r.get('record') == 'job']), acted)

        original_hash = base.get('b.txt', {}).get('sha256')

        def overwrite_in_place(path):
            size = os.path.getsize(path)
            with open(path, 'r+b') as f:
                f.seek(size // 2)
                f.write(b'CHANGED-DURING-THE-SCAN'[:max(1, size - size // 2)])
                f.flush()
                os.fsync(f.fileno())
            return 'overwrote bytes in the middle in place, size still %d: %s' % (size, os.path.getsize(path) == size)

        code, got, reasons, jobs_now, acted = during_scan('overwrite', overwrite_in_place)
        b, reason = got.get('b.txt', {}), reasons.get('b.txt', {})
        check(code == 0 and not acted.startswith(('REFUSED', 'the start line')) and b.get('verdict') == NOT_FULLY and
              b.get('score') == 0 and b.get('categories') == [] and reason.get('state') == 'not_fully_scanned' and
              reason.get('reason', '').startswith('the file changed during the scan') and
              got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'),
              'B: a file CHANGED IN PLACE during the scan (%s): b.txt is %r, state %r, reason %r; a.txt and c.txt as '
              'before: %s; parent exit %d' % (acted, b.get('verdict'), reason.get('state'), reason.get('reason'),
                                               got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'),
                                               code))

        def replace_by_rename(path):
            other = path + '.new'
            with open(other, 'w', encoding='ascii', newline='\n') as f:
                f.write('quite another file with the same name\n' * 30)
            try:
                os.replace(other, path)
                return 'replaced by rename over the open file'
            except OSError as first:
                os.rename(path, path + '.old')   # move the open original away, then put the new one in
                os.rename(other, path)
                return 'renamed the open original away and the new file in (rename over it was refused: %r)' % (first,)

        # Expectation: the worker reads the ORIGINAL through its handle, so both hashes agree and
        # the result is the original file's (its hash, its verdict). What is at the path afterwards
        # is another file, which this scan does not speak about.
        code, got, reasons, jobs_now, acted = during_scan('rename', replace_by_rename)
        b = got.get('b.txt', {})
        check(code == 0 and not acted.startswith(('REFUSED', 'the start line')) and
              jobs_now.get('b.txt', {}).get('answered') is True and b.get('sha256') == original_hash and
              b.get('verdict') == base.get('b.txt', {}).get('verdict') and b.get('score') == base.get('b.txt', {}).get('score') and
              got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'),
              'B: a file REPLACED BY RENAME during the scan (%s): the worker read the ORIGINAL through its handle: '
              'result hash %s, the original\'s %s, verdict %r; neighbours as before; parent exit %d' % (
                  acted, b.get('sha256'), original_hash, b.get('verdict'), code))

        # ---------------------------------------------------------------- part C
        table = os.path.join(tmp, 'shipped-fault.jsonl')
        details = os.path.join(tmp, 'shipped-fault.details.jsonl')
        code, out, err = worker_run(WORKER, small, table, common,
                                    ['--details', details, '--wall', '120', '--test-fault', 'b.txt=crash'])
        got = by_path(records(table))
        reason = by_path(records(details)).get('b.txt', {}).get('reason', '')
        check(code == 0 and got.get('b.txt', {}).get('verdict') == NOT_FULLY and 'test switch' in reason and
              got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'),
              'C: the shipped worker refuses a job that carries a test switch: b.txt %r, reason %r' % (
                  got.get('b.txt', {}).get('verdict'), reason))

        # ---------------------------------------------------------------- part D
        environment = {k: v for k, v in os.environ.items() if k != 'MIE_SANDBOX'}
        by_hand = subprocess.run([WORKER], input=b'', capture_output=True, timeout=120, env=environment)
        check(by_hand.returncode == 43 and by_hand.stdout == b'' and b'not started confined' in by_hand.stderr,
              'D: the shipped worker started by hand, without confinement, refuses: exit %d, no answer, says %r' % (
                  by_hand.returncode, by_hand.stderr.decode('ascii', 'replace').strip()[-200:]))
        with_argument = subprocess.run([WORKER, '--test-allow-unconfined'], input=b'', capture_output=True, timeout=120,
                                       env=environment)
        check(with_argument.returncode == 42 and with_argument.stdout == b'',
              'D: the shipped worker does not know the test argument: exit %d' % with_argument.returncode)

        table = os.path.join(tmp, 'unconfined-shipped.jsonl')
        code, out, err = worker_run(WORKER, small, table, common, ['--unconfined', '--wall', '120'])
        check(code == 3 and 'did not describe itself' in err,
              'D: mie-worker-run --unconfined with the shipped worker gets no worker at all: exit %d, %r' % (
                  code, err.strip()[-300:]))

        table = os.path.join(tmp, 'unconfined-hooks.jsonl')
        weak_log = os.path.join(tmp, 'unconfined-hooks.log.jsonl')
        code, out, err = worker_run(WORKER_HOOKS, small, table, common, ['--unconfined', '--log', weak_log, '--wall', '120'])
        got = by_path(records(table))
        jobs = [r for r in records(weak_log) if r.get('record') == 'job']
        says = sorted({j.get('worker_confinement', '') for j in jobs})
        check(code == 0 and got == base and len(jobs) == 3 and all(s.startswith('WEAKER') for s in says),
              'D: the test-hooks worker started unconfined on purpose gives the same three results and SAYS so: %s' % says)

    print('worker_cases: %d passed, %d failed' % (RESULTS['passed'], RESULTS['failed']), flush=True)
    return 0 if RESULTS['failed'] == 0 and RESULTS['passed'] > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
