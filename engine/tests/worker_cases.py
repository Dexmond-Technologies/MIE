#!/usr/bin/env python3
"""CI test of the REAL worker: every scan in a confined worker process (one per file), in both
shapes of engine/include/mie/worker.hpp:
  shape A  --pool 0  one worker STARTED per file (today's shipped shape)
  shape B  --pool 2  PRE-STARTED one-shot workers (reviewer's ruling M-13)

    worker_cases.py <mie-worker-run> <mie-worker> <mie-worker-testhooks> <mie-parity-run> <repo root>

Parts:
  0. Set S is generated once. On Windows the seven zip files the Windows Python packs into other
     bytes are replaced by the Linux job's copies (MIE_SET_S_REFERENCE), checked against the
     manifest, as set_s_parity does. The Python reference's table: made here on Linux, taken
     from the Linux job on Windows.
  A. Set S through mie-worker-run with the SHIPPED worker, in BOTH shapes: each table is
     identical to the unconfined runner's (compare.py --identical: file records) and to the
     other shape's; the HEADERS are compared separately (equal except the worker_pool field);
     the details tables are byte-equal. GATE 2 in each shape: compare.py with the reviewer's
     pass lines against the reference table. From the logs: every job answered by a worker
     that ended by itself, confinement named and not weaker, one process per file.
  B. A worker that hangs, dies, exhausts its memory, or ends with a bad answer is a RESULT
     (M-9): NOT FULLY SCANNED with the reason, neighbours unchanged; a file changed during the
     scan; a file replaced by rename; the shared read position (SB-2). Both shapes.
  P. Shape B only (M-13): a second hand-over to the same worker is refused (condition 3); a
     worker that dies while waiting is logged and replaced; waiting workers are replaced after
     their age; a configuration change ends the waiting workers and later files are served by
     the new generation (condition 5); an answer from another configuration is discarded and
     scanned again once, a second time it is NOT FULLY SCANNED; when no worker can be had the
     file is NOT SCANNED, never clean (condition 6).
  C. The shipped worker has no test hooks: a job carrying a fault is refused. Both shapes.
  D. No silent weaker run (shape A; and a pre-started worker without confinement refuses).
  T. A-8 figures, PRINTED, NEVER ASSERTED (CI runners, generated files; not the corpus, not the
     reference machine): (a) one file after idle with the pool full; (b) set S, median and 95th
     percentile, both shapes and the reference; (c) a burst of 210 small files, both shapes,
     the unconfined runner and the reference. An empty pool costs shape A's price.

A case that cannot run prints NOT RUN with the reason and fails the test.
No malware and no EICAR file: set S and small text files made here.
"""
import hashlib
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
SHAPES = (('A', ['--pool', '0']), ('B', ['--pool', '2']))

RESULTS = {'passed': 0, 'failed': 0}


def check(ok, text):
    RESULTS['passed' if ok else 'failed'] += 1
    print(('PASS    ' if ok else 'FAIL    ') + text, flush=True)
    return ok


def run(args, timeout=2400, stdin=None, env=None):
    done = subprocess.run(args, capture_output=True, timeout=timeout, input=stdin, env=env)
    return done.returncode, done.stdout.decode('utf-8', 'replace'), done.stderr.decode('utf-8', 'replace')


def records(path):
    """The lines of a table or log, split on line feeds only."""
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path, 'rb') as f:
        for raw in f.read().split(b'\n'):
            if raw.strip():
                out.append(json.loads(raw.decode('utf-8', 'replace')))
    return out


def by_path(items):
    return {r['path']: r for r in items if 'path' in r}


def header_of(path):
    heads = [r for r in records(path) if r.get('record') == 'header']
    return heads[0] if heads else {}


def jobs_of(log):
    return [r for r in records(log) if r.get('record') == 'job']


def pool_events(log):
    return [r for r in records(log) if r.get('record') == 'pool']


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def at(values, share):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(share * (len(values) - 1))))] if values else 0.0


def spread(values):
    values = sorted(values)
    if not values:
        return 'no values'
    return 'median %.1f, 95th percentile %.1f, max %.1f' % (at(values, 0.5), at(values, 0.95), values[-1])


BREAKDOWN = (('hand_over_file returned (parent)', 't_hand_over_returned_ms'),
             ('sealed: fully confined, file received (worker)', 't_sealed_ms'),
             ('result ready, answer about to be written (worker)', 't_scan_done_ms'),
             ('answer handed to the system (worker)', 't_answer_written_ms'),
             ('main() returned (worker)', 't_main_ended_ms'),
             ('sandbox: the parent saw the worker\'s end', 'tl_process_ended_ms'),
             ('sandbox: its pipes read to the end', 'tl_output_drained_ms'),
             ('sandbox: job and process handles closed (Windows)', 'tl_job_closed_ms'),
             ('sandbox: collect() about to return', 'tl_returned_ms'),
             ('collect() returned (parent)', 't_collect_returned_ms'),
             ('every check done (parent)', 'from_hand_over_ms'))


def print_breakdown(jobs, indent='      '):
    """Shape B: where the time of a file goes, milliseconds FROM THE START OF THE HAND-OVER
    CALL (worker moments on the machine-wide steady clock)."""
    print('%smilliseconds from the start of the hand-over call (median / 95th percentile / max):' % indent)
    for label, key in BREAKDOWN:
        values = [j.get(key, -1.0) for j in jobs if j.get(key, -1.0) is not None and j.get(key, -1.0) >= 0]
        print('%s  %-58s %s' % (indent, label, spread(values) if values else 'NOT MEASURED'), flush=True)
    retire = [j.get('retire_ms', -1.0) for j in jobs if (j.get('retire_ms') or -1.0) >= 0]
    deleted = [j.get('retire_deleted_ms', -1.0) for j in jobs if (j.get('retire_deleted_ms') or -1.0) >= 0]
    refill = [j.get('refill_after_delivery_ms', 0.0) for j in jobs]
    print('%sAFTER the result was delivered, not in the file\'s time (the pool\'s cost): retiring the used worker %s '
          '(of which deleting its profile %s); starting the replacement %s' % (
              indent, spread(retire) if retire else 'NOT MEASURED', spread(deleted) if deleted else 'not applicable',
              spread(refill)), flush=True)


def grant_container_access():
    """Windows: the worker's AppContainer must be able to read the program folder. The
    installer does this for the product; the test does it for the build folder."""
    code, out, err = run([RUNNER, '--sid'], timeout=60)
    sid = ''
    try:
        sid = json.loads(out.strip().split('\n')[0]).get('sid', '')
    except (ValueError, IndexError):
        pass
    print('setup: AppContainer SID %r (exit %d, %r)' % (sid, code, (out + err)[:300]), flush=True)
    for folder in sorted({os.path.dirname(p) for p in (WORKER, WORKER_HOOKS)}):
        for who in (sid, 'S-1-15-2-1'):
            if not who:
                continue
            granted = subprocess.run(['icacls', folder, '/grant', '*%s:(OI)(CI)(RX)' % who],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            print('setup: icacls %s grant %s read+execute: exit %d, %s' % (
                folder, who, granted.returncode, granted.stdout.decode('ascii', 'replace').strip()[-200:]), flush=True)


def worker_run(worker, corpus, out, common, extra=(), timeout=2400, shape=('--pool', '0')):
    args = [RUNNER, '--worker', worker, '--corpus', corpus, '--out', out] + common + list(shape) + list(extra)
    return run(args, timeout=timeout)


def run_reference(corpus, out, times, reputation):
    """Linux only: the Python reference over `corpus`, with its per-file times."""
    return run([PY, os.path.join(PARITY, 'run_reference.py'), '--corpus', corpus, '--out', out, '--times', times,
                '--reputation', reputation])


def main():
    if WINDOWS:
        grant_container_access()
    with tempfile.TemporaryDirectory(prefix='mie-worker-') as tmp:
        # ---------------------------------------------------------------- part 0
        set_dir = os.path.join(tmp, 'set_s')
        code, out, err = run([PY, os.path.join(PARITY, 'make_set_s.py'), '--out', set_dir])
        print(out.strip(), flush=True)
        if code != 0:
            print('NOT RUN set S could not be generated:', err.strip()[-800:])
            return 1
        files = os.path.join(set_dir, 'files')
        reputation_file = os.path.join(set_dir, 'set_s.reputation.json')
        common = ['--rules', os.path.join(REPO, 'rules'), '--reputation', reputation_file,
                  '--scoring', os.path.join(REPO, 'engine', 'data', 'scoring.reference.json')]

        linux_dir = os.environ.get('MIE_SET_S_REFERENCE', '')
        reference_table, reference_times = '', ''
        if WINDOWS:
            # The manifest is the authority (reviewer, B-3629): a file whose bytes differ is
            # replaced by the Linux job's copy and checked again.
            with open(os.path.join(PARITY, 'set_s.manifest.json'), encoding='utf-8') as f:
                wanted = {e['path']: e['sha256'] for e in json.load(f)['files'] if e.get('sha256')}
            replaced, wrong = [], []
            for name, digest in sorted(wanted.items()):
                local = os.path.join(files, name)
                if not os.path.isfile(local) or file_sha256(local) == digest:
                    continue
                copy = os.path.join(linux_dir, 'files', name) if linux_dir else ''
                if copy and os.path.isfile(copy) and file_sha256(copy) == digest:
                    shutil.copyfile(copy, local)
                    replaced.append(name)
                else:
                    wrong.append(name)
            print('set S files generated with other bytes here and replaced by the Linux copy: %d %s' % (
                len(replaced), replaced), flush=True)
            if wrong:
                print('NOT RUN files of set S whose bytes are not the manifest\'s and no Linux copy came: %s' % wrong)
                return 1
            if linux_dir and os.path.isfile(os.path.join(linux_dir, 'reference.jsonl')):
                reference_table = os.path.join(linux_dir, 'reference.jsonl')
        elif LINUX:
            reference_table = os.path.join(tmp, 'reference.jsonl')
            reference_times = os.path.join(tmp, 'reference.times.jsonl')
            code, out, err = run_reference(files, reference_table, reference_times, reputation_file)
            if code != 0:
                print('the Python reference run failed (exit %d): %s' % (code, err.strip()[-600:]), flush=True)
                reference_table, reference_times = '', ''

        direct, direct_details = os.path.join(tmp, 'direct.jsonl'), os.path.join(tmp, 'direct.details.jsonl')
        direct_times = os.path.join(tmp, 'direct.times.jsonl')
        started = time.perf_counter()
        code, out, err = run([PARITY_RUNNER, '--corpus', files, '--out', direct, '--details', direct_details,
                              '--times', direct_times] + common)
        direct_wall = time.perf_counter() - started
        print(out.strip(), flush=True)
        if code != 0:
            print('NOT RUN mie-parity-run failed (exit %d): %s' % (code, err.strip()[-800:]))
            return 1

        # ---------------------------------------------------------------- part A
        tables, logs, walls = {}, {}, {}
        for shape, shape_args in SHAPES:
            table = os.path.join(tmp, 'confined-%s.jsonl' % shape)
            details = os.path.join(tmp, 'confined-%s.details.jsonl' % shape)
            log = os.path.join(tmp, 'confined-%s.log.jsonl' % shape)
            tables[shape], logs[shape] = table, log
            # The wall limit is raised for this part only: under a sanitizer build the large
            # files of the set take longer than the product's 60 seconds. The product's limit
            # is tested in part B.
            started = time.perf_counter()
            code, out, err = worker_run(WORKER, files, table, common, ['--details', details, '--log', log, '--wall', '900'],
                                        shape=shape_args)
            walls[shape] = time.perf_counter() - started
            print(out.strip(), flush=True)
            if err.strip():
                print(err.strip()[-1500:], flush=True)
            check(code == 0, 'A%s: mie-worker-run with the shipped worker over set S ends normally (exit %d)' % (shape, code))

            code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', direct, table])
            same = code == 0
            if not same:
                a, b = by_path(records(direct)), by_path(records(table))
                for path in [p for p in sorted(set(a) | set(b)) if a.get(p) != b.get(p)][:20]:
                    print('  DIFF %s\n    unconfined: %s\n    shape %s:    %s' % (
                        path, json.dumps(a.get(path), sort_keys=True), shape, json.dumps(b.get(path), sort_keys=True)))
            check(same, 'A%s: the FILE RECORDS from confined workers are identical to the unconfined runner\'s (%d records; '
                        'compare.py --identical leaves the header out)' % (shape, len(by_path(records(table)))))
            head_direct, head_here = header_of(direct), header_of(table)
            pool_field = head_here.pop('worker_pool', None)
            check(head_direct == head_here and isinstance(pool_field, dict) and
                  pool_field.get('size') == int(shape_args[1]),
                  'A%s: the HEADER equals the unconfined runner\'s except the worker_pool field %s%s' % (
                      shape, json.dumps(pool_field, sort_keys=True),
                      '' if head_direct == head_here else '; DIFFERENT: %s against %s' % (
                          json.dumps(head_here, sort_keys=True)[:1500], json.dumps(head_direct, sort_keys=True)[:1500])))
            with open(direct_details, 'rb') as f1, open(details, 'rb') as f2:
                check(f1.read() == f2.read(), 'A%s: the details tables (every finding, weight, family, state, reason) '
                                              'are byte-equal' % shape)

            # Gate 2 in this shape: the reviewer's pass lines against the Python reference's table.
            if reference_table:
                code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), reference_table, table])
                print('--- gate 2, shape %s: compare.py (reference against confined C++) ---\n%s' % (shape, out.strip()),
                      flush=True)
                check(code == 0, 'A%s: GATE 2 in this shape: compare.py exit %d against the reference table %s' % (
                    shape, code, 'made on Linux in this run' if WINDOWS else 'made here'))
            else:
                check(False, 'A%s: GATE 2 in this shape: NOT RUN (no reference table: %s)' % (
                    shape, 'MIE_SET_S_REFERENCE not given' if WINDOWS else 'the reference run failed or this system has none'))

            jobs = jobs_of(log)
            scanned = [j for j in jobs if j.get('state') != 'not_scanned' or j.get('answered')]
            check(len(jobs) > 0 and all(j.get('answered') and j.get('end') == 'exited' and j.get('exit_code') == 0
                                        for j in scanned),
                  'A%s: every job was answered by a worker that ended by itself (%d jobs, %d answered)' % (
                      shape, len(jobs), sum(1 for j in jobs if j.get('answered'))))
            confinements = sorted({j.get('confinement', '') for j in scanned})
            worker_says = sorted({j.get('worker_confinement', '') for j in scanned})
            print('shape %s: confinement applied by the parent: %s' % (shape, confinements), flush=True)
            print('shape %s: confinement as the worker reports it: %s' % (shape, worker_says), flush=True)
            check(all(c and 'WEAKER' not in c.upper() for c in confinements + worker_says),
                  'A%s: parent and worker both name the confinement, and neither says WEAKER' % shape)
            if LINUX:
                check(all('seccomp' in c for c in worker_says),
                      'A%s (Linux): the worker reports the system-call filter in force for the scan' % shape)
            if WINDOWS:
                check(all('appcontainer' in (j.get('confinement', '') + j.get('worker_confinement', '')).lower()
                          for j in scanned), 'A%s (Windows): the AppContainer is named for every job' % shape)
            pids = [j.get('worker_pid') for j in scanned]
            check(all(pids) and len(set(pids)) >= max(2, len(pids) // 2),
                  'A%s: one worker process per file: %d jobs, %d different worker process ids (the system may reuse a '
                  'number)' % (shape, len(pids), len(set(pids))))
            if shape == 'B':
                events = pool_events(log)
                kinds = sorted({e.get('what') for e in events})
                print('shape B pool events: %s' % {k: sum(1 for e in events if e.get('what') == k) for k in kinds},
                      flush=True)
                check(all(j.get('attempts') == 1 and j.get('worker_generation') == 1 for j in scanned) and
                      any(e.get('what') == 'ready' for e in events),
                      'AB: every file was served by a pre-started worker of the first configuration, at the first attempt')
        code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', tables['A'], tables['B']])
        check(code == 0, 'A: the tables of shape A and shape B are identical (file records)')

        # ---------------------------------------------------------------- part B (both shapes)
        small = os.path.join(tmp, 'small')
        os.mkdir(small)
        for name, text in (('a.txt', 'first file, plain text\n'), ('b.txt', 'second file, plain text\n'),
                           ('c.txt', 'third file, plain text\n')):
            with open(os.path.join(small, name), 'w', encoding='ascii', newline='\n') as f:
                f.write(text * 20)
        bases = {}
        for shape, shape_args in SHAPES:
            clean_table = os.path.join(tmp, 'small-%s.jsonl' % shape)
            code, out, err = worker_run(WORKER_HOOKS, small, clean_table, common, ['--wall', '120'], shape=shape_args)
            bases[shape] = by_path(records(clean_table))
            check(code == 0 and len(bases[shape]) == 3 and
                  all(r.get('verdict') not in (None, NOT_FULLY) for r in bases[shape].values()),
                  'B%s: without a fault the three small files are scanned by the test-hooks worker: %s' % (
                      shape, {p: r.get('verdict') for p, r in sorted(bases[shape].items())}))
        check(bases['A'] == bases['B'], 'B: the three small files give the same results in both shapes')
        base = bases['A']

        def fault_case(shape, shape_args, kind, words, wall, timeout):
            table = os.path.join(tmp, 'fault-%s-%s.jsonl' % (shape, kind))
            details = os.path.join(tmp, 'fault-%s-%s.details.jsonl' % (shape, kind))
            fault_log = os.path.join(tmp, 'fault-%s-%s.log.jsonl' % (shape, kind))
            code, out, err = worker_run(WORKER_HOOKS, small, table, common,
                                        ['--details', details, '--log', fault_log, '--wall', str(wall),
                                         '--test-fault', 'b.txt=%s' % kind], timeout=timeout, shape=shape_args)
            got = by_path(records(table))
            reason = by_path(records(details)).get('b.txt', {})
            job = by_path(jobs_of(fault_log)).get('b.txt', {})
            b = got.get('b.txt', {})
            neighbours = got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt')
            ok = (code == 0 and b.get('verdict') == NOT_FULLY and b.get('score') == 0 and b.get('categories') == [] and
                  reason.get('state') == 'not_fully_scanned' and any(w in reason.get('reason', '') for w in words) and
                  neighbours)
            check(ok, 'B%s: a worker that %s: b.txt is %r with reason %r (worker end %r); a.txt and c.txt as without '
                      'the fault: %s; the parent ended normally (exit %d)' % (
                          shape,
                          {'spin': 'never ends', 'crash': 'dies', 'allocate': 'exhausts its memory',
                           'answer-none': 'exits 0 having written NOTHING',
                           'answer-half': 'exits 0 having written HALF of its answer frame',
                           'answer-extra': 'exits 0 having written a whole frame FOLLOWED BY EXTRA BYTES',
                           'answer-wrong-file': 'exits 0 with a well-formed answer about ANOTHER FILE (other hash)'}[kind],
                          b.get('verdict'), reason.get('reason'), job.get('end'), neighbours, code))

        for shape, shape_args in SHAPES:
            fault_case(shape, shape_args, 'spin', ['time limit'], 5, 600)
            # (under a sanitizer build a crash may be an ordinary exit of the sanitizer's own)
            fault_case(shape, shape_args, 'crash', ['crashed', 'ended without an answer'], 60, 600)
            fault_case(shape, shape_args, 'allocate', ['memory limit'], 300, 1200)
            # "Exit code 0 with an answer that is not exactly one whole frame about the handed-over
            # file" is a failed worker (reviewer, B-3631): each form has its own case.
            fault_case(shape, shape_args, 'answer-none', ['the answer is cut short (0 bytes received'], 60, 600)
            fault_case(shape, shape_args, 'answer-half', ['the answer is cut short ('], 60, 600)
            fault_case(shape, shape_args, 'answer-extra', ['bytes follow the answer'], 60, 600)
            fault_case(shape, shape_args, 'answer-wrong-file', ['the file changed during the scan'], 60, 600)

            # SB-2: a worker that MOVES the shared read position and then answers normally
            # changes nothing.
            table = os.path.join(tmp, 'move-position-%s.jsonl' % shape)
            move_log = os.path.join(tmp, 'move-position-%s.log.jsonl' % shape)
            code, out, err = worker_run(WORKER_HOOKS, small, table, common,
                                        ['--log', move_log, '--wall', '120', '--test-fault', 'b.txt=move-position'],
                                        shape=shape_args)
            got = by_path(records(table))
            job = by_path(jobs_of(move_log)).get('b.txt', {})
            said = job.get('detail', '')
            check(code == 0 and got == base and job.get('answered') is True and 'moved the shared read position' in said,
                  'B%s (SB-2): a worker that moves the shared read position of the handed-over file changes nothing: '
                  'results as without it: %s; b.txt answered: %s; the worker says: %r' % (
                      shape, got == base, job.get('answered'), said[-200:]))

            # A file that CHANGES while it is scanned / is REPLACED by rename. The test-hooks
            # worker pauses 3 seconds before its first read; the test waits for the runner's
            # "start" line of b.txt, then 0.7 s, then acts.
            def during_scan(label, action):
                folder = os.path.join(tmp, 'changing-%s-%s' % (shape, label))
                os.mkdir(folder)
                for name in ('a.txt', 'b.txt', 'c.txt'):
                    shutil.copyfile(os.path.join(small, name), os.path.join(folder, name))
                table = os.path.join(tmp, 'changing-%s-%s.jsonl' % (shape, label))
                details = os.path.join(tmp, 'changing-%s-%s.details.jsonl' % (shape, label))
                change_log = os.path.join(tmp, 'changing-%s-%s.log.jsonl' % (shape, label))
                process = subprocess.Popen([RUNNER, '--worker', WORKER_HOOKS, '--corpus', folder, '--out', table,
                                            '--details', details, '--log', change_log, '--wall', '120',
                                            '--test-fault', 'b.txt=pause-before-read'] + common + list(shape_args),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                acted = 'the start line of b.txt never appeared'
                deadline = time.time() + 300
                while time.time() < deadline and process.poll() is None:
                    try:
                        begun = any(r.get('record') == 'start' and r.get('path') == 'b.txt' for r in records(change_log))
                    except ValueError:
                        begun = False  # a line half written
                    if begun:
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
                        by_path(jobs_of(change_log)), acted)

            def overwrite_in_place(path):
                size = os.path.getsize(path)
                with open(path, 'r+b') as f:
                    f.seek(size // 2)
                    f.write(b'CHANGED-DURING-THE-SCAN'[:max(1, size - size // 2)])
                    f.flush()
                    os.fsync(f.fileno())
                return 'overwrote bytes in the middle in place, size still %d: %s' % (size, os.path.getsize(path) == size)

            code, got, reasons, _, acted = during_scan('overwrite', overwrite_in_place)
            b, reason = got.get('b.txt', {}), reasons.get('b.txt', {})
            neighbours = got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt')
            check(code == 0 and not acted.startswith(('REFUSED', 'the start line')) and b.get('verdict') == NOT_FULLY and
                  b.get('score') == 0 and b.get('categories') == [] and reason.get('state') == 'not_fully_scanned' and
                  reason.get('reason', '').startswith('the file changed during the scan') and neighbours,
                  'B%s: a file CHANGED IN PLACE during the scan (%s): b.txt is %r, state %r, reason %r; neighbours as '
                  'before: %s; parent exit %d' % (shape, acted, b.get('verdict'), reason.get('state'),
                                                  reason.get('reason'), neighbours, code))

            def replace_by_rename(path):
                other = path + '.new'
                with open(other, 'w', encoding='ascii', newline='\n') as f:
                    f.write('quite another file with the same name\n' * 30)
                try:
                    os.replace(other, path)
                    return 'replaced by rename over the open file'
                except OSError as first:
                    os.rename(path, path + '.old')
                    os.rename(other, path)
                    return 'renamed the open original away and the new file in (rename over it was refused: %r)' % (first,)

            code, got, _, jobs_now, acted = during_scan('rename', replace_by_rename)
            b = got.get('b.txt', {})
            neighbours = got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt')
            original = base.get('b.txt', {})
            check(code == 0 and not acted.startswith(('REFUSED', 'the start line')) and
                  jobs_now.get('b.txt', {}).get('answered') is True and b.get('sha256') == original.get('sha256') and
                  b.get('verdict') == original.get('verdict') and b.get('score') == original.get('score') and neighbours,
                  'B%s: a file REPLACED BY RENAME during the scan (%s): the worker read the ORIGINAL through its handle: '
                  'result hash %s, the original\'s %s, verdict %r; neighbours as before; parent exit %d' % (
                      shape, acted, b.get('sha256'), original.get('sha256'), b.get('verdict'), code))

        # ---------------------------------------------------------------- part P (shape B only)
        pool_args = ['--pool', '2']

        def pool_case(label, extra, timeout=600):
            table = os.path.join(tmp, 'pool-%s.jsonl' % label)
            details = os.path.join(tmp, 'pool-%s.details.jsonl' % label)
            log = os.path.join(tmp, 'pool-%s.log.jsonl' % label)
            code, out, err = worker_run(WORKER_HOOKS, small, table, common,
                                        ['--details', details, '--log', log, '--wall', '120'] + extra,
                                        timeout=timeout, shape=pool_args)
            return code, by_path(records(table)), by_path(records(details)), by_path(jobs_of(log)), pool_events(log), err

        # Condition 3: one file per worker.
        code, got, _, jobs, events, err = pool_case('second', ['--test-second-hand-over'])
        seconds = {p: j.get('second_hand_over', '') for p, j in jobs.items()}
        check(code == 0 and got == base and len(seconds) == 3 and
              all('right after the first: refused' in s and 'after the answer: refused' in s for s in seconds.values()),
              'P (condition 3): a second hand-over to the same worker is refused, right after the first and after the '
              'answer; results unchanged: %s' % seconds)

        # A worker that dies while waiting is logged and replaced.
        code, got, _, jobs, events, err = pool_case('die-waiting', ['--test-die-waiting', '2'])
        died = [e for e in events if e.get('what') == 'died_waiting']
        check(code == 0 and got == base and len(died) >= 2,
              'P: two workers that died while waiting were logged (%d events: %s) and replaced; results unchanged' % (
                  len(died), [e.get('detail', '')[:120] for e in died]))

        # Waiting workers are replaced after their age (here 2 s, well above the time a worker
        # takes to become ready, also under a sanitizer build; the idle pause is 5 s).
        code, got, _, jobs, events, err = pool_case('age', ['--max-age', '2', '--idle-before-first', '5'])
        old = [e for e in events if e.get('what') == 'too_old']
        check(code == 0 and got == base and len(old) >= 1 and all(j.get('answered') for j in jobs.values()),
              'P: waiting workers older than the age limit were replaced (%d too_old events); results unchanged' % len(old))

        # Condition 5: a configuration change ends the waiting workers; later files are served by
        # workers of the new configuration.
        code, got, _, jobs, events, err = pool_case('reload', ['--reload-after', 'a.txt'])
        changed = [e for e in events if e.get('what') == 'config_changed']
        ended = [int(e.get('detail', '0').rsplit(' ', 1)[-1]) for e in changed if e.get('detail', '')[-1:].isdigit()]
        gens = {p: j.get('worker_generation') for p, j in jobs.items()}
        check(code == 0 and got == base and changed and sum(ended) >= 1 and gens.get('a.txt') == 1 and
              gens.get('b.txt') == 2 and gens.get('c.txt') == 2,
              'P (condition 5): after a configuration change %d waiting worker(s) were ended and the later files were '
              'served by the new generation: %s; results unchanged' % (sum(ended), gens))

        # Condition 5: an answer from another configuration is discarded and scanned again ONCE.
        code, got, reasons, jobs, events, err = pool_case('mismatch-once', ['--test-fault', 'b.txt=rules-mismatch-once'])
        b_job = jobs.get('b.txt', {})
        check(code == 0 and got == base and b_job.get('attempts') == 2 and
              any(e.get('what') == 'config_mismatch' for e in events),
              'P (condition 5): an answer claiming other rules was discarded and the file scanned again by a fresh '
              'worker: attempts %r, result as without it: %s' % (b_job.get('attempts'), got == base))
        code, got, reasons, jobs, events, err = pool_case('mismatch-twice', ['--test-fault', 'b.txt=rules-mismatch'])
        b, reason = got.get('b.txt', {}), reasons.get('b.txt', {})
        check(code == 0 and b.get('verdict') == NOT_FULLY and reason.get('state') == 'not_fully_scanned' and
              'not from the current configuration twice' in reason.get('reason', '') and
              got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt') and
              jobs.get('b.txt', {}).get('attempts') == 2,
              'P (condition 5): a second answer from another configuration: b.txt %r, reason %r' % (
                  b.get('verdict'), reason.get('reason')))

        # Condition 6: when no worker can be had the file is NOT SCANNED, never clean. Workers 1
        # and 2 become ready; every worker from the 3rd on dies while waiting.
        code, got, reasons, jobs, events, err = pool_case('no-worker', ['--test-die-waiting-from', '3'])
        c = got.get('c.txt', {})
        check(code == 0 and got.get('a.txt') == base.get('a.txt') and got.get('b.txt') == base.get('b.txt') and
              c.get('verdict') is None and c.get('score') is None and
              str(c.get('error', '')).startswith('NOT SCANNED: no worker could be had'),
              'P (condition 6): with no worker to be had, c.txt is %r (error %r), never clean; a.txt and b.txt as '
              'before' % (c.get('verdict'), c.get('error')))

        # ---------------------------------------------------------------- part C (both shapes)
        for shape, shape_args in SHAPES:
            table = os.path.join(tmp, 'shipped-fault-%s.jsonl' % shape)
            details = os.path.join(tmp, 'shipped-fault-%s.details.jsonl' % shape)
            code, out, err = worker_run(WORKER, small, table, common,
                                        ['--details', details, '--wall', '120', '--test-fault', 'b.txt=crash'],
                                        shape=shape_args)
            got = by_path(records(table))
            reason = by_path(records(details)).get('b.txt', {}).get('reason', '')
            check(code == 0 and got.get('b.txt', {}).get('verdict') == NOT_FULLY and 'test switch' in reason and
                  got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'),
                  'C%s: the shipped worker refuses a job that carries a test switch: b.txt %r, reason %r' % (
                      shape, got.get('b.txt', {}).get('verdict'), reason))

        # ---------------------------------------------------------------- part D
        environment = {k: v for k, v in os.environ.items() if k != 'MIE_SANDBOX'}
        by_hand = subprocess.run([WORKER], input=b'', capture_output=True, timeout=120, env=environment)
        check(by_hand.returncode == 43 and by_hand.stdout == b'' and b'not started confined' in by_hand.stderr,
              'D: the shipped worker started by hand, without confinement, refuses: exit %d, no answer, says %r' % (
                  by_hand.returncode, by_hand.stderr.decode('ascii', 'replace').strip()[-200:]))
        by_hand = subprocess.run([WORKER, '--prestarted'], input=b'', capture_output=True, timeout=120, env=environment)
        check(by_hand.returncode == 43 and by_hand.stdout == b'' and b'must be started confined' in by_hand.stderr,
              'D: the shipped worker started by hand as a pre-started worker, without confinement, refuses: exit %d, %r' % (
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
        jobs = jobs_of(weak_log)
        says = sorted({j.get('worker_confinement', '') for j in jobs})
        check(code == 0 and got == base and len(jobs) == 3 and all(s.startswith('WEAKER') for s in says),
              'D: the test-hooks worker started unconfined on purpose gives the same three results and SAYS so: %s' % says)
        code, out, err = worker_run(WORKER_HOOKS, small, table, common, ['--unconfined'], shape=pool_args)
        check(code == 2, 'D: pre-started workers are never started unconfined (mie-worker-run refuses: exit %d)' % code)

        # ---------------------------------------------------------------- part T: A-8 figures
        sanitized = any(r.get('sanitizer_build') for r in records(logs['A']) if r.get('record') == 'describe')
        label = 'measured on this CI runner%s' % (
            ' (SANITIZER BUILD of the C++ side: its times are not the product\'s)' if sanitized else '')
        reference = {r['path']: r['seconds'] * 1000.0 for r in records(reference_times) if 'seconds' in r and 'path' in r}
        engine_built = [r['seconds'] for r in records(reference_times) if r.get('record') == 'engine_built']
        unconfined = {r['path']: r.get('total_ms', 0.0) for r in records(direct_times)}

        print('\n===== A-8 figures, milliseconds per file, %s; generated files, not the corpus =====' % label)
        # (a) one file after idle, the pool full.
        idle_dir = os.path.join(tmp, 'idle')
        os.mkdir(idle_dir)
        shutil.copyfile(os.path.join(small, 'a.txt'), os.path.join(idle_dir, 'a.txt'))
        idle_figures = {}
        for shape, shape_args in SHAPES:
            idle_log = os.path.join(tmp, 'idle-%s.log.jsonl' % shape)
            extra = ['--log', idle_log] + (['--idle-before-first', '3'] if shape == 'B' else [])
            code, out, err = worker_run(WORKER, idle_dir, os.path.join(tmp, 'idle-%s.jsonl' % shape), common, extra,
                                        shape=shape_args)
            job = by_path(jobs_of(idle_log)).get('a.txt', {})
            idle_figures[shape] = job.get('total_ms')
            if shape == 'B':
                idle_figures['B from the hand-over'] = job.get('from_hand_over_ms')
                print_breakdown([job] if job else [], indent='  (a) ')
                idle_record = [r for r in records(idle_log) if r.get('record') == 'idle']
                print('  (a) pool before the file: %s' % (json.dumps(idle_record[0], sort_keys=True) if idle_record else
                                                          'NOT MEASURED'))
        print('  (a) ONE FILE AFTER IDLE (3 s, pool of 2 full, nothing else running; default order: result delivered, '
              'worker retired, replacement started): shape B %s ms from when the parent '
              'got the file, %s ms from the start of the hand-over; shape A (a worker started for it: the price of an '
              'empty pool) %s ms' % (idle_figures.get('B'), idle_figures.get('B from the hand-over'), idle_figures.get('A')))
        # The other order: the replacement started right after the hand-over, while the file is
        # scanned (shows whether a starting worker slows the one that scans). The figure above is
        # the default order: result delivered, used worker retired, then the replacement started.
        busy_log = os.path.join(tmp, 'idle-B-during.log.jsonl')
        worker_run(WORKER, idle_dir, os.path.join(tmp, 'idle-B-during.jsonl'), common,
                   ['--log', busy_log, '--idle-before-first', '3', '--refill-during-scan'], shape=('--pool', '2'))
        busy = by_path(jobs_of(busy_log)).get('a.txt', {})
        print('  (a) shape B with the replacement started DURING the scan: %s ms from when the parent got the '
              'file, %s ms from the start of the hand-over' % (busy.get('total_ms'), busy.get('from_hand_over_ms')))
        print_breakdown([busy] if busy else [], indent='  (a) ')
        if LINUX:
            idle_ref_times = os.path.join(tmp, 'idle-reference.times.jsonl')
            run_reference(idle_dir, os.path.join(tmp, 'idle-reference.jsonl'), idle_ref_times, reputation_file)
            idle_ref = [r['seconds'] * 1000.0 for r in records(idle_ref_times) if 'path' in r]
            print('  (a) the Python reference on the same file (engine built before): %s ms' % (
                '%.1f' % idle_ref[0] if idle_ref else 'NOT MEASURED'))

        # (b) set S.
        def figures(name, per_file, total_wall=None):
            line = '  %-58s %s' % (name, spread(list(per_file.values())))
            line += '; total %.3f s' % (sum(per_file.values()) / 1000.0)
            if total_wall is not None:
                line += ' (whole run %.3f s)' % total_wall
            print(line, flush=True)

        print('  (b) SET S, %d files:' % len(by_path(records(direct)) or {}))
        shape_ms = {}
        for shape in ('A', 'B'):
            shape_ms[shape] = {j['path']: j.get('total_ms', 0.0) for j in jobs_of(logs[shape]) if j.get('answered')}
            figures('C++ shape %s, total in the parent per file' % shape, shape_ms[shape], walls[shape])
            if shape == 'B':
                waits = [j.get('wait_ready_ms', 0.0) for j in jobs_of(logs[shape]) if j.get('answered')]
                refills = [j.get('refill_ms', 0.0) for j in jobs_of(logs[shape]) if j.get('answered')]
                print('      of which waiting for a ready worker: %s; starting replacements: %s' % (
                    spread(waits), spread(refills)))
                print('      (back-to-back files drain a pool of 2: these figures measure how fast workers can be '
                      'started and prepared; figure (a) is the case the pool is for)')
                print_breakdown([j for j in jobs_of(logs[shape]) if j.get('answered')])
        figures('C++ unconfined test runner, Engine::scan_file', unconfined, direct_wall)
        if reference:
            figures('Python reference, Engine.scan_file (engine built once: %s s)' % (
                '%.3f' % engine_built[0] if engine_built else '?'), reference)
            for shape in ('A', 'B'):
                paths = sorted(set(reference) & set(shape_ms[shape]))
                ref = [reference[p] for p in paths]
                cpp = [shape_ms[shape][p] for p in paths]
                if paths:
                    print('A-8 on set S, shape %s: confined C++ %s slower than the reference at the median (%.1f against '
                          '%.1f); %s slower at the 95th percentile (%.1f against %.1f). (Numbers only; %s.)' % (
                              shape, 'IS' if at(cpp, 0.5) > at(ref, 0.5) else 'is not', at(cpp, 0.5), at(ref, 0.5),
                              'IS' if at(cpp, 0.95) > at(ref, 0.95) else 'is not', at(cpp, 0.95), at(ref, 0.95), label))
        else:
            print('  the Python reference on set S: NOT MEASURED here (run on Linux only)')

        # (c) a burst of 210 small files: copies of set S's small files, each with a different
        # last line (harmless; generated here).
        burst = os.path.join(tmp, 'burst')
        os.mkdir(burst)
        small_sources = sorted(p for p in os.listdir(files)
                               if os.path.isfile(os.path.join(files, p)) and os.path.getsize(os.path.join(files, p)) <= 256 * 1024)
        for i in range(210):
            source = small_sources[i % len(small_sources)]
            with open(os.path.join(files, source), 'rb') as f:
                data = f.read()
            with open(os.path.join(burst, 'burst-%03d-%s' % (i, source)), 'wb') as f:
                f.write(data + b'\n# copy %d\n' % i)
        burst_direct = os.path.join(tmp, 'burst-direct.jsonl')
        burst_direct_times = os.path.join(tmp, 'burst-direct.times.jsonl')
        started = time.perf_counter()
        run([PARITY_RUNNER, '--corpus', burst, '--out', burst_direct, '--times', burst_direct_times] + common)
        burst_direct_wall = time.perf_counter() - started
        print('  (c) A BURST OF %d small files:' % len(os.listdir(burst)))
        for shape, shape_args in SHAPES:
            burst_table = os.path.join(tmp, 'burst-%s.jsonl' % shape)
            burst_log = os.path.join(tmp, 'burst-%s.log.jsonl' % shape)
            started = time.perf_counter()
            code, out, err = worker_run(WORKER, burst, burst_table, common, ['--log', burst_log], shape=shape_args)
            wall = time.perf_counter() - started
            per_file = {j['path']: j.get('total_ms', 0.0) for j in jobs_of(burst_log) if j.get('answered')}
            figures('C++ shape %s, total in the parent per file' % shape, per_file, wall)
            if shape == 'B':
                waits = [j.get('wait_ready_ms', 0.0) for j in jobs_of(burst_log) if j.get('answered')]
                refills = [j.get('refill_ms', 0.0) for j in jobs_of(burst_log) if j.get('answered')]
                print('      of which waiting for a ready worker: %s; starting replacements: %s (an empty pool costs '
                      'shape A\'s price; preparations are written between files, so they are in the whole-run time, '
                      'not in the per-file totals)' % (spread(waits), spread(refills)))
                print_breakdown([j for j in jobs_of(burst_log) if j.get('answered')])
            code, out, err = run([PY, os.path.join(PARITY, 'compare.py'), '--identical', burst_direct, burst_table])
            check(code == 0, 'T: the burst table of shape %s is identical to the unconfined runner\'s' % shape)
        figures('C++ unconfined test runner, Engine::scan_file',
                {r['path']: r.get('total_ms', 0.0) for r in records(burst_direct_times)}, burst_direct_wall)
        if LINUX:
            burst_ref_times = os.path.join(tmp, 'burst-reference.times.jsonl')
            run_reference(burst, os.path.join(tmp, 'burst-reference.jsonl'), burst_ref_times, reputation_file)
            figures('Python reference, Engine.scan_file',
                    {r['path']: r['seconds'] * 1000.0 for r in records(burst_ref_times) if 'path' in r})
        print('===== end of the A-8 figures (printed, never asserted) =====\n', flush=True)

    print('worker_cases: %d passed, %d failed' % (RESULTS['passed'], RESULTS['failed']), flush=True)
    return 0 if RESULTS['failed'] == 0 and RESULTS['passed'] > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
