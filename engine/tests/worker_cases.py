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
import subprocess
import sys
import tempfile

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
        code, out, err = run([PARITY_RUNNER, '--corpus', files, '--out', direct, '--details', direct_details,
                              '--times', direct_times] + common)
        if code == 2:  # a runner without --times
            direct_times = ''
            code, out, err = run([PARITY_RUNNER, '--corpus', files, '--out', direct, '--details', direct_details] + common)
        print(out.strip(), flush=True)
        if code != 0:
            print('NOT RUN mie-parity-run failed (exit %d): %s' % (code, err.strip()[-800:]))
            return 1

        # The wall limit is raised for this part only: under a sanitizer build the large files
        # of the set take longer than the product's 60 seconds. The product's limit is tested
        # in part B.
        code, out, err = worker_run(WORKER, files, confined, common,
                                    ['--details', confined_details, '--log', log, '--wall', '900'])
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
                          {'spin': 'never ends', 'crash': 'dies', 'allocate': 'exhausts its memory'}[kind],
                          b.get('verdict'), reason.get('reason'), job.get('end'),
                          got.get('a.txt') == base.get('a.txt') and got.get('c.txt') == base.get('c.txt'), code))

        fault_case('spin', ['time limit'], 5, 600)
        # (under a sanitizer build a crash may be an ordinary exit of the sanitizer's own)
        fault_case('crash', ['crashed', 'ended without an answer'], 60, 600)
        fault_case('allocate', ['memory limit'], 300, 1200)

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
