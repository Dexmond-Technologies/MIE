#!/usr/bin/env python3
"""CI test: the service skeleton and the command line talk over the local channel.

Usage: service_smoke.py <path to mie-service> <path to mie>

Checks: the service starts and answers ping and status; an unknown operation is refused
by the command line; a second service on the same endpoint exits with code 3; shutdown
stops the service with exit code 0; afterwards the command line reports "not reachable"
(exit code 4); the service opened no TCP or UDP listening port (checked on Linux from
/proc, where the process's sockets can be listed without extra tools).
"""
import json
import os
import subprocess
import sys
import tempfile
import time

SERVICE, CLI = sys.argv[1], sys.argv[2]
failures = []


def check(name, condition, detail=''):
    print(f"{'PASS' if condition else 'FAIL'}  {name} {detail}")
    if not condition:
        failures.append(name)


def cli(endpoint, *args):
    out = subprocess.run([CLI, '--endpoint', endpoint, *args], capture_output=True, timeout=30)
    return out.returncode, out.stdout.decode('utf-8', 'replace').strip(), out.stderr.decode('utf-8', 'replace').strip()


def inet_sockets_of(pid):
    """Linux only: number of sockets of the process that are not Unix-domain sockets."""
    count = 0
    fd_dir = f'/proc/{pid}/fd'
    inodes = set()
    for fd in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[len('socket:['):-1])
    if not inodes:
        return 0
    # Unix-domain sockets are listed in /proc/net/unix with their inode in the last-but-one field.
    unix_inodes = set()
    with open('/proc/net/unix', encoding='utf-8') as f:
        next(f)
        for line in f:
            parts = line.split()
            if len(parts) >= 7:
                unix_inodes.add(parts[6])
    for inode in inodes:
        if inode not in unix_inodes:
            count += 1
    return count


with tempfile.TemporaryDirectory(prefix='mie-svc-') as tmp:
    if os.name == 'nt':
        endpoint = r'\\.\pipe\DexmondMIE.smoke.%d' % os.getpid()
    else:
        os.chmod(tmp, 0o700)
        endpoint = os.path.join(tmp, 'service.sock')

    code, _, err = cli(endpoint, 'ping')
    check('command line reports "not reachable" when no service runs', code == 4, f'(exit {code}: {err})')

    service = subprocess.Popen([SERVICE, '--endpoint', endpoint], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready = False
        for _ in range(100):
            code, out, err = cli(endpoint, 'ping')
            if code == 0:
                ready = True
                break
            if service.poll() is not None:
                break
            time.sleep(0.1)
        check('service starts and answers ping', ready, f'(last exit {code}: {out} {err})')

        if ready:
            body = json.loads(out)
            check('ping answer is ok with pong', body.get('ok') is True and body.get('pong') is True, f'({body})')

            code, out, err = cli(endpoint, 'status')
            status = json.loads(out) if code == 0 else {}
            check('status answers', code == 0, f'(exit {code}: {err})')
            check('status says the engine is absent (nothing is scanned yet)',
                  status.get('engine') == 'absent' and status.get('monitoring') is False and status.get('rules') == 'OFF',
                  f'({status})')
            check('status carries protocol 1 and result schema 1',
                  status.get('protocol') == 1 and status.get('result_schema') == 1, f'({status})')
            check('status carries the pid of the service', status.get('pid') == service.pid,
                  f'(status {status.get("pid")}, started {service.pid})')

            second = subprocess.run([SERVICE, '--endpoint', endpoint], capture_output=True, timeout=30)
            check('a second service on the same endpoint exits with code 3', second.returncode == 3,
                  f'(exit {second.returncode}: {second.stderr.decode("utf-8", "replace").strip()})')

            code, out, err = cli(endpoint, 'ping')
            check('the first service still answers after the second one was refused', code == 0, f'(exit {code}: {err})')

            if sys.platform.startswith('linux'):
                n = inet_sockets_of(service.pid)
                check('the service holds no socket other than Unix-domain sockets', n == 0, f'({n} found)')
            else:
                print('NOT RUN  no-TCP/UDP-socket check: only implemented for Linux in week 0')

            code, out, err = cli(endpoint, 'shutdown')
            check('shutdown is accepted', code == 0, f'(exit {code}: {out} {err})')
            try:
                exit_code = service.wait(timeout=15)
            except subprocess.TimeoutExpired:
                exit_code = None
            check('the service stops with exit code 0 after shutdown', exit_code == 0, f'(exit {exit_code})')

            code, _, err = cli(endpoint, 'ping')
            check('command line reports "not reachable" after shutdown', code == 4, f'(exit {code}: {err})')

            # the endpoint can be used again
            again = subprocess.Popen([SERVICE, '--endpoint', endpoint], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ok = False
                for _ in range(100):
                    code, out, err = cli(endpoint, 'ping')
                    if code == 0:
                        ok = True
                        break
                    if again.poll() is not None:
                        break
                    time.sleep(0.1)
                check('a new service can take the endpoint after the old one stopped', ok, f'(exit {code}: {err})')
                cli(endpoint, 'shutdown')
                again.wait(timeout=15)
            finally:
                if again.poll() is None:
                    again.kill()
    finally:
        if service.poll() is None:
            service.kill()
            service.wait(timeout=15)

    code = subprocess.run([CLI, '--endpoint', endpoint, 'bogus'], capture_output=True, timeout=30).returncode
    check('an unknown command-line operation is a usage error (exit 2)', code == 2, f'(exit {code})')

    # The channel name held by ANOTHER account: neither program may treat that as "running" or
    # as "not running"; both must say in plain words that MIE is not protecting this computer.
    # Built here by handing the socket directory to root, which needs sudo without a password
    # (present on the GitHub Ubuntu runner).
    HELD = 'not protected by MIE'
    if os.name == 'nt':
        print('NOT RUN  channel name held by another account: on Windows this needs a pipe created by '
              'another account, which this test cannot make; not written in week 0')
    else:
        held_dir = os.path.join(tmp, 'held')
        os.mkdir(held_dir, 0o700)
        took = subprocess.run(['sudo', '-n', 'chown', 'root:root', held_dir], capture_output=True)
        if took.returncode != 0:
            print('NOT RUN  channel name held by another account: no password-less sudo to hand the '
                  'directory to another account')
        else:
            try:
                held_endpoint = os.path.join(held_dir, 'service.sock')
                code, out, err = cli(held_endpoint, 'ping')
                check('command line: channel name held by another account gives exit 6 and the plain sentence',
                      code == 6 and HELD in err, f'(exit {code}: {err})')
                refused = subprocess.run([SERVICE, '--endpoint', held_endpoint], capture_output=True, timeout=30)
                refused_err = refused.stderr.decode('utf-8', 'replace').strip()
                check('service: channel name held by another account gives exit 5 and the plain sentence',
                      refused.returncode == 5 and HELD in refused_err,
                      f'(exit {refused.returncode}: {refused_err})')
            finally:
                subprocess.run(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', held_dir],
                               capture_output=True)

print(f'service_smoke: {len(failures)} failed')
sys.exit(1 if failures else 0)
