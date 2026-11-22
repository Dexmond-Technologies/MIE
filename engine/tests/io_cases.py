#!/usr/bin/env python3
"""CI test: the safe open accepts regular files and refuses everything else.

Usage: io_cases.py <path to mie-probe>

Covers review finding S-10: links, junctions, directories, pipes and devices must be
refused before anything is read; a missing file must be reported as missing.
Each case prints one line; the script exits 1 if any case fails.
Cases the platform cannot build (for example no right to create a link) are printed
as NOT RUN with the reason, and counted; they are never counted as passed.
"""
import json
import os
import subprocess
import sys
import tempfile

PROBE = sys.argv[1]
failures = []
not_run = []
passed = 0


def probe(path):
    out = subprocess.run([PROBE, 'file', path], capture_output=True, timeout=60)
    text = out.stdout.decode('utf-8', 'replace').strip()
    try:
        return json.loads(text)
    except ValueError:
        return {'state': 'no-json', 'stdout': text, 'stderr': out.stderr.decode('utf-8', 'replace'),
                'returncode': out.returncode}


def expect(name, path, state, code=None):
    global passed
    got = probe(path)
    ok = got.get('state') == state and (code is None or got.get('code') in code)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: expected {state} {sorted(code) if code else ''} got {got}")
    if ok:
        passed += 1
    else:
        failures.append(name)


def skip(name, reason):
    print(f'NOT RUN  {name}: {reason}')
    not_run.append(name)


with tempfile.TemporaryDirectory(prefix='mie-io-') as tmp:
    regular = os.path.join(tmp, 'regular.bin')
    with open(regular, 'wb') as f:
        f.write(b'hello world\n' * 100)
    empty = os.path.join(tmp, 'empty.bin')
    open(empty, 'wb').close()
    folder = os.path.join(tmp, 'folder')
    os.mkdir(folder)

    expect('regular file is accepted', regular, 'ok')
    got = probe(regular)
    if got.get('size') != 1200:
        print(f'FAIL  regular file size: expected 1200 got {got.get("size")}')
        failures.append('regular file size')
    else:
        passed += 1
        print('PASS  regular file size is 1200')
    expect('empty file is accepted', empty, 'ok')
    expect('missing file is refused as not found', os.path.join(tmp, 'nothing-here'), 'refused', {'not_found'})
    expect('directory is refused', folder, 'refused', {'not_regular'})

    # symbolic link to a regular file
    link = os.path.join(tmp, 'link-to-regular')
    try:
        os.symlink(regular, link)
    except (OSError, NotImplementedError) as e:
        skip('symbolic link to a file is refused', f'cannot create a symbolic link here: {e}')
    else:
        expect('symbolic link to a file is refused', link, 'refused', {'link'})

    # dangling symbolic link
    dangling = os.path.join(tmp, 'dangling-link')
    try:
        os.symlink(os.path.join(tmp, 'no-target'), dangling)
    except (OSError, NotImplementedError) as e:
        skip('dangling symbolic link is refused', f'cannot create a symbolic link here: {e}')
    else:
        expect('dangling symbolic link is refused', dangling, 'refused', {'link'})

    # symbolic link to a directory
    dirlink = os.path.join(tmp, 'link-to-folder')
    try:
        os.symlink(folder, dirlink, target_is_directory=True)
    except (OSError, NotImplementedError) as e:
        skip('symbolic link to a directory is refused', f'cannot create a symbolic link here: {e}')
    else:
        expect('symbolic link to a directory is refused', dirlink, 'refused', {'link'})

    if os.name == 'nt':
        # junction (a directory link that needs no special right)
        junction = os.path.join(tmp, 'junction')
        made = subprocess.run(['cmd', '/c', 'mklink', '/J', junction, folder], capture_output=True)
        if made.returncode != 0:
            skip('junction is refused', 'mklink /J failed: ' + made.stderr.decode('utf-8', 'replace').strip())
        else:
            expect('junction is refused', junction, 'refused', {'link'})
        # device names
        expect('device name NUL is refused', 'NUL', 'refused', {'not_regular', 'not_found', 'access_denied', 'other'})
        expect('device name CON is refused', 'CON', 'refused', {'not_regular', 'not_found', 'access_denied', 'other'})
        expect('device path \\\\.\\NUL is refused', '\\\\.\\NUL', 'refused',
               {'not_regular', 'not_found', 'access_denied', 'other'})
    else:
        # named pipe: opening it must neither hang nor succeed
        fifo = os.path.join(tmp, 'pipe')
        os.mkfifo(fifo)
        expect('named pipe is refused', fifo, 'refused', {'not_regular'})
        expect('character device /dev/null is refused', '/dev/null', 'refused', {'not_regular'})
        expect('character device /dev/zero is refused', '/dev/zero', 'refused', {'not_regular'})
        # Unix socket file
        import socket
        sock_path = os.path.join(tmp, 's.sock')
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(sock_path)
            expect('socket file is refused', sock_path, 'refused', {'not_regular'})
        finally:
            s.close()
        # a link in the middle of the path is allowed (only the final name must not be a link);
        # recorded here so the behaviour is a decision, not an accident
        via = os.path.join(tmp, 'link-to-folder')
        if os.path.islink(via):
            inner = os.path.join(folder, 'inner.bin')
            with open(inner, 'wb') as f:
                f.write(b'x')
            expect('file reached through a linked folder is accepted (final name is not a link)',
                   os.path.join(via, 'inner.bin'), 'ok')

print(f'io_cases: {passed} passed, {len(failures)} failed, {len(not_run)} not run')
sys.exit(1 if failures else 0)
