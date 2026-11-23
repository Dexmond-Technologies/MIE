#!/usr/bin/env python3
"""CI test: the C++ string indicators equal the Python reference's, on generated cases.

Usage: strings_parity.py <path to mie-probe> <repository root>

Reference side: dexmond_mie.utils.StringExtractor.extract_ascii_unicode(data, 5) and, for the
cases with import-name spans, dexmond_mie.core._api_names_outside_spans (read from the source
file and executed on its own, so the engine's other imports are not needed).
C++ side: `mie-probe strings <dir>`.

Compared per case: whether each of the four SCORED indicators is present (powershell,
suspicious_api, b64_executable, obfuscated_script) and the number of strings. The reference's
other patterns are report-only and are not compared.

Cases (all harmless bytes built here): every token of the patterns with neighbours that must
and must not match, in ASCII and in UTF-16LE at even and odd offsets; case variants; tokens
split by a non-printable byte; runs just below and at the minimum length; a fixed-seed random
part that mixes tokens, separators and noise; and the files of set S below 32 MiB.
"""
import json
import os
import random
import re
import subprocess
import sys
import tempfile

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
from dexmond_mie.utils import StringExtractor  # noqa: E402  (standard library only)

KEYS = ('powershell', 'suspicious_api', 'b64_executable', 'obfuscated_script')


def reference_outside_spans():
    """The reference's _api_names_outside_spans, taken from core.py without importing the engine."""
    with open(os.path.join(REPO, 'dexmond_mie', 'core.py'), encoding='utf-8') as f:
        source = f.read()
    start = source.index('def _api_names_outside_spans(')
    end = source.index('\ndef ', start + 10)
    namespace = {'re': re, 'StringExtractor': StringExtractor}
    exec(compile(source[start:end], 'core.py:_api_names_outside_spans', 'exec'), namespace)  # reference code, read-only
    return namespace['_api_names_outside_spans']


def reference(data, spans):
    strings, iocs = StringExtractor.extract_ascii_unicode(data, 5)
    if spans and 'suspicious_api' in iocs:
        outside = OUTSIDE(data, set(spans))
        if not outside:
            del iocs['suspicious_api']
    out = {k: (k in iocs) for k in KEYS}
    out['string_count'] = len(strings)
    return out


def build_cases():
    rng = random.Random(20261123)
    cases = []

    def add(data, spans=()):
        cases.append((bytes(data), tuple(spans)))

    def both(text):
        raw = text.encode('ascii')
        add(raw)
        add(text.encode('utf-16le'))
        add(b'\x01' + text.encode('utf-16le'))          # odd offset
        add(b'\x00\x01\x02' + raw + b'\x00\xff')
        add(raw + b'\x00' + raw)                          # two runs

    enc_words = ['enc'] + ['enc' + 'odedcommand'[:k] for k in range(1, 12)] + ['encodedcommandx', 'encrypt',
                                                                              'encoding', 'encx', 'en', 'ENC', 'EncodedCommand']
    for word in enc_words:
        for dashes in ('-', '--', '---', ''):
            for before in ('', ' ', 'a', '_', '-', '/', '"', '9', '.'):
                for after in ('', ' ', 'a', '_', '-', '1', '"', '=', ':'):
                    both(f'cmd {before}{dashes}{word}{after} tail')
                    both(f'{before}{dashes}{word}{after}')
    for token in ('powershell', 'PowerShell.exe', 'pwsh', 'PWSH.EXE', 'xpowershellx', 'power shell', 'pws', 'powershel',
                  'VirtualAlloc', 'virtualallocex', 'CreateRemoteThread', 'WriteProcessMemory', 'LdrLoadDll',
                  'ReflectiveLoader', 'REFLECTIVELOADER', 'Virtual Alloc', 'VirtualAllo',
                  'TVqQAAMAAAA4A', 'TVqQAAMAAAA4AA', 'TVqQAAMAAAA4A=', 'TVqQAAMAAAA4A!', 'tvqqaamaaaa4aa', 'TVqQAAMAAAA4',
                  'xxTVqQAAMAAAA4A+/', 'TVqQAAMAAAAEAAAA',
                  '[char[]]', '[CHAR[]]', '[char[] ]', 'Invoke-Expression', 'invoke-expression', 'Invoke_Expression',
                  'iex(', 'iex (', 'IEX   (', 'iex', 'iex x(', 'iexx(', 'FromBase64String', 'frombase64string',
                  'FromBase64Strin', 'Bypass -noprofile', 'bypass   -NoProfile', 'Bypass-noprofile', 'Bypass -noprofil',
                  'bypass  -noprofilex'):
        for pad in ('', 'abcde ', ' abcde', '12345'):
            both(pad + token)
            both(token + pad)
        both(token)
    # minimum run length and runs split by non-printable bytes
    for n in range(0, 12):
        add(b'iex(' [:n] + b'\x00')
        add(b'pwsh'[:n])
        add((b'pwsh' + b'A' * 8)[:n])
        add(b'\x7f' + (b'x' * n) + b'\x7f')
        add(('x' * n).encode('utf-16le'))
    add(b'power\x01shell')
    add(b'pw\x7fsh pwsh')
    add('iex ('.encode('utf-16le') + b'\x41')            # trailing odd byte
    add(b'A\x00B\x00C\x00D\x00' + b'pwsh')               # four pairs then ASCII
    add(b'A\x00B\x00C\x00D\x00E\x00pwsh')
    add(b'\x00' * 64)
    add(b'')
    add(bytes(range(256)) * 4)
    # spans: suspicious_api only inside a run that is exactly a skipped span
    base = b'\x00\x00VirtualAllocEx\x00\x00WriteProcessMemory\x00rest of file\x00'
    a0 = base.index(b'VirtualAllocEx'); a1 = a0 + len(b'VirtualAllocEx')
    b0 = base.index(b'WriteProcessMemory'); b1 = b0 + len(b'WriteProcessMemory')
    add(base)
    add(base, [(a0, a1)])
    add(base, [(a0, a1), (b0, b1)])
    add(base, [(a0, a1 - 1), (b0, b1)])                   # not exactly the run: does not skip
    add(base, [(a0 + 1, a1), (b0, b1)])
    add(base + 'VirtualAlloc'.encode('utf-16le'), [(a0, a1), (b0, b1)])   # UTF-16 runs are never skipped
    add(b'xxVirtualAllocEx', [(2, 16)])                   # span inside a longer run: does not skip
    add(b'\x01VirtualAllocEx\x01', [(1, 15)])
    add(b'\x01VirtualAllocEx\x01plain text only', [(1, 15)])
    # fixed-seed random mixtures
    tokens = ['powershell', 'pwsh', '-enc', '--EncodedCommand', '-encod', '-encx', 'Content-Encoding', 'VirtualAlloc',
              'ReflectiveLoader', 'TVqQAAMAAAA4AAAA', 'TVqQAAMAAAA4', '[char[]]', 'iex (', 'iex', 'FromBase64String',
              'Bypass  -noprofile', 'Bypass', 'hello', 'world', ' ', '-', '_', '=', 'a', 'Z', '0']
    separators = [b'', b' ', b'\x00', b'\x01', b'\n', b'\xff', b'\x7f']
    for _ in range(1500):
        parts = []
        for _ in range(rng.randint(1, 8)):
            token = rng.choice(tokens)
            form = rng.random()
            if form < 0.6:
                parts.append(token.encode('ascii'))
            elif form < 0.9:
                parts.append(token.encode('utf-16le'))
            else:
                parts.append(rng.randbytes(rng.randint(1, 12)))
            parts.append(rng.choice(separators))
        add(b''.join(parts))
    return cases


def main():
    cases = build_cases()
    failures = 0
    with tempfile.TemporaryDirectory(prefix='mie-strings-') as tmp:
        case_dir = os.path.join(tmp, 'cases')
        os.mkdir(case_dir)
        expected = {}
        for index, (data, spans) in enumerate(cases):
            name = f'c{index:06d}.bin'
            with open(os.path.join(case_dir, name), 'wb') as f:
                f.write(data)
            if spans:
                with open(os.path.join(case_dir, name + '.spans'), 'w', encoding='ascii') as f:
                    f.writelines(f'{a} {b}\n' for a, b in spans)
            expected[name] = (reference(data, spans), data, spans)

        made = subprocess.run([sys.executable, os.path.join(REPO, 'engine', 'tools', 'parity', 'make_set_s.py'),
                               '--out', os.path.join(tmp, 'set_s'), '--no-large'], capture_output=True, text=True)
        set_dir = os.path.join(tmp, 'set_s', 'files')
        if made.returncode != 0:
            print('FAIL  set S could not be generated:', made.stderr)
            return 1
        set_expected = {}
        for name in sorted(os.listdir(set_dir)):
            with open(os.path.join(set_dir, name), 'rb') as f:
                data = f.read()
            set_expected[name] = (reference(data, ()), data, ())

        for label, folder, wanted in (('generated cases', case_dir, expected), ('set S files', set_dir, set_expected)):
            out = subprocess.run([PROBE, 'strings', folder], capture_output=True, timeout=540)
            got = {}
            for line in out.stdout.decode('utf-8', 'replace').splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                got[record.pop('name')] = record
            different = 0
            for name, (want, data, spans) in wanted.items():
                if got.get(name) != want:
                    different += 1
                    if different <= 15:
                        print(f'FAIL  {name}: data {data[:80]!r} spans {spans}: reference {want}, C++ {got.get(name)}')
            hits = {k: sum(1 for want, _, _ in wanted.values() if want[k]) for k in KEYS}
            print(f'{label}: {len(wanted)} compared, {different} different; cases where the reference reports each '
                  f'indicator: {hits}')
            failures += different
    print(f'strings_parity: {failures} differences')
    return 1 if failures else 0


OUTSIDE = reference_outside_spans()

if __name__ == '__main__':
    sys.exit(main())
