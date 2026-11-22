#!/usr/bin/env python3
"""CI test: the C++ hashes and entropy figures equal the Python reference, exactly.

Usage: parity_primitives.py <path to mie-probe> <repository root>

For a set of generated files (harmless bytes from a fixed-seed generator) this compares
  - MD5, SHA-1, SHA-256 with Python's hashlib (what the reference uses),
  - whole-buffer entropy with dexmond_mie.utils.calculate_entropy,
  - sliding-window figures with dexmond_mie.utils.calculate_sliding_window_entropy.
Floating-point values must be equal bit for bit (the probe prints 17 significant digits).
The reference functions are imported from this checkout; they need only the standard library.
The Python version is printed, because the reference's average uses sum(), whose
floating-point behaviour changed in Python 3.12.
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

PROBE, REPO = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.abspath(REPO))
from dexmond_mie.utils import calculate_entropy, calculate_sliding_window_entropy  # noqa: E402

rng = random.Random(20261123)


def skewed(n, alphabet):
    return bytes(rng.choice(alphabet) for _ in range(n))


CASES = {
    'empty': b'',
    'one_byte': b'A',
    'zeros_4095': bytes(4095),
    'zeros_4096': bytes(4096),
    'zeros_4097': bytes(4097),
    'text': (b'The quick brown fox jumps over the lazy dog.\r\n' * 400),
    'random_100': rng.randbytes(100),
    'random_4096': rng.randbytes(4096),
    'random_6143': rng.randbytes(6143),
    'random_6144': rng.randbytes(6144),
    'random_64k': rng.randbytes(65536),
    'random_1m_plus_7': rng.randbytes(1024 * 1024 + 7),
    'skewed_small_alphabet': skewed(50000, b'abc'),
    'skewed_text_like': skewed(70000, b'etaoin shrdlu\n' * 3 + bytes(range(256))),
    'half_zero_half_random': bytes(30000) + rng.randbytes(30000),
    'pockets': b''.join(bytes(5000) + rng.randbytes(3000) for _ in range(12)),
    'all_values_repeated': bytes(range(256)) * 300,
    'two_values': b'\x00\xff' * 9999,
    'near_threshold': skewed(40000, bytes(range(150))),
    'near_threshold_2': skewed(40000, bytes(range(147))),
}


def exact(text):
    return float(text)


def main():
    print(f'Python {sys.version.split()[0]} on {sys.platform}')
    failures = 0
    compared = 0
    with tempfile.TemporaryDirectory(prefix='mie-parity-') as tmp:
        for name, data in CASES.items():
            path = os.path.join(tmp, name + '.bin')
            with open(path, 'wb') as f:
                f.write(data)
            out = subprocess.run([PROBE, 'file', path], capture_output=True, timeout=120)
            try:
                got = json.loads(out.stdout.decode('utf-8'))
            except ValueError:
                print(f'FAIL  {name}: probe printed no JSON: {out.stdout!r} {out.stderr!r}')
                failures += 1
                continue
            ref_sliding = calculate_sliding_window_entropy(data)
            want = {
                'state': 'ok',
                'size': len(data),
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(),
                'entropy': float(calculate_entropy(data)),
                'sliding.max': float(ref_sliding['max']),
                'sliding.min': float(ref_sliding['min']),
                'sliding.avg': float(ref_sliding['avg']),
                'sliding.high_entropy_windows': ref_sliding['high_entropy_windows'],
                'sliding.total_windows': ref_sliding['total_windows'],
            }
            sliding = got.get('sliding', {})
            have = {
                'state': got.get('state'),
                'size': got.get('size'),
                'md5': got.get('md5'),
                'sha1': got.get('sha1'),
                'sha256': got.get('sha256'),
                'entropy': exact(got['entropy']) if 'entropy' in got else None,
                'sliding.max': exact(sliding['max']) if 'max' in sliding else None,
                'sliding.min': exact(sliding['min']) if 'min' in sliding else None,
                'sliding.avg': exact(sliding['avg']) if 'avg' in sliding else None,
                'sliding.high_entropy_windows': sliding.get('high_entropy_windows'),
                'sliding.total_windows': sliding.get('total_windows'),
            }
            diffs = [f'{k}: reference {want[k]!r}, C++ {have[k]!r}' for k in want if want[k] != have[k]]
            compared += len(want)
            if diffs:
                failures += 1
                print(f'FAIL  {name} ({len(data)} bytes)')
                for d in diffs:
                    print('        ' + d)
            else:
                print(f'PASS  {name} ({len(data)} bytes): 3 hashes, entropy {want["entropy"]!r}, '
                      f'{want["sliding.total_windows"]} windows, {want["sliding.high_entropy_windows"]} high')
    print(f'parity_primitives: {len(CASES)} files, {compared} values compared, {failures} files differ')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
