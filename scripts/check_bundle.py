#!/usr/bin/env python3
'''Static check of a PyInstaller one-folder build of MIE (dist/DexmondMIE).

It does not run the program (the exe is a windowed app). It checks that the
bundle holds what the engine needs at run time and nothing it must not:
  - DexmondMIE.exe exists and is not UPX-packed (MIE flags UPX itself);
  - every live rule file rules/*.yar is bundled byte-equal, and no
    rules/proposed/ or rules/auto_generated.yar (F1);
  - data/reputation.json and config/trusted_publishers.json are bundled;
  - trust/authenticode_roots.pem is bundled and its SHA-256 equals
    PINNED_ROOTS_SHA256 in dexmond_mie/signature.py (otherwise X12 reports
    'unavailable' inside the exe and no signature is ever honoured).

Usage: python scripts/check_bundle.py dist/DexmondMIE
Exit 0 = all checks passed; 1 = a check failed (each failure is printed).
'''
import glob
import hashlib
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def pinned_roots_sha256(repo=REPO):
    with open(os.path.join(repo, 'dexmond_mie', 'signature.py'), encoding='utf-8') as f:
        found = re.findall(r'^PINNED_ROOTS_SHA256 = "([0-9a-f]{64})"', f.read(), re.M)
    return found[0] if len(found) == 1 else None


def resource_root(bundle):
    '''PyInstaller 6 puts data files under _internal/ next to the exe.'''
    internal = os.path.join(bundle, '_internal')
    return internal if os.path.isdir(internal) else bundle


def check_bundle(bundle, repo=REPO):
    problems = []
    exe = os.path.join(bundle, 'DexmondMIE.exe')
    if not os.path.isfile(exe):
        problems.append(f'missing {exe}')
    else:
        with open(exe, 'rb') as f:
            head = f.read(4096)
        if b'UPX0' in head or b'UPX1' in head:
            problems.append('DexmondMIE.exe is UPX-packed (upx must stay off in the spec)')
    root = resource_root(bundle)
    live = sorted(p for p in glob.glob(os.path.join(repo, 'rules', '*.yar'))
                  if os.path.basename(p) != 'auto_generated.yar')
    if not live:
        problems.append('no rules/*.yar in the source tree')
    for src in live:
        dst = os.path.join(root, 'rules', os.path.basename(src))
        if not os.path.isfile(dst):
            problems.append(f'rule file not bundled: rules/{os.path.basename(src)}')
        elif sha256_file(dst) != sha256_file(src):
            problems.append(f'bundled rule file differs from source: rules/{os.path.basename(src)}')
    if os.path.exists(os.path.join(root, 'rules', 'proposed')):
        problems.append('rules/proposed/ is bundled (proposals must never ship as live rules)')
    if os.path.exists(os.path.join(root, 'rules', 'auto_generated.yar')):
        problems.append('rules/auto_generated.yar is bundled')
    for rel in ('data/reputation.json', 'config/trusted_publishers.json'):
        if not os.path.isfile(os.path.join(root, *rel.split('/'))):
            problems.append(f'missing {rel}')
    pem = os.path.join(root, 'trust', 'authenticode_roots.pem')
    pinned = pinned_roots_sha256(repo)
    if not os.path.isfile(pem):
        problems.append('missing trust/authenticode_roots.pem')
    elif pinned is None:
        problems.append('PINNED_ROOTS_SHA256 is not set in dexmond_mie/signature.py')
    elif sha256_file(pem) != pinned:
        problems.append(f'bundled trust/authenticode_roots.pem sha256 {sha256_file(pem)} '
                        f'!= PINNED_ROOTS_SHA256 {pinned} (line endings changed?)')
    return problems


def main(argv):
    if len(argv) != 2:
        print('Usage: python scripts/check_bundle.py dist/DexmondMIE', file=sys.stderr)
        return 2
    problems = check_bundle(argv[1])
    for p in problems:
        print(f'BUNDLE CHECK FAILED: {p}', file=sys.stderr)
    if not problems:
        print(f'Bundle check passed: {argv[1]}')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
