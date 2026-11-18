#!/usr/bin/env python3
'''Release gate for the MIE licence key (same rules as the CypherNight
desktop's scripts/check-release-key.cjs).

A SALE build may embed one public key only: the production key. This script
reads dexmond_mie/licence_key.py AS TEXT (it imports nothing from the app)
and exits non-zero unless
    sha256(embedded public key) == PROD_PUBKEY_SHA256
and that fingerprint is not in NON_PRODUCTION_PUBKEY_SHA256.
The embedded key must be an ML-DSA-65 public key (1952 bytes).

Usage: python scripts/check_release_key.py [path to licence_key.py]
It reads public values only. It checks the source tree, not a built bundle:
build the sale build from this tree in the same run.
CI runs it on every Windows build; a build that fails it is a TEST BUILD,
and a run started with sale_build=true stops (.github/workflows/tests.yml).
'''
import base64
import binascii
import hashlib
import os
import re
import sys

KEY_MODULE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'dexmond_mie', 'licence_key.py')
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
FINGERPRINT = re.compile(r'^[0-9a-f]{64}$')


def fingerprint_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _one(source, pattern, name):
    found = re.findall(pattern, source, re.M)
    if len(found) != 1:
        raise ValueError(f'{name}: expected one declaration, found {len(found)}')
    return found[0]


def read_key_module(source: str):
    public_key_b64 = _one(source, r'^LICENSE_PUBLIC_KEY_B64 = "([^"]*)"\s*$', 'LICENSE_PUBLIC_KEY_B64')
    production = _one(source, r'^PROD_PUBKEY_SHA256 = "([^"]*)"\s*$', 'PROD_PUBKEY_SHA256')
    listed = _one(source, r'^NON_PRODUCTION_PUBKEY_SHA256 = \[([^\]]*)\]', 'NON_PRODUCTION_PUBKEY_SHA256')
    without_comments = re.sub(r'#[^\n]*', '', listed)
    blocklist = re.findall(r'"([^"]*)"', without_comments)
    if re.sub(r'[\s,]', '', re.sub(r'"[^"]*"', '', without_comments)):
        raise ValueError('NON_PRODUCTION_PUBKEY_SHA256: only quoted fingerprints are allowed')
    for entry in blocklist:
        if not FINGERPRINT.match(entry):
            raise ValueError(f'NON_PRODUCTION_PUBKEY_SHA256: not a fingerprint: {entry}')
    return public_key_b64, production, blocklist


def check_release_key(source: str) -> dict:
    '''{'ok', 'reason', 'fingerprint'}; ok is True only when every check passed.'''
    fp = None
    try:
        public_key_b64, production, blocklist = read_key_module(str(source))
        if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', public_key_b64):
            return {'ok': False, 'fingerprint': fp,
                    'reason': 'LICENSE_PUBLIC_KEY_B64 is empty or not base64: no licence key is embedded.'}
        key = base64.b64decode(public_key_b64, validate=True)
        if len(key) != ML_DSA_65_PUBLIC_KEY_BYTES or \
                base64.b64encode(key).decode('ascii') != public_key_b64:
            return {'ok': False, 'fingerprint': fp,
                    'reason': f'LICENSE_PUBLIC_KEY_B64 is not an ML-DSA-65 public key '
                              f'({len(key)} bytes, expected {ML_DSA_65_PUBLIC_KEY_BYTES}).'}
        fp = fingerprint_of(key)
        if fp in blocklist:
            return {'ok': False, 'fingerprint': fp,
                    'reason': f'The embedded licence key ({fp}) is a development or test key '
                              f'(NON_PRODUCTION_PUBKEY_SHA256). A sale build must embed the production key.'}
        if not FINGERPRINT.match(production):
            return {'ok': False, 'fingerprint': fp,
                    'reason': f'PROD_PUBKEY_SHA256 is not set (it reads "{production}"). The production '
                              f'key has to be made in the owner\'s offline ceremony first; then set '
                              f'PROD_PUBKEY_SHA256 in dexmond_mie/licence_key.py to its fingerprint.'}
        if production in blocklist:
            return {'ok': False, 'fingerprint': fp,
                    'reason': 'PROD_PUBKEY_SHA256 is in the list of development and test keys.'}
        if fp != production:
            return {'ok': False, 'fingerprint': fp,
                    'reason': f'The embedded licence key ({fp}) is not the production key '
                              f'(PROD_PUBKEY_SHA256 {production}).'}
        return {'ok': True, 'fingerprint': fp, 'reason': 'The embedded licence key is the production key.'}
    except (ValueError, binascii.Error) as e:
        return {'ok': False, 'fingerprint': fp,
                'reason': f'The licence key module could not be read: {e}'}


def check_release_key_file(path: str = KEY_MODULE) -> dict:
    try:
        with open(path, encoding='utf-8') as f:
            source = f.read()
    except OSError as e:
        return {'ok': False, 'fingerprint': None, 'reason': f'Cannot read {path}: {e}'}
    return check_release_key(source)


def main(argv):
    result = check_release_key_file(os.path.abspath(argv[1]) if len(argv) > 1 else KEY_MODULE)
    if result['fingerprint']:
        print(f"Embedded licence key fingerprint (SHA-256): {result['fingerprint']}")
    if result['ok']:
        print(f"Release key check passed: {result['reason']}")
        return 0
    print(f"Release key check FAILED: {result['reason']}", file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
