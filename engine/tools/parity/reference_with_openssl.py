#!/usr/bin/env python3
"""Runs a Python script of the parity tools with the reference's oscrypto pointed at a given
OpenSSL, and changes nothing else (reviewer's ruling on the gate-3 reference environment,
option b, 2026-11-23).

Why: oscrypto 1.3.0, which the reference's lock file pins, cannot read an OpenSSL version with a
two-digit number in it (for example the system OpenSSL 3.0.13 of Ubuntu 24.04); then every
signature answer of the reference is "unavailable". Pointing it at a shared build of the OpenSSL
the C++ engine uses (3.6.5, from the same vcpkg commit) keeps every locked Python package as it
is and takes OpenSSL-version differences out of the comparison.

    reference_with_openssl.py --libcrypto PATH/libcrypto.so.3 --libssl PATH/libssl.so.3 \\
                              SCRIPT.py [its arguments]

Before the script runs it prints one header line per library (path, SHA-256) and the OpenSSL
version oscrypto then reports. It calls oscrypto.use_openssl() and nothing else.
"""
import argparse
import hashlib
import runpy
import sys


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--libcrypto', required=True)
    parser.add_argument('--libssl', required=True)
    parser.add_argument('script')
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    import oscrypto
    oscrypto.use_openssl(args.libcrypto, args.libssl)      # the only change; must come before any other oscrypto import
    from oscrypto._openssl._libcrypto import libcrypto_version
    print(f'reference OpenSSL for oscrypto: libcrypto {args.libcrypto} sha256 {sha256_of(args.libcrypto)}', flush=True)
    print(f'reference OpenSSL for oscrypto: libssl {args.libssl} sha256 {sha256_of(args.libssl)}', flush=True)
    print(f'reference OpenSSL for oscrypto: version as oscrypto reads it {libcrypto_version}; '
          f'oscrypto {oscrypto.__version__}; backend {oscrypto.backend()}', flush=True)

    sys.argv = [args.script] + list(args.args)
    runpy.run_path(args.script, run_name='__main__')


if __name__ == '__main__':
    main()
