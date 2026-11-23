#!/usr/bin/env python3
"""Chooses the files for the run on real signed files, by a rule that does not depend on either
signature check: a file is chosen when it is a PE file (MZ header, PE signature) whose certificate
table (data directory 4) is not empty. Catalog-signed files carry no certificate table and are
not chosen.

    select_signed_pe.py --from DIR [--from DIR ...] --to OUT_DIR

Every chosen file is COPIED into OUT_DIR under its SHA-256 (so equal files are kept once and no
name clashes); OUT_DIR.selection.tsv (BESIDE the folder, so the folder holds only the chosen
files) lists sha256, size and the path it was copied from. The source folders are only read.
File content is never printed. Files over 32 MiB are left out (the engine verifies up to 32 MiB).
"""
import argparse
import hashlib
import os
import shutil
import struct
import sys

MAX_BYTES = 32 * 1024 * 1024


def certificate_table(path):
    """(offset, size) of the certificate table, or None when the file is not a PE file or has none."""
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
            if len(head) < 0x40 or head[:2] != b'MZ':
                return None
            pe = struct.unpack_from('<I', head, 0x3C)[0]
            f.seek(pe)
            nt = f.read(4 + 20 + 240)
    except OSError:
        return None
    if len(nt) < 24 or nt[:4] != b'PE\0\0':
        return None
    optional_size = struct.unpack_from('<H', nt, 20)[0]
    opt = nt[24:24 + optional_size]
    if len(opt) < 2:
        return None
    magic = struct.unpack_from('<H', opt, 0)[0]
    dirs_at = {0x10B: 96, 0x20B: 112}.get(magic)
    if dirs_at is None or len(opt) < dirs_at + 5 * 8:
        return None
    count = struct.unpack_from('<I', opt, dirs_at - 4)[0]
    if count < 5:
        return None
    offset, size = struct.unpack_from('<II', opt, dirs_at + 4 * 8)
    return (offset, size) if size else None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--from', dest='sources', action='append', required=True)
    parser.add_argument('--to', required=True)
    args = parser.parse_args()
    os.makedirs(args.to, exist_ok=True)
    seen, looked, chosen, too_big = set(), 0, 0, 0
    rows = []
    for source in args.sources:
        for root, dirs, names in os.walk(source):
            dirs.sort()
            for name in sorted(names):
                path = os.path.join(root, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                looked += 1
                if certificate_table(path) is None:
                    continue
                size = os.path.getsize(path)
                if size > MAX_BYTES:
                    too_big += 1
                    continue
                digest = hashlib.sha256()
                with open(path, 'rb') as f:
                    for block in iter(lambda: f.read(1 << 20), b''):
                        digest.update(block)
                sha = digest.hexdigest()
                if sha in seen:
                    continue
                seen.add(sha)
                shutil.copyfile(path, os.path.join(args.to, sha))
                rows.append(f'{sha}\t{size}\t{os.path.relpath(path, source)}\t{source}')
                chosen += 1
    listing = os.path.normpath(args.to) + '.selection.tsv'
    with open(listing, 'w', encoding='utf-8') as f:
        f.write('sha256\tsize\tpath\tfrom\n' + ''.join(row + '\n' for row in rows))
    print(f'looked at {looked} files; chosen {chosen} PE files with a certificate table '
          f'(equal files once); left out over 32 MiB: {too_big}; list: {listing}')
    return 0 if chosen else 1


if __name__ == '__main__':
    sys.exit(main())
