#!/usr/bin/env python3
"""Writes the base files of the executable reader's parity test into a folder (harmless
generated files; no reference library needed). Used as seeds for the fuzz target and for
the regression check of the old fuzz target.

    write_pe_bases.py OUT_FOLDER
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    sys.argv = [sys.argv[0], 'no-probe', REPO]
    sys.path.insert(0, os.path.join(REPO, 'engine', 'tests'))
    import pe_parity
    with tempfile.TemporaryDirectory(prefix='mie-pe-bases-') as tmp:
        bases = pe_parity.base_files(tmp)
        for name, data in sorted(bases.items()):
            with open(os.path.join(out, name), 'wb') as f:
                f.write(data)
    print(f'{len(bases)} base files written to {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
