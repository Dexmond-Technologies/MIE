#!/usr/bin/env python3
"""Authenticode check on REAL signed files: the Python reference against the C++ probe.

    signature_corpus_check.py --folder DIR --probe PATH/mie-signature-probe [--repo CHECKOUT]
                              [--profile parity|shipped]

For every regular file directly in DIR, one by one (so that a crash names its file):
  - the reference: dexmond_mie.signature.verify_portable on the file's bytes, with the
    reference's own pinned root store and publisher policy (trust/authenticode_roots.pem and
    config/trusted_publishers.json of the checkout; this script passes their PATHS on and
    never reads or prints them);
  - the C++ probe on a private copy of that one file, with the same store, pinned hash and
    policy.
Printed per file: sha256, size, reference status / cap / detail, C++ status / cap / detail,
"same" or "DIFFERENT". "cap" is the scorer's condition: status valid AND publisher_allowed
AND the publisher is in the allowlist. File CONTENT is never printed; file names are.

Exit code 1 if any file differs in status or in cap, or if a side gave no answer; else 0.
--profile shipped runs the probe with strict fields and the second check: it prints the
second check's answer too and compares nothing more (the reference has no such profile).

This is meant for the files of the corpus sets on the machine that holds them. It reads the
files; it changes nothing in DIR.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--probe', required=True)
    parser.add_argument('--repo', default=os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
    parser.add_argument('--profile', choices=('parity', 'shipped'), default='parity')
    args = parser.parse_args()

    sys.path.insert(0, args.repo)
    from dexmond_mie import signature as ref
    roots = os.path.join(args.repo, 'trust', 'authenticode_roots.pem')
    policy_path = os.path.join(args.repo, 'config', 'trusted_publishers.json')
    pinned = ref.PINNED_ROOTS_SHA256 or '-'
    policy = ref.load_policy(policy_path)
    allowlist = tuple(policy['publishers'])

    names = sorted(n for n in os.listdir(args.folder) if os.path.isfile(os.path.join(args.folder, n)))
    different, counts = 0, {}
    with tempfile.TemporaryDirectory(prefix='mie-sigcorpus-') as tmp:
        for index, name in enumerate(names):
            source = os.path.join(args.folder, name)
            with open(source, 'rb') as f:
                data = f.read(ref.MAX_VERIFY_BYTES + 1)
            size = os.path.getsize(source)
            digest = hashlib.sha256(data).hexdigest() if size <= ref.MAX_VERIFY_BYTES else 'not hashed (over 32 MiB)'
            if size > ref.MAX_VERIFY_BYTES:
                print(f'{name}: {size} bytes, over the 32 MiB the engine verifies: SKIPPED on both sides')
                continue
            try:
                r = ref.verify_portable(source, data=data, policy=policy, timeout=120.0)
            except Exception as e:  # noqa: BLE001
                r = {'status': 'NO ANSWER', 'detail': f'{type(e).__name__}: {e}'}
            r_cap = (r.get('status') == 'valid' and r.get('publisher_allowed') is True
                     and r.get('publisher') in allowlist)

            one = os.path.join(tmp, f'one{index}')
            os.mkdir(one)
            shutil.copyfile(source, os.path.join(one, 'file.bin'))
            c = {'status': 'NO ANSWER', 'detail': ''}
            try:
                done = subprocess.run([args.probe, roots, pinned, policy_path, one, args.profile],
                                      capture_output=True, timeout=600)
                lines = [line for line in done.stdout.split(b'\n') if line.strip()]
                if done.returncode == 0 and lines:
                    c = json.loads(lines[0].decode('ascii'))
                else:
                    c['detail'] = f'probe exit code {done.returncode}'
            except subprocess.TimeoutExpired:
                c['detail'] = 'probe timed out after 600 s'
            finally:
                shutil.rmtree(one, ignore_errors=True)
            c_cap = (c.get('status') == 'valid' and c.get('publisher_allowed') is True
                     and c.get('publisher') in allowlist)
            if args.profile == 'shipped':
                c_cap = c_cap and c.get('second_check') is True

            same = r.get('status') == c.get('status') and r_cap == c_cap and 'NO ANSWER' not in (r.get('status'), c.get('status'))
            if args.profile == 'shipped':
                same = 'NO ANSWER' not in (r.get('status'), c.get('status'))
            different += 0 if same else 1
            counts[r.get('status')] = counts.get(r.get('status'), 0) + 1
            print(f'{name}: sha256 {digest} size {size}')
            print(f"    reference: {r.get('status')} cap={r_cap} publisher={r.get('publisher')!r} {r.get('detail', '')!r}")
            print(f"    C++:       {c.get('status')} cap={c_cap} publisher={c.get('publisher')!r} {c.get('detail', '')!r}")
            if args.profile == 'shipped':
                print(f"    second check: {c.get('second_check')} {c.get('second_check_reason', '')!r}")
            print(f"    {'same' if same else 'DIFFERENT'}")
    print(f'files: {len(names)}; reference statuses: {json.dumps(counts, sort_keys=True)}; different: {different}')
    print('signature_corpus_check:', 'FAIL' if different else 'PASS')
    return 1 if different else 0


if __name__ == '__main__':
    sys.exit(main())
