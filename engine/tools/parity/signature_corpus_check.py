#!/usr/bin/env python3
"""Authenticode check on REAL signed files: the Python reference against the C++ probe.

    signature_corpus_check.py --folder DIR --probe PATH/mie-signature-probe [--repo CHECKOUT]
                              [--profile parity|shipped] [--selection-rule TEXT]

Before anything else a LOG HEADER (reviewer's conditions for the 50-file run): host, commit of
--repo and whether its tree is clean, Python's version (3.12.16 required), the installed
versions of signify, certvalidator, oscrypto, asn1crypto and mscerts, the root store's SHA-256
(the hash only) against the reference's PINNED_ROOTS_SHA256, the probe's path and SHA-256, the
profile, the selection rule and the SHA-256 of every file in the folder, counted.

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
Also per file (reviewer's SG-7): the FILE DIGEST verdict of both sides. signify's: the
Authenticode digest signify computes from the file against the digest in the signed indirect
data of the first embedded signature, with its algorithm (signify's own API, the reference is
not changed); ours: the walker's computed digest against the same field (probe fields
walker_digest_*). A disagreement makes the file DIFFERENT and is counted.
And (reviewer's SG-5) the keys and signature digests along the chains our check built, counted.

Exit code 1 if any file differs in status or in cap, or if a side gave no answer; else 0.
--profile shipped runs the probe with strict fields and the second check: it prints the
second check's answer too and compares nothing more (the reference has no such profile).

This is meant for the files of the corpus sets on the machine that holds them. It reads the
files; it changes nothing in DIR.
"""
import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile

SELECTION_RULE = ('PE files of v1 normal files with a non-empty certificate table, copied under their SHA-256 '
                  'by select_signed_pe.py')


def sha256_of_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def log_header(args, roots, names):
    """Printed before anything else, before the reference is even imported (so an import failure
    still leaves a header). Never prints the content of a file, only hashes."""
    def git(*words):
        done = subprocess.run(['git', '-C', args.repo, *words], capture_output=True, text=True)
        return done.stdout.strip() if done.returncode == 0 else f'(git failed: {done.stderr.strip()[:80]})'
    print('=== signature_corpus_check: log header ===')
    print(f'host: {socket.gethostname()}')
    lines = git('status', '--porcelain').splitlines()
    tracked = [x for x in lines if not x.startswith('??')]
    untracked = [x for x in lines if x.startswith('??')]
    print(f"repo: {os.path.abspath(args.repo)} commit {git('rev-parse', 'HEAD')}; tracked files "
          f"{'unchanged' if not tracked else 'CHANGED (' + str(len(tracked)) + ' paths): NOT CLEAN'}; "
          f'untracked paths: {len(untracked)}')
    version = platform.python_version()
    print(f'python: {version} ({sys.executable})')
    if version != '3.12.16':
        print('NOT 3.12.16: not valid for the reviewer\'s run')
    for package in ('signify', 'certvalidator', 'oscrypto', 'asn1crypto', 'mscerts'):
        try:
            installed = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            installed = 'NOT INSTALLED'
        print(f'package {package}: {installed}')
    store = sha256_of_file(roots) if os.path.isfile(roots) else 'MISSING'
    try:
        sys.path.insert(0, args.repo)
        from dexmond_mie import signature as ref
        pinned = (ref.PINNED_ROOTS_SHA256 or '').lower()
    except Exception as e:  # noqa: BLE001 - shown in the header, the run stops after it
        pinned = f'(the reference cannot be imported: {type(e).__name__}: {e})'
    print(f"root store sha256: {store}; reference PINNED_ROOTS_SHA256: {pinned or '(unset)'}: "
          f"{'equal' if store == pinned else 'DIFFERENT'}")
    probe_hash = sha256_of_file(args.probe) if os.path.isfile(args.probe) else 'MISSING'
    print(f'probe: {os.path.abspath(args.probe)} sha256 {probe_hash}')
    print(f'profile: {args.profile}')
    print(f'selection rule: {args.selection_rule}')
    hashes = [sha256_of_file(os.path.join(args.folder, n)) for n in names]
    print(f'files in the folder: {len(hashes)}')
    for value in sorted(hashes):
        print(f'  sha256 {value}')
    print('=== end of log header ===')


def signify_file_digest(data):
    """signify 0.9.3's own verdict on the file digest of the FIRST embedded signature, by its
    public API, as the reference uses it (signature.py:282-289): AuthenticodeFile.from_stream
    (signed_file/base.py:43), iter_signatures (base.py:175), AuthenticodeSignature.indirect_data
    (authenticode/signed_data.py:98), IndirectData.digest_algorithm and .digest
    (indirect_data.py:296, :304), the fingerprint signify computes (signed_file/pe.py:302), compared
    as verify_indirect_data compares them (base.py:529). Returns (algorithm, equal) or (reason, None)."""
    try:
        from signify.authenticode import AuthenticodeFile
        authenticode_file = AuthenticodeFile.from_stream(io.BytesIO(data))
        signatures = list(authenticode_file.iter_signatures(signature_types='embedded', include_nested=False,
                                                            ignore_parse_errors=False))
        if not signatures:
            return 'no embedded signature', None
        indirect = signatures[0].indirect_data
        algorithm = indirect.digest_algorithm
        computed = authenticode_file.get_fingerprint(algorithm)
        return algorithm().name, computed == indirect.digest
    except Exception as e:  # noqa: BLE001 - reported, not hidden
        return f'error {type(e).__name__}', None


DIGEST_ORDER = ('md2', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')  # weakest first


def chain_minima(text):
    """'rsa:2048/sha256,rsa:4096/sha256,rsa:4096' -> ({'rsa': 2048}, {'sha256'})."""
    smallest, digests = {}, set()
    for item in filter(None, (text or '').split(',')):
        key, _, digest = item.partition('/')
        kind, _, bits = key.partition(':')
        if bits.isdigit():
            smallest[kind] = min(smallest.get(kind, int(bits)), int(bits))
        if digest:
            digests.add(digest)
    return smallest, digests

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--folder', required=True)
    parser.add_argument('--probe', required=True)
    parser.add_argument('--repo', default=os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
    parser.add_argument('--profile', choices=('parity', 'shipped'), default='parity')
    parser.add_argument('--selection-rule', default=SELECTION_RULE)
    args = parser.parse_args()

    roots = os.path.join(args.repo, 'trust', 'authenticode_roots.pem')
    names = sorted(n for n in os.listdir(args.folder) if os.path.isfile(os.path.join(args.folder, n)))
    log_header(args, roots, names)
    sys.path.insert(0, args.repo)
    from dexmond_mie import signature as ref
    policy_path = os.path.join(args.repo, 'config', 'trusted_publishers.json')
    pinned = ref.PINNED_ROOTS_SHA256 or '-'
    policy = ref.load_policy(policy_path)
    allowlist = tuple(policy['publishers'])

    different, counts, digest_counts = 0, {}, {}
    file_digest_disagreements, chain_counts = 0, {}
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
                lines = [json.loads(line.decode('ascii')) for line in done.stdout.split(b'\n') if line.strip()]
                lines = [line for line in lines if 'file' in line]     # the first line is the probe's settings
                if done.returncode == 0 and lines:
                    c = lines[0]
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
            # SG-7: the file-digest verdict of both sides
            s_alg, s_equal = signify_file_digest(data)
            w_alg, w_equal = c.get('walker_digest_name') or 'not read', c.get('walker_digest_equal')
            digest_agree = s_equal is not None and w_equal is not None and s_alg == w_alg and s_equal == w_equal
            if not digest_agree and not (s_equal is None and w_equal is None):
                file_digest_disagreements += 1
                same = False
            # SG-5: keys and digests along the chains our check built
            for label, part in (('signer chain', 'signer_chain'), ('time-stamp chain', 'timestamp_chain')):
                smallest, digests = chain_minima(c.get(part))
                for kind, bits in smallest.items():
                    key = f'{label} smallest {kind} key: {bits}'
                    chain_counts[key] = chain_counts.get(key, 0) + 1
                for digest_name in digests:
                    key = f'{label} uses digest {digest_name}'
                    chain_counts[key] = chain_counts.get(key, 0) + 1
                known = [d.lower() for d in digests if d.lower() in DIGEST_ORDER]
                if digests:
                    weakest = min(known, key=DIGEST_ORDER.index) if known else 'not ordered: ' + '/'.join(sorted(digests))
                    key = f'{label} weakest digest {weakest}'
                    chain_counts[key] = chain_counts.get(key, 0) + 1
                first = (c.get(part) or '').split(',')[0].split('/')[0]
                if first:
                    key = f'{label} first key {first}'
                    chain_counts[key] = chain_counts.get(key, 0) + 1
            different += 0 if same else 1
            counts[r.get('status')] = counts.get(r.get('status'), 0) + 1
            for part in ('file_digest', 'signer_digest', 'countersigner_digest'):
                key = f"{part} {c.get(part) or '-'}"
                digest_counts[key] = digest_counts.get(key, 0) + 1
            print(f'{name}: sha256 {digest} size {size}')
            print(f"    reference: {r.get('status')} cap={r_cap} publisher={r.get('publisher')!r} {r.get('detail', '')!r}")
            print(f"    C++:       {c.get('status')} cap={c_cap} publisher={c.get('publisher')!r} {c.get('detail', '')!r}")
            print(f"    digests:   file {c.get('file_digest') or '-'}, signer {c.get('signer_digest') or '-'}, "
                  f"time-stamp {c.get('countersigner_digest') or '-'}")
            print(f'    file digest: signify {s_alg} equal={s_equal}; walker {w_alg} equal={w_equal}: '
                  f"{'agree' if digest_agree else 'DISAGREE' if not (s_equal is None and w_equal is None) else 'neither read it'}")
            print(f"    chains:    signer {c.get('signer_chain') or '-'}; time-stamp {c.get('timestamp_chain') or '-'}")
            if args.profile == 'shipped':
                print(f"    second check: {c.get('second_check')} {c.get('second_check_reason', '')!r}")
            print(f"    {'same' if same else 'DIFFERENT'}")
    print(f'files: {len(names)}; reference statuses: {json.dumps(counts, sort_keys=True)}; different: {different}')
    print(f'digest algorithms the C++ check read (D-21: md5; sha1 counted): {json.dumps(digest_counts, sort_keys=True)}')
    print(f'file-digest verdicts where signify and the walker disagree (SG-7): {file_digest_disagreements}')
    print(f'keys and digests along the chains (SG-5, counted, no refusal): {json.dumps(chain_counts, sort_keys=True)}')
    print('signature_corpus_check:', 'FAIL' if different else 'PASS')
    return 1 if different else 0


if __name__ == '__main__':
    sys.exit(main())
