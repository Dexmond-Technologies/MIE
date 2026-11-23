#!/usr/bin/env python3
"""CI test: the C++ rules engine gives the same matches as the Python reference.

Usage: rules_parity.py <path to mie-probe> <repository root>

Reference side: the reference's own class, dexmond_mie.yara_analyzer.YaraAnalyzer, over the
repository's rules/ folder, with yara-python (the version is printed; the reviewer's
condition M-5 wants 4.5.1 on both sides).
C++ side: `mie-probe rules <rules dir> <file>`.

Compared for every file of parity set S below 32 MiB (generated here, harmless, no malware
and no EICAR file): the set of matching rules with their name space, severity, category and
description. Also compared: the state of the rule set and the number of rule files for the
real rules folder, for a folder with one broken rule file, for a folder where every file is
broken, and for an empty folder; and the hash of the rule set against the definition in
engine/docs/INTERFACES.md, computed here independently.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
failures = []
compared = 0


def check(name, ok, detail=''):
    global compared
    compared += 1
    if not ok:
        failures.append(name)
    if not ok or detail:
        print(f"{'PASS' if ok else 'FAIL'}  {name} {detail}")


def probe(rules_dir, path=None):
    args = [PROBE, 'rules', rules_dir] + ([path] if path else [])
    out = subprocess.run(args, capture_output=True, timeout=300)
    try:
        return json.loads(out.stdout.decode('utf-8'))
    except ValueError:
        return {'unreadable': out.stdout.decode('utf-8', 'replace'), 'stderr': out.stderr.decode('utf-8', 'replace'),
                'returncode': out.returncode}


def expected_set_hash(rules_dir, names):
    lines = ''
    for name in sorted(names):
        with open(os.path.join(rules_dir, name), 'rb') as f:
            lines += f'{name} {hashlib.sha256(f.read()).hexdigest()}\n'
    return hashlib.sha256(lines.encode('utf-8')).hexdigest()


STATE = {'ON': 'ON', 'DEGRADED': 'DEGRADED', 'YARA-OFF': 'OFF'}


def main():
    try:
        import yara
    except ImportError:
        print('NOT RUN  rules parity: yara-python is not installed in this job')
        return 1  # this test is the evidence for the rules engine; a silent skip is not a pass
    from dexmond_mie.yara_analyzer import YaraAnalyzer
    print(f'reference: yara-python {getattr(yara, "__version__", "?")}, YARA library {getattr(yara, "YARA_VERSION", "?")}')

    rules_dir = os.path.join(REPO, 'rules')
    reference = YaraAnalyzer(rules_dir)
    ours = probe(rules_dir)
    # The reviewer wants these three in the log (board B-3598): the YARA version on the C++ side,
    # the five rule-file hashes against the manifest of set S, and the matches per file on both sides.
    print(f"C++ side: YARA library {ours.get('yara_library')} (the version constant of the linked library's own header; "
          f"YARA has no run-time version call)")
    check('the C++ side is built with exactly the reference\'s YARA version',
          ours.get('yara_library') == getattr(yara, 'YARA_VERSION', None) == '4.5.1',
          f"(reference {getattr(yara, 'YARA_VERSION', None)}, C++ {ours.get('yara_library')})")
    with open(os.path.join(REPO, 'engine', 'tools', 'parity', 'set_s.manifest.json'), encoding='utf-8') as f:
        manifest_rules = json.load(f)['reference']['rules']
    for name in sorted(manifest_rules):
        print(f"rule file {name}: manifest {manifest_rules[name]}  C++ {ours.get('rule_files', {}).get(name)}")
    check('the five rule-file hashes equal the manifest of set S', ours.get('rule_files') == manifest_rules,
          f"({len(manifest_rules)} files in the manifest, {len(ours.get('rule_files', {}))} loaded)")
    rule_files = sorted(f for f in os.listdir(rules_dir) if f.endswith(('.yar', '.yara')))
    check('rule set state equals the reference', ours.get('rules_state') == STATE[reference.status],
          f"(reference {reference.status}, C++ {ours.get('rules_state')})")
    check('number of rule files equals the reference', ours.get('files_loaded') == reference.rules_count,
          f"(reference {reference.rules_count}, C++ {ours.get('files_loaded')})")
    check('rule set hash equals the definition', ours.get('rules_sha256') == expected_set_hash(rules_dir, rule_files),
          f"({ours.get('rules_sha256')})")

    with tempfile.TemporaryDirectory(prefix='mie-rules-') as tmp:
        made = subprocess.run([sys.executable, os.path.join(REPO, 'engine', 'tools', 'parity', 'make_set_s.py'),
                               '--out', os.path.join(tmp, 'set_s'), '--no-large'], capture_output=True, text=True)
        if made.returncode != 0:
            print('FAIL  set S could not be generated:', made.stderr)
            return 1
        files_dir = os.path.join(tmp, 'set_s', 'files')
        with_matches = 0
        for name in sorted(os.listdir(files_dir)):
            path = os.path.join(files_dir, name)
            want = sorted((m['rule'], m['namespace'], str(m['meta'].get('severity', '')).lower(),
                           str(m['meta'].get('category', '')).lower(), m['meta'].get('description', ''))
                          for m in reference.scan(path))
            got = probe(rules_dir, path)
            have = sorted((m['rule'], m['namespace'], m['severity'], m['category'], m['description'])
                          for m in got.get('matches', []))
            ok = got.get('scan') == 'ok' and want == have
            with_matches += 1 if want else 0
            print(f"{'PASS' if ok else 'FAIL'}  {name}: reference {[w[0] for w in want]}  C++ {[h[0] for h in have]}")
            check(f'matches on {name}', ok, '' if ok else f'(reference {want}, C++ {got})')
        print(f'set S: {len(os.listdir(files_dir))} files compared, {with_matches} of them with at least one match in the reference')
        check('the set exercises the rules (at least 15 files match a rule in the reference)', with_matches >= 15,
              f'({with_matches})')

        # a rule folder with one broken file: both sides DEGRADED, the broken file left out
        degraded = os.path.join(tmp, 'degraded')
        shutil.copytree(rules_dir, degraded)
        with open(os.path.join(degraded, 'zz_broken.yar'), 'w', encoding='utf-8') as f:
            f.write('rule broken { strings: $a = "x" condition: }\n')
        ref = YaraAnalyzer(degraded)
        got = probe(degraded, os.path.join(files_dir, 't05_critical_words.txt'))
        check('one broken rule file: state equals the reference', got.get('rules_state') == STATE[ref.status],
              f"(reference {ref.status}, C++ {got.get('rules_state')})")
        check('one broken rule file: number of loaded files equals the reference',
              got.get('files_loaded') == ref.rules_count, f"(reference {ref.rules_count}, C++ {got.get('files_loaded')})")
        check('one broken rule file: exactly one error, naming that file',
              len(got.get('errors', [])) == 1 and 'zz_broken.yar' in got['errors'][0]['file'], f"({got.get('errors')})")
        check('one broken rule file: the good rules still match',
              any(m['rule'] == 'Mimikatz_Credential_Tool' for m in got.get('matches', [])), f"({got.get('matches')})")
        check('one broken rule file: the hash covers the loaded files only',
              got.get('rules_sha256') == expected_set_hash(degraded, rule_files), f"({got.get('rules_sha256')})")

        # every rule file broken, and no rule file at all: OFF on both sides, and a scan is a FAILURE, not "no matches"
        for label, content in (('all_broken', 'rule broken { condition: }\n'), ('empty', None)):
            folder = os.path.join(tmp, label)
            os.mkdir(folder)
            if content is not None:
                with open(os.path.join(folder, 'only.yar'), 'w', encoding='utf-8') as f:
                    f.write(content)
            ref = YaraAnalyzer(folder)
            got = probe(folder, os.path.join(files_dir, 't05_critical_words.txt'))
            check(f'{label}: state equals the reference', got.get('rules_state') == STATE[ref.status],
                  f"(reference {ref.status}, C++ {got.get('rules_state')})")
            check(f'{label}: no rule-set hash', got.get('rules_sha256') == '', f"({got.get('rules_sha256')!r})")
            check(f'{label}: a scan without rules is reported as failed, not as "no matches"',
                  got.get('scan') == 'failed', f"({got.get('scan')})")

        # the sub-folder "proposed" and a top-level auto_generated.yar are never loaded
        extra = os.path.join(tmp, 'extra')
        shutil.copytree(rules_dir, extra)
        os.mkdir(os.path.join(extra, 'proposed'))
        for target in (os.path.join(extra, 'proposed', 'p.yar'), os.path.join(extra, 'auto_generated.yar')):
            with open(target, 'w', encoding='utf-8') as f:
                f.write('rule never_loaded { strings: $a = "Meeting notes" condition: $a }\n')
        ref = YaraAnalyzer(extra)
        got = probe(extra, os.path.join(files_dir, 't01_clean.txt'))
        check('proposed/ and auto_generated.yar are not loaded: number of files equals the reference',
              got.get('files_loaded') == ref.rules_count == len(rule_files),
              f"(reference {ref.rules_count}, C++ {got.get('files_loaded')})")
        check('proposed/ and auto_generated.yar are not loaded: their rule does not match',
              got.get('matches') == [], f"({got.get('matches')})")

        # A rule file that tries to include another file is refused on the C++ side: rules enter
        # only as the files that were handed in (reviewer's condition, board B-3616). The
        # reference would follow the include; the shipped rules use none.
        include_dir = os.path.join(tmp, 'with_include')
        shutil.copytree(rules_dir, include_dir)
        outside = os.path.join(tmp, 'outside_rules.yar')
        with open(outside, 'w', encoding='utf-8') as f:
            f.write('rule from_outside { strings: $a = "Meeting notes" condition: $a }\n')
        with open(os.path.join(include_dir, 'zz_includer.yar'), 'w', encoding='utf-8') as f:
            f.write('include "' + outside.replace('\\', '/') + '"\n')
        got = probe(include_dir, os.path.join(files_dir, 't01_clean.txt'))
        check('a rule file with an include directive is refused (state DEGRADED, the file named)',
              got.get('rules_state') == 'DEGRADED' and len(got.get('errors', [])) == 1
              and 'zz_includer.yar' in got['errors'][0]['file'], f"({got.get('rules_state')}, {got.get('errors')})")
        check('the rule from the included file does not match', got.get('matches') == [], f"({got.get('matches')})")

    print(f'rules_parity: {compared} checks, {len(failures)} failed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
