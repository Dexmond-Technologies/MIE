#!/usr/bin/env python3
"""Checks what parity set S really exercises in the Python reference, from the reference's
OWN output, and writes the manifest of the set (reviewer's condition M-1, board B-3484).

    set_s_coverage.py --results REF.jsonl --details REF.details.jsonl --intent set_s.intent.json
                      [--manifest OUT.json] [--expect MANIFEST.json]

Reads engine/data/scoring.reference.json for the table (weights, families, caps, boundaries).
For every item of the table it says which files of the set trigger it:
  - each of the weight rows (a finding of that category in the reference's output);
  - each rule-severity weight; the reduced entropy weight;
  - each family cap (a file whose family sum, before the cap, is above the cap);
  - the floors (a known-bad hash; an archive taking its worst member's score);
  - the clamp at 100;
  - each verdict, and for each verdict line a file on it and the highest reachable score below;
  - the partial-scan verdict text; the trusted-hash early return.
Items that NO file can trigger are listed with the reason; they are covered by the direct
comparison of the scoring function (same findings into both scorers), not by files.

Exit code 0: every item that files can trigger is triggered. 1: something is missing.
--expect: also require that every file's hash, score, verdict and categories equal the
committed manifest (so a change of the generator or of the reference is noticed).
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

# Items no file of the set can trigger, with the reason. Covered by the direct scoring comparison.
NOT_BY_FILES = {
    'yara_severity:low': 'no rule of the reference has severity "low"',
    'default_weight': 'the reference never creates a finding of an unknown category',
    'signed_cap': 'needs a file with a genuine trusted signature; cannot be generated '
                  '(r-01, B-3488: named Microsoft-signed corpus files, or NOT COVERED by files)',
}


def overlay_rows_reachable():
    """The reference asks pefile for the overlay with PE.get_overlay_data_offset() inside a
    try/except that swallows every error (dexmond_mie/pe_analyzer.py, get_overlay_info and
    get_overlay_entropy). If the installed pefile has no method of that name, the call fails,
    the reference sees no overlay in any file, and the rows pe_overlay and overlay_high_entropy
    can never be produced. This function looks at the installed pefile and says which it is.
    Returns (reachable, sentence)."""
    try:
        import pefile
    except ImportError:
        return True, 'pefile is not installed here; cannot tell'
    has_called = hasattr(pefile.PE, 'get_overlay_data_offset')
    has_real = hasattr(pefile.PE, 'get_overlay_data_start_offset')
    version = getattr(pefile, '__version__', '?')
    sentence = (f'pefile {version}: PE.get_overlay_data_offset (the name the reference calls) exists: {has_called}; '
                f'PE.get_overlay_data_start_offset exists: {has_real}')
    return has_called, sentence


def load_lines(path):
    with open(path, encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def family_of(finding, table):
    return finding.get('family') or table['families'].get(finding['category'], finding['category'])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--results', required=True)
    parser.add_argument('--details', required=True)
    parser.add_argument('--intent', required=True)
    parser.add_argument('--manifest')
    parser.add_argument('--expect')
    args = parser.parse_args()

    with open(os.path.join(REPO, 'engine', 'data', 'scoring.reference.json'), encoding='utf-8') as f:
        table = json.load(f)
    with open(args.intent, encoding='utf-8') as f:
        intent = json.load(f)
    records = load_lines(args.results)
    header = next(r for r in records if r.get('record') == 'header')
    files = {r['path']: r for r in records if r.get('record') == 'file'}
    details = {d['path']: d for d in load_lines(args.details)}

    hit = {}

    def mark(item, path):
        hit.setdefault(item, []).append(path)

    labels = table['verdicts']['labels']
    scores = {}
    print('--- what the reference reports for each file of set S ---')
    for path in sorted(files):
        record = files[path]
        detail = details.get(path, {})
        findings = detail.get('findings', [])
        shown = []
        raw = {}
        for f in findings:
            floor = f.get('mode') == 'floor'
            family = family_of(f, table)
            shown.append(f"{f['category']}:{f['weight']}" + (f"@{f['family']}" if f.get('family') else '')
                         + ('(floor)' if floor else ''))
            if floor:
                mark('floor:' + f['category'], path)
                continue
            mark('weight:' + f['category'], path)
            raw[family] = raw.get(family, 0) + f['weight']
            if f['category'] == 'yara_match':
                for severity, weight in table['yara_severity_weights'].items():
                    if severity != 'critical' and f['weight'] == weight:
                        mark('yara_severity:' + severity, path)
            if f['category'] == 'critical_yara':
                mark('yara_severity:critical', path)
            if f['category'] in ('high_entropy', 'sliding_entropy_spike') and \
                    f['weight'] == table['limits']['REDUCED_ENTROPY_WEIGHT']:
                mark('reduced_entropy_weight', path)
        capped_total = 0
        for family, total in raw.items():
            cap = table['family_caps'].get(family)
            # r-01 (B-3579): each cap once exactly AT the cap and once ABOVE it, so that a scorer
            # that uses "greater or equal" where the reference uses "greater" is caught
            if cap is not None and total > cap:
                mark('family_cap_above:' + family, path)
            if cap is not None and total == cap:
                mark('family_cap_exactly:' + family, path)
            capped_total += min(total, cap) if cap is not None else total
        if record['score'] == table['score_max'] and capped_total > table['score_max']:
            mark('clamp_at_100', path)
        if 'reputation_malicious' in record['categories'] and (record['score'] or 0) >= table['limits']['MALICIOUS_FLOOR']:
            mark('floor:reputation', path)
        if record['verdict'] is not None:
            mark('verdict:' + record['verdict'], path)
            scores.setdefault(record['score'], []).append(path)
        if record['verdict'] == labels['partial']:
            mark('partial_scan_verdict', path)
        reasons = (detail.get('archive_coverage') or {}).get('reasons', [])
        if detail.get('archive_not_unpacked') or any(str(r).startswith('nested archive') for r in reasons):
            mark('archive_depth_limit', path)
        print(f"{path}: score {record['score']} {record['verdict']!r} error={record['error']!r} "
              f"[{', '.join(shown)}]"
              + (f" not_unpacked={detail.get('archive_not_unpacked')}" if detail.get('archive_not_unpacked') else '')
              + (f" coverage={json.dumps(detail.get('archive_coverage'))}" if detail.get('archive_coverage') else ''))

    trusted = files.get('r02_listed_trusted.txt')
    if trusted and trusted['verdict'] == labels['clean'] and trusted['categories'] == []:
        mark('trusted_hash_early_return', 'r02_listed_trusted.txt')

    # boundaries: a file on each line, and the highest score below it that the set reaches
    present = sorted(s for s in scores if s is not None)
    medium, malicious = table['verdicts']['medium_from'], table['verdicts']['malicious_from']
    below_medium = [s for s in present if 0 < s < medium]
    below_malicious = [s for s in present if medium <= s < malicious]
    # r-01 (B-3579): every weight is a multiple of 5 (only the signature cap is 29), so "just below"
    # a line means 25 and 65. The set must hold files whose REFERENCE score is exactly each of these.
    step = 5
    wanted_scores = [0, step, medium - step, medium, malicious - step, malicious, table['score_max']]
    boundary = {f'a file with reference score exactly {s}': s in present for s in wanted_scores}

    required = (['weight:' + c for c in table['weights']]
                + ['yara_severity:' + s for s in table['yara_severity_weights']]
                + ['family_cap_above:' + f for f in table['family_caps']]
                + ['family_cap_exactly:' + f for f in table['family_caps']]
                + ['reduced_entropy_weight', 'floor:archive_member', 'floor:reputation', 'clamp_at_100',
                   'partial_scan_verdict', 'trusted_hash_early_return', 'archive_depth_limit',
                   'default_weight', 'signed_cap']
                + ['verdict:' + labels[k] for k in ('clean', 'low', 'medium', 'malicious')])

    overlay_reachable, overlay_sentence = overlay_rows_reachable()
    unreachable = {}
    if not overlay_reachable:
        for item in ('weight:pe_overlay', 'weight:overlay_high_entropy'):
            unreachable[item] = ('cannot be produced by the reference: it asks pefile for the overlay through a '
                                 'method this pefile does not have, and swallows the error. ' + overlay_sentence)

    print('\n--- coverage of the scoring table by set S ---')
    print('overlay rows: ' + overlay_sentence)
    missing = []
    for item in required:
        if item in hit and item in unreachable:
            # the reference DID produce it: the claim "unreachable" is wrong and must not be kept
            print(f'MISSING      {item}: produced by {hit[item]} although judged unreachable; check overlay_rows_reachable')
            missing.append(item)
        elif item in unreachable:
            print(f'UNREACHABLE  {item}: {unreachable[item]}')
        elif item in hit:
            print(f'COVERED      {item}: {", ".join(sorted(set(hit[item]))[:6])}'
                  + (' ...' if len(set(hit[item])) > 6 else ''))
        elif item in NOT_BY_FILES:
            print(f'NOT BY FILES {item}: {NOT_BY_FILES[item]}')
        else:
            print(f'MISSING      {item}')
            missing.append(item)
    for name, ok in boundary.items():
        print(f"{'COVERED     ' if ok else 'MISSING     '} boundary: {name}")
        if not ok:
            missing.append('boundary: ' + name)
    print(f'scores present in the set: {present}')
    covered = [i for i in required if i in hit]
    print(f'set S: {len(files)} files; {len(covered)} items covered by files, '
          f'{len([i for i in required if i not in hit and i in NOT_BY_FILES])} not coverable by files, '
          f'{len(unreachable)} unreachable in the reference, '
          f'{len(missing)} missing')

    manifest = {
        'set': 'S',
        'seed': intent.get('seed'),
        'reference': {k: header.get(k) for k in ('commit', 'python', 'yara_python', 'yara_library', 'pefile',
                                                 'rules', 'options', 'yara_status')},
        'files': [{'path': p, 'sha256': files[p]['sha256'], 'size': files[p]['size'],
                   'intent': intent['files'].get(p, {}).get('intent'),
                   'score': files[p]['score'], 'verdict': files[p]['verdict'],
                   'categories': files[p]['categories'], 'error_class': files[p].get('error_class')}
                  for p in sorted(files)],
        'covered': {i: sorted(set(hit[i])) for i in required if i in hit},
        'not_by_files': {i: NOT_BY_FILES[i] for i in required if i not in hit and i in NOT_BY_FILES},
        'unreachable_in_reference': unreachable,
        'missing': missing,
        'scores_present': present,
        'scores_required': wanted_scores,
    }
    text = json.dumps(manifest, indent=1, sort_keys=True)
    if args.manifest:
        with open(args.manifest, 'w', encoding='utf-8') as f:
            f.write(text + '\n')
    print('\n--- MANIFEST BEGIN ---')
    print(text)
    print('--- MANIFEST END ---')

    changed = []
    if args.expect:
        with open(args.expect, encoding='utf-8') as f:
            expected = {e['path']: e for e in json.load(f)['files']}
        now = {e['path']: e for e in manifest['files']}
        for path in sorted(set(expected) | set(now)):
            a, b = expected.get(path), now.get(path)
            if a is None or b is None:
                changed.append(f'{path}: present on one side only')
                continue
            for key in ('sha256', 'size', 'score', 'verdict', 'categories'):
                if a.get(key) != b.get(key):
                    changed.append(f'{path}: {key} is {b.get(key)!r}, the committed manifest says {a.get(key)!r}')
        print(f'\ncompared with the committed manifest: {len(changed)} differences')
        for line in changed:
            print('  DIFFERENT', line)

    return 1 if (missing or changed) else 0


if __name__ == '__main__':
    sys.exit(main())
