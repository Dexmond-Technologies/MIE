#!/usr/bin/env python3
"""Parity harness, comparison side: compares two result files written in the format of
run_reference.py (one from the Python reference, one from the C++ engine).

    compare.py REFERENCE.jsonl CANDIDATE.jsonl [--explained FILE.json] [--max-explained N]
    compare.py --identical A.jsonl B.jsonl      (two runs of the same engine: byte-equal after sorting)

Compared per file, all four (r-01's pass line for A-1, board B-3484): SHA-256, score, verdict,
sorted list of finding categories; and the error CLASS (not the error text, which is the
operating system's wording and differs between systems).

Outcome per file:
  identical     all fields equal
  explained     differs, and the --explained file has an entry for this path naming the library
                and the field that differs; a difference in VERDICT is never explainable
  unexplained   anything else, including a file present on one side only

PASS only if: 0 unexplained, 0 verdict differences of any cause, explained <= N (default 5),
and the rule-file hashes in the two headers are equal.

Error classes (r-01, board B-3551): the corpus sets are expected to hold no unreadable and no
non-regular entry. The number of entries of each error class is reported for each side. If any
count is above 0 the run STOPS (exit 3): the corpus is inspected first; such entries are never
compared away. --allow-error-classes turns the stop off; it exists for the tests of this tool
and must not be used on v1, B' or S.

Exit code: 0 PASS, 1 FAIL, 2 usage or unreadable input, 3 STOPPED on error-class entries.

--explained file: {"<relative path>": {"library": "...", "field": "score|categories|error_class", "reason": "..."}}
The cap of 5 is across all sets together; run the tool once per set and add the counts, or pass
the remaining allowance with --max-explained.
"""
import argparse
import json
import sys

FIELDS = ('sha256', 'score', 'verdict', 'categories', 'error_class')


def load(path):
    header, files = None, {}
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            kind = record.get('record')
            if kind == 'header':
                if header is not None:
                    raise ValueError(f'{path}: second header at line {number}')
                header = record
            elif kind == 'file':
                if record['path'] in files:
                    raise ValueError(f'{path}: path listed twice: {record["path"]}')
                files[record['path']] = record
            else:
                raise ValueError(f'{path}: unknown record kind at line {number}')
    if header is None:
        raise ValueError(f'{path}: no header record')
    return header, files


def compare(reference, candidate, explained, max_explained):
    ref_header, ref_files = reference
    cand_header, cand_files = candidate
    def class_counts(files):
        counts = {}
        for record in files.values():
            cls = record.get('error_class')
            if cls is not None:
                counts[cls] = counts.get(cls, 0) + 1
        return counts

    report = {'identical': 0, 'explained': [], 'unexplained': [], 'verdict_differences': [],
              'error_classes_reference': class_counts(ref_files),
              'error_classes_candidate': class_counts(cand_files),
              'rules_equal': ref_header.get('rules') == cand_header.get('rules'),
              'files_reference': len(ref_files), 'files_candidate': len(cand_files)}

    for path in sorted(set(ref_files) | set(cand_files)):
        a, b = ref_files.get(path), cand_files.get(path)
        if a is None or b is None:
            report['unexplained'].append({'path': path, 'fields': ['missing on one side']})
            continue
        differing = [k for k in FIELDS if a.get(k) != b.get(k)]
        if not differing:
            report['identical'] += 1
            continue
        entry = {'path': path, 'fields': differing,
                 'reference': {k: a.get(k) for k in differing}, 'candidate': {k: b.get(k) for k in differing}}
        if 'verdict' in differing:
            report['verdict_differences'].append(entry)
            report['unexplained'].append(entry)
            continue
        note = explained.get(path)
        valid = (isinstance(note, dict) and note.get('library') and note.get('reason')
                 and note.get('field') in differing and 'sha256' not in differing)
        if valid:
            entry['explanation'] = note
            report['explained'].append(entry)
        else:
            report['unexplained'].append(entry)

    report['pass'] = (not report['unexplained'] and not report['verdict_differences']
                      and len(report['explained']) <= max_explained and report['rules_equal'])
    return report


def identical(path_a, path_b):
    def body(path):
        with open(path, encoding='utf-8') as f:
            return sorted(line.rstrip('\n') for line in f if line.strip() and '"record": "header"' not in line
                          and '"record":"header"' not in line)
    return body(path_a) == body(path_b)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('reference')
    parser.add_argument('candidate')
    parser.add_argument('--explained')
    parser.add_argument('--max-explained', type=int, default=5)
    parser.add_argument('--identical', action='store_true')
    parser.add_argument('--json', action='store_true', help='print the full report as JSON')
    parser.add_argument('--allow-error-classes', action='store_true',
                        help='do not stop when a side holds error-class entries (tool tests only)')
    args = parser.parse_args()

    try:
        if args.identical:
            same = identical(args.reference, args.candidate)
            print('identical: yes' if same else 'identical: NO')
            return 0 if same else 1
        explained = {}
        if args.explained:
            with open(args.explained, encoding='utf-8') as f:
                explained = json.load(f)
        report = compare(load(args.reference), load(args.candidate), explained, args.max_explained)
    except (OSError, ValueError) as e:
        print(f'compare: {e}', file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"files: reference {report['files_reference']}, candidate {report['files_candidate']}")
        print(f"identical: {report['identical']}")
        print(f"explained differences: {len(report['explained'])} (allowed {args.max_explained})")
        print(f"unexplained differences: {len(report['unexplained'])}")
        print(f"verdict differences: {len(report['verdict_differences'])}")
        print(f"rule files equal: {'yes' if report['rules_equal'] else 'NO'}")
        print(f"error classes, reference: {json.dumps(report['error_classes_reference'], sort_keys=True)}")
        print(f"error classes, candidate: {json.dumps(report['error_classes_candidate'], sort_keys=True)}")
        for entry in report['unexplained'][:50]:
            print('  UNEXPLAINED', json.dumps(entry, sort_keys=True))
        for entry in report['explained']:
            print('  explained', json.dumps(entry, sort_keys=True))
    stopped = bool(report['error_classes_reference'] or report['error_classes_candidate'])
    if stopped and not args.allow_error_classes:
        print('RESULT: STOPPED. The sets must hold no unreadable and no non-regular entry; '
              'inspect the corpus before any comparison.')
        return 3
    if not args.json:
        print('RESULT:', 'PASS' if report['pass'] else 'FAIL')
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
