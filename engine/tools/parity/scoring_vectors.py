#!/usr/bin/env python3
"""Direct comparison of the scoring function (reviewer's ruling, board B-3488).

The same lists of findings are given to the Python reference scorer and, later, to the C++
scorer, with no file involved. This tool builds the lists and records what the PYTHON
reference (dexmond_mie/scoring.py of this checkout) answers for each.

    scoring_vectors.py --out FILE.json      writes the vectors with the reference's answers
    scoring_vectors.py --check FILE.json    recomputes and requires FILE.json to be identical

Each vector: the calls made on a fresh Scorer, in order, and the answers.
  {"id": n, "group": "...",
   "calls": [["finding", category, weight_override|null, family|null],
             ["floor_finding", category, floor],
             ["set_floor", floor],
             ["cap_heuristics", cap|null]],
   "expected": {"score": get_score(), "verdict": get_verdict(), "family_scores": {...}}}

The lists are built from engine/data/scoring.reference.json so that every weight, every
family, every cap, the signature cap, the floors, the clamp and both verdict lines are
exercised, alone and combined; a fixed-seed random part adds mixed cases. This covers the
items no file can trigger (the low rule severity, the default weight of an unknown
category, the signature cap).
"""
import argparse
import itertools
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SEED = 20261123


def build_calls(table):
    """Returns [(group, [calls])], deterministic."""
    weights = table['weights']
    categories = list(weights)
    families = table['families']
    caps = table['family_caps']
    severities = table['yara_severity_weights']
    out = []

    def add(group, calls):
        out.append((group, [list(c) for c in calls]))

    add('empty', [])

    # every category alone, twice, three times, six times
    for category in categories + ['some_unknown_category']:
        for count in (1, 2, 3, 6):
            add('single category', [('finding', category, None, None)] * count)

    # every rule severity through a weight override, in the yara family and in the imports family
    for severity, weight in severities.items():
        for family in (None, 'imports'):
            for count in (1, 2, 3, 5):
                add('rule severity', [('finding', 'yara_match', weight, family)] * count)

    # every family: all its categories together, and each pair
    by_family = {}
    for category, family in families.items():
        by_family.setdefault(family, []).append(category)
    for family, members in sorted(by_family.items()):
        add('whole family', [('finding', c, None, None) for c in members])
        add('whole family twice', [('finding', c, None, None) for c in members] * 2)
        for a, b in itertools.combinations(members, 2):
            add('family pair', [('finding', a, None, None), ('finding', b, None, None)])

    # family overrides the engine uses (packing for a confirmed packer's own findings)
    for category in ('high_entropy', 'wx_section', 'tls_callback', 'dynamic_resolution_chain', 'packer_detected'):
        for count in (1, 2, 3):
            add('packing override', [('finding', category, None, 'packing')] * count)
    add('packing mix', [('finding', 'high_entropy', None, 'packing'), ('finding', 'wx_section', None, 'packing'),
                        ('finding', 'packer_detected', None, None), ('finding', 'tls_callback', None, 'packing'),
                        ('finding', 'dynamic_resolution_chain', None, 'packing')])

    # weight overrides (the reduced entropy weight and others)
    for category in ('high_entropy', 'sliding_entropy_spike'):
        for weight in (table['limits']['REDUCED_ENTROPY_WEIGHT'], 0, 1, 14, 15, 16):
            add('weight override', [('finding', category, weight, None)])

    # just below, on and above each family cap, with unit weights
    for family, cap in sorted(caps.items()):
        member = next(c for c, f in families.items() if f == family)
        for total in (cap - 1, cap, cap + 1, cap * 2):
            add('family cap edge', [('finding', member, total, None)])
            add('family cap edge split', [('finding', member, total - 1, None), ('finding', member, 1, None)])

    # every exact score from 0 to 105 built from an uncapped category, to walk across both lines and the clamp
    for total in range(0, 106):
        add('score walk', [('finding', 'obfuscated_script', total, None)] if total else [])

    # the signature cap: heuristic sums around 29, with and without uncappable evidence
    for total in (0, 5, 28, 29, 30, 31, 60, 100, 150):
        base = [('finding', 'obfuscated_script', total, None)] if total else []
        add('signature cap', base + [('cap_heuristics', None)])
        add('signature cap before findings', [('cap_heuristics', None)] + base)
        add('signature cap + critical rule', base + [('finding', 'critical_yara', None, None), ('cap_heuristics', None)])
        add('signature cap + known bad', base + [('finding', 'reputation_malicious', None, None),
                                                 ('set_floor', table['limits']['MALICIOUS_FLOOR']),
                                                 ('cap_heuristics', None)])
        add('signature cap + floor finding', base + [('floor_finding', 'archive_member', 45), ('cap_heuristics', None)])
        for cap in (0, 10, 29, 50):
            add('explicit heuristic cap', base + [('cap_heuristics', cap)])
    for combo in itertools.combinations(categories, 3):
        if combo[0] in ('yara_match', 'high_entropy', 'api_chain'):
            add('signature cap on three categories',
                [('finding', c, None, None) for c in combo] + [('cap_heuristics', None)])

    # floors
    for floor in (0, 5, 29, 30, 69, 70, 75, 100, 130):
        add('floor only', [('set_floor', floor)])
        add('floor finding only', [('floor_finding', 'archive_member', floor)])
        for total in (0, 10, 40, 80):
            base = [('finding', 'obfuscated_script', total, None)] if total else []
            add('floor and findings', base + [('floor_finding', 'archive_member', floor)])
            add('two floors', base + [('set_floor', floor), ('floor_finding', 'archive_member', 30)])

    # every pair of categories
    for a, b in itertools.combinations(categories, 2):
        add('category pair', [('finding', a, None, None), ('finding', b, None, None)])

    # all categories at once, and twice
    add('all categories', [('finding', c, None, None) for c in categories])
    add('all categories twice', [('finding', c, None, None) for c in categories] * 2)

    # fixed-seed random mixtures
    rng = random.Random(SEED)
    family_choices = [None, None, None, 'packing', 'imports', 'entropy', 'yara', 'made_up_family']
    for _ in range(3000):
        calls = []
        for _ in range(rng.randint(0, 9)):
            kind = rng.random()
            if kind < 0.80:
                category = rng.choice(categories + ['some_unknown_category'])
                override = rng.choice([None, None, None, 0, 1, 5, 10, 20, 33, 70])
                calls.append(('finding', category, override, rng.choice(family_choices)))
            elif kind < 0.88:
                calls.append(('floor_finding', 'archive_member', rng.choice([0, 5, 25, 30, 45, 70, 85, 100])))
            elif kind < 0.94:
                calls.append(('set_floor', rng.choice([0, 30, 70])))
            else:
                calls.append(('cap_heuristics', rng.choice([None, None, 0, 15, 29])))
        add('random mixture', calls)
    return out


def reference_answers(calls):
    """Runs the calls on the Python reference scorer."""
    sys.path.insert(0, REPO)
    from dexmond_mie.scoring import Scorer
    scorer = Scorer()
    for call in calls:
        kind = call[0]
        if kind == 'finding':
            scorer.add_finding(call[1], 'vector', weight_override=call[2], family=call[3])
        elif kind == 'floor_finding':
            scorer.add_floor_finding(call[1], 'vector', call[2])
        elif kind == 'set_floor':
            scorer.set_floor(call[1])
        elif kind == 'cap_heuristics':
            scorer.cap_heuristics(call[1])
        else:
            raise ValueError(kind)
    return {'score': scorer.get_score(), 'verdict': scorer.get_verdict(),
            'family_scores': dict(sorted(scorer.family_scores().items()))}


def build(table):
    vectors = []
    for index, (group, calls) in enumerate(build_calls(table)):
        vectors.append({'id': index, 'group': group, 'calls': calls, 'expected': reference_answers(calls)})
    return vectors


def summary(vectors):
    scores = sorted({v['expected']['score'] for v in vectors})
    verdicts = {}
    groups = {}
    for v in vectors:
        verdicts[v['expected']['verdict']] = verdicts.get(v['expected']['verdict'], 0) + 1
        groups[v['group']] = groups.get(v['group'], 0) + 1
    return {'vectors': len(vectors), 'distinct_scores': len(scores),
            'has_scores_29_30_69_70': [s in scores for s in (29, 30, 69, 70)],
            'verdicts': dict(sorted(verdicts.items())), 'groups': dict(sorted(groups.items()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out')
    parser.add_argument('--check')
    args = parser.parse_args()
    with open(os.path.join(REPO, 'engine', 'data', 'scoring.reference.json'), encoding='utf-8') as f:
        table = json.load(f)
    vectors = build(table)
    document = {'seed': SEED, 'source': 'dexmond_mie/scoring.py of this checkout', 'summary': summary(vectors),
                'vectors': vectors}
    text = json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n'
    print(json.dumps(document['summary'], sort_keys=True))
    if args.out:
        with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
    if args.check:
        with open(args.check, encoding='utf-8') as f:
            committed = f.read()
        if committed != text:
            print('scoring vectors: the committed file differs from what the reference answers now')
            return 1
        print('scoring vectors: the committed file equals what the reference answers now')
    return 0


if __name__ == '__main__':
    sys.exit(main())
