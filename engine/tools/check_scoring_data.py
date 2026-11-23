#!/usr/bin/env python3
"""Checks engine/data/scoring.reference.json against the Python reference source.

Every value in the data file must equal the value in dexmond_mie/scoring.py,
dexmond_mie/core.py or dexmond_mie/realtime.py of THIS checkout. The reference
files are read with `ast` (not imported), so no third-party package is needed.

Exit code 0 = identical, 1 = at least one difference (each printed).

    check_scoring_data.py                 checks engine/data/scoring.reference.json
    check_scoring_data.py --data FILE     checks another copy of the data file
    check_scoring_data.py --self-test     proves the check can fail: for a list of single wrong
                                          values it writes a changed copy and requires that the
                                          check reports exactly that value (reviewer's condition W-3)
"""
import ast
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def _const(node):
    """Evaluates a literal expression made of constants, + - * / and containers."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = _const(node.left), _const(node.right)
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        raise ValueError('unsupported operator')
    if isinstance(node, ast.Dict):
        return {_const(k): _const(v) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        return [_const(e) for e in node.elts]
    raise ValueError(f'unsupported node {type(node).__name__}')


def _assignments(body):
    out = {}
    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            try:
                out[stmt.targets[0].id] = _const(stmt.value)
            except ValueError:
                pass
    return out


def _module(path):
    with open(os.path.join(REPO, path), encoding='utf-8') as f:
        return ast.parse(f.read())


def _class_body(tree, name):
    for stmt in tree.body:
        if isinstance(stmt, ast.ClassDef) and stmt.name == name:
            return stmt
    raise SystemExit(f'class {name} not found')


def _verdict_facts(scorer_cls):
    """Reads the boundaries and labels out of Scorer.get_verdict and get_score."""
    facts = {'labels': []}
    for stmt in scorer_cls.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == 'get_verdict':
            # ast.walk is breadth-first; sort by line so the order is the source order
            for node in sorted(ast.walk(stmt), key=lambda n: getattr(n, 'lineno', 0)):
                if isinstance(node, ast.Compare) and isinstance(node.comparators[0], ast.Constant):
                    facts.setdefault('compares', []).append(
                        (type(node.ops[0]).__name__, node.comparators[0].value))
                if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
                    facts['labels'].append(node.value.value)
        if isinstance(stmt, ast.FunctionDef) and stmt.name == 'get_score':
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'min':
                    facts['score_max'] = node.args[1].value
        if isinstance(stmt, ast.FunctionDef) and stmt.name == 'add_finding':
            for node in ast.walk(stmt):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == 'get' and len(node.args) == 2
                        and isinstance(node.args[1], ast.Constant)):
                    facts['default_weight'] = node.args[1].value
    return facts


DATA_FILE = os.path.join(REPO, 'engine', 'data', 'scoring.reference.json')


def self_test():
    """One deliberate wrong value at a time; each must make the check fail and be named."""
    import copy
    with open(DATA_FILE, encoding='utf-8') as f:
        good = json.load(f)
    mutations = [
        ('weights', lambda d: d['weights'].__setitem__('api_chain', d['weights']['api_chain'] + 1)),
        ('weights', lambda d: d['weights'].pop('tls_callback')),
        ('families', lambda d: d['families'].__setitem__('pe_overlay', 'entropy')),
        ('family_caps', lambda d: d['family_caps'].__setitem__('imports', 30)),
        ('yara_severity_weights', lambda d: d['yara_severity_weights'].__setitem__('high', 25)),
        ('uncappable_families', lambda d: d['uncappable_families'].append('yara')),
        ('signed_cap', lambda d: d.__setitem__('signed_cap', 30)),
        ('default_weight', lambda d: d.__setitem__('default_weight', 10)),
        ('score_max', lambda d: d.__setitem__('score_max', 99)),
        ('verdict compares', lambda d: d['verdicts'].__setitem__('medium_from', 31)),
        ('verdict compares', lambda d: d['verdicts'].__setitem__('malicious_from', 69)),
        ('verdict labels', lambda d: d['verdicts']['labels'].__setitem__('medium', 'SUSPICIOUS')),
        ('partial verdict label', lambda d: d['verdicts']['labels'].__setitem__('partial', 'x')),
        ('limits.MAX_ARCHIVE_DEPTH', lambda d: d['limits'].__setitem__('MAX_ARCHIVE_DEPTH', 4)),
        ('limits.MAX_ANALYSIS_BYTES', lambda d: d['limits'].__setitem__('MAX_ANALYSIS_BYTES', 33554433)),
        ('limits.SLIDING_HIGH_SHARE', lambda d: d['limits'].__setitem__('SLIDING_HIGH_SHARE', 0.3)),
        ('alert_threshold', lambda d: d.__setitem__('alert_threshold', 29)),
    ]
    missed = 0
    for expected_label, mutate in mutations:
        changed = copy.deepcopy(good)
        mutate(changed)
        problems = compare_with_reference(changed)
        named = [p for p in problems if p.startswith(expected_label + ':')]
        ok = bool(named)
        print(f"{'CAUGHT' if ok else 'MISSED'}  wrong {expected_label}: {named[0] if named else problems}")
        missed += 0 if ok else 1
    clean = compare_with_reference(good)
    print(f"{'OK    ' if not clean else 'BROKEN'}  the unchanged file gives {len(clean)} differences")
    print(f'self-test: {len(mutations)} wrong values tried, {len(mutations) - missed} caught, {missed} missed')
    return 1 if (missed or clean) else 0


def main():
    data_file = DATA_FILE
    if len(sys.argv) == 2 and sys.argv[1] == '--self-test':
        return self_test()
    if len(sys.argv) == 3 and sys.argv[1] == '--data':
        data_file = sys.argv[2]
    elif len(sys.argv) != 1:
        print(__doc__)
        return 2
    with open(data_file, encoding='utf-8') as f:
        data = json.load(f)
    problems = compare_with_reference(data)
    if problems:
        print('scoring.reference.json differs from the reference source:')
        for p in problems:
            print('  -', p)
        return 1
    print('scoring.reference.json equals the reference source: '
          f"{len(data['weights'])} weights, {len(data['families'])} family entries, "
          f"{len(data['family_caps'])} caps, {len(data['limits'])} limits.")
    return 0


def compare_with_reference(data):

    scorer_cls = _class_body(_module('dexmond_mie/scoring.py'), 'Scorer')
    scorer = _assignments(scorer_cls.body)
    core = _assignments(_module('dexmond_mie/core.py').body)
    realtime = _assignments(_module('dexmond_mie/realtime.py').body)
    facts = _verdict_facts(scorer_cls)

    problems = []

    def same(label, ours, theirs):
        if ours != theirs:
            problems.append(f'{label}: data file has {ours!r}, reference has {theirs!r}')

    same('weights', data['weights'], scorer['WEIGHTS'])
    same('families', data['families'], scorer['FAMILIES'])
    same('yara_severity_weights', data['yara_severity_weights'], scorer['YARA_SEVERITY_WEIGHTS'])
    same('family_caps', data['family_caps'], scorer['FAMILY_CAPS'])
    same('uncappable_families', sorted(data['uncappable_families']), sorted(scorer['UNCAPPABLE_FAMILIES']))
    same('signed_cap', data['signed_cap'], scorer['SIGNED_CAP'])
    same('default_weight', data['default_weight'], facts.get('default_weight'))
    same('score_max', data['score_max'], facts.get('score_max'))
    same('verdict compares',
         [('Eq', data['verdicts']['clean_score']), ('Lt', data['verdicts']['medium_from']),
          ('Lt', data['verdicts']['malicious_from'])],
         facts.get('compares'))
    labels = data['verdicts']['labels']
    same('verdict labels', [labels['clean'], labels['low'], labels['medium'], labels['malicious']],
         facts['labels'])
    same('partial verdict label', labels['partial'], core.get('PARTIAL_VERDICT'))
    for name, value in data['limits'].items():
        if name not in core:
            problems.append(f'limits.{name}: not found in dexmond_mie/core.py')
        else:
            same(f'limits.{name}', value, core[name])
    same('alert_threshold', data['alert_threshold'], realtime.get('ALERT_THRESHOLD'))
    return problems


if __name__ == '__main__':
    sys.exit(main())
