'''F1: auto-generated YARA rules are proposals: written to rules/proposed/,
never loaded, OFF by default, and only a human approval command moves a
(validated) rule into the live set.'''
import hashlib
import json
import os

import pytest

from dexmond_mie import auto_evolution
from dexmond_mie.core import Engine

DISTINCT = b'contact operator_unit_test_7f3a@example.invalid for the key\n'


def _live_rules_hash(rules_dir):
    h = hashlib.sha256()
    for root, dirs, files in os.walk(rules_dir):
        dirs[:] = sorted(d for d in dirs if d != 'proposed')
        for name in sorted(files):
            path = os.path.join(root, name)
            h.update(os.path.relpath(path, rules_dir).encode())
            with open(path, 'rb') as f:
                h.update(f.read())
    return h.hexdigest()


def _threat(tmp_path):
    '''A file forced to score >= 70 via a reputation entry, with no YARA match.'''
    p = tmp_path / 'sample.bin'
    p.write_bytes(DISTINCT * 4)
    rep = tmp_path / 'rep.json'
    rep.write_text(json.dumps({'malicious': {hashlib.sha256(p.read_bytes()).hexdigest(): 't'},
                               'trusted': {}}))
    return str(p), str(rep)


def test_rules_hash_unchanged_after_scan_with_feature_on(tmp_path, rules_copy):
    sample, rep = _threat(tmp_path)
    before = _live_rules_hash(rules_copy)
    engine = Engine(rules_copy, rep, auto_evolution=True)
    results = engine.scan_file(sample)
    assert results['score'] >= 70
    proposed = results['details'].get('proposed_rule')
    assert proposed and proposed['active'] is False
    assert os.path.exists(auto_evolution.proposed_path(rules_copy))
    assert _live_rules_hash(rules_copy) == before


def test_off_by_default(tmp_path, rules_copy, monkeypatch):
    monkeypatch.delenv('DEXMOND_AUTO_EVOLUTION', raising=False)
    sample, rep = _threat(tmp_path)
    results = Engine(rules_copy, rep).scan_file(sample)
    assert 'proposed_rule' not in results['details']
    assert not os.path.exists(auto_evolution.proposed_path(rules_copy))


def test_proposed_dir_is_not_loaded(tmp_path, rules_copy, monkeypatch):
    seen = {}
    from dexmond_mie import yara_analyzer

    class FakeYara:
        class Error(Exception):
            pass
        TimeoutError = Error

        @staticmethod
        def compile(filepath=None, filepaths=None, **kw):
            seen.setdefault('files', []).extend([filepath] if filepath else list(filepaths.values()))
            return object()
    os.makedirs(os.path.join(rules_copy, 'proposed'), exist_ok=True)
    with open(auto_evolution.proposed_path(rules_copy), 'w') as f:
        f.write('rule p { condition: true }\n')
    monkeypatch.setattr(yara_analyzer, 'yara', FakeYara)
    yara_analyzer.YaraAnalyzer(rules_copy)
    rel = [os.path.relpath(p, rules_copy) for p in seen['files']]
    assert rel and not any(r.startswith('proposed') for r in rel), rel


def test_approve_moves_validated_rule_into_live_set(tmp_path, rules_copy):
    sample, rep = _threat(tmp_path)
    name = Engine(rules_copy, rep, auto_evolution=True).scan_file(sample)['details'][
        'proposed_rule']['name']
    assert auto_evolution.list_proposed(rules_copy) == [name]
    dest = auto_evolution.approve_rule(rules_copy, name, compiler=lambda src: None)
    assert name in open(dest).read()
    assert auto_evolution.list_proposed(rules_copy) == []


def test_approve_refuses_rule_that_does_not_compile(tmp_path, rules_copy):
    os.makedirs(os.path.join(rules_copy, 'proposed'))
    with open(auto_evolution.proposed_path(rules_copy), 'w') as f:
        f.write('rule broken_one {\n    condition:\n        nonsense(\n}\n')

    def bad(src):
        raise SyntaxError('syntax error')
    with pytest.raises(ValueError):
        auto_evolution.approve_rule(rules_copy, 'broken_one', compiler=bad)
    assert not os.path.exists(os.path.join(rules_copy, auto_evolution.APPROVED_FILE))


def test_approve_with_real_yara(tmp_path, rules_copy):
    pytest.importorskip('yara')
    sample, rep = _threat(tmp_path)
    name = Engine(rules_copy, rep, auto_evolution=True).scan_file(sample)['details'][
        'proposed_rule']['name']
    auto_evolution.approve_rule(rules_copy, name)
    assert name in Engine(rules_copy, rep).scan_file(sample)['yara']
