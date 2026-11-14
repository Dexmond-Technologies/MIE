'''X13: per-family caps (entropy <= 15, imports/chains <= 35, packer 15 /
packing <= 25, non-critical YARA by severity <= 40); critical YARA and the
reputation floor are uncapped; thresholds unchanged (30 / 70).'''
from dexmond_mie.core import Engine
from dexmond_mie.scoring import Scorer


def test_entropy_family_cap():
    s = Scorer()
    for _ in range(4):
        s.add_finding('high_entropy', 'section')
    s.add_finding('overlay_high_entropy', 'overlay')
    assert s.get_score() == 15


def test_imports_family_cap_includes_import_yara():
    s = Scorer()
    s.add_finding('api_chain', 'injection')
    s.add_finding('api_chain_minor', 'privilege')
    s.add_finding('suspicious_import', 'singles')
    Engine._add_yara_findings(s, [{'rule': 'Process_Injection_APIs',
                                   'meta': {'severity': 'high', 'category': 'imports'}}])
    assert s.get_score() == 35
    assert s.get_verdict() == 'SUSPICIOUS (MEDIUM)'


def test_yara_weight_by_severity_and_cap():
    s = Scorer()
    Engine._add_yara_findings(s, [{'rule': 'm', 'meta': {'severity': 'medium'}}])
    assert s.get_score() == 10
    Engine._add_yara_findings(s, [{'rule': f'h{i}', 'meta': {'severity': 'high'}} for i in range(3)])
    assert s.family_scores()['yara'] == 40


def test_critical_yara_uncapped_and_families_add():
    s = Scorer()
    Engine._add_yara_findings(s, [{'rule': 'c', 'meta': {'severity': 'critical'}}])
    s.add_finding('high_entropy', 'x')
    assert s.get_score() == 85
    assert s.get_verdict() == 'MALICIOUS'


def test_thresholds_unchanged():
    s = Scorer()
    s.add_finding('x', 'x', weight_override=29)
    assert s.get_verdict() == 'SUSPICIOUS (LOW)'
    s.add_finding('y', 'y', weight_override=1)
    assert s.get_verdict() == 'SUSPICIOUS (MEDIUM)'
    s.add_finding('z', 'z', weight_override=40)
    assert s.get_verdict() == 'MALICIOUS'
