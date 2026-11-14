'''Global must-holds G1/G2 for the official EICAR files.

G1: the 4 official EICAR files stay MALICIOUS (reputation on).
G2: with the reputation list OFF, the YARA rule EICAR_Test_File matches each
    file itself (eicar.com, eicar.com.txt) or the archive member that holds it
    (eicar_com.zip, eicar_com2.zip), and the verdict stays MALICIOUS.
'''
import pytest

from conftest import EICAR_FILES, eicar_path


def _all_yara_rules(results):
    '''Rule names matched on the file itself plus on any archive member.'''
    rules = set(results.get('yara', []))
    for entry in results.get('details', {}).get('archive', {}).get('member_yara', []):
        rules.update(entry['rules'])
    return rules


@pytest.mark.parametrize('name', EICAR_FILES)
def test_g1_eicar_malicious_with_reputation(make_engine, name):
    engine = make_engine()
    results = engine.scan_file(eicar_path(name))
    assert results['verdict'] == 'MALICIOUS', results


@pytest.mark.parametrize('name', EICAR_FILES)
def test_g2_eicar_matched_by_yara_without_reputation(make_engine, name):
    pytest.importorskip('yara')
    engine = make_engine(use_reputation=False)
    results = engine.scan_file(eicar_path(name))
    assert 'reputation' not in results['details']
    assert 'EICAR_Test_File' in _all_yara_rules(results), results
    assert results['verdict'] == 'MALICIOUS', results


@pytest.mark.parametrize('name', EICAR_FILES)
def test_x1_reputation_hit_still_runs_yara(make_engine, name):
    '''X1: a malicious reputation hit no longer returns before YARA.'''
    pytest.importorskip('yara')
    engine = make_engine()
    results = engine.scan_file(eicar_path(name))
    if name in ('eicar.com', 'eicar.com.txt'):
        assert results['details']['reputation']['reputation'] == 'malicious'
    assert 'EICAR_Test_File' in _all_yara_rules(results), results
    assert results['verdict'] == 'MALICIOUS'
