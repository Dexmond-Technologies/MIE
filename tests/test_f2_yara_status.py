'''F2: each rule file compiles on its own; a broken file is skipped with an
error and cannot silently disable all of YARA. Status ON / DEGRADED /
YARA-OFF is visible. Fake-yara tests are PASS UNDER MOCK; real-yara tests
are skipped when yara-python is not installed.'''
import os

import pytest

from conftest import eicar_path
from dexmond_mie import yara_analyzer
from dexmond_mie.core import Engine

BROKEN = 'rule broken {\n    condition:\n        this is not yara\n'


class FakeYara:
    '''compile() fails for any file containing "this is not yara".'''
    class Error(Exception):
        pass
    SyntaxError = Error
    TimeoutError = Error

    @staticmethod
    def compile(filepath=None, filepaths=None, source=None):
        paths = [filepath] if filepath else list((filepaths or {}).values())
        for p in paths:
            if 'this is not yara' in open(p).read():
                raise FakeYara.SyntaxError(f'{p}: syntax error')
        return object()


def _break(rules_dir, name='zz_broken.yar', where=''):
    d = os.path.join(rules_dir, where) if where else rules_dir
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), 'w') as f:
        f.write(BROKEN)


def test_one_broken_file_degrades_not_disables(rules_copy, monkeypatch):
    monkeypatch.setattr(yara_analyzer, 'yara', FakeYara)
    _break(rules_copy)
    ya = yara_analyzer.YaraAnalyzer(rules_copy)
    assert ya.status == yara_analyzer.YARA_DEGRADED
    assert ya.rules is not None and ya.rules_count == 5
    assert len(ya.errors) == 1 and ya.errors[0]['file'].endswith('zz_broken.yar')


def test_all_broken_shows_yara_off(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_analyzer, 'yara', FakeYara)
    d = tmp_path / 'rules'
    _break(str(d), 'a.yar')
    _break(str(d), 'b.yar')
    ya = yara_analyzer.YaraAnalyzer(str(d))
    assert ya.status == yara_analyzer.YARA_OFF and ya.rules is None
    assert len(ya.errors) == 2


def test_yara_missing_shows_yara_off(rules_copy, monkeypatch):
    monkeypatch.setattr(yara_analyzer, 'yara', None)
    assert yara_analyzer.YaraAnalyzer(rules_copy).status == yara_analyzer.YARA_OFF


def test_broken_proposed_file_is_ignored(rules_copy, monkeypatch):
    monkeypatch.setattr(yara_analyzer, 'yara', FakeYara)
    _break(rules_copy, 'auto_generated.yar', 'proposed')
    ya = yara_analyzer.YaraAnalyzer(rules_copy)
    assert ya.status == yara_analyzer.YARA_ON and ya.errors == []


def test_status_in_scan_results_and_cli(rules_copy, rep_copy, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(yara_analyzer, 'yara', None)
    p = tmp_path / 'a.txt'
    p.write_text('hello')
    assert Engine(rules_copy, rep_copy).scan_file(str(p))['details']['yara_status'] == 'YARA-OFF'
    from dexmond_mie import cli
    monkeypatch.setattr('sys.argv', ['mie', 'scan', str(p), '--rules-dir', rules_copy])
    cli.run()
    out = capsys.readouterr()
    assert 'YARA-OFF' in out.err and 'YARA status: YARA-OFF' in out.out


@pytest.mark.parametrize('where', ['', 'proposed'])
def test_real_yara_corrupt_file_eicar_still_matched(rules_copy, rep_copy, where):
    pytest.importorskip('yara')
    _break(rules_copy, 'zz_broken.yar', where)
    engine = Engine(rules_copy, rep_copy, use_reputation=False)
    assert engine.yara_engine.status == ('DEGRADED' if not where else 'ON')
    results = engine.scan_file(eicar_path('eicar.com'))
    assert 'EICAR_Test_File' in results['yara']


def test_real_yara_all_rules_broken_is_off(tmp_path, rep_copy):
    pytest.importorskip('yara')
    d = tmp_path / 'rules'
    _break(str(d), 'only.yar')
    assert Engine(str(d), rep_copy).yara_engine.status == 'YARA-OFF'
