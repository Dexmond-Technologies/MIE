'''X1: reputation no longer short-circuits the pipeline; --no-reputation mode.'''
import json
import hashlib

from dexmond_mie.core import Engine


def _engine_with_bad_hash(tmp_path, rules_copy, data, use_reputation=True):
    sample = tmp_path / 'sample.bin'
    sample.write_bytes(data)
    rep = tmp_path / 'rep.json'
    rep.write_text(json.dumps({'malicious': {hashlib.sha256(data).hexdigest(): 'unit-test-bad'},
                               'trusted': {}}))
    return Engine(rules_copy, str(rep), use_reputation=use_reputation), str(sample)


def test_malicious_reputation_runs_full_pipeline(tmp_path, rules_copy):
    engine, sample = _engine_with_bad_hash(tmp_path, rules_copy, b'plain benign text ' * 20)
    results = engine.scan_file(sample)
    assert results['verdict'] == 'MALICIOUS'
    assert results['details']['reputation']['label'] == 'unit-test-bad'
    # the rest of the pipeline ran (entropy and strings are always computed)
    assert 'entropy' in results['details']
    assert 'string_count' in results['details']
    assert 'yara' in results
    assert any(f['category'] == 'reputation_malicious' for f in results['findings'])


def test_no_reputation_mode_ignores_list(tmp_path, rules_copy):
    engine, sample = _engine_with_bad_hash(tmp_path, rules_copy, b'plain benign text ' * 20,
                                           use_reputation=False)
    results = engine.scan_file(sample)
    assert 'reputation' not in results['details']
    assert results['verdict'] == 'CLEAN'


def test_cli_has_no_reputation_flag(monkeypatch, tmp_path, rules_copy, capsys):
    from dexmond_mie import cli
    sample = tmp_path / 'x.txt'
    sample.write_bytes(b'hello world')
    seen = {}
    real_engine = cli.Engine

    def fake_engine(*args, **kwargs):
        seen.update(kwargs)
        return real_engine(*args, **kwargs)
    monkeypatch.setattr(cli, 'Engine', fake_engine)
    monkeypatch.setattr('sys.argv', ['mie', 'scan', str(sample), '--rules-dir', rules_copy,
                                     '--no-reputation', '--output', 'json'])
    cli.run()
    assert seen.get('use_reputation') is False


def test_nested_archive_budget_is_shared(tmp_path, rules_copy, rep_copy, monkeypatch):
    '''Nested archives are opened (depth > 1) but share one member budget.'''
    import io
    import zipfile
    from dexmond_mie import core

    def _zip(members):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            for name, data in members:
                zf.writestr(name, data)
        return buf.getvalue()

    inner = _zip([(f'f{i}.txt', b'benign text') for i in range(5)])
    outer = _zip([(f'inner{i}.zip', inner) for i in range(5)])
    path = tmp_path / 'outer.zip'
    path.write_bytes(outer)
    monkeypatch.setattr(core, 'MAX_ARCHIVE_MEMBERS', 8)
    engine = core.Engine(rules_copy, rep_copy)
    results = engine.scan_file(str(path))
    archive = results['details']['archive']
    assert archive['members_scanned'] >= 1
    # 8 members total across all levels, not 8 per archive
    scanned = []

    real_scan = core.Engine.scan_file

    def counting(self, fp, _depth=0, _budget=None):
        if _depth > 0:
            scanned.append(fp)
        return real_scan(self, fp, _depth, _budget)
    monkeypatch.setattr(core.Engine, 'scan_file', counting)
    engine.scan_file(str(path))
    assert len(scanned) <= 8
