'''X14: files over the size limit are not mapped by YARA or pefile and get a
stated skip verdict, never a silent CLEAN.'''
import json
import hashlib
import os
import subprocess
import sys

import pytest

from conftest import REPO
from dexmond_mie import core


def _fail(*a, **k):
    raise AssertionError('must not be called above the size limit')


def test_over_limit_skips_yara_pe_archive(tmp_path, make_engine, monkeypatch):
    big = tmp_path / 'big.zip'
    big.write_bytes(b'\0' * 4096)
    engine = make_engine(max_scan_bytes=1024)
    monkeypatch.setattr(engine.yara_engine, 'scan', _fail)
    monkeypatch.setattr(core, 'PEAnalyzer', _fail)
    monkeypatch.setattr(core.Engine, '_scan_archive', _fail)
    results = engine.scan_file(str(big))
    assert results['verdict'] == core.SKIPPED_VERDICT
    assert results['details']['skipped']['reason'] == 'size limit'
    assert results['score'] == 0
    assert results['hashes']['sha256']


def test_over_limit_reputation_hit_still_malicious(tmp_path, rules_copy):
    data = b'A' * 4096
    big = tmp_path / 'big.bin'
    big.write_bytes(data)
    rep = tmp_path / 'rep.json'
    rep.write_text(json.dumps({'malicious': {hashlib.sha256(data).hexdigest(): 'known'},
                               'trusted': {}}))
    engine = core.Engine(rules_copy, str(rep), max_scan_bytes=1024)
    results = engine.scan_file(str(big))
    assert results['verdict'] == 'MALICIOUS'
    assert results['details']['skipped']['reason'] == 'size limit'


def test_under_limit_is_scanned(tmp_path, make_engine):
    small = tmp_path / 'small.txt'
    small.write_bytes(b'hello ' * 100)
    results = make_engine(max_scan_bytes=1 << 20).scan_file(str(small))
    assert 'skipped' not in results['details']
    assert results['verdict'] == 'CLEAN'


def test_default_limit_is_256_mib():
    assert core.MAX_SCAN_BYTES == 256 * 1024 * 1024


@pytest.mark.skipif(os.environ.get('MIE_RUN_HEAVY') != '1',
                    reason='hashes a 1 GiB sparse file (CPU-heavy); set MIE_RUN_HEAVY=1')
def test_1gib_file_peak_rss_under_1gib(tmp_path, rules_copy, rep_copy):
    '''B5-large stand-in: a 1 GiB sparse file. Peak RSS of the scanning
    process must stay at or below 1 GiB, verdict a stated skip.'''
    big = tmp_path / 'large.bin'
    with open(big, 'wb') as f:
        f.truncate(1024 ** 3)
    code = (
        'import sys, json, resource\n'
        f'sys.path.insert(0, {REPO!r})\n'
        'from dexmond_mie.core import Engine\n'
        f'r = Engine({rules_copy!r}, {rep_copy!r}).scan_file({str(big)!r})\n'
        'print(json.dumps({"verdict": r["verdict"], '
        '"rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))\n')
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res['verdict'] == core.SKIPPED_VERDICT
    assert res['rss_kib'] <= 1024 * 1024
