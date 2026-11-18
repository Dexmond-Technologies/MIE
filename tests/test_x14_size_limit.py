'''X14: files over the size limit are never mapped whole (YARA match(file),
pefile), but are not skipped blind either: a bounded partial scan reads the
first and last window, YARA runs on them via match(data=...), and the PE
header/import table is parsed from the head. Nothing found = a visible
SUSPICIOUS (LOW) partial-scan verdict, never CLEAN, never auto-quarantined.'''
import json
import hashlib
import os
import subprocess
import sys

import pytest

from conftest import REPO
from dexmond_mie import core

MARKER = b'DEXMOND-TEST-MARKER-7f3a91c2-not-malware'
MARKER_RULE = '''
rule Dexmond_Test_Marker
{
    meta:
        description = "harmless unit-test marker"
        severity = "high"
    strings:
        $m = "DEXMOND-TEST-MARKER-7f3a91c2-not-malware" ascii
    condition:
        $m
}
'''


def _fail(*a, **k):
    raise AssertionError('must not be called above the size limit')


def _oversize(tmp_path, name='big.bin', size=8192, tail=b''):
    p = tmp_path / name
    with open(p, 'wb') as f:
        f.write(b'benign padding ' * (size // 15))
        f.write(tail)
    return p


def test_oversize_never_maps_file_and_gets_partial_verdict(tmp_path, make_engine, monkeypatch):
    big = _oversize(tmp_path, 'big.zip')
    engine = make_engine(max_scan_bytes=1024, oversize_window_bytes=512)
    monkeypatch.setattr(engine.yara_engine, 'scan', _fail)       # whole-file YARA
    monkeypatch.setattr(core, 'calculate_entropy', _fail)        # whole-file entropy
    monkeypatch.setattr(core.Engine, '_scan_archive', _fail)
    results = engine.scan_file(str(big))
    assert results['verdict'] == core.PARTIAL_VERDICT
    assert 0 < results['score'] < 30
    assert results['details']['partial_scan']['reason'] == 'size limit'
    assert core.needs_alert(results)
    assert not core.auto_quarantine_allowed(results)


def test_marker_in_last_window_reaches_yara_windows(tmp_path, make_engine, monkeypatch):
    '''PASS UNDER MOCK: the bytes handed to scan_data include the tail.'''
    big = _oversize(tmp_path, size=64 * 1024, tail=MARKER + b'\n' * 100)
    engine = make_engine(max_scan_bytes=4096, oversize_window_bytes=1024)
    seen = []
    monkeypatch.setattr(engine.yara_engine, 'scan_data',
                        lambda data, label='': seen.append((label, data)) or [])
    engine.scan_file(str(big))
    labels = [label for label, _ in seen]
    assert any(label.endswith('[head]') for label in labels)
    tail = [d for label, d in seen if label.endswith('[tail]')]
    assert tail and MARKER in tail[0] and len(tail[0]) <= 1024


def test_low_window_finding_is_not_labelled_nothing_found(tmp_path, make_engine, monkeypatch):
    '''PASS UNDER MOCK: a window finding that scores LOW (high YARA 20 +
    oversize 5 = 25) keeps the normal LOW verdict; PARTIAL_VERDICT is only for
    "nothing found". It still alerts and is still not auto-quarantined.'''
    big = _oversize(tmp_path, size=64 * 1024)
    engine = make_engine(max_scan_bytes=4096, oversize_window_bytes=1024)
    hit = {'rule': 'Dexmond_Test_Marker', 'meta': {'severity': 'high'}, 'strings': []}
    monkeypatch.setattr(engine.yara_engine, 'scan_data',
                        lambda data, label='': [dict(hit)] if label.endswith('[tail]') else [])
    results = engine.scan_file(str(big))
    assert results['verdict'] == 'SUSPICIOUS (LOW)'
    assert results['details']['partial_scan']['reason'] == 'size limit'
    assert core.needs_alert(results)
    assert not core.auto_quarantine_allowed(results)


def test_marker_in_last_mib_seen_by_real_yara(tmp_path, rules_copy, rep_copy):
    pytest.importorskip('yara')
    with open(os.path.join(rules_copy, 'zz_test_marker.yar'), 'w') as f:
        f.write(MARKER_RULE)
    big = tmp_path / 'big.bin'
    with open(big, 'wb') as f:
        f.truncate(3 * 1024 * 1024)          # sparse 3 MiB of zeros
        f.seek(3 * 1024 * 1024 - 512 * 1024)  # marker inside the last MiB
        f.write(MARKER)
    engine = core.Engine(rules_copy, rep_copy, max_scan_bytes=1024 * 1024,
                         oversize_window_bytes=1024 * 1024)
    results = engine.scan_file(str(big))
    assert 'Dexmond_Test_Marker' in results['yara']
    assert results['verdict'] != core.PARTIAL_VERDICT


def test_oversize_reputation_hit_still_malicious(tmp_path, rules_copy):
    data = b'A' * 4096
    big = tmp_path / 'big.bin'
    big.write_bytes(data)
    rep = tmp_path / 'rep.json'
    rep.write_text(json.dumps({'malicious': {hashlib.sha256(data).hexdigest(): 'known'},
                               'trusted': {}}))
    engine = core.Engine(rules_copy, str(rep), max_scan_bytes=1024)
    results = engine.scan_file(str(big))
    assert results['verdict'] == 'MALICIOUS'
    assert core.auto_quarantine_allowed(results)


def test_under_limit_is_scanned_fully(tmp_path, make_engine):
    small = tmp_path / 'small.txt'
    small.write_bytes(b'hello ' * 100)
    results = make_engine(max_scan_bytes=1 << 20).scan_file(str(small))
    assert 'partial_scan' not in results['details']
    assert results['verdict'] == 'CLEAN'
    assert not core.needs_alert(results)


def test_defaults():
    assert core.MAX_SCAN_BYTES == 256 * 1024 * 1024
    assert core.OVERSIZE_WINDOW_BYTES == 16 * 1024 * 1024


@pytest.mark.skipif(os.environ.get('MIE_RUN_HEAVY') != '1',
                    reason='hashes a 1 GiB sparse file (CPU-heavy); set MIE_RUN_HEAVY=1')
def test_1gib_file_peak_rss_under_1gib(tmp_path, rules_copy, rep_copy):
    '''B5-large stand-in: a 1 GiB + 1 byte sparse benign file. Peak RSS of
    the scanning process must stay at or below 1 GiB; verdict partial scan.'''
    big = tmp_path / 'large.bin'
    with open(big, 'wb') as f:
        f.truncate(1024 ** 3 + 1)
    code = (
        'import sys, json, resource\n'
        f'sys.path.insert(0, {REPO!r})\n'
        'from dexmond_mie.core import Engine\n'
        f'r = Engine({rules_copy!r}, {rep_copy!r}).scan_file({str(big)!r})\n'
        'print(json.dumps({"verdict": r["verdict"], '
        '"rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))\n')
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
    res = json.loads(out.stdout.strip().splitlines()[-1])
    print(res)
    assert res['verdict'] == core.PARTIAL_VERDICT
    assert res['rss_kib'] <= 1024 * 1024
