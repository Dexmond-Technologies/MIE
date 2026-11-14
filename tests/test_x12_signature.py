'''X12: a VALID Authenticode signature from a trusted publisher caps the
heuristic score at LOW. Anything less (unsigned, invalid, unavailable,
untrusted publisher) changes nothing, and critical YARA / reputation are
never capped. The verifier is mocked here (PASS UNDER MOCK); the real
WinVerifyTrust path is Windows-only and NOT RUN on Linux.'''
import struct
import sys

import pytest

from fakepe import FakeSection, patch_engine_pe
from dexmond_mie import signature

SYSINTERNALS_LIKE = dict(
    sections=[FakeSection('.text', 6.0, 'RX')],
    imports={'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                              'ReadProcessMemory'],
             'ADVAPI32.dll': ['OpenProcessToken', 'AdjustTokenPrivileges']})
INJECTION_YARA = {'rule': 'Process_Injection_APIs', 'namespace': 'suspicious_behavior',
                  'tags': [], 'strings': 3,
                  'meta': {'description': 'injection APIs', 'severity': 'high'}}
CRITICAL_YARA = {'rule': 'Mimikatz_Credential_Tool', 'namespace': 'malware_families',
                 'tags': [], 'strings': 2,
                 'meta': {'description': 'mimikatz', 'severity': 'critical'}}


def _pe_file(tmp_path):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    p = tmp_path / 'procexp.exe'
    p.write_bytes(bytes(hdr) + b'\0' * 4096)
    return str(p)


def _scan(tmp_path, make_engine, monkeypatch, sig, yara=(INJECTION_YARA,)):
    patch_engine_pe(monkeypatch, **SYSINTERNALS_LIKE)
    engine = make_engine(signature_verifier=lambda path: dict(sig),
                         trusted_publishers=('Microsoft Corporation',))
    monkeypatch.setattr(engine.yara_engine, 'scan', lambda path: [dict(m) for m in yara])
    return engine.scan_file(_pe_file(tmp_path))


def test_valid_trusted_signature_caps_at_low(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch,
                    {'status': 'valid', 'publisher': 'Microsoft Corporation'})
    assert results['score'] <= 29
    assert results['details']['signature']['heuristics_capped_at'] == 29


@pytest.mark.parametrize('sig', [
    {'status': 'unavailable', 'publisher': None},
    {'status': 'unsigned', 'publisher': None},
    {'status': 'invalid', 'publisher': 'Microsoft Corporation'},
    {'status': 'valid', 'publisher': 'Some Other Vendor Ltd'},
])
def test_no_cap_without_valid_trusted_signature(tmp_path, make_engine, monkeypatch, sig):
    results = _scan(tmp_path, make_engine, monkeypatch, sig)
    assert results['score'] >= 30, results['findings']
    assert 'heuristics_capped_at' not in results['details']['signature']


def test_critical_yara_not_capped_by_signature(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch,
                    {'status': 'valid', 'publisher': 'Microsoft Corporation'},
                    yara=(INJECTION_YARA, CRITICAL_YARA))
    assert results['verdict'] == 'MALICIOUS'


@pytest.mark.skipif(sys.platform == 'win32', reason='checks the non-Windows path')
def test_non_windows_reports_unavailable(tmp_path):
    p = tmp_path / 'x.exe'
    p.write_bytes(b'MZ')
    assert signature.verify_authenticode(str(p))['status'] == 'unavailable'


def test_trusted_publishers_configurable(monkeypatch):
    monkeypatch.setenv('DEXMOND_TRUSTED_PUBLISHERS', 'A Corp; B Ltd')
    assert signature.trusted_publishers() == ('A Corp', 'B Ltd')
    monkeypatch.delenv('DEXMOND_TRUSTED_PUBLISHERS')
    assert signature.trusted_publishers() == ('Microsoft Corporation',)
