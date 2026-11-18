'''FA-1 / FA-2: the string IOCs no longer re-count evidence that is not what
they were written for. Synthetic benign and synthetic matching content only
(no malware, no EICAR content). The PE is a stand-in (fakepe), so the
engine tests are PASS UNDER MOCK; the string tests use the real regexes.

FA-1: in a parsed PE, an API name that is exactly one of the file's own
      imported function names is the import evidence (already judged by the
      import analysis); it is no longer scored again as a suspicious string.
      API names that are NOT imported (run-time resolution strings) still are.
FA-2: the "-enc" PowerShell IOC must be a command-line token (a prefix of
      -EncodedCommand from -enc on), not a substring of "Content-Encoding",
      "--encoding" or "-encrypt".'''
import struct

import pytest

from fakepe import FakeSection, patch_engine_pe
from dexmond_mie import core
from dexmond_mie.utils import StringExtractor


def _iocs(text, key):
    _, iocs = StringExtractor.extract_ascii_unicode(text.encode('ascii'), 5)
    return iocs.get(key, [])


# ------------------------------------------------------------- FA-2 regex

@pytest.mark.parametrize('text', [
    'powershell.exe -enc SQBFAFgA',                 # literal name + token
    'cmd /c start -enc SQBFAFgA',                   # token alone
    'x -EncodedCommand SQBFAFgA',
    'x -encod SQBFAFgA',                            # abbreviation PowerShell accepts
    'x -ENCODEDCOMMAND SQBFAFgA',
    'pwsh --enc SQBFAFgA',
    'run "-enc" SQBFAFgA',
])
def test_powershell_encoded_parameter_still_matches(text):
    assert _iocs(text, 'powershell')


@pytest.mark.parametrize('text', [
    'Accept-Encoding: gzip, deflate',
    'Content-Encoding: br',
    'git log --encoding=utf-8',
    'javac -encoding UTF-8 Main.java',
    'openssl smime -encrypt -in file',
    'x-enc-y header value',
])
def test_encoding_words_are_not_the_powershell_parameter(text):
    assert _iocs(text, 'powershell') == []


# ------------------------------------------------------------- FA-1 engine

def _pe_file(tmp_path, strings=b''):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    p = tmp_path / 'tool.exe'
    p.write_bytes(bytes(hdr) + b'\0' * 64 + strings + b'\0' * 4096)
    return str(p)


def _scan(tmp_path, make_engine, monkeypatch, imports, strings):
    patch_engine_pe(monkeypatch, sections=[FakeSection('.text', 6.0, 'RX')], imports=imports)
    engine = make_engine(signature_verifier=lambda path, **kw: {'status': 'unsigned',
                                                                 'publisher': None})
    monkeypatch.setattr(engine.yara_engine, 'scan', lambda path: [])
    return engine.scan_file(_pe_file(tmp_path, strings))


def _string_findings(results):
    return [f for f in results['findings'] if f['category'] == 'suspicious_string']


def test_imported_api_name_is_not_counted_again_as_a_string(tmp_path, make_engine, monkeypatch):
    # benign: the import name table holds "VirtualAlloc" because the file imports it
    imports = {'KERNEL32.dll': ['VirtualAlloc', 'CreateFileW', 'ReadFile', 'CloseHandle']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports,
                    b'\0\0VirtualAlloc\0\0CreateFileW\0\0ReadFile\0')
    assert _string_findings(results) == []
    assert 'suspicious_api' not in results['details'].get('iocs', {})
    assert results['details']['api_strings_in_imports_only'] is True


def test_api_name_not_imported_still_counts(tmp_path, make_engine, monkeypatch):
    # matching: the name is in the file as a string for run-time resolution,
    # but NOT in the import table
    imports = {'KERNEL32.dll': ['VirtualAlloc', 'CreateFileW', 'ReadFile', 'CloseHandle']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports,
                    b'\0\0VirtualAlloc\0\0WriteProcessMemory\0\0CreateRemoteThread\0')
    found = _string_findings(results)
    assert len(found) == 1 and 'suspicious_api' in found[0]['description']
    assert results['details']['iocs']['suspicious_api'] == ['CreateRemoteThread',
                                                            'WriteProcessMemory']


def test_imported_dangerous_api_is_still_judged_by_the_import_analysis(
        tmp_path, make_engine, monkeypatch):
    imports = {'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports,
                    b'\0\0VirtualAllocEx\0\0WriteProcessMemory\0\0CreateRemoteThread\0')
    cats = {f['category'] for f in results['findings']}
    assert {'api_chain', 'suspicious_import'} <= cats
    assert results['score'] >= 30


def test_non_pe_file_keeps_api_string_finding(tmp_path, make_engine):
    # a script that names injection APIs: no import table, the strings count
    p = tmp_path / 'loader.ps1'
    p.write_bytes(b'$k = "VirtualAlloc"; $w = "WriteProcessMemory"\n')
    results = make_engine().scan_file(str(p))
    assert any('suspicious_api' in f['description'] for f in _string_findings(results))


def test_helper_drops_only_exact_import_names():
    strings = ['VirtualAlloc', 'call VirtualAlloc here', 'WriteProcessMemory']
    assert core._api_names_outside_imports(strings, {'VirtualAlloc'}) == [
        'VirtualAlloc', 'WriteProcessMemory']
    assert core._api_names_outside_imports(['VirtualAlloc'], {'VirtualAlloc'}) == []
