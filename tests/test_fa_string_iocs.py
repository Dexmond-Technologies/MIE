'''FA-1 / FA-2: the string IOCs no longer re-count evidence that is not what
they were written for. Synthetic benign and synthetic matching content only
(no malware, no EICAR content). The PE is a stand-in (fakepe), so the
engine tests are PASS UNDER MOCK; the string tests use the real regexes.

FA-1: in a parsed PE, the import hint/name-table string of an import that
      the import analysis SCORED (SUSPICIOUS_IMPORTS or a reported chain) is
      not scored again as a suspicious string. Suppression is by file offset:
      the same name elsewhere in the file, names the import analysis does
      not score, and unknown offsets still count (bypass tests below).
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
# Layout of the synthetic PE: header, then the "import hint/name table" at
# NAME_TABLE (2 hint bytes + name + NUL per entry), then other strings at
# ELSEWHERE. fakepe reports each import's name_offset like pefile does.
NAME_TABLE = 0x300
ELSEWHERE = 0x800


def _pe_bytes(table_names, other=b''):
    data = bytearray(0x1000)
    data[0:2] = b'MZ'
    data[0x3c:0x40] = struct.pack('<I', 0x40)
    data[0x40:0x44] = b'PE\0\0'
    offsets, pos = {}, NAME_TABLE
    for name in table_names:
        raw = name.encode('ascii')
        data[pos:pos + 2] = b'\x01\x00'          # hint: high byte not printable
        offsets[name] = pos + 2
        data[pos + 2:pos + 2 + len(raw)] = raw
        pos += 2 + len(raw) + 1
    data[ELSEWHERE:ELSEWHERE + len(other)] = other
    return bytes(data), offsets


def _scan(tmp_path, make_engine, monkeypatch, imports, other=b'', with_offsets=True):
    names = [f for funcs in imports.values() for f in funcs]
    data, offsets = _pe_bytes(names, other)
    patch_engine_pe(monkeypatch, sections=[FakeSection('.text', 6.0, 'RX')], imports=imports,
                    import_offsets=offsets if with_offsets else None)
    engine = make_engine(signature_verifier=lambda path, **kw: {'status': 'unsigned',
                                                                 'publisher': None})
    monkeypatch.setattr(engine.yara_engine, 'scan', lambda path: [])
    p = tmp_path / 'tool.exe'
    p.write_bytes(data)
    return engine.scan_file(str(p))


def _api_strings(results):
    return results['details'].get('iocs', {}).get('suspicious_api', [])


def _string_findings(results):
    return [f for f in results['findings'] if f['category'] == 'suspicious_string']


# The dynamic-resolution chain fires, so VirtualAlloc is a scored import.
DYNAMIC = {'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress', 'VirtualAlloc', 'CreateFileW',
                            'ReadFile', 'CloseHandle']}


def test_benign_scored_import_name_is_not_counted_twice(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch, DYNAMIC)
    assert any(f['category'] == 'dynamic_resolution_chain' for f in results['findings'])
    assert _api_strings(results) == []
    assert _string_findings(results) == []
    assert results['details']['api_strings_in_scored_imports_only'] is True


def test_bypass_import_cannot_hide_the_same_name_elsewhere(tmp_path, make_engine, monkeypatch):
    # matching: VirtualAlloc is imported (and scored) AND appears again as a
    # separate string elsewhere: the second occurrence must still count
    results = _scan(tmp_path, make_engine, monkeypatch, DYNAMIC,
                    other=b'\0resolve VirtualAlloc at run time\0')
    assert _api_strings(results) == ['VirtualAlloc']
    assert len(_string_findings(results)) == 1


def test_bypass_unscored_import_name_is_never_suppressed(tmp_path, make_engine, monkeypatch):
    # matching: "ReflectiveLoader" listed as an import; the import analysis
    # never scores it, so its string match stays
    imports = {'evil.dll': ['ReflectiveLoader'], 'KERNEL32.dll': ['CreateFileW', 'ReadFile']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports)
    assert _api_strings(results) == ['ReflectiveLoader']
    assert len(_string_findings(results)) == 1


def test_routine_import_outside_any_chain_is_not_suppressed(tmp_path, make_engine, monkeypatch):
    # VirtualAlloc imported without a reported chain: not scored by the import
    # analysis, so the string still counts (old behaviour kept)
    imports = {'KERNEL32.dll': ['VirtualAlloc', 'CreateFileW', 'ReadFile', 'CloseHandle']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports)
    assert _api_strings(results) == ['VirtualAlloc']


def test_unknown_name_offset_fails_safe(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch, DYNAMIC, with_offsets=False)
    assert _api_strings(results) == ['VirtualAlloc']


def test_imported_dangerous_api_is_still_judged_by_the_import_analysis(
        tmp_path, make_engine, monkeypatch):
    imports = {'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']}
    results = _scan(tmp_path, make_engine, monkeypatch, imports)
    cats = {f['category'] for f in results['findings']}
    assert {'api_chain', 'suspicious_import'} <= cats
    assert results['score'] >= 30


def test_non_pe_file_keeps_api_string_finding(tmp_path, make_engine):
    # a script that names injection APIs: no import table, the strings count
    p = tmp_path / 'loader.ps1'
    p.write_bytes(b'$k = "VirtualAlloc"; $w = "WriteProcessMemory"\n')
    results = make_engine().scan_file(str(p))
    assert any('suspicious_api' in f['description'] for f in _string_findings(results))


def test_helper_skips_only_exact_spans():
    data = b'\0\0VirtualAlloc\0\0VirtualAlloc\0'
    first = (2, 2 + len('VirtualAlloc'))
    assert core._api_names_outside_spans(data, {first}) == ['VirtualAlloc']
    second = (16, 16 + len('VirtualAlloc'))
    assert core._api_names_outside_spans(data, {first, second}) == []


@pytest.mark.parametrize('imports', [
    {'K.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']},
    {'U.dll': ['URLDownloadToFileA'], 'S.dll': ['ShellExecuteA']},
    {'U.dll': ['SetWindowsHookExA', 'GetAsyncKeyState']},
    {'K.dll': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'A', 'B', 'C']},
    {'K.dll': ['LoadLibraryA', 'GetProcAddress', 'ExitProcess']},
    {'A.dll': ['RegSetValueExW'], 'K.dll': ['CreateProcessW']},
    {'A.dll': ['OpenProcessToken', 'AdjustTokenPrivileges']},
    {'K.dll': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']},
])
def test_every_reported_chain_has_its_api_list(imports):
    '''scored_import_names() must know the APIs of every chain the analyzer
    can report, or FA-1 would leave that chain's strings double-counted.'''
    from fakepe import analyzer
    from dexmond_mie.pe_analyzer import CHAIN_APIS
    a = analyzer(imports=imports)
    chains = a.get_api_chains() + a.get_minor_api_chains()
    assert chains
    for chain in chains:
        assert any(chain.startswith(prefix) for prefix in CHAIN_APIS), chain
    imported = {f for funcs in imports.values() for f in funcs}
    assert a.scored_import_names() <= imported and a.scored_import_names()
