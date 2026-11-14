'''X3: routine APIs no longer count as suspicious imports on their own, but
each one still feeds a real behavioural chain (no silent fail-open).'''
import pytest

from fakepe import analyzer
from dexmond_mie.pe_analyzer import CHAIN_ONLY_IMPORTS
from dexmond_mie.scoring import Scorer

ROUTINE = ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'VirtualProtect', 'VirtualAlloc',
           'IsDebuggerPresent', 'OpenProcessToken', 'RegSetValueExA', 'RegSetValueExW',
           'ShellExecuteA', 'ShellExecuteW']

# A typical benign import set: dynamic loading plus ordinary file/UI APIs
BENIGN = {'KERNEL32.dll': ['LoadLibraryW', 'GetProcAddress', 'CreateFileW', 'ReadFile',
                           'WriteFile', 'CloseHandle', 'GetLastError', 'HeapAlloc',
                           'HeapFree', 'GetModuleHandleW', 'OutputDebugStringW',
                           'IsDebuggerPresent'],
          'USER32.dll': ['MessageBoxW', 'GetAsyncKeyState', 'GetKeyboardState']}


def _all(a):
    return a.get_api_chains() + a.get_minor_api_chains()


def test_routine_apis_alone_are_not_suspicious():
    a = analyzer(imports={'KERNEL32.dll': ROUTINE[:7], 'ADVAPI32.dll': ROUTINE[7:9],
                          'SHELL32.dll': ROUTINE[9:]})
    assert a.get_suspicious_imports() == []
    assert set(ROUTINE) == CHAIN_ONLY_IMPORTS


def test_injection_apis_still_reported():
    a = analyzer(imports={'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'LoadLibraryA']})
    assert a.get_suspicious_imports() == ['VirtualAllocEx', 'WriteProcessMemory']


def test_typical_benign_import_set_fires_no_chain():
    a = analyzer(imports=BENIGN)
    assert _all(a) == []
    assert a.get_suspicious_imports() == []


def test_loadlibrary_getprocaddress_alone_does_not_fire():
    a = analyzer(imports={'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress', 'CreateFileA',
                                           'ReadFile', 'CloseHandle', 'ExitProcess']})
    assert _all(a) == []


@pytest.mark.parametrize('imports,expect', [
    ({'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'CreateFileA',
                       'ReadFile', 'CloseHandle', 'ExitProcess']}, 'Dynamic API Resolution'),
    ({'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress', 'ExitProcess']}, 'only 3 imports'),
    ({'ADVAPI32.dll': ['RegSetValueExW'], 'KERNEL32.dll': ['CreateProcessW']}, 'Persistence'),
    ({'ADVAPI32.dll': ['OpenProcessToken', 'AdjustTokenPrivileges',
                       'LookupPrivilegeValueW']}, 'Privilege Adjustment'),
    ({'KERNEL32.dll': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']}, 'Anti-Debug'),
    ({'KERNEL32.dll': ['IsDebuggerPresent'], 'ntdll.dll': ['NtQueryInformationProcess']},
     'Anti-Debug'),
])
def test_each_minor_chain_fires(imports, expect):
    chains = analyzer(imports=imports).get_minor_api_chains()
    assert any(expect in c for c in chains), chains


def test_every_chain_only_import_is_used_by_a_chain():
    '''The comment "still used inside chains" must be true for each API.'''
    partners = {
        'LoadLibraryA': ['GetProcAddress', 'VirtualAlloc'],
        'LoadLibraryW': ['GetProcAddress', 'VirtualAlloc'],
        'GetProcAddress': ['LoadLibraryA', 'VirtualAlloc'],
        'VirtualProtect': ['LoadLibraryA', 'GetProcAddress'],
        'VirtualAlloc': ['LoadLibraryA', 'GetProcAddress'],
        'IsDebuggerPresent': ['CheckRemoteDebuggerPresent'],
        'OpenProcessToken': ['AdjustTokenPrivileges'],
        'RegSetValueExA': ['WinExec'],
        'RegSetValueExW': ['WinExec'],
        'ShellExecuteA': ['RegSetValueExA'],
        'ShellExecuteW': ['RegSetValueExA'],
    }
    assert set(partners) == CHAIN_ONLY_IMPORTS
    for api, others in partners.items():
        with_api = analyzer(imports={'X.dll': [api] + others + ['A', 'B', 'C', 'D']})
        without = analyzer(imports={'X.dll': others + ['A', 'B', 'C', 'D']})
        assert len(_all(with_api)) > len(_all(without)), api


def test_minor_chain_weight_is_moderate():
    assert Scorer.WEIGHTS['api_chain_minor'] < 30


def test_routine_apis_still_count_inside_strong_chains():
    a = analyzer(imports={'URLMON.dll': ['URLDownloadToFileA'], 'SHELL32.dll': ['ShellExecuteA']})
    assert any('Download' in c for c in a.get_api_chains())
