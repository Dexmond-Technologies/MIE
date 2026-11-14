'''X3: routine APIs no longer count as suspicious imports on their own.'''
from fakepe import analyzer
from dexmond_mie.pe_analyzer import CHAIN_ONLY_IMPORTS

ROUTINE = ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'VirtualProtect', 'VirtualAlloc',
           'IsDebuggerPresent', 'OpenProcessToken', 'RegSetValueExA', 'RegSetValueExW',
           'ShellExecuteA', 'ShellExecuteW']


def test_routine_apis_alone_are_not_suspicious():
    a = analyzer(imports={'KERNEL32.dll': ROUTINE[:7], 'ADVAPI32.dll': ROUTINE[7:9],
                          'SHELL32.dll': ROUTINE[9:]})
    assert a.get_suspicious_imports() == []
    assert set(ROUTINE) == CHAIN_ONLY_IMPORTS


def test_injection_apis_still_reported():
    a = analyzer(imports={'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'LoadLibraryA']})
    assert a.get_suspicious_imports() == ['VirtualAllocEx', 'WriteProcessMemory']


def test_routine_apis_still_count_inside_chains():
    a = analyzer(imports={'URLMON.dll': ['URLDownloadToFileA'], 'SHELL32.dll': ['ShellExecuteA']})
    assert any('Download' in c for c in a.get_api_chains())
