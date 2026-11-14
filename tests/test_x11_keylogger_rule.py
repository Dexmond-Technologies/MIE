'''X11: Keylogger_Indicators needs a keystroke-log marker ([BACKSPACE] or
[ENTER]) plus 2 of the key-state APIs; the APIs alone (every UI tool) do not
match. Test inputs are harmless synthetic MZ files.'''
import os
import re

import pytest

from conftest import REPO

RULE = os.path.join(REPO, 'rules', 'malware_families.yar')


def _keylogger_condition():
    text = open(RULE).read()
    block = text[text.index('rule Keylogger_Indicators'):]
    block = block[:block.index('\n}') + 2]
    return block.split('condition:')[1]


def test_condition_requires_marker():
    cond = re.sub(r'//[^\n]*', '', _keylogger_condition())
    assert '($d or $e)' in cond
    assert '2 of ($a, $b, $c)' in cond


def _mz(tmp_path, name, body):
    p = tmp_path / name
    p.write_bytes(b'MZ' + b'\0' * 62 + body)
    return str(p)


def test_ui_tool_imports_do_not_match(tmp_path):
    yara = pytest.importorskip('yara')
    rules = yara.compile(filepath=RULE)
    path = _mz(tmp_path, 'ui.exe', b'GetAsyncKeyState\0GetKeyboardState\0SetWindowsHookExW\0')
    assert 'Keylogger_Indicators' not in [m.rule for m in rules.match(path)]


def test_marker_plus_apis_matches(tmp_path):
    yara = pytest.importorskip('yara')
    rules = yara.compile(filepath=RULE)
    path = _mz(tmp_path, 'kl.exe', b'GetAsyncKeyState\0GetKeyboardState\0[BACKSPACE]\0')
    assert 'Keylogger_Indicators' in [m.rule for m in rules.match(path)]
