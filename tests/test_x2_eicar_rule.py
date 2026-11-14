'''X2: the EICAR rule matches only a real EICAR file (string at offset 0,
file at most 128 bytes), not a document that mentions the string.'''
import os
import re

import pytest

from conftest import REPO, eicar_path

RULE = os.path.join(REPO, 'rules', 'eicar.yar')


def test_rule_is_anchored_and_size_limited():
    text = open(RULE).read()
    cond = text.split('condition:')[1]
    assert re.search(r'\$head at 0', cond)
    assert re.search(r'\$body at 28', cond)
    assert 'filesize <= 128' in cond


@pytest.mark.parametrize('name', ['eicar.com', 'eicar.com.txt'])
def test_official_files_match(name):
    yara = pytest.importorskip('yara')
    rules = yara.compile(filepath=RULE)
    assert [m.rule for m in rules.match(eicar_path(name))] == ['EICAR_Test_File']


def test_document_mentioning_the_name_does_not_match(tmp_path):
    '''The old rule fired on the bare name anywhere in a file.'''
    yara = pytest.importorskip('yara')
    doc = tmp_path / 'notes.txt'
    doc.write_text('Our scanner test uses the EICAR-STANDARD-ANTIVIRUS-TEST-FILE '
                   'as described in the vendor documentation.\n' * 3)
    rules = yara.compile(filepath=RULE)
    assert rules.match(str(doc)) == []
