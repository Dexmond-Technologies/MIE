'''Shared fixtures for the MIE test suite.

Rules:
- Every Engine test works on a COPY of rules/ and data/reputation.json in
  tmp_path, so scans never write into the repository.
- EICAR content is never generated. The official EICAR files are referenced
  by path; tests that need them are skipped when the folder is absent.
'''
import os
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

EICAR_DIR = os.environ.get('MIE_EICAR_DIR', '/home/r/Downloads/EICAR-for-MIE')
EICAR_FILES = ('eicar.com', 'eicar.com.txt', 'eicar_com.zip', 'eicar_com2.zip')


def eicar_path(name):
    path = os.path.join(EICAR_DIR, name)
    if not os.path.isfile(path):
        pytest.skip(f'official EICAR file not present: {path}')
    return path


@pytest.fixture
def rules_copy(tmp_path):
    dst = tmp_path / 'rules'
    shutil.copytree(os.path.join(REPO, 'rules'), dst,
                    ignore=shutil.ignore_patterns('proposed', 'auto_generated.yar'))
    return str(dst)


@pytest.fixture
def rep_copy(tmp_path):
    dst = tmp_path / 'reputation.json'
    shutil.copyfile(os.path.join(REPO, 'data', 'reputation.json'), dst)
    return str(dst)


@pytest.fixture
def make_engine(rules_copy, rep_copy):
    from dexmond_mie.core import Engine

    def _make(**kwargs):
        return Engine(rules_copy, rep_copy, **kwargs)
    return _make
