'''scripts/check_bundle.py: the static check run on the Windows build in CI.
Uses a synthetic bundle folder (no build here).'''
import hashlib
import importlib.util
import os
import shutil

import pytest

from conftest import REPO

_spec = importlib.util.spec_from_file_location('check_bundle',
                                               os.path.join(REPO, 'scripts', 'check_bundle.py'))
check_bundle = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_bundle)


def _good_bundle(tmp_path):
    bundle = tmp_path / 'DexmondMIE'
    root = bundle / '_internal'
    (root / 'rules').mkdir(parents=True)
    for name in os.listdir(os.path.join(REPO, 'rules')):
        if name.endswith('.yar') and name != 'auto_generated.yar':
            shutil.copyfile(os.path.join(REPO, 'rules', name), root / 'rules' / name)
    for rel in ('data/reputation.json', 'config/trusted_publishers.json',
                'trust/authenticode_roots.pem'):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(os.path.join(REPO, *rel.split('/')), root / rel)
    (bundle / 'DexmondMIE.exe').write_bytes(b'MZ' + b'\0' * 4094)
    return bundle


def test_pinned_value_is_read_from_source():
    pinned = check_bundle.pinned_roots_sha256()
    assert pinned and len(pinned) == 64


def test_complete_bundle_passes(tmp_path):
    pem = os.path.join(REPO, 'trust', 'authenticode_roots.pem')
    with open(pem, 'rb') as f:
        if hashlib.sha256(f.read()).hexdigest() != check_bundle.pinned_roots_sha256():
            pytest.skip('checkout changed the PEM bytes (autocrlf); the build job disables it')
    assert check_bundle.check_bundle(str(_good_bundle(tmp_path))) == []


@pytest.mark.parametrize('damage,expect', [
    (lambda b: (b / '_internal' / 'rules' / 'eicar.yar').unlink(), 'rule file not bundled'),
    (lambda b: (b / '_internal' / 'rules' / 'proposed').mkdir(), 'rules/proposed/'),
    (lambda b: (b / '_internal' / 'trust' / 'authenticode_roots.pem').write_bytes(b'x'),
     'authenticode_roots.pem sha256'),
    (lambda b: (b / 'DexmondMIE.exe').write_bytes(b'MZ' + b'\0' * 500 + b'UPX0'), 'UPX'),
    (lambda b: (b / '_internal' / 'data' / 'reputation.json').unlink(), 'data/reputation.json'),
])
def test_damaged_bundle_fails(tmp_path, damage, expect):
    bundle = _good_bundle(tmp_path)
    damage(bundle)
    problems = check_bundle.check_bundle(str(bundle))
    assert any(expect in p for p in problems), problems
