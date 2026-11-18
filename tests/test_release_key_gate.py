'''scripts/check_release_key.py: the sale-build gate (port of the CypherNight
desktop's check-release-key.cjs). Synthetic 1952-byte keys only.'''
import base64
import hashlib
import importlib.util
import os

import pytest

from conftest import REPO

_spec = importlib.util.spec_from_file_location('check_release_key',
                                               os.path.join(REPO, 'scripts', 'check_release_key.py'))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

KEY = os.urandom(1952)
KEY_B64 = base64.b64encode(KEY).decode()
FP = hashlib.sha256(KEY).hexdigest()


def _module(key_b64=KEY_B64, production=FP, blocklist=()):
    listed = ''.join(f'    "{b}",  # test key\n' for b in blocklist)
    return (f'LICENSE_PUBLIC_KEY_B64 = "{key_b64}"\n'
            f'PROD_PUBKEY_SHA256 = "{production}"\n'
            f'NON_PRODUCTION_PUBKEY_SHA256 = [\n{listed}]\n')


def test_current_tree_is_refused():
    r = gate.check_release_key_file()
    assert r['ok'] is False
    assert 'no licence key is embedded' in r['reason']


def test_production_key_passes():
    r = gate.check_release_key(_module())
    assert r == {'ok': True, 'fingerprint': FP,
                 'reason': 'The embedded licence key is the production key.'}


@pytest.mark.parametrize('source,expect', [
    (_module(production='UNSET-PRODUCTION-KEY-NOT-YET-CREATED'), 'PROD_PUBKEY_SHA256 is not set'),
    (_module(blocklist=[FP]), 'development or test key'),
    (_module(production='0' * 64), 'is not the production key'),
    (_module(key_b64=base64.b64encode(os.urandom(100)).decode()), 'not an ML-DSA-65 public key'),
    (_module(key_b64=''), 'no licence key is embedded'),
    (_module() + 'PROD_PUBKEY_SHA256 = "x"\n', 'expected one declaration'),
    (_module().replace(']', '    not_a_string,\n]'), 'only quoted fingerprints'),
])
def test_refusals(source, expect):
    r = gate.check_release_key(source)
    assert r['ok'] is False and expect in r['reason'], r


def test_production_in_blocklist_refused():
    other = hashlib.sha256(b'other').hexdigest()
    r = gate.check_release_key(_module(production=other, blocklist=[other]))
    assert r['ok'] is False


def test_cli_exit_codes(tmp_path, capsys):
    good = tmp_path / 'licence_key.py'
    good.write_text(_module())
    assert gate.main(['x', str(good)]) == 0
    assert gate.main(['x']) == 1
