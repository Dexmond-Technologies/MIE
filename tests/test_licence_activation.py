'''Licence by activation code (client side, dexmond_mie/licence.py). No
network: the HTTP post is injected. No ML-DSA library: the verifier is
injected (PASS UNDER MOCK for the signature step). No real key: the public
key is 1952 synthetic random bytes.'''
import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

from dexmond_mie import licence, licence_key

HWID = 'A' * 32
KEY = os.urandom(licence.ML_DSA_65_PUBLIC_KEY_BYTES)
SIG = os.urandom(licence.ML_DSA_65_SIGNATURE_BYTES)
NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


def _licence(hwid=HWID, expiry='2027-11-18T00:00:00Z', sig=SIG):
    payload = f'{hwid}|{expiry}'.encode('ascii')
    return base64.b64encode(sig).decode() + '.' + base64.b64encode(payload).decode()


def _accept(signature, message, public_key):
    return signature == SIG and public_key == KEY


# ------------------------------------------------------------- hardware id

def test_hardware_id_matches_the_desktop_formula():
    inputs = {'platform': 'win32', 'arch': 'x64', 'cpuModel': 'Example CPU 3.0GHz',
              'cpuCount': 8, 'hostname': 'DESKTOP-1'}
    expect = hashlib.sha256(b'win32-x64-Example CPU 3.0GHz-8-DESKTOP-1').hexdigest()[:32].upper()
    assert licence.hardware_id(inputs) == expect
    assert len(expect) == 32


def test_hwid_inputs_use_node_names(monkeypatch):
    monkeypatch.setattr(licence.platform, 'machine', lambda: 'AMD64')
    monkeypatch.setattr(licence.sys, 'platform', 'win32')
    monkeypatch.setattr(licence, '_cpu_model', lambda: 'Example CPU')
    monkeypatch.setattr(licence.os, 'cpu_count', lambda: 4)
    monkeypatch.setattr(licence.socket, 'gethostname', lambda: 'host')
    assert licence.hwid_inputs() == {'platform': 'win32', 'arch': 'x64', 'cpuModel': 'Example CPU',
                                     'cpuCount': 4, 'hostname': 'host'}
    monkeypatch.setattr(licence.platform, 'machine', lambda: 'aarch64')
    monkeypatch.setattr(licence.sys, 'platform', 'linux')
    assert licence.hwid_inputs()['arch'] == 'arm64'
    assert licence.hwid_inputs()['platform'] == 'linux'


def test_renaming_the_computer_changes_the_id():
    base = {'platform': 'win32', 'arch': 'x64', 'cpuModel': 'c', 'cpuCount': 2, 'hostname': 'a'}
    assert licence.hardware_id(base) != licence.hardware_id(dict(base, hostname='b'))


# -------------------------------------------------------------- activation

def test_empty_activation_url_is_disabled_and_sends_nothing():
    sent = []
    with pytest.raises(licence.ActivationError) as e:
        licence.activate('CODE-1', url='', hwid=HWID, post=lambda *a: sent.append(a))
    assert str(e.value) == licence.DISABLED_MESSAGE
    assert sent == []


def test_shipped_activation_url_is_empty():
    assert licence.ACTIVATION_URL == ''


def test_plain_http_is_refused_and_sends_nothing():
    sent = []
    with pytest.raises(licence.ActivationError, match='not https'):
        licence.activate('CODE-1', url='http://example.invalid/activate', hwid=HWID,
                         post=lambda *a: sent.append(a))
    assert sent == []


def test_request_holds_exactly_product_code_hwid_version():
    seen = {}

    def post(url, body, timeout):
        seen.update(url=url, body=body, timeout=timeout)
        return 200, {'licence': 'L'}
    assert licence.activate(' CODE-1 ', url='https://example.invalid/a', hwid=HWID, post=post) == 'L'
    assert seen['body'] == {'product': 'mie', 'code': 'CODE-1', 'hwid': HWID,
                            'app_version': licence.__version__}
    assert seen['timeout'] == licence.ACTIVATION_TIMEOUT_S


@pytest.mark.parametrize('answer,expect', [
    ((403, {'error': 'This code was cancelled.'}), 'This code was cancelled.'),
    ((500, None), 'cannot read'),
    ((200, {'licence': ''}), 'HTTP 200'),
])
def test_refusals_give_plain_messages(answer, expect):
    with pytest.raises(licence.ActivationError, match=expect):
        licence.activate('CODE-1', url='https://example.invalid/a', hwid=HWID,
                         post=lambda *a: answer)


@pytest.mark.parametrize('code', ['', '   ', 'x' * 129, 'bad\ncode'])
def test_bad_code_is_refused_before_sending(code):
    with pytest.raises(licence.ActivationError, match='activation code'):
        licence.activate(code, url='https://example.invalid/a', hwid=HWID,
                         post=lambda *a: pytest.fail('must not send'))


# ----------------------------------------------------------- licence check

def test_valid_licence_accepted():
    r = licence.check_licence(_licence(), HWID, KEY, _accept, NOW)
    assert r['valid'] is True and r['days_remaining'] == 365


@pytest.mark.parametrize('text,hwid,verify,reason', [
    (_licence(hwid='B' * 32), HWID, _accept, 'OTHER_COMPUTER'),
    (_licence(expiry='2026-01-01'), HWID, _accept, 'EXPIRED'),
    (_licence(sig=os.urandom(licence.ML_DSA_65_SIGNATURE_BYTES)), HWID, _accept, 'BAD_SIGNATURE'),
    (_licence(sig=b'short'), HWID, _accept, 'BAD_SIGNATURE'),
    ('not-a-licence', HWID, _accept, 'MALFORMED'),
    ('a.b.c', HWID, _accept, 'MALFORMED'),
    (_licence(expiry='someday'), HWID, _accept, 'MALFORMED'),
    (_licence(), '', _accept, 'MALFORMED'),
    (None, HWID, _accept, 'MALFORMED'),
])
def test_refusals(text, hwid, verify, reason):
    r = licence.check_licence(text, hwid, KEY, verify, NOW)
    assert r['valid'] is False and r['refusal'] == reason


def test_signature_is_checked_before_the_payload_is_believed():
    # another computer's licence with a bad signature: BAD_SIGNATURE, not OTHER_COMPUTER
    bad = _licence(hwid='B' * 32, sig=os.urandom(licence.ML_DSA_65_SIGNATURE_BYTES))
    assert licence.check_licence(bad, HWID, KEY, _accept, NOW)['refusal'] == 'BAD_SIGNATURE'


def test_default_verifier_fails_closed():
    r = licence.check_licence(_licence(), HWID, KEY, None, NOW)
    assert r['valid'] is False and r['refusal'] == 'NO_VERIFIER'
    assert 'verifier not available' in r['message']


def test_verifier_exception_is_a_refusal():
    def boom(*a):
        raise RuntimeError('x')
    assert licence.check_licence(_licence(), HWID, KEY, boom, NOW)['refusal'] == 'CHECK_FAILED'


def test_shipped_build_has_no_key_and_is_a_test_build():
    assert licence.embedded_public_key() == b''
    assert licence.is_test_build() is True
    # with no embedded key nothing can be accepted, whatever the verifier says
    r = licence.check_licence(_licence(), HWID, None, lambda *a: True, NOW)
    assert r['refusal'] == 'BAD_SIGNATURE'


def test_classify_fingerprint():
    fp = hashlib.sha256(KEY).hexdigest()
    assert licence.classify_fingerprint(fp, production=fp, blocklist=[]) == 'PRODUCTION'
    assert licence.classify_fingerprint(fp, production=fp, blocklist=[fp]) == 'BLOCKLISTED'
    assert licence.classify_fingerprint(fp, production='UNSET', blocklist=[]) == 'UNKNOWN'
    assert licence_key.TEST_BUILD_NOTICE.startswith('TEST BUILD')


def test_licence_saved_and_loaded_from_given_path(tmp_path):
    path = str(tmp_path / 'licence.txt')
    licence.save_licence(_licence() + '\n', path)
    assert licence.load_licence(path) == _licence()
    assert licence.load_licence(str(tmp_path / 'missing.txt')) is None
