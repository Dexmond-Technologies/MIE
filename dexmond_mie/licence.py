'''Licence by activation code (client side). NOT WIRED INTO THE APP YET.

MIE has no paid tier today (the dashboard says "Free Edition"); which
features a licence would unlock is an OPEN QUESTION for the owner
(RELEASE_GAPS.md). This module only provides the pieces the shared Dexmond
activation service needs, so the decision can be wired in later:

  1. hardware_id(): first 32 hex characters (upper case, as the CypherNight
     desktop's electron/hwid.js) of SHA-256 over
         "platform-arch-cpuModel-cpuCount-hostname"
     with Node's names for platform and arch (see hwid_inputs()). These five
     inputs are personal data in the privacy texts; renaming the computer
     changes the id.
  2. activation_request() / activate(): POST JSON
         {"product": "mie", "code": ..., "hwid": ..., "app_version": ...}
     to ACTIVATION_URL over HTTPS. ACTIVATION_URL empty = activation is
     disabled and the user gets a plain message. Nothing else is sent: no
     files, no scan results, no keys.
     The response the client expects ({"licence": "<text>"} on success,
     {"error": "<text>"} otherwise) is an ASSUMPTION until the service exists.
  3. check_licence(): the licence text is base64(signature) + "." +
     base64("HWID|EXPIRY"), as in CypherNight. It is accepted only if the
     ML-DSA-65 signature verifies with the embedded public key
     (licence_key.LICENSE_PUBLIC_KEY_B64), the hardware id is this
     computer's and the expiry is in the future. Every other case, an
     exception included, is a refusal.

The ML-DSA-65 verify function is INJECTED. No ML-DSA library is a dependency
of MIE yet (choosing one is a SENTINEL item), so the default verifier refuses
everything with "licence verifier not available": the check fails closed.
'''
import base64
import binascii
import hashlib
import json
import logging
import os
import platform
import socket
import sys
from datetime import datetime, timezone

from . import __version__
from . import licence_key

logger = logging.getLogger('DEXMOND_MIE')

PRODUCT = 'mie'
# Empty = activation disabled. Set to the Dexmond activation endpoint (https://)
# once the service exists. Read by the app; tests pass their own URL.
ACTIVATION_URL = ''
ACTIVATION_TIMEOUT_S = 15
MAX_RESPONSE_BYTES = 64 * 1024

ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SIGNATURE_BYTES = 3309
MAX_PAYLOAD_BYTES = 512

DISABLED_MESSAGE = ('Activation is not available in this version of DEXMOND MIE. '
                    'No data was sent.')
LICENCE_MESSAGES = {
    'MALFORMED': 'This is not a DEXMOND MIE licence. It was not accepted.',
    'BAD_SIGNATURE': 'This licence is not valid. It was not accepted.',
    'OTHER_COMPUTER': 'This licence was issued for another computer. It was not accepted.',
    'EXPIRED': 'This licence has expired. It was not accepted.',
    'CHECK_FAILED': 'The licence could not be checked. It was not accepted.',
    'NO_VERIFIER': 'The licence could not be checked: licence verifier not available. '
                   'It was not accepted.',
}

# Node's os.arch() names for Python's platform.machine() values
_NODE_ARCH = {'amd64': 'x64', 'x86_64': 'x64', 'x64': 'x64',
              'arm64': 'arm64', 'aarch64': 'arm64',
              'x86': 'ia32', 'i386': 'ia32', 'i686': 'ia32',
              'armv7l': 'arm', 'armv6l': 'arm'}


class ActivationError(Exception):
    '''Activation did not produce a licence. str(e) is a plain message for
    the user.'''


# ------------------------------------------------------------- hardware id

def _cpu_model() -> str:
    '''The CPU brand string, read where Node (libuv) reads it, so the same
    computer gives the same id in every Dexmond app. "unknown" if absent.'''
    try:
        if sys.platform == 'win32':
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
                return str(winreg.QueryValueEx(key, 'ProcessorNameString')[0])
        if sys.platform.startswith('linux'):
            with open('/proc/cpuinfo', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if line.startswith('model name'):
                        return line.split(':', 1)[1].strip()
    except (OSError, ImportError, IndexError):
        pass
    return 'unknown'


def hwid_inputs() -> dict:
    '''The five inputs, with Node's names: platform = os.platform()
    ("win32", "linux", "darwin"), arch = os.arch() ("x64", "arm64", "ia32"),
    cpuModel = os.cpus()[0].model, cpuCount = os.cpus().length (logical
    CPUs), hostname = os.hostname().'''
    machine = platform.machine().lower()
    return {
        'platform': 'linux' if sys.platform.startswith('linux') else sys.platform,
        'arch': _NODE_ARCH.get(machine, machine or 'unknown'),
        'cpuModel': _cpu_model(),
        'cpuCount': os.cpu_count() or 0,
        'hostname': socket.gethostname(),
    }


def hardware_id(inputs: dict = None) -> str:
    i = inputs if inputs is not None else hwid_inputs()
    fingerprint = f"{i['platform']}-{i['arch']}-{i['cpuModel']}-{i['cpuCount']}-{i['hostname']}"
    return hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()[:32].upper()


# -------------------------------------------------------------- activation

def activation_request(code: str, hwid: str, app_version: str = __version__) -> dict:
    code = (code or '').strip()
    if not code or len(code) > 128 or not code.isprintable():
        raise ActivationError('Enter the activation code from your order e-mail.')
    return {'product': PRODUCT, 'code': code, 'hwid': hwid, 'app_version': app_version}


def _post_json(url: str, body: dict, timeout: float):
    '''Returns (status, parsed JSON or None). Network errors raise
    ActivationError with a plain message.'''
    import urllib.error
    import urllib.request
    data = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'User-Agent': f'DexmondMIE/{__version__}'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, OSError) as e:
        raise ActivationError('The activation service could not be reached. '
                              'Check the internet connection and try again.') from e
    if len(raw) > MAX_RESPONSE_BYTES:
        return status, None
    try:
        return status, json.loads(raw.decode('utf-8'))
    except ValueError:
        return status, None


def activate(code: str, url: str = None, hwid: str = None, post=None,
             timeout: float = ACTIVATION_TIMEOUT_S) -> str:
    '''Sends the activation request and returns the licence text the service
    issued (NOT yet checked: call check_licence). Raises ActivationError.'''
    url = ACTIVATION_URL if url is None else url
    if not url:
        raise ActivationError(DISABLED_MESSAGE)
    if not url.lower().startswith('https://'):
        raise ActivationError('Activation is misconfigured (the service address is not '
                              'https). No data was sent.')
    body = activation_request(code, hwid or hardware_id())
    status, answer = (post or _post_json)(url, body, timeout)
    if not isinstance(answer, dict):
        raise ActivationError('The activation service gave an answer this version '
                              'cannot read. No licence was saved.')
    if status == 200 and isinstance(answer.get('licence'), str) and answer['licence']:
        return answer['licence']
    message = answer.get('error') if isinstance(answer.get('error'), str) else ''
    raise ActivationError(message[:300] or f'Activation was refused (HTTP {status}).')


# ----------------------------------------------------------- licence check

def _no_verifier(signature: bytes, message: bytes, public_key: bytes) -> bool:
    raise LookupError('licence verifier not available')


def _b64(text: str) -> bytes:
    return base64.b64decode(text.encode('ascii'), validate=True)


def _expiry(text: str):
    value = text[:-1] + '+00:00' if text.endswith('Z') else text
    when = datetime.fromisoformat(value)
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _refused(reason, hwid='', expiry=''):
    return {'valid': False, 'refusal': reason, 'message': LICENCE_MESSAGES[reason],
            'hwid': hwid, 'expiry': expiry}


def check_licence(licence_text, current_hwid, public_key: bytes = None, verify=None,
                  now: datetime = None) -> dict:
    '''{'valid': True, 'hwid', 'expiry', 'days_remaining'} only when every
    step passed; otherwise {'valid': False, 'refusal', 'message'}. Never
    raises.'''
    try:
        if not isinstance(licence_text, str) or not isinstance(current_hwid, str) \
                or not current_hwid:
            return _refused('MALFORMED')
        pieces = licence_text.strip().split('.')
        if len(pieces) != 2 or not pieces[0] or not pieces[1]:
            return _refused('MALFORMED')
        try:
            signature, payload = _b64(pieces[0]), _b64(pieces[1])
        except (binascii.Error, ValueError):
            return _refused('MALFORMED')
        if not payload or len(payload) > MAX_PAYLOAD_BYTES or \
                any(b < 0x20 or b > 0x7e for b in payload):
            return _refused('MALFORMED')
        fields = payload.decode('ascii').split('|')
        if len(fields) != 2 or not fields[0] or not fields[1]:
            return _refused('MALFORMED')
        hwid, expiry = fields
        try:
            expiry_at = _expiry(expiry)
        except ValueError:
            return _refused('MALFORMED')
        key = public_key if public_key is not None else embedded_public_key()
        # the signature is checked before anything in the payload is believed
        if len(signature) != ML_DSA_65_SIGNATURE_BYTES or len(key) != ML_DSA_65_PUBLIC_KEY_BYTES:
            return _refused('BAD_SIGNATURE')
        try:
            ok = (verify or _no_verifier)(signature, payload, key)
        except LookupError:
            return _refused('NO_VERIFIER')
        if ok is not True:
            return _refused('BAD_SIGNATURE')
        if hwid != current_hwid:
            return _refused('OTHER_COMPUTER', hwid, expiry)
        remaining = (expiry_at - (now or datetime.now(timezone.utc))).total_seconds()
        if remaining <= 0:
            return _refused('EXPIRED', hwid, expiry)
        return {'valid': True, 'hwid': hwid, 'expiry': expiry,
                'days_remaining': int(-(-remaining // 86400)), 'scheme': 'ML-DSA-65'}
    except Exception:  # noqa: BLE001 - any failure is a refusal
        return _refused('CHECK_FAILED')


# ------------------------------------------------------------- key / build

def embedded_public_key() -> bytes:
    try:
        return _b64(licence_key.LICENSE_PUBLIC_KEY_B64) if licence_key.LICENSE_PUBLIC_KEY_B64 else b''
    except (binascii.Error, ValueError):
        return b''


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def classify_fingerprint(fp: str, production: str = None, blocklist=None) -> str:
    '''PRODUCTION only when fp is the production fingerprint and not
    blocklisted; BLOCKLISTED for a known development/test key; else UNKNOWN.'''
    production = licence_key.PROD_PUBKEY_SHA256 if production is None else production
    blocklist = licence_key.NON_PRODUCTION_PUBKEY_SHA256 if blocklist is None else blocklist
    if fp in blocklist:
        return 'BLOCKLISTED'
    if len(production) == 64 and all(c in '0123456789abcdef' for c in production) \
            and fp == production:
        return 'PRODUCTION'
    return 'UNKNOWN'


def is_test_build() -> bool:
    '''True unless the embedded key is the production key. A test build
    shows licence_key.TEST_BUILD_NOTICE.'''
    key = embedded_public_key()
    if len(key) != ML_DSA_65_PUBLIC_KEY_BYTES:
        return True
    return classify_fingerprint(fingerprint(key)) != 'PRODUCTION'


# ----------------------------------------------------------------- storage

def licence_file() -> str:
    '''In the per-user data folder (never the program folder).'''
    from . import paths
    return os.environ.get('DEXMOND_LICENCE_FILE') or os.path.join(paths.data_dir(), 'licence.txt')


def save_licence(text: str, path: str = None) -> str:
    path = path or licence_file()
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='ascii') as f:
        f.write(text.strip() + '\n')
    os.replace(tmp, path)
    return path


def load_licence(path: str = None):
    try:
        with open(path or licence_file(), encoding='ascii') as f:
            return f.read(16 * 1024).strip() or None
    except (OSError, UnicodeDecodeError):
        return None
