'''Authenticode signature check (fix X12 v2, cross-platform).

Design: .review/X12_CROSS_PLATFORM_AUTHENTICODE_DESIGN_2026-11-14.md
(SENTINEL, sha256 256ab93a...).

A VALID signature from an ALLOWLISTED publisher lets the engine cap
heuristic scores at LOW (Scorer.SIGNED_CAP). Because that lowers detection,
"valid" requires ALL of:
 1. the PE parses, the certificate table lies inside the file and NOTHING
    follows it (CVE-2013-3900 class padding refused); table <= 1 MiB;
    WIN_CERTIFICATE entries well formed (revision 2.0, PKCS#7 type, DER
    length matching dwLength);
 2. the recomputed Authenticode image digest equals the signed digest;
 3. the PKCS#7 signature verifies against the signer certificate;
 4. the signer chains to a root in the PINNED store (trust/
    authenticode_roots.pem, sha256 pinned below; never the OS store or a
    package bundle), intermediates only from the signature's own
    certificate set, EKU code signing;
 5. time: valid at the countersignature (timestamp) time if there is one,
    else now;
 6. only the PRIMARY signature counts (nested signatures are ignored);
 7. revocation is NOT checked (offline); every result says so.
The publisher allowlist (config/trusted_publishers.json, Microsoft
Corporation only by default) is reported as publisher_allowed; a valid
signature from another publisher stays 'valid' but gets no cap.

Platforms: Windows uses WinVerifyTrust (primary); Linux and macOS use the
pure-Python `signify` library with the pinned store. Any exception,
timeout (2 s), missing dependency or unprovisioned / mismatching store
gives 'unavailable', i.e. no cap (fails closed).
'''
import hashlib
import json
import logging
import os
import struct
import sys
import threading
from datetime import datetime, timezone

logger = logging.getLogger('DEXMOND_MIE')

from .paths import resource_dir

_ROOT = resource_dir()   # project root, or the PyInstaller bundle dir
TRUST_STORE_PATH = os.path.join(_ROOT, 'trust', 'authenticode_roots.pem')
PUBLISHERS_CONFIG = os.path.join(_ROOT, 'config', 'trusted_publishers.json')
# sha256 of trust/authenticode_roots.pem. None = the reviewed store has NOT
# been provisioned yet, so every portable check returns 'unavailable'.
# Setting it is a SENTINEL-reviewed commit together with the PEM file.
PINNED_ROOTS_SHA256 = "59934744aa41b1432da5196f37e97bac269df7be62bb02d65b74d08d80b6d2c4"  # SENTINEL-provisioned 2026-11-14: Microsoft Root CA 2011, 2010, 2001 (see trust/README)
DEFAULT_TRUSTED_PUBLISHERS = ('Microsoft Corporation',)
MAX_SIGNATURE_BYTES = 1024 * 1024
VERIFY_TIMEOUT_S = 2.0
REVOCATION_NOTE = 'revocation not checked (offline)'
WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002


class StoreError(Exception):
    pass


def _result(status, publisher=None, detail='', **extra):
    if status in ('valid', 'invalid') and REVOCATION_NOTE not in detail:
        detail = f'{detail}; {REVOCATION_NOTE}' if detail else REVOCATION_NOTE
    out = {'status': status, 'publisher': publisher, 'detail': detail,
           'revocation': 'not checked (offline)'}
    out.update(extra)
    return out


def trusted_publishers(config_path: str = None):
    '''Allowlist from config/trusted_publishers.json ({"publishers": [...]}).
    Missing or unreadable file: Microsoft Corporation only.'''
    path = config_path or PUBLISHERS_CONFIG
    try:
        with open(path, encoding='utf-8') as f:
            names = json.load(f).get('publishers', [])
        names = tuple(n for n in names if isinstance(n, str) and n.strip())
        return names or DEFAULT_TRUSTED_PUBLISHERS
    except (OSError, ValueError, AttributeError):
        return DEFAULT_TRUSTED_PUBLISHERS


# ---------------------------------------------------------------- check 1
def precheck_pe(path: str):
    '''Pure-Python structural check (no dependency). Returns
    ('ok', info) or (status, detail) with status unsigned / invalid.'''
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        head = f.read(4096)
        if len(head) < 0x40 or head[:2] != b'MZ':
            return 'invalid', 'not a PE file'
        e_lfanew = struct.unpack_from('<I', head, 0x3c)[0]
        if e_lfanew + 24 + 2 > len(head) or head[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            return 'invalid', 'no PE signature'
        opt = e_lfanew + 24
        magic = struct.unpack_from('<H', head, opt)[0]
        if magic == 0x10b:
            nrva_off, dirs = opt + 92, opt + 96
        elif magic == 0x20b:
            nrva_off, dirs = opt + 108, opt + 112
        else:
            return 'invalid', f'unknown optional header magic 0x{magic:04x}'
        if dirs + 5 * 8 > len(head):
            return 'invalid', 'optional header truncated'
        if struct.unpack_from('<I', head, nrva_off)[0] < 5:
            return 'unsigned', 'no security data directory'
        cert_off, cert_size = struct.unpack_from('<II', head, dirs + 4 * 8)
        if cert_off == 0 or cert_size == 0:
            return 'unsigned', 'no certificate table'
        if cert_size > MAX_SIGNATURE_BYTES:
            return 'invalid', f'certificate table {cert_size} bytes is over the 1 MiB limit'
        if cert_off + cert_size > size:
            return 'invalid', 'certificate table runs past the end of the file'
        if cert_off + cert_size != size:
            return 'invalid', (f'{size - cert_off - cert_size} bytes follow the certificate '
                               f'table (data outside the signed digest)')
        f.seek(cert_off)
        table = f.read(cert_size)
    entries, pos = [], 0
    while pos + 8 <= len(table):
        length, revision, cert_type = struct.unpack_from('<IHH', table, pos)
        if length < 12 or pos + length > len(table):
            return 'invalid', f'bad WIN_CERTIFICATE dwLength {length}'
        if revision != WIN_CERT_REVISION_2_0 or cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return 'invalid', 'WIN_CERTIFICATE is not revision 2.0 PKCS#7 signed data'
        body = table[pos + 8:pos + length]
        if body[:2] != b'\x30\x82':
            return 'invalid', 'PKCS#7 body is not a DER SEQUENCE (30 82 LL LL)'
        der_len = 4 + int.from_bytes(body[2:4], 'big')
        if not 0 <= len(body) - der_len <= 7 or body[der_len:].count(0) != len(body) - der_len:
            return 'invalid', 'PKCS#7 DER length does not match dwLength (truncated or padded)'
        entries.append(body[:der_len])
        aligned = (length + 7) & ~7
        if table[pos + length:pos + aligned].count(0) != len(table[pos + length:pos + aligned]):
            return 'invalid', 'non-zero alignment bytes in the certificate table'
        pos += aligned
    if not entries:
        return 'invalid', 'empty certificate table'
    if pos < len(table):
        return 'invalid', 'trailing bytes inside the certificate table'
    return 'ok', {'cert_offset': cert_off, 'cert_size': cert_size,
                  'entries': len(entries), 'primary_der': entries[0]}


# ---------------------------------------------------------------- check 4 (store)
def load_pinned_store(store_path: str = None, pinned_sha256=PINNED_ROOTS_SHA256) -> bytes:
    '''Returns the PEM bytes of the pinned root store, or raises StoreError.'''
    if not pinned_sha256:
        raise StoreError('pinned Authenticode root store not provisioned (PINNED_ROOTS_SHA256 unset)')
    path = store_path or TRUST_STORE_PATH
    try:
        with open(path, 'rb') as f:
            pem = f.read()
    except OSError as e:
        raise StoreError(f'pinned root store missing: {e}')
    digest = hashlib.sha256(pem).hexdigest()
    if digest != pinned_sha256.lower():
        raise StoreError(f'pinned root store sha256 mismatch ({digest[:16]}...)')
    return pem


# ---------------------------------------------------------------- checks 2-6
def _import_signify():
    '''Imports the signify pieces used here; raises ImportError if absent.'''
    from signify.authenticode import SignedPEFile          # noqa: F401
    try:
        from signify.x509 import Certificate, CertificateStore
    except ImportError:
        from signify.x509.certificates import Certificate
        from signify.x509.context import CertificateStore
    return SignedPEFile, Certificate, CertificateStore


def _leaf_certificate(signed_data):
    '''The primary signer's leaf as a cryptography certificate.'''
    from cryptography import x509
    info = signed_data.signer_info
    for cert in signed_data.certificates:
        if cert.serial_number == info.serial_number and cert.issuer == info.issuer:
            return x509.load_der_x509_certificate(cert.to_der)
    raise ValueError('signer certificate not in the signature certificate set')


def _signing_time(signed_data):
    '''Countersignature (timestamp) time, None if the signature has none.
    A countersignature whose time cannot be read raises (fails closed).'''
    cs = getattr(signed_data.signer_info, 'countersigner', None)
    if cs is None:
        return None
    t = getattr(cs, 'signing_time', None)
    if t is None and getattr(cs, 'tst_info', None) is not None:
        t = cs.tst_info.gen_time
    if t is None:
        raise ValueError('countersignature present but its time is unreadable')
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _publisher(leaf):
    from cryptography.x509.oid import NameOID
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = leaf.subject.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return None


def _leaf_checks(leaf, signing_time):
    '''Our own checks on top of signify: leaf EKU code signing, and the
    leaf valid at the timestamp (or now).'''
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return 'signer certificate has no EKU (code signing required)'
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        return 'signer certificate EKU does not allow code signing'
    when = signing_time or datetime.now(timezone.utc)
    nb = getattr(leaf, 'not_valid_before_utc', None) or leaf.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(leaf, 'not_valid_after_utc', None) or leaf.not_valid_after.replace(tzinfo=timezone.utc)
    if not nb <= when <= na:
        src = 'timestamp' if signing_time else 'now'
        return f'signer certificate not valid at {src} ({when.isoformat()})'
    return None


def _verify_portable_inner(path, store_path, pinned_sha256, publishers):
    status, info = precheck_pe(path)
    if status != 'ok':
        return _result(status, detail=info)
    try:
        pem = load_pinned_store(store_path, pinned_sha256)
    except StoreError as e:
        return _result('unavailable', detail=str(e))
    try:
        SignedPEFile, Certificate, CertificateStore = _import_signify()
    except ImportError as e:
        return _result('unavailable', detail=f'signify not installed: {e}')
    store = CertificateStore(list(Certificate.from_pems(pem)), trusted=True)
    with open(path, 'rb') as f:
        pe = SignedPEFile(f)
        signed_datas = list(pe.signed_datas)
        if not signed_datas:
            return _result('invalid', detail='no Authenticode signature parsed')
        primary = signed_datas[0]          # nested / extra signatures ignored
        try:
            # digest (2), PKCS#7 (3), chain to the pinned store with EKU code
            # signing (4), countersignature time (5), primary only (6); no
            # fetching, so no revocation (7)
            pe.verify(multi_verify_mode='first',
                      trusted_certificate_store=store,
                      verification_context_kwargs={'allow_fetching': False,
                                                   'extended_key_usages': ['code_signing'],
                                                   'optional_eku': True})
        except TypeError:
            raise                          # API mismatch: unavailable, never valid
        except Exception as e:  # noqa: BLE001 - signify's verification errors
            return _result('invalid', detail=f'signify: {type(e).__name__}: {e}')
        leaf = _leaf_certificate(primary)
        signing_time = _signing_time(primary)
    problem = _leaf_checks(leaf, signing_time)
    if problem:
        return _result('invalid', detail=problem)
    publisher = _publisher(leaf)
    allowed = publisher in tuple(publishers if publishers is not None else trusted_publishers())
    return _result('valid', publisher=publisher,
                   detail=f'signify OK (primary signature, pinned store)',
                   publisher_allowed=allowed,
                   timestamp=signing_time.isoformat() if signing_time else None)


def verify_portable(path: str, store_path: str = None, pinned_sha256=PINNED_ROOTS_SHA256,
                    publishers=None, timeout: float = VERIFY_TIMEOUT_S):
    '''Linux/macOS verifier (also used for the Windows parity test).
    Any exception or a timeout gives 'unavailable'.'''
    box = {}

    def run():
        try:
            box['r'] = _verify_portable_inner(path, store_path, pinned_sha256, publishers)
        except Exception as e:  # noqa: BLE001 - fail closed
            box['r'] = _result('unavailable', detail=f'verification error: {type(e).__name__}: {e}')
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return _result('unavailable', detail=f'verification timed out after {timeout} s')
    return box.get('r') or _result('unavailable', detail='no result')


def verify_authenticode(path: str, publishers=None):
    '''Returns {'status': 'valid'|'invalid'|'unsigned'|'unavailable',
    'publisher', 'publisher_allowed', 'detail', ...}.'''
    pubs = tuple(publishers if publishers is not None else trusted_publishers())
    if sys.platform != 'win32':
        return verify_portable(path, publishers=pubs)
    # Same structural precheck as the portable path: stock WinVerifyTrust
    # accepts data appended after the certificate table (CVE-2013-3900
    # class) unless EnableCertPaddingCheck is set, so the platforms would
    # not be at parity without it.
    try:
        status, info = precheck_pe(path)
    except Exception as e:  # noqa: BLE001 - fail closed
        return _result('unavailable', detail=f'precheck error: {type(e).__name__}: {e}')
    if status != 'ok':
        return _result(status, detail=info)
    try:
        result = _verify_windows(path)
    except Exception as e:  # noqa: BLE001 - any failure means "not verified"
        logger.error(f'Signature verification failed for {path}: {e}')
        return _result('unavailable', detail=f'verification error: {e}')
    if result['status'] == 'valid':
        result['publisher_allowed'] = result.get('publisher') in pubs
    result['os_cert_padding_check'] = _cert_padding_check_enabled()
    return result


def _cert_padding_check_enabled():
    '''True/False if the Windows EnableCertPaddingCheck setting can be read,
    None otherwise (informational only; MIE's own precheck always runs).'''
    if sys.platform != 'win32':
        return None
    try:  # pragma: no cover - Windows only
        import winreg
        for key in (r'Software\Microsoft\Cryptography\Wintrust\Config',
                    r'Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                    value, _ = winreg.QueryValueEx(k, 'EnableCertPaddingCheck')
                    if str(value) == '1':
                        return True
            except OSError:
                continue
        return False
    except Exception:  # noqa: BLE001
        return None


def _verify_windows(path: str):  # pragma: no cover - Windows only, NOT RUN on Linux
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD),
                    ('Data3', wintypes.WORD), ('Data4', ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('pcwszFilePath', wintypes.LPCWSTR),
                    ('hFile', wintypes.HANDLE), ('pgKnownSubject', ctypes.POINTER(GUID))]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [('cbStruct', wintypes.DWORD), ('pPolicyCallbackData', ctypes.c_void_p),
                    ('pSIPClientData', ctypes.c_void_p), ('dwUIChoice', wintypes.DWORD),
                    ('fdwRevocationChecks', wintypes.DWORD), ('dwUnionChoice', wintypes.DWORD),
                    ('pFile', ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ('dwStateAction', wintypes.DWORD), ('hWVTStateData', wintypes.HANDLE),
                    ('pwszURLReference', wintypes.LPCWSTR), ('dwProvFlags', wintypes.DWORD),
                    ('dwUIContext', wintypes.DWORD), ('pSignatureSettings', ctypes.c_void_p)]

    class CRYPT_PROVIDER_CERT(ctypes.Structure):   # leading fields only
        _fields_ = [('cbStruct', wintypes.DWORD), ('pCert', ctypes.c_void_p)]

    class FILETIME(ctypes.Structure):
        _fields_ = [('lo', wintypes.DWORD), ('hi', wintypes.DWORD)]

    class CRYPT_PROVIDER_SGNR(ctypes.Structure):   # leading fields only
        _fields_ = [('cbStruct', wintypes.DWORD), ('sftVerifyAsOf', FILETIME),
                    ('csCertChain', wintypes.DWORD),
                    ('pasCertChain', ctypes.POINTER(CRYPT_PROVIDER_CERT))]

    WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE = 2, 0, 1
    WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2
    WTD_REVOCATION_CHECK_NONE, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x10, 0x1000
    TRUST_E_NOSIGNATURE = 0x800B0100
    TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
    TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
    CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

    action = GUID(0xaac56b, 0xcd44, 0x11d0,
                  (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
    file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

    wintrust = ctypes.WinDLL('wintrust')
    crypt32 = ctypes.WinDLL('crypt32')
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_SGNR)
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                                        wintypes.BOOL, wintypes.DWORD]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                           ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]

    status = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF
    try:
        if status in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN):
            return _result('unsigned', detail=f'WinVerifyTrust 0x{status:08x}')
        if status != 0:
            return _result('invalid', detail=f'WinVerifyTrust 0x{status:08x}')
        prov = wintrust.WTHelperProvDataFromStateData(data.hWVTStateData)
        signer = wintrust.WTHelperGetProvSignerFromChain(prov, 0, False, 0) if prov else None
        if not signer or signer.contents.csCertChain < 1:
            return _result('invalid', detail='verified, but no signer certificate')
        cert = signer.contents.pasCertChain[0].pCert
        buf = ctypes.create_unicode_buffer(512)
        crypt32.CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 512)
        return _result('valid', publisher=buf.value or None,
                       detail=f'WinVerifyTrust OK; {REVOCATION_NOTE}')
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
