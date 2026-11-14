'''Authenticode signature check (fix X12).

A VALID signature from a TRUSTED publisher lets the engine cap heuristic
scores at LOW (see Scorer.cap_heuristics). Because that lowers detection,
the check must be real cryptographic verification, never "a certificate is
present" or "the subject string says Microsoft" (a copied certificate blob
would pass those):

- Windows: WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) verifies the
  file hash, the signature and the chain to a trusted root. The publisher
  name is read from the verified signer's leaf certificate. No network:
  revocation checking is off and URL retrieval is cache-only.
- Elsewhere: status 'unavailable', and no cap is ever applied.
'''
import logging
import os
import sys

logger = logging.getLogger('DEXMOND_MIE')

DEFAULT_TRUSTED_PUBLISHERS = ('Microsoft Corporation',)


def trusted_publishers():
    '''Publishers whose valid signature caps heuristics. Configurable with
    DEXMOND_TRUSTED_PUBLISHERS="Name One;Name Two" (exact subject names).'''
    env = os.environ.get('DEXMOND_TRUSTED_PUBLISHERS')
    if env:
        return tuple(p.strip() for p in env.split(';') if p.strip())
    return DEFAULT_TRUSTED_PUBLISHERS


def _result(status, publisher=None, detail=''):
    return {'status': status, 'publisher': publisher, 'detail': detail}


def verify_authenticode(path: str):
    '''Returns {'status': 'valid'|'invalid'|'unsigned'|'unavailable',
    'publisher': str|None, 'detail': str}.'''
    if sys.platform != 'win32':
        return _result('unavailable', detail='Authenticode verification needs Windows WinVerifyTrust')
    try:
        return _verify_windows(path)
    except Exception as e:  # noqa: BLE001 - any failure means "not verified"
        logger.error(f'Signature verification failed for {path}: {e}')
        return _result('unavailable', detail=f'verification error: {e}')


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
        return _result('valid', publisher=buf.value or None, detail='WinVerifyTrust OK')
    finally:
        data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
