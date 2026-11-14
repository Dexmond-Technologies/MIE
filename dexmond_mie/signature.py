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
import io
import json
import logging
import os
import stat as stat_mod
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
# Only files that fit in one analysed buffer are verified (TOCTOU: the exact
# bytes scanned are the bytes verified). Same value as core.MAX_ANALYSIS_BYTES.
MAX_VERIFY_BYTES = 32 * 1024 * 1024
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


def load_policy(config_path: str = None) -> dict:
    '''Publisher policy from config/trusted_publishers.json:
      publishers            leaf CN AND O must both equal one entry
      issuing_intermediates the leaf's issuing CA must be one of these,
                            matched by subject CN AND SPKI sha256 (an entry
                            whose spki_sha256 is null is not usable yet)
      rejected_issuers / rejected_leaf_cns  explicit denials (WHCP and
                            third-party component chains)
    Missing or unreadable file: Microsoft Corporation, no usable
    intermediates (so no cap).'''
    path = config_path or PUBLISHERS_CONFIG
    try:
        with open(path, encoding='utf-8') as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    pubs = tuple(n for n in cfg.get('publishers', []) if isinstance(n, str) and n.strip())
    inters = []
    for e in cfg.get('issuing_intermediates', []) or []:
        if isinstance(e, dict) and isinstance(e.get('cn'), str):
            spki = e.get('spki_sha256')
            inters.append({'cn': e['cn'],
                           'spki_sha256': spki.lower() if isinstance(spki, str) and spki else None})
    return {
        'publishers': pubs or DEFAULT_TRUSTED_PUBLISHERS,
        'issuing_intermediates': inters,
        'rejected_issuers': tuple(cfg.get('rejected_issuers', []) or ()),
        'rejected_leaf_cns': tuple(cfg.get('rejected_leaf_cns', []) or ()),
    }


def trusted_publishers(config_path: str = None):
    '''Allowlisted publisher names (leaf CN and O).'''
    return load_policy(config_path)['publishers']


# ---------------------------------------------------------------- TOCTOU
def read_for_verify(path: str, limit: int = MAX_VERIFY_BYTES):
    '''Opens the file ONCE (no symlink following, regular files only),
    fstats it and reads it. Returns (data, stat_key). Raises ValueError if
    the file is not a regular file or is bigger than `limit`.'''
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            raise ValueError('not a regular file')
        if st.st_size > limit:
            raise ValueError(f'file is {st.st_size} bytes, bigger than the analysed buffer')
        with os.fdopen(os.dup(fd), 'rb') as f:
            data = f.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) != st.st_size:
        raise ValueError('file changed while it was read')
    return data, stat_key(st)


def stat_key(st):
    return (st.st_size, st.st_mtime_ns, st.st_ino, st.st_dev)


def _unchanged(path, key) -> bool:
    try:
        return stat_key(os.stat(path, follow_symlinks=False)) == key
    except OSError:
        return False


# ---------------------------------------------------------------- check 1
def precheck_pe(path: str):
    '''precheck_data() on a file read from disk (tests, tools).'''
    with open(path, 'rb') as f:
        return precheck_data(f.read(MAX_VERIFY_BYTES + 1))


def precheck_data(data: bytes):
    '''Pure-Python structural check (no dependency) on the exact bytes that
    were scanned. Returns ('ok', info) or (status, detail) with status
    unsigned / invalid.'''
    size = len(data)
    head = data[:4096]
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
    table = data[cert_off:cert_off + cert_size]
    entries, pos = [], 0
    while pos + 8 <= len(table):
        length, revision, cert_type = struct.unpack_from('<IHH', table, pos)
        if length < 12 or pos + length > len(table):
            return 'invalid', f'bad WIN_CERTIFICATE dwLength {length}'
        if revision != WIN_CERT_REVISION_2_0 or cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return 'invalid', 'WIN_CERTIFICATE is not revision 2.0 PKCS#7 signed data'
        body = table[pos + 8:pos + length]
        # Only 30 82 (two-byte DER length) is accepted, so a PKCS#7 blob over
        # 64 KiB is refused (fail closed). This precheck runs on Windows too
        # (before WinVerifyTrust), so Windows refuses them as well: parity.
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
_PINNED = object()   # "use the module's PINNED_ROOTS_SHA256 at call time"


def load_pinned_store(store_path: str = None, pinned_sha256=_PINNED) -> bytes:
    '''Returns the PEM bytes of the pinned root store, or raises StoreError.'''
    if pinned_sha256 is _PINNED:
        pinned_sha256 = PINNED_ROOTS_SHA256
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


def _pem_to_ders(pem: bytes):
    from asn1crypto import pem as apem
    return [der for _, _, der in apem.unarmor(pem, multiple=True)]


# ---------------------------------------------------------------- checks 2-6
# Only the packages in requirements-signify.lock are used here (signify,
# asn1crypto, certvalidator, oscrypto); `cryptography` is NOT a dependency.
def _import_signify():
    '''Imports the signify (0.9.x) pieces used here; raises ImportError if
    absent. signify 0.9.3: signify.authenticode.AuthenticodeFile (base class,
    from_stream() returns the concrete subclass), signify.x509.'''
    from signify.authenticode import AuthenticodeFile
    try:
        from signify.x509 import Certificate, CertificateStore
    except ImportError:
        from signify.x509.certificates import Certificate
        from signify.x509.context import CertificateStore
    return AuthenticodeFile, Certificate, CertificateStore


def primary_signature(data: bytes):
    '''(authenticode_file, primary embedded signature) for a buffer. Only
    EMBEDDED signatures (never catalogs), nested signatures excluded.'''
    AuthenticodeFile, _, _ = _import_signify()
    af = AuthenticodeFile.from_stream(io.BytesIO(data))
    sigs = list(af.iter_signatures(signature_types='embedded', include_nested=False,
                                   ignore_parse_errors=False))
    return af, (sigs[0] if sigs else None)


def _as_asn1(cert):
    from asn1crypto import x509 as ax509
    return ax509.Certificate.load(cert.to_der)


def _find_cert(pool, issuer, serial):
    for cert in pool:
        if cert.serial_number == serial and cert.issuer == issuer:
            return cert
    return None


def _leaf_certificate(signed_data):
    '''The primary signer's leaf certificate (asn1crypto).'''
    info = signed_data.signer_info
    cert = _find_cert(signed_data.certificates, info.issuer, info.serial_number)
    if cert is None:
        raise ValueError('signer certificate not in the signature certificate set')
    return _as_asn1(cert)


def _countersignature(signed_data):
    '''(time, signer certificate, certificate pool) of the countersignature,
    or None if there is none. Authenticode (CounterSignerInfo) and RFC 3161
    countersignatures are both handled.'''
    cs = getattr(signed_data.signer_info, 'countersigner', None)
    if cs is None:
        return None
    pool = list(signed_data.certificates)
    if getattr(cs, 'signer_info', None) is not None:          # RFC 3161 token
        pool = list(getattr(cs, 'certificates', [])) + pool
        info = cs.signer_info
        tst = getattr(cs, 'tst_info', None)
        # signify 0.9.3: TSTInfo.signing_time (= gen_time)
        t = (getattr(tst, 'signing_time', None) or getattr(tst, 'gen_time', None)) if tst is not None else None
    else:                                                     # Authenticode
        info = cs
        t = getattr(cs, 'signing_time', None)
    if t is None:
        raise ValueError('countersignature present but its time is unreadable')
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    cert = _find_cert(pool, info.issuer, info.serial_number)
    return t, cert, pool


def _countersigner_trusted(cert, pool, when, pem) -> bool:
    '''True only if the countersigner's chain reaches a root in the PINNED
    store (never signify's mscerts bundle), with EKU time stamping, at the
    countersignature time. certvalidator, no fetching, no revocation.'''
    if cert is None:
        return False
    from asn1crypto import x509 as ax509
    from certvalidator import CertificateValidator, ValidationContext
    roots = [ax509.Certificate.load(der) for der in _pem_to_ders(pem)]
    others = [_as_asn1(c) for c in pool if c is not cert]
    ctx = ValidationContext(trust_roots=roots, moment=when, allow_fetching=False,
                            revocation_mode='soft-fail', weak_hash_algos={'md2', 'md5'})
    try:
        CertificateValidator(_as_asn1(cert), intermediate_certs=others,
                             validation_context=ctx).validate_usage(
            set(), extended_key_usage={'time_stamping'})
        return True
    except Exception:  # noqa: BLE001 - untrusted / invalid chain: ignore the timestamp
        return False


def _signing_time(signed_data, pem):
    '''The countersignature time, used ONLY if the countersigner chains to
    the pinned store; otherwise None, so validity is checked at "now".'''
    cs = _countersignature(signed_data)
    if cs is None:
        return None
    when, cert, pool = cs
    return when if _countersigner_trusted(cert, pool, when, pem) else None


def _name_field(cert, key):
    value = cert.subject.native.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    return value or None


def _publisher(leaf):
    '''Publisher name: subject CN first, then O (same field on every platform).'''
    return _name_field(leaf, 'common_name') or _name_field(leaf, 'organization_name')


def _spki_sha256(cert) -> str:
    return hashlib.sha256(cert['tbs_certificate']['subject_public_key_info'].dump()).hexdigest()


def _issuing_ca(leaf, pool, pem, when):
    '''The CA that really issued the leaf, from a path that certvalidator
    builds and verifies cryptographically to the PINNED roots (independent
    of signify's store handling). Returns the asn1crypto certificate.'''
    from asn1crypto import x509 as ax509
    from certvalidator import CertificateValidator, ValidationContext
    roots = [ax509.Certificate.load(der) for der in _pem_to_ders(pem)]
    ctx = ValidationContext(trust_roots=roots, moment=when, allow_fetching=False,
                            revocation_mode='soft-fail', weak_hash_algos={'md2', 'md5'})
    path = CertificateValidator(leaf, intermediate_certs=[_as_asn1(c) for c in pool],
                                validation_context=ctx).validate_usage(
        set(), extended_key_usage={'code_signing'})
    chain = list(path)                      # root ... leaf
    if len(chain) < 2:
        raise ValueError('leaf is directly a root')
    return chain[-2]


def publisher_decision(leaf, issuer, policy) -> tuple:
    '''(allowed, reason). Allowed only if: leaf CN and O both equal an
    allowlisted publisher; the issuing CA is an allowlisted intermediate by
    CN AND SPKI sha256; neither the issuer nor the leaf is on a deny list.'''
    cn, org = _name_field(leaf, 'common_name'), _name_field(leaf, 'organization_name')
    issuer_cn = _name_field(issuer, 'common_name')
    if cn in policy['rejected_leaf_cns'] or issuer_cn in policy['rejected_issuers']:
        return False, f'rejected chain (leaf {cn!r}, issuer {issuer_cn!r})'
    if cn not in policy['publishers'] or org not in policy['publishers']:
        return False, f'publisher not allowlisted (CN {cn!r}, O {org!r})'
    spki = _spki_sha256(issuer)
    for entry in policy['issuing_intermediates']:
        if entry['cn'] == issuer_cn:
            if not entry['spki_sha256']:
                return False, f'issuing CA {issuer_cn!r} SPKI not pinned yet'
            if entry['spki_sha256'] == spki:
                return True, f'issuer {issuer_cn} (SPKI {spki[:16]}...)'
            return False, f'issuing CA {issuer_cn!r} SPKI mismatch ({spki[:16]}...)'
    return False, f'issuing CA {issuer_cn!r} not an allowlisted intermediate'


def _validity(leaf):
    v = leaf['tbs_certificate']['validity']
    return v['not_before'].native, v['not_after'].native


def _leaf_checks(leaf, signing_time):
    '''Our own checks on top of signify: leaf EKU code signing, and the
    leaf valid at the trusted timestamp (or now).'''
    eku = leaf.extended_key_usage_value
    if eku is None:
        return 'signer certificate has no EKU (code signing required)'
    if 'code_signing' not in eku.native:
        return 'signer certificate EKU does not allow code signing'
    when = signing_time or datetime.now(timezone.utc)
    nb, na = _validity(leaf)
    if not nb <= when <= na:
        src = 'timestamp' if signing_time else 'now'
        return f'signer certificate not valid at {src} ({when.isoformat()})'
    return None


def _signify_verify(data, pem):
    '''Runs signify on the buffer. Returns (primary, leaf, signing_time) or
    a result dict on failure. TypeError (API mismatch) propagates.'''
    _, Certificate, CertificateStore = _import_signify()
    store = CertificateStore(list(Certificate.from_pems(pem)), trusted=True)
    af, primary = primary_signature(data)
    if primary is None:
        return _result('invalid', detail='no embedded Authenticode signature parsed')
    try:
        # digest (2), PKCS#7 (3), chain to the pinned store ONLY with EKU code
        # signing (4), countersignature strict (5), primary embedded
        # signature only (6); no fetching, so no revocation (7)
        af.verify(multi_verify_mode='first',
                  signature_types='embedded',
                  ignore_parse_errors=False,
                  trusted_certificate_store=store,
                  countersignature_mode='strict',
                  # only allow_fetching: signify passes extended_key_usages
                  # itself (Authenticode default); our own leaf EKU check
                  # (code signing) runs after verification
                  verification_context_kwargs={'allow_fetching': False})
    except TypeError:
        raise
    except Exception as e:  # noqa: BLE001 - signify's verification errors
        return _result('invalid', detail=f'signify: {type(e).__name__}: {e}')
    leaf = _leaf_certificate(primary)
    # (5) the countersignature time counts ONLY if the countersigner chains
    # to OUR pinned store (own check, on top of signify's strict mode);
    # otherwise validity is checked at now
    signing_time = _signing_time(primary, pem)
    return primary, leaf, signing_time


def _verify_portable_inner(data, store_path, pinned_sha256, policy):
    status, info = precheck_data(data)
    if status != 'ok':
        return _result(status, detail=info)
    try:
        pem = load_pinned_store(store_path, pinned_sha256)
    except StoreError as e:
        return _result('unavailable', detail=str(e))
    try:
        _import_signify()
    except ImportError as e:
        return _result('unavailable', detail=f'signify not installed: {e}')
    out = _signify_verify(data, pem)
    if isinstance(out, dict):
        return out
    primary, leaf, signing_time = out
    problem = _leaf_checks(leaf, signing_time)
    if problem:
        return _result('invalid', detail=problem)
    when = signing_time or datetime.now(timezone.utc)
    issuer = _issuing_ca(leaf, list(primary.certificates), pem, when)
    allowed, reason = publisher_decision(leaf, issuer, policy)
    return _result('valid', publisher=_publisher(leaf),
                   detail=f'signify OK (primary signature, pinned store); {reason}',
                   publisher_allowed=allowed,
                   issuer=_name_field(issuer, 'common_name'),
                   issuer_spki_sha256=_spki_sha256(issuer),
                   timestamp=signing_time.isoformat() if signing_time else None)


def verify_portable(path: str, store_path: str = None, pinned_sha256=_PINNED,
                    publishers=None, timeout: float = VERIFY_TIMEOUT_S,
                    data: bytes = None, scanned_stat=None, policy=None):
    '''Linux/macOS verifier (also used for the Windows parity test).
    data/scanned_stat: the exact buffer the engine scanned and its fstat key;
    if absent the file is read once here. Any exception, a timeout, a file
    bigger than the buffer or a file changed since the scan: 'unavailable'.'''
    policy = dict(policy or load_policy())
    if publishers is not None:
        policy['publishers'] = tuple(publishers)
    box = {}

    def run():
        try:
            buf, key = data, scanned_stat
            if buf is None:
                buf, key = read_for_verify(path)
            changed = _result('unavailable', detail='file changed between scan and verification')
            # checked BEFORE parsing (a changed file is the reason, not
            # whatever parse error it causes) and again AFTER verification
            if key is not None and not _unchanged(path, key):
                box['r'] = changed
                return
            try:
                r = _verify_portable_inner(buf, store_path, pinned_sha256, policy)
            except Exception as e:  # noqa: BLE001 - fail closed
                r = _result('unavailable', detail=f'verification error: {type(e).__name__}: {e}')
            if key is not None and not _unchanged(path, key):
                r = changed
            box['r'] = r
        except Exception as e:  # noqa: BLE001 - fail closed
            box['r'] = _result('unavailable', detail=f'verification error: {type(e).__name__}: {e}')
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return _result('unavailable', detail=f'verification timed out after {timeout} s')
    return box.get('r') or _result('unavailable', detail='no result')


def verify_authenticode(path: str, publishers=None, data: bytes = None, scanned_stat=None):
    '''Returns {'status': 'valid'|'invalid'|'unsigned'|'unavailable',
    'publisher', 'publisher_allowed', 'detail', 'revocation', ...}.
    data/scanned_stat: the buffer the engine scanned and its fstat key, so
    the verified bytes are the scanned bytes (TOCTOU).'''
    policy = load_policy()
    if publishers is not None:
        policy['publishers'] = tuple(publishers)
    if sys.platform != 'win32':
        return verify_portable(path, data=data, scanned_stat=scanned_stat, policy=policy)
    try:
        if data is None:
            data, scanned_stat = read_for_verify(path)
        # Same structural precheck as the portable path: stock WinVerifyTrust
        # accepts data appended after the certificate table (CVE-2013-3900
        # class) unless EnableCertPaddingCheck is set, and the 30 82 rule
        # refuses PKCS#7 blobs over 64 KiB, the same as on Linux.
        status, info = precheck_data(data)
        if status != 'ok':
            return _result(status, detail=info)
        result = _verify_windows(path)
        if scanned_stat is not None and not _unchanged(path, scanned_stat):
            return _result('unavailable', detail='file changed between scan and verification')
    except Exception as e:  # noqa: BLE001 - any failure means "not verified"
        logger.error(f'Signature verification failed for {path}: {e}')
        return _result('unavailable', detail=f'verification error: {e}')
    if result['status'] == 'valid':
        # publisher identity: the same issuer-intermediate check as Linux,
        # on the same buffer; without signify it cannot be done -> no cap
        result['publisher_allowed'] = False
        try:
            pem = load_pinned_store()
            out = _signify_verify(data, pem)
            if isinstance(out, dict):
                result['detail'] += f"; issuer check: {out['detail']}"
            else:
                primary, leaf, signing_time = out
                when = signing_time or datetime.now(timezone.utc)
                issuer = _issuing_ca(leaf, list(primary.certificates), pem, when)
                allowed, reason = publisher_decision(leaf, issuer, policy)
                result['publisher'] = _publisher(leaf)        # CN first, as on Linux
                result['publisher_allowed'] = allowed
                result['detail'] += f'; {reason}'
        except Exception as e:  # noqa: BLE001
            result['detail'] += f'; issuer check unavailable ({type(e).__name__}: {e})'
    result['os_cert_padding_check'] = _cert_padding_check_enabled()
    return result


def spki_report(paths):
    '''Tool for SENTINEL: prints the issuing CA (CN + SPKI sha256) of each
    signed file, to fill config/trusted_publishers.json after review.'''
    pem = load_pinned_store()
    for path in paths:
        try:
            data, _ = read_for_verify(path)
            out = _signify_verify(data, pem)
            if isinstance(out, dict):
                print(f'{path}: {out["status"]} {out["detail"]}')
                continue
            primary, leaf, signing_time = out
            issuer = _issuing_ca(leaf, list(primary.certificates), pem,
                                 signing_time or datetime.now(timezone.utc))
            print(f'{path}\tleaf CN={_name_field(leaf, "common_name")!r} '
                  f'O={_name_field(leaf, "organization_name")!r}\tissuer CN='
                  f'{_name_field(issuer, "common_name")!r}\tSPKI sha256={_spki_sha256(issuer)}')
        except Exception as e:  # noqa: BLE001
            print(f'{path}: error {type(e).__name__}: {e}')


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


if __name__ == '__main__':   # python -m dexmond_mie.signature spki FILE...
    if len(sys.argv) > 2 and sys.argv[1] == 'spki':
        spki_report(sys.argv[2:])
    else:
        print('usage: python -m dexmond_mie.signature spki FILE.exe [...]')
