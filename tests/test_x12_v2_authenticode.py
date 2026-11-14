'''X12 v2: cross-platform Authenticode verification (design
.review/X12_CROSS_PLATFORM_AUTHENTICODE_DESIGN_2026-11-14.md, sha 256ab93a).

Two groups:
- STRUCTURAL / FAIL-CLOSED tests on synthetic PE bytes: run anywhere, no
  signify, no real binaries.
- REAL tests on Microsoft-signed Sysinternals binaries with signify and a
  pinned root store. They need:
    MIE_SYSINTERNALS_DIR  folder with >= 10 Sysinternals .exe files
    MIE_TEST_TRUST_STORE  the reviewed authenticode_roots.pem
  and are skipped otherwise (run them on tiny).
'''
import glob
import hashlib
import os
import shutil
import statistics
import struct
import subprocess
import sys
import time
from datetime import timedelta

import pytest

from dexmond_mie import signature

# ---------------------------------------------------------------- helpers

def _synthetic_pe(cert_table=None, trailing=b'', pe32_plus=False):
    '''Minimal PE header + body; optional certificate table at the end.'''
    hdr = bytearray(0x400)
    hdr[0:2] = b'MZ'
    struct.pack_into('<I', hdr, 0x3c, 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    opt = 0x40 + 24
    struct.pack_into('<H', hdr, opt, 0x20b if pe32_plus else 0x10b)
    nrva, dirs = (opt + 108, opt + 112) if pe32_plus else (opt + 92, opt + 96)
    struct.pack_into('<I', hdr, nrva, 16)
    body = bytes(hdr) + b'\x90' * 0x1000
    if cert_table is not None:
        out = bytearray(body)
        struct.pack_into('<II', out, dirs + 4 * 8, len(body), len(cert_table))
        return bytes(out) + cert_table + trailing
    return body + trailing


def _win_cert(content_len=1500, der_len_delta=0, revision=0x0200, ctype=0x0002):
    content = (b'\x06\x09' + b'\x01' * 9) * (content_len // 11)
    der = b'\x30\x82' + struct.pack('>H', len(content) + der_len_delta) + content
    blob = struct.pack('<IHH', 8 + len(der), revision, ctype) + der
    return blob + b'\0' * ((-len(blob)) % 8)


def _write(tmp_path, data, name='a.exe'):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ------------------------------------------- structural / fail-closed (run anywhere)

def test_appended_data_after_cert_table_is_invalid(tmp_path):
    path = _write(tmp_path, _synthetic_pe(_win_cert(), trailing=b'\0' * 1024))
    assert signature.precheck_pe(path)[0] == 'invalid'
    assert signature.verify_portable(path)['status'] == 'invalid'


def test_removed_cert_table_is_unsigned(tmp_path):
    path = _write(tmp_path, _synthetic_pe(None))
    assert signature.verify_portable(path)['status'] == 'unsigned'


@pytest.mark.parametrize('delta', [+64, -64])
def test_truncated_or_overlong_pkcs7_is_invalid(tmp_path, delta):
    # +64: the DER header claims 64 bytes more than the body holds (truncated)
    # -64: the body runs 64 bytes past its DER length (smuggled bytes)
    path = _write(tmp_path, _synthetic_pe(_win_cert(der_len_delta=delta)))
    assert signature.verify_portable(path)['status'] == 'invalid'


def test_wrong_revision_or_type_is_invalid(tmp_path):
    for table in (_win_cert(revision=0x0100), _win_cert(ctype=0x0001)):
        path = _write(tmp_path, _synthetic_pe(table))
        assert signature.verify_portable(path)['status'] == 'invalid'


def test_signature_over_1mib_is_invalid(tmp_path):
    path = _write(tmp_path, _synthetic_pe(b'\0' * (signature.MAX_SIGNATURE_BYTES + 8)))
    assert signature.precheck_pe(path) == ('invalid',
                                           f'certificate table {signature.MAX_SIGNATURE_BYTES + 8} '
                                           f'bytes is over the 1 MiB limit')


def test_structurally_ok_but_store_not_provisioned_is_unavailable(tmp_path):
    path = _write(tmp_path, _synthetic_pe(_win_cert(), pe32_plus=True))
    assert signature.precheck_pe(path)[0] == 'ok'
    r = signature.verify_portable(path)
    assert r['status'] == 'unavailable' and 'not provisioned' in r['detail']


def test_wrong_pinned_store_sha_is_unavailable(tmp_path):
    store = tmp_path / 'roots.pem'
    store.write_bytes(b'-----BEGIN CERTIFICATE-----\nnot reviewed\n-----END CERTIFICATE-----\n')
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    r = signature.verify_portable(path, store_path=str(store), pinned_sha256='00' * 32)
    assert r['status'] == 'unavailable' and 'mismatch' in r['detail']


def test_missing_signify_is_unavailable(tmp_path, monkeypatch):
    store = tmp_path / 'roots.pem'
    store.write_bytes(b'pem')
    sha = hashlib.sha256(b'pem').hexdigest()

    def no_signify():
        raise ImportError('No module named signify')
    monkeypatch.setattr(signature, '_import_signify', no_signify)
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    r = signature.verify_portable(path, store_path=str(store), pinned_sha256=sha)
    assert r['status'] == 'unavailable' and 'signify' in r['detail']


def test_any_exception_is_unavailable(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('unexpected')
    monkeypatch.setattr(signature, '_verify_portable_inner', boom)
    assert signature.verify_portable(_write(tmp_path, b'MZ'))['status'] == 'unavailable'


def test_timeout_is_unavailable(tmp_path, monkeypatch):
    def slow(*a, **k):
        time.sleep(1.0)
        return signature._result('valid', publisher='Microsoft Corporation')
    monkeypatch.setattr(signature, '_verify_portable_inner', slow)
    r = signature.verify_portable(_write(tmp_path, b'MZ'), timeout=0.05)
    assert r['status'] == 'unavailable' and 'timed out' in r['detail']


def test_every_result_states_revocation_not_checked(tmp_path):
    r = signature.verify_portable(_write(tmp_path, _synthetic_pe(None)))
    assert r['revocation'] == 'not checked (offline)'


def test_shipped_store_matches_pin():
    if not signature.PINNED_ROOTS_SHA256:
        pytest.skip('pinned root store NOT PROVISIONED (needs SENTINEL review)')
    with open(signature.TRUST_STORE_PATH, 'rb') as f:
        assert hashlib.sha256(f.read()).hexdigest() == signature.PINNED_ROOTS_SHA256


# ------------------------------------------------ real binaries (tiny / Windows VM)

def _real_env():
    pytest.importorskip('signify')
    pytest.importorskip('cryptography')
    folder = os.environ.get('MIE_SYSINTERNALS_DIR')
    store = os.environ.get('MIE_TEST_TRUST_STORE')
    if not folder or not store:
        pytest.skip('set MIE_SYSINTERNALS_DIR and MIE_TEST_TRUST_STORE (run on tiny)')
    files = sorted(glob.glob(os.path.join(folder, '*.exe')))[:10]
    if len(files) < 10:
        pytest.skip('need 10 Sysinternals .exe files')
    with open(store, 'rb') as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return files, store, sha


def _verify(path, store, sha, **kw):
    return signature.verify_portable(path, store_path=store, pinned_sha256=sha, **kw)


def _cert_dir(data):
    e = struct.unpack_from('<I', data, 0x3c)[0]
    opt = e + 24
    dirs = opt + (112 if struct.unpack_from('<H', data, opt)[0] == 0x20b else 96)
    return dirs + 4 * 8


def test_positive_10_sysinternals_valid_microsoft():
    files, store, sha = _real_env()
    for path in files:
        r = _verify(path, store, sha)
        assert r['status'] == 'valid', (path, r)
        assert r['publisher'] == 'Microsoft Corporation' and r['publisher_allowed'] is True


def test_neg_flipped_byte_in_signed_area(tmp_path):
    files, store, sha = _real_env()
    data = bytearray(open(files[0], 'rb').read())
    data[0x400 + 0x100] ^= 0xFF          # inside the first section, inside the digest
    r = _verify(_write(tmp_path, bytes(data)), store, sha)
    assert r['status'] != 'valid', r


def test_neg_appended_1kb_after_cert_table(tmp_path):
    files, store, sha = _real_env()
    r = _verify(_write(tmp_path, open(files[0], 'rb').read() + b'\0' * 1024), store, sha)
    assert r['status'] != 'valid', r


def test_neg_cert_table_removed(tmp_path):
    files, store, sha = _real_env()
    data = bytearray(open(files[0], 'rb').read())
    d = _cert_dir(data)
    off, _ = struct.unpack_from('<II', data, d)
    struct.pack_into('<II', data, d, 0, 0)
    r = _verify(_write(tmp_path, bytes(data[:off])), store, sha)
    assert r['status'] == 'unsigned', r


def _strip_signature(data):
    data = bytearray(data)
    d = _cert_dir(data)
    off, _ = struct.unpack_from('<II', data, d)
    struct.pack_into('<II', data, d, 0, 0)
    return bytes(data[:off])


def test_neg_self_signed_test_certificate(tmp_path):
    files, store, sha = _real_env()
    tool = shutil.which('osslsigncode')
    if not tool:
        pytest.skip('osslsigncode not installed (needed to sign with a throwaway key)')
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    import datetime as dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Microsoft Corporation'),
                      x509.NameAttribute(NameOID.COMMON_NAME, 'Microsoft Corporation')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False)
            .sign(key, hashes.SHA256()))
    (tmp_path / 'k.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (tmp_path / 'c.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    unsigned = _write(tmp_path, _strip_signature(open(files[0], 'rb').read()), 'u.exe')
    out = str(tmp_path / 's.exe')
    subprocess.run([tool, 'sign', '-certs', str(tmp_path / 'c.pem'), '-key', str(tmp_path / 'k.pem'),
                    '-in', unsigned, '-out', out], check=True, capture_output=True)
    r = _verify(out, store, sha)
    assert r['status'] != 'valid', r


def test_neg_valid_but_publisher_not_allowlisted():
    files, store, sha = _real_env()
    r = _verify(files[0], store, sha, publishers=('Some Other Vendor Ltd',))
    assert r['status'] == 'valid' and r['publisher_allowed'] is False


def test_neg_timestamp_outside_leaf_validity(monkeypatch):
    files, store, sha = _real_env()
    real_leaf = signature._leaf_certificate
    captured = {}

    def leaf(sd):
        captured['leaf'] = real_leaf(sd)
        return captured['leaf']

    def late(sd):
        lf = captured['leaf']
        na = getattr(lf, 'not_valid_after_utc', None) or lf.not_valid_after
        return na + timedelta(days=1)
    monkeypatch.setattr(signature, '_leaf_certificate', leaf)
    monkeypatch.setattr(signature, '_signing_time', late)
    r = _verify(files[0], store, sha)
    assert r['status'] != 'valid', r


def test_neg_truncated_pkcs7_real(tmp_path):
    files, store, sha = _real_env()
    data = bytearray(open(files[0], 'rb').read())
    d = _cert_dir(data)
    off, size = struct.unpack_from('<II', data, d)
    der_len = 4 + int.from_bytes(data[off + 10:off + 12], 'big')
    der = bytearray(data[off + 8:off + 8 + der_len - 256])      # cut 256 bytes
    der[2:4] = struct.pack('>H', len(der) - 4)                 # header agrees: ASN.1 is broken
    blob = struct.pack('<IHH', 8 + len(der), 0x0200, 0x0002) + bytes(der)
    blob += b'\0' * ((-len(blob)) % 8)
    struct.pack_into('<II', data, d, off, len(blob))
    r = _verify(_write(tmp_path, bytes(data[:off]) + blob), store, sha)
    assert r['status'] != 'valid', r


def test_neg_wrong_pinned_store_sha_real():
    files, store, _ = _real_env()
    assert _verify(files[0], store, 'ab' * 32)['status'] == 'unavailable'


def test_performance_median_under_50ms():
    files, store, sha = _real_env()
    times = []
    for path in files:
        t0 = time.perf_counter()
        _verify(path, store, sha)
        times.append(time.perf_counter() - t0)
    assert statistics.median(times) < 0.050, times


@pytest.mark.skipif(sys.platform != 'win32', reason='parity test runs in the Windows VM')
def test_parity_windows_vs_signify():
    files, store, sha = _real_env()
    for path in files:
        w = signature._verify_windows(path)
        p = _verify(path, store, sha)
        assert (w['status'], w['publisher']) == (p['status'], p['publisher']), path


def test_neg_pinned_store_really_used_not_os_or_bundle(tmp_path):
    '''A real Microsoft-signed file checked against a pinned store that holds
    ONLY a throwaway root must NOT be valid. Catches signify silently falling
    back to its bundled or the OS trust store.'''
    files, _, _ = _real_env()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime as dt
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Throwaway Test Root')])
    now = dt.datetime.now(dt.timezone.utc)
    root = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    pem = root.public_bytes(serialization.Encoding.PEM)
    store = tmp_path / 'only_throwaway.pem'
    store.write_bytes(pem)
    r = _verify(files[0], str(store), hashlib.sha256(pem).hexdigest())
    assert r['status'] != 'valid', r


def test_windows_path_runs_precheck_appended_data_is_invalid(tmp_path, monkeypatch):
    '''Parity: even if WinVerifyTrust says valid (no EnableCertPaddingCheck),
    data appended after the certificate table makes the result invalid.'''
    monkeypatch.setattr(signature.sys, 'platform', 'win32')
    monkeypatch.setattr(signature, '_verify_windows',
                        lambda p: signature._result('valid', publisher='Microsoft Corporation'))
    monkeypatch.setattr(signature, '_cert_padding_check_enabled', lambda: False)
    appended = _write(tmp_path, _synthetic_pe(_win_cert(), trailing=b'\0' * 1024))
    assert signature.verify_authenticode(appended)['status'] == 'invalid'
    clean = _write(tmp_path, _synthetic_pe(_win_cert()), 'b.exe')
    r = signature.verify_authenticode(clean)
    assert r['status'] == 'valid' and r['os_cert_padding_check'] is False
    assert signature.verify_authenticode(_write(tmp_path, _synthetic_pe(None), 'c.exe'))[
        'status'] == 'unsigned'
