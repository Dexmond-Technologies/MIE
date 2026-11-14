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


def _throwaway_cert(cn, org=None, ca=False, code_signing=False):
    '''A throwaway key + self-signed certificate made with asn1crypto and
    oscrypto (both in requirements-signify.lock; no `cryptography`).'''
    pytest.importorskip('asn1crypto')
    pytest.importorskip('oscrypto')
    import datetime as dt
    from asn1crypto import x509 as ax509
    from oscrypto import asymmetric
    pub, priv = asymmetric.generate_pair('rsa', bit_size=2048)
    attrs = {'common_name': cn}
    if org:
        attrs['organization_name'] = org
    name = ax509.Name.build(attrs)
    now = dt.datetime.now(dt.timezone.utc)
    exts = [{'extn_id': 'basic_constraints', 'critical': True, 'extn_value': {'ca': ca}}]
    if code_signing:
        exts.append({'extn_id': 'extended_key_usage', 'critical': False,
                     'extn_value': ['code_signing']})
    tbs = ax509.TbsCertificate({
        'version': 'v3', 'serial_number': int.from_bytes(os.urandom(8), 'big'),
        'signature': {'algorithm': 'sha256_rsa'}, 'issuer': name, 'subject': name,
        'validity': {'not_before': ax509.Time({'utc_time': now - dt.timedelta(days=1)}),
                     'not_after': ax509.Time({'utc_time': now + dt.timedelta(days=30)})},
        'subject_public_key_info': pub.asn1, 'extensions': exts})
    cert = ax509.Certificate({'tbs_certificate': tbs,
                              'signature_algorithm': {'algorithm': 'sha256_rsa'},
                              'signature_value': asymmetric.rsa_pkcs1v15_sign(priv, tbs.dump(),
                                                                             'sha256')})
    return cert, asymmetric.dump_private_key(priv, None)


def _pem(cert):
    from asn1crypto import pem as apem
    return apem.armor('CERTIFICATE', cert.dump())


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


def test_structurally_ok_but_store_not_provisioned_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(signature, 'PINNED_ROOTS_SHA256', None)
    path = _write(tmp_path, _synthetic_pe(_win_cert(), pe32_plus=True))
    assert signature.precheck_pe(path)[0] == 'ok'
    r = signature.verify_portable(path)
    assert r['status'] == 'unavailable' and 'not provisioned' in r['detail']


def test_empty_store_file_is_unavailable(tmp_path):
    store = tmp_path / 'empty.pem'
    store.write_bytes(b'')
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    r = signature.verify_portable(path, store_path=str(store), pinned_sha256='00' * 32)
    assert r['status'] == 'unavailable'


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
    assert signature.PINNED_ROOTS_SHA256, 'pinned root store must be provisioned'
    with open(signature.TRUST_STORE_PATH, 'rb') as f:
        assert hashlib.sha256(f.read()).hexdigest() == signature.PINNED_ROOTS_SHA256
    assert signature.load_pinned_store()          # loads with the shipped pin


# ------------------------------------------------ real binaries (tiny / Windows VM)

def _real_env():
    pytest.importorskip('signify')
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
        assert r['publisher'] == 'Microsoft Corporation'
        assert r['issuer'] and r['issuer_spki_sha256']


def test_positive_cap_allowed_when_intermediates_pinned():
    files, store, sha = _real_env()
    policy = signature.load_policy()
    if not any(e['spki_sha256'] for e in policy['issuing_intermediates']):
        pytest.skip('issuing-intermediate SPKIs NOT PINNED yet (SENTINEL review)')
    allowed = [_verify(p, store, sha)['publisher_allowed'] for p in files]
    assert all(allowed), allowed


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
    cert, key_pem = _throwaway_cert('Microsoft Corporation', 'Microsoft Corporation',
                                    code_signing=True)
    (tmp_path / 'k.pem').write_bytes(key_pem)
    (tmp_path / 'c.pem').write_bytes(_pem(cert))
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

    def late(sd, pem):
        return signature._validity(captured['leaf'])[1] + timedelta(days=1)
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
    back to mscerts (its bundled store) or the OS trust store.'''
    files, _, _ = _real_env()
    root, _ = _throwaway_cert('Throwaway Test Root', ca=True)
    pem = _pem(root)
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
    assert r['publisher_allowed'] is False      # issuer check could not run: no cap
    assert signature.verify_authenticode(_write(tmp_path, _synthetic_pe(None), 'c.exe'))[
        'status'] == 'unsigned'


# ------------------------------------------------ T-TS (SENTINEL must-test)

def _chains_to(cert_asn1, pool_asn1, root_asn1, when, eku):
    '''Independent of signature.py: does cert chain to this one root?'''
    from certvalidator import CertificateValidator, ValidationContext
    ctx = ValidationContext(trust_roots=[root_asn1], moment=when, allow_fetching=False,
                            revocation_mode='soft-fail', weak_hash_algos={'md2', 'md5'})
    try:
        CertificateValidator(cert_asn1, intermediate_certs=pool_asn1,
                             validation_context=ctx).validate_usage(set(), extended_key_usage={eku})
        return True
    except Exception:
        return False


def _ts_case(files):
    '''A file whose timestamp root differs from its signing root.'''
    from asn1crypto import pem as apem, x509 as ax509
    roots = [ax509.Certificate.load(d) for _, _, d in
             apem.unarmor(open(signature.TRUST_STORE_PATH, 'rb').read(), multiple=True)]
    for path in files:
        _, primary = signature.primary_signature(open(path, 'rb').read())
        cs = signature._countersignature(primary) if primary is not None else None
        if cs is None or cs[1] is None:
            continue
        when, ts_cert, pool = cs
        leaf = signature._leaf_certificate(primary)
        pool_a = [signature._as_asn1(c) for c in pool]
        ts_a = signature._as_asn1(ts_cert)
        ts_root = [r for r in roots if _chains_to(ts_a, pool_a, r, when, 'time_stamping')]
        sig_root = [r for r in roots if _chains_to(leaf, pool_a, r, when, 'code_signing')]
        if ts_root and sig_root and ts_root[0].sha256 != sig_root[0].sha256:
            return path, leaf, sig_root[0], ts_root[0]
    pytest.skip('no sample whose timestamp root differs from its signing root')


def _store(tmp_path, certs, name):
    from asn1crypto import pem as apem
    pem = b''.join(apem.armor('CERTIFICATE', c.dump()) for c in certs)
    p = tmp_path / name
    p.write_bytes(pem)
    return str(p), hashlib.sha256(pem).hexdigest()


def test_ts_countersigner_outside_store_is_ignored(tmp_path):
    '''T-TS (outside): the timestamp root is NOT in the pinned store, so the
    timestamp is ignored and the leaf is judged at "now".'''
    files, _, _ = _real_env()
    path, leaf, sig_root, _ = _ts_case(files)
    store, sha = _store(tmp_path, [sig_root], 'sign_root_only.pem')
    r = _verify(path, store, sha)
    assert r.get('timestamp') is None, r
    from datetime import datetime, timezone
    nb, na = signature._validity(leaf)
    if not nb <= datetime.now(timezone.utc) <= na:
        assert r['status'] != 'valid', r      # expired now, timestamp not trusted


def test_ts_countersigner_inside_store_is_used(tmp_path):
    '''T-TS (inside): with the timestamp root in the pinned store, the
    timestamp is used.'''
    files, _, _ = _real_env()
    path, _, sig_root, ts_root = _ts_case(files)
    store, sha = _store(tmp_path, [sig_root, ts_root], 'sign_and_ts_roots.pem')
    r = _verify(path, store, sha)
    assert r['status'] == 'valid' and r.get('timestamp'), r


# ------------------------------------------------ publisher identity (issuer pin)

class _FakeSPKI:
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return self.raw


class _FakeCert:
    '''asn1crypto-shaped stand-in (PASS UNDER MOCK).'''
    def __init__(self, cn=None, org=None, spki=b'key'):
        self.subject = type('S', (), {'native': {k: v for k, v in
                                                 (('common_name', cn), ('organization_name', org)) if v}})()
        self._tbs = {'subject_public_key_info': _FakeSPKI(spki)}

    def __getitem__(self, key):
        return self._tbs


def _policy(spki=None):
    pol = signature.load_policy()
    pol['issuing_intermediates'] = [
        {'cn': 'Microsoft Code Signing PCA 2011',
         'spki_sha256': hashlib.sha256(spki).hexdigest() if spki else None}]
    return pol


MS_LEAF = _FakeCert('Microsoft Corporation', 'Microsoft Corporation')
PCA2011 = _FakeCert('Microsoft Code Signing PCA 2011', 'Microsoft Corporation', b'pca-2011-key')


def test_issuer_pinned_by_cn_and_spki_is_allowed():
    assert signature.publisher_decision(MS_LEAF, PCA2011, _policy(b'pca-2011-key'))[0] is True


def test_issuer_spki_mismatch_or_not_pinned_is_not_allowed():
    assert signature.publisher_decision(MS_LEAF, PCA2011, _policy(b'other-key'))[0] is False
    allowed, reason = signature.publisher_decision(MS_LEAF, PCA2011, _policy(None))
    assert allowed is False and 'not pinned' in reason


def test_whcp_and_third_party_component_chains_rejected():
    pol = _policy(b'pca-2011-key')
    whcp = _FakeCert('Microsoft Windows Hardware Compatibility Publisher', 'Microsoft Corporation')
    assert signature.publisher_decision(whcp, PCA2011, pol)[0] is False
    tpc = _FakeCert('Microsoft Windows Third Party Component CA 2014', 'Microsoft Corporation',
                    b'pca-2011-key')
    assert signature.publisher_decision(MS_LEAF, tpc, pol)[0] is False


def test_leaf_cn_and_o_must_both_match():
    pol = _policy(b'pca-2011-key')
    for leaf in (_FakeCert('Contoso Ltd', 'Microsoft Corporation'),
                 _FakeCert('Microsoft Corporation', 'Contoso Ltd'),
                 _FakeCert('Microsoft Corporation', None)):
        assert signature.publisher_decision(leaf, PCA2011, pol)[0] is False


def test_unlisted_issuer_not_allowed():
    other = _FakeCert('Some Other CA', 'Microsoft Corporation', b'pca-2011-key')
    assert signature.publisher_decision(MS_LEAF, other, _policy(b'pca-2011-key'))[0] is False


def test_publisher_name_is_cn_first():
    assert signature._publisher(_FakeCert('Microsoft Corporation', 'Something Else')) == \
        'Microsoft Corporation'
    assert signature._publisher(_FakeCert(None, 'Org Only')) == 'Org Only'


def test_shipped_policy_has_the_three_pcas_and_denials():
    pol = signature.load_policy()
    assert [e['cn'] for e in pol['issuing_intermediates']] == [
        'Microsoft Code Signing PCA 2010', 'Microsoft Code Signing PCA 2011',
        'Microsoft Code Signing PCA 2024']
    assert 'Microsoft Windows Hardware Compatibility Publisher' in pol['rejected_leaf_cns']
    assert pol['publishers'] == ('Microsoft Corporation',)


# ------------------------------------------------ timestamp strict mode

def test_timestamp_used_only_if_countersigner_chains_to_pinned_store(monkeypatch):
    from datetime import datetime, timezone
    t = datetime(2020, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(signature, '_countersignature', lambda sd: (t, object(), []))
    monkeypatch.setattr(signature, '_countersigner_trusted', lambda *a: False)
    assert signature._signing_time(None, b'pem') is None          # ignored -> "now"
    monkeypatch.setattr(signature, '_countersigner_trusted', lambda *a: True)
    assert signature._signing_time(None, b'pem') == t
    monkeypatch.setattr(signature, '_countersignature', lambda sd: None)
    assert signature._signing_time(None, b'pem') is None


# ------------------------------------------------ TOCTOU

def test_verified_bytes_are_the_scanned_buffer(tmp_path):
    '''The on-disk file is clean; the scanned buffer has data appended: the
    verifier judges the buffer, so the result is invalid.'''
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    buf, key = signature.read_for_verify(path)
    r = signature.verify_portable(path, data=buf + b'\0' * 1024, scanned_stat=key)
    assert r['status'] == 'invalid'


def test_file_changed_after_scan_is_unavailable(tmp_path):
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    buf, key = signature.read_for_verify(path)
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    r = signature.verify_portable(path, data=buf, scanned_stat=key)
    assert r['status'] == 'unavailable' and 'changed' in r['detail']


def test_read_for_verify_refuses_symlink_nonregular_and_oversize(tmp_path):
    real = _write(tmp_path, _synthetic_pe(_win_cert()))
    link = tmp_path / 'link.exe'
    os.symlink(real, link)
    with pytest.raises(OSError):
        signature.read_for_verify(str(link))
    with pytest.raises((ValueError, OSError)):
        signature.read_for_verify(str(tmp_path))
    with pytest.raises(ValueError):
        signature.read_for_verify(real, limit=100)
    assert signature.verify_portable(str(link))['status'] == 'unavailable'


def test_engine_no_signature_check_when_file_bigger_than_buffer(tmp_path, make_engine,
                                                              monkeypatch):
    from fakepe import FakeSection, patch_engine_pe
    from dexmond_mie import core
    patch_engine_pe(monkeypatch, sections=[FakeSection('.text', 6.0, 'RX')])
    monkeypatch.setattr(core, 'MAX_ANALYSIS_BYTES', 1024)
    called = []
    engine = make_engine(signature_verifier=lambda *a, **k: called.append(1) or
                         {'status': 'valid', 'publisher': 'Microsoft Corporation',
                          'publisher_allowed': True})
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    results = engine.scan_file(path)
    assert not called
    assert results['details']['signature']['status'] == 'unavailable'
    assert 'heuristics_capped_at' not in results['details']['signature']


def test_engine_passes_scanned_buffer_to_verifier(tmp_path, make_engine, monkeypatch):
    from fakepe import FakeSection, patch_engine_pe
    patch_engine_pe(monkeypatch, sections=[FakeSection('.text', 6.0, 'RX')])
    seen = {}

    def verifier(path, data=None, scanned_stat=None):
        seen['data'], seen['stat'] = data, scanned_stat
        return {'status': 'unsigned', 'publisher': None}
    path = _write(tmp_path, _synthetic_pe(_win_cert()))
    make_engine(signature_verifier=verifier).scan_file(path)
    assert seen['data'] == open(path, 'rb').read()
    assert seen['stat'][0] == os.path.getsize(path)
