#!/usr/bin/env python3
"""Authenticode check: the C++ engine against the Python reference (CI only).

    signature_parity.py PROBE REPO

PROBE is mie-signature-probe; REPO is the checkout (the reference is dexmond_mie/signature.py,
function verify_portable, with signify, certvalidator, asn1crypto and oscrypto from
requirements-signify.lock installed).

Everything is made inside this test and thrown away with its temporary folder: a root, an
issuing CA, a second issuing CA with the same name and another key, a time-stamping
certificate, several leaf certificates, an untrusted second root, and small generated
executables signed with them. No key or certificate is committed. The throwaway root is
given to BOTH sides as the root store (path + its SHA-256 as the pinned value); the real
store trust/authenticode_roots.pem is never opened.

Compared for every input:
  HARD (a difference fails the test)
    cap                the scorer's condition: status valid AND publisher_allowed
    status             for the named cases exactly; for the randomly damaged variants the
                       pair invalid/unavailable is counted separately (both mean "no cap";
                       which of the two a damaged structure gives depends on WHERE a Python
                       library notices it, which is not reproduced), every other difference
                       is hard
    publisher, publisher_allowed, issuer, issuer_spki_sha256, timestamp
    detail             where the text is the reference's own (structural precheck, leaf
                       checks up to the clock value, the valid text)
  REPORTED, NOT FAILING
    the exception class inside "signify: <class>: ..." and "verification error: <class>: ..."
    (the texts behind the class name are not reproduced)
The named cases also carry the status the REFERENCE must give; if the reference answers
otherwise the test fails, so a missing signature library cannot make the test pass empty.
"""
import datetime
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

SEED = 20261123
PROBE = sys.argv[1]
REPO = sys.argv[2]
sys.path.insert(0, REPO)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

NOW = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
DAY = datetime.timedelta(days=1)


# ----------------------------------------------------------------------------- DER
def der(tag, content=b''):
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        digits = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        head = bytes([tag, 0x80 | len(digits)]) + digits
    return head + content


def der_int(value):
    return der(0x02, value.to_bytes(value.bit_length() // 8 + 1, 'big'))


def oid(dotted):
    parts = [int(p) for p in dotted.split('.')]
    out = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7f))
            part >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, bytes(out))


def seq(*items):
    return der(0x30, b''.join(items))


OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_DATA = '1.2.840.113549.1.7.1'
OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6'
OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'
OID_SPC_INDIRECT = '1.3.6.1.4.1.311.2.1.4'
OID_SPC_PE_IMAGE = '1.3.6.1.4.1.311.2.1.15'
OID_MS_TIMESTAMP = '1.3.6.1.4.1.311.3.3.1'
OID_PAGE_HASH_V2 = '1.3.6.1.4.1.311.2.3.2'
OID_RSA = '1.2.840.113549.1.1.1'
DIGESTS = {'sha1': ('1.3.14.3.2.26', hashes.SHA1), 'sha256': ('2.16.840.1.101.3.4.2.1', hashes.SHA256),
           'md5': ('1.2.840.113549.2.5', hashes.MD5)}
OID_NESTED_SIGNATURE = '1.3.6.1.4.1.311.2.4.1'
OID_LIFETIME_SIGNING = '1.3.6.1.4.1.311.10.3.13'
PAGE_HASH_CLASS_ID = bytes.fromhex('a6b586d5b4a12466ae05a217da8e60d6')


def alg_id(name):
    return seq(oid(DIGESTS[name][0]), der(0x05))


def attribute(type_oid, *values):
    return seq(oid(type_oid), der(0x31, b''.join(values)))


# ----------------------------------------------------------------------------- certificates
class Identity:
    def __init__(self, cert, key):
        self.cert, self.key = cert, key
        self.der = cert.public_bytes(serialization.Encoding.DER)


def make_identity(cn, issuer=None, org=None, ca=False, eku=None, key_usage='default',
                  not_before=None, not_after=None, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    name = x509.Name(attrs)
    builder = (x509.CertificateBuilder()
               .subject_name(name)
               .issuer_name(issuer.cert.subject if issuer else name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before or NOW - 3000 * DAY)
               .not_valid_after(not_after or NOW + 3000 * DAY)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if key_usage == 'default':
        key_usage = 'ca' if ca else 'digital_signature'
    if key_usage is not None:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=key_usage == 'digital_signature', content_commitment=False,
            key_encipherment=key_usage == 'key_encipherment', data_encipherment=False, key_agreement=False,
            key_cert_sign=key_usage == 'ca', crl_sign=key_usage == 'ca', encipher_only=False,
            decipher_only=False), critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(issuer.key if issuer else key, hashes.SHA256())
    return Identity(cert, key)


def issuer_and_serial(identity):
    return seq(identity.cert.issuer.public_bytes(), der_int(identity.cert.serial_number))


def signer_info(identity, digest, attrs):
    """A SignerInfo whose signed attributes are `attrs` (each a DER attribute)."""
    body = b''.join(sorted(attrs))
    algorithm = DIGESTS[digest][1]()
    if isinstance(identity.key, rsa.RSAPrivateKey):
        signature, key_oid = identity.key.sign(der(0x31, body), padding.PKCS1v15(), algorithm), OID_RSA
    elif isinstance(identity.key, dsa.DSAPrivateKey):
        signature, key_oid = identity.key.sign(der(0x31, body), algorithm), '1.2.840.10040.4.1'
    else:
        signature, key_oid = identity.key.sign(der(0x31, body), ec.ECDSA(algorithm)), '1.2.840.10045.2.1'
    return signature, [der_int(1), issuer_and_serial(identity), alg_id(digest), der(0xA0, body),
                       seq(oid(key_oid), der(0x05)), der(0x04, signature)]


# ----------------------------------------------------------------------------- executables
def make_pe(plus=True, fill=0x41):
    """A minimal executable image: headers of 0x200 bytes and one section of 0x200 bytes."""
    optional_size = 240 if plus else 224
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    coff = struct.pack('<HHIIIHH', 0x8664 if plus else 0x14C, 1, 0, 0, 0, optional_size, 0x22 if plus else 0x102)
    optional = bytearray(optional_size)
    struct.pack_into('<H', optional, 0, 0x20B if plus else 0x10B)
    struct.pack_into('<I', optional, 16, 0x1000)                    # entry point
    struct.pack_into('<II', optional, 32, 0x1000, 0x200)            # section and file alignment
    struct.pack_into('<I', optional, 56, 0x2000)                    # size of image
    struct.pack_into('<I', optional, 60, 0x200)                     # size of headers
    struct.pack_into('<H', optional, 68, 3)                         # subsystem
    struct.pack_into('<I', optional, 108 if plus else 92, 16)       # number of directories
    section = struct.pack('<8sIIIIIIHHI', b'.text', 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + b'PE\0\0' + coff + bytes(optional) + section
    assert len(headers) <= 0x200
    return headers.ljust(0x200, b'\0') + bytes([fill]) * 0x200


def layout(pe):
    e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
    optional = e_lfanew + 24
    plus = struct.unpack_from('<H', pe, optional)[0] == 0x20B
    return optional + 64, optional + (144 if plus else 128)


def image_digest(pe, digest, start=0, end=None, pad_to=None):
    """Digest of the image without the checksum and the certificate-table directory entry,
    restricted to [start, end), zero-padded to `pad_to`."""
    checksum, entry = layout(pe)
    end = len(pe) if end is None else end
    h = hashlib.new(digest)
    for a, b in ((0, checksum), (checksum + 4, entry), (entry + 8, len(pe))):
        a, b = max(a, start), min(b, end)
        if a < b:
            h.update(pe[a:b])
    if pad_to and (end - start) % pad_to:
        h.update(b'\0' * (pad_to - (end - start) % pad_to))
    return h.digest()


def spc_indirect(pe, digest, page_hashes=None):
    if page_hashes is None:
        link = der(0xA2, der(0x80, b''))                                       # file: empty unicode string
    else:
        tables = page_hashes if isinstance(page_hashes, list) else [page_hashes]
        serialized = der(0x31, seq(oid(OID_PAGE_HASH_V2), der(0x31, b''.join(der(0x04, x) for x in tables))))
        link = der(0xA1, der(0x04, PAGE_HASH_CLASS_ID) + der(0x04, serialized))  # moniker
    image_data = seq(der(0x03, b'\x00'), der(0xA0, link))
    return seq(seq(oid(OID_SPC_PE_IMAGE), image_data),
               seq(alg_id(digest), der(0x04, image_digest(pe, digest))))


def page_hash_table(pe, wrong=False):
    table = b''
    for start in (0, 0x200):
        digest = image_digest(pe, 'sha256', start, start + 0x200, 0x1000)
        if wrong and start == 0x200:
            digest = bytes(32)
        table += struct.pack('<I', start) + digest
    return table + struct.pack('<I', 0x400) + bytes(32)


def page_hash_entries(pe, pairs):
    """A page-hash table for the given (start, end) pairs, each with the digest signify
    expects for it, closed by the usual last entry."""
    table = b''
    for start, end in pairs:
        if start < end:
            digest = image_digest(pe, 'sha256', start, end, 0x1000)
        else:
            digest = hashlib.sha256(b'').digest()
        table += struct.pack('<I', start) + digest
    return table + struct.pack('<I', pairs[-1][1]) + bytes(32)


def authenticode_blob(pe, leaf, extra_certs, digest='sha256', timestamp=None, tsa=None, stamp_time=None,
                      wrong_stamp_digest=False, page_hashes=None, nested=None):
    """The PKCS#7 SignedData (ContentInfo) of an Authenticode signature over `pe`."""
    spc = spc_indirect(pe, digest, page_hashes)
    spc_contents = spc[len(spc) - len(seq_contents(spc)):]
    content_digest = hashlib.new(digest, spc_contents).digest()
    attrs = [attribute(OID_CONTENT_TYPE, oid(OID_SPC_INDIRECT)),
             attribute(OID_MESSAGE_DIGEST, der(0x04, content_digest))]
    signature, fields = signer_info(leaf, digest, attrs)
    certs = [leaf.der] + [c.der for c in extra_certs]
    stamped = hashlib.sha256(b'wrong' if wrong_stamp_digest else signature).digest()
    unsigned = []
    if nested:
        unsigned.append(attribute(OID_NESTED_SIGNATURE, *nested))
    if timestamp == 'authenticode':
        when = stamp_time.strftime('%y%m%d%H%M%SZ').encode()
        counter_attrs = [attribute(OID_CONTENT_TYPE, oid(OID_DATA)),
                         attribute(OID_SIGNING_TIME, der(0x17, when)),
                         attribute(OID_MESSAGE_DIGEST, der(0x04, stamped))]
        _, counter_fields = signer_info(tsa, 'sha256', counter_attrs)
        unsigned.append(attribute(OID_COUNTER_SIGNATURE, seq(*counter_fields)))
        certs.append(tsa.der)
    elif timestamp == 'rfc3161':
        when = stamp_time.strftime('%Y%m%d%H%M%SZ').encode()
        tst = seq(der_int(1), oid('1.2.3.4'), seq(alg_id('sha256'), der(0x04, stamped)), der_int(7),
                  der(0x18, when))
        token_attrs = [attribute(OID_CONTENT_TYPE, oid(OID_TST_INFO)),
                       attribute(OID_MESSAGE_DIGEST, der(0x04, hashlib.sha256(tst).digest()))]
        _, token_fields = signer_info(tsa, 'sha256', token_attrs)
        token = seq(oid(OID_SIGNED_DATA), der(0xA0, seq(
            der_int(3), der(0x31, alg_id('sha256')), seq(oid(OID_TST_INFO), der(0xA0, der(0x04, tst))),
            der(0xA0, tsa.der), der(0x31, seq(*token_fields)))))
        unsigned.append(attribute(OID_MS_TIMESTAMP, token))
    if unsigned:
        fields.append(der(0xA1, b''.join(unsigned)))
    signed_data = seq(der_int(1), der(0x31, alg_id(digest)), seq(oid(OID_SPC_INDIRECT), der(0xA0, spc)),
                      der(0xA0, b''.join(certs)), der(0x31, seq(*fields)))
    return seq(oid(OID_SIGNED_DATA), der(0xA0, signed_data))


def seq_contents(element):
    """The content bytes of a DER element."""
    n = element[1]
    if n < 0x80:
        return element[2:2 + n]
    count = n & 0x7f
    return element[2 + count:]


def attach(pe, blobs):
    """`pe` with a certificate table holding `blobs` (one entry each)."""
    table = b''
    for blob in blobs:
        entry = struct.pack('<IHH', 8 + len(blob), 0x0200, 0x0002) + blob
        table += entry.ljust((len(entry) + 7) & ~7, b'\0')
    out = bytearray(pe)
    struct.pack_into('<II', out, layout(pe)[1], len(pe), len(table))
    return bytes(out) + table


def der_path(blob, target):
    """Where the byte `target` of the DER text `blob` lies: the chain of elements around it,
    outermost first, each as tag@offset+length, and whether the byte is in the header (tag or
    length bytes) or the content of the innermost one. Only constructed elements are entered."""
    path, start, end = [], 0, len(blob)
    while True:
        pos, found = start, False
        while pos + 2 <= end:
            tag, n, head = blob[pos], blob[pos + 1], 2
            if n & 0x80:
                count = n & 0x7f
                if count == 0 or count > 4 or pos + 2 + count > end:
                    break
                n, head = int.from_bytes(blob[pos + 2:pos + 2 + count], 'big'), 2 + count
            if pos + head + n > end:
                break
            if pos <= target < pos + head + n:
                where = 'header' if target < pos + head else 'content'
                path.append(f'{tag:02x}@{pos}+{head + n}:{where}')
                if where == 'content' and tag & 0x20:
                    start, end, found = pos + head, pos + head + n, True
                break
            pos += head + n
        if not found:
            return ' > '.join(path) or 'outside any element'


def describe_mutation(base, changed, where, kind, table_at):
    """One line for a damaged variant: where, what, the bytes around it before and after, and
    the ASN.1 elements of the ORIGINAL signature the first changed byte lies in."""
    a, b = max(0, where - 8), min(len(base), where + 8)
    text = f'{kind} at file offset {where}; before {base[a:b].hex()} after {changed[a:b].hex()}'
    if where < table_at:
        return text + '; in the image (headers or section), not in the certificate table'
    inside = where - table_at
    if inside < 8:
        return text + '; in the WIN_CERTIFICATE header (dwLength, revision, type)'
    blob = base[table_at + 8:]
    return text + f'; blob offset {inside - 8}; elements: {der_path(blob, inside - 8)}'


# ----------------------------------------------------------------------------- the inputs
def build_cases():
    code = [ExtendedKeyUsageOID.CODE_SIGNING]
    root = make_identity('MIE Test Root', ca=True)
    other_root = make_identity('MIE Other Root', ca=True)
    inter = make_identity('Test Issuing CA', issuer=root, ca=True)
    inter_other_key = make_identity('Test Issuing CA', issuer=root, ca=True)
    other_inter = make_identity('Test Issuing CA', issuer=other_root, ca=True)
    tsa = make_identity('Test TSA', issuer=root, eku=[ExtendedKeyUsageOID.TIME_STAMPING])
    leaf = make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=code)
    expired = make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=code,
                            not_before=NOW - 800 * DAY, not_after=NOW - 400 * DAY)
    no_eku = make_identity('Test Publisher', issuer=inter, org='Test Publisher')
    server_eku = make_identity('Test Publisher', issuer=inter, org='Test Publisher',
                               eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    no_ku = make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=code, key_usage=None)
    wrong_ku = make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=code,
                             key_usage='key_encipherment')
    stranger = make_identity('Other Publisher', issuer=inter, org='Other Publisher', eku=code)
    cn_only = make_identity('Test Publisher', issuer=inter, eku=code)
    rejected = make_identity('Rejected Leaf', issuer=inter, org='Test Publisher', eku=code)
    other_key_leaf = make_identity('Test Publisher', issuer=inter_other_key, org='Test Publisher', eku=code)
    untrusted_leaf = make_identity('Test Publisher', issuer=other_inter, org='Test Publisher', eku=code)

    policy = {'publishers': ['Test Publisher'],
              'issuing_intermediates': [{'cn': 'Test Issuing CA', 'spki_sha256': hashlib.sha256(
                  inter.cert.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()}],
              'rejected_issuers': ['Some Rejected CA'], 'rejected_leaf_cns': ['Rejected Leaf']}
    roots_pem = root.cert.public_bytes(serialization.Encoding.PEM)

    pe = make_pe()
    pe32 = make_pe(plus=False)
    mid = NOW - 600 * DAY
    cases = []  # (name, bytes, status the reference must give or None, cap the reference must give or None)

    def add(name, data, status=None, cap=None):
        cases.append((name, data, status, cap))

    def signed(image, who, extra, **kw):
        return attach(image, [authenticode_blob(image, who, extra, **kw)])

    good = signed(pe, leaf, [inter])
    add('valid_sha256', good, 'valid', True)
    add('valid_sha1_digest', signed(pe, leaf, [inter], digest='sha1'), 'valid', True)
    add('valid_pe32', signed(pe32, leaf, [inter]), 'valid', True)
    add('root_in_certificate_set', signed(pe, leaf, [inter, root]))   # no asserted status: compared only
    stamped_a = signed(pe, leaf, [inter], timestamp='authenticode', tsa=tsa, stamp_time=NOW - 10 * DAY)
    stamped_r = signed(pe, leaf, [inter], timestamp='rfc3161', tsa=tsa, stamp_time=NOW - 10 * DAY)
    add('valid_stamp_authenticode', stamped_a, 'valid', True)
    add('valid_stamp_rfc3161', stamped_r, 'valid', True)
    add('expired_leaf_no_stamp', signed(pe, expired, [inter]), 'invalid', False)
    add('expired_leaf_stamp_authenticode',
        signed(pe, expired, [inter], timestamp='authenticode', tsa=tsa, stamp_time=mid), 'valid', True)
    add('expired_leaf_stamp_rfc3161',
        signed(pe, expired, [inter], timestamp='rfc3161', tsa=tsa, stamp_time=mid), 'valid', True)
    add('stamp_after_expiry_rfc3161',
        signed(pe, expired, [inter], timestamp='rfc3161', tsa=tsa, stamp_time=NOW - 100 * DAY), 'invalid', False)
    add('stamp_wrong_digest_authenticode',
        signed(pe, leaf, [inter], timestamp='authenticode', tsa=tsa, stamp_time=mid, wrong_stamp_digest=True),
        'invalid', False)
    add('stamp_wrong_digest_rfc3161',
        signed(pe, leaf, [inter], timestamp='rfc3161', tsa=tsa, stamp_time=mid, wrong_stamp_digest=True),
        'invalid', False)
    add('stamp_by_code_signing_cert',
        signed(pe, leaf, [inter], timestamp='rfc3161', tsa=leaf, stamp_time=mid), 'invalid', False)
    add('untrusted_root', signed(pe, untrusted_leaf, [other_inter, other_root]), 'invalid', False)
    add('missing_intermediate', signed(pe, leaf, []), 'invalid', False)
    add('leaf_without_eku', signed(pe, no_eku, [inter]), 'invalid', False)
    add('leaf_with_server_eku', signed(pe, server_eku, [inter]), 'invalid', False)
    add('leaf_without_key_usage', signed(pe, no_ku, [inter]), 'valid', True)
    add('leaf_key_usage_without_signing', signed(pe, wrong_ku, [inter]), 'invalid', False)
    add('publisher_not_listed', signed(pe, stranger, [inter]), 'valid', False)
    add('publisher_without_organization', signed(pe, cn_only, [inter]), 'valid', False)
    add('rejected_leaf_name', signed(pe, rejected, [inter]), 'valid', False)
    add('issuer_same_name_other_key', signed(pe, other_key_leaf, [inter_other_key]), 'valid', False)

    # the image changed after signing
    changed = bytearray(good)
    changed[0x300] ^= 1
    add('digest_mismatch', bytes(changed), 'invalid', False)
    # the checksum field is outside the digest: changing it keeps the signature valid
    checksum_changed = bytearray(good)
    checksum_changed[layout(pe)[0]] ^= 0xFF
    add('checksum_changed', bytes(checksum_changed), 'valid', True)

    # structure of the certificate table
    add('bytes_appended', good + b'\0' * 8, 'invalid', False)
    add('bytes_appended_nonzero', good + b'EVIL' * 2, 'invalid', False)
    add('file_cut', good[:-16], 'invalid', False)
    table_at = len(pe)
    shorter = bytearray(good)
    struct.pack_into('<I', shorter, layout(pe)[1] + 4, len(good) - table_at - 8)
    add('table_size_too_small', bytes(shorter), 'invalid', False)
    huge = bytearray(good)
    struct.pack_into('<I', huge, layout(pe)[1] + 4, 2 * 1024 * 1024)
    add('table_over_limit', bytes(huge), 'invalid', False)
    for name, offset, value in (('wrong_length_field', 0, struct.pack('<I', 9)),
                                ('length_field_too_long', 0, struct.pack('<I', 0x00FFFFFF)),
                                ('wrong_revision', 4, struct.pack('<H', 0x0100)),
                                ('wrong_type', 6, struct.pack('<H', 0x0001)),
                                ('not_a_sequence', 8, b'\x31'),
                                ('long_form_length', 9, b'\x83')):
        broken = bytearray(good)
        broken[table_at + offset:table_at + offset + len(value)] = value
        add(name, bytes(broken), 'invalid', False)
    blob = authenticode_blob(pe, leaf, [inter])
    pad = (-(8 + len(blob))) % 8
    if pad:
        dirty = bytearray(good)
        dirty[-1] = 0x55
        add('nonzero_alignment', bytes(dirty), 'invalid', False)
    else:
        print('NOT RUN  nonzero_alignment: this signature needs no alignment bytes')

    # more than one entry: the reference verifies only the first (numbered difference D-13)
    add('two_entries_same', attach(pe, [blob, blob]), 'valid', True)
    add('second_entry_untrusted',
        attach(pe, [blob, authenticode_blob(pe, untrusted_leaf, [other_inter, other_root])]), 'valid', True)
    add('first_entry_untrusted',
        attach(pe, [authenticode_blob(pe, untrusted_leaf, [other_inter, other_root]), blob]), 'invalid', False)
    garbage = seq(oid(OID_DATA), der(0xA0, der(0x04, b'x' * 300)))
    add('second_entry_not_signed_data', attach(pe, [blob, garbage]), 'unavailable', False)

    # signature bytes damaged
    flipped = bytearray(good)
    flipped[len(flipped) - pad - 5] ^= 0x10          # inside the signer's signature (the blob's last element)
    add('signature_bit_flipped', bytes(flipped), 'invalid', False)

    # page hashes (no asserted status: the comparison with the reference is the check)
    add('page_hashes_right', signed(pe, leaf, [inter], page_hashes=page_hash_table(pe)))
    add('page_hashes_wrong', signed(pe, leaf, [inter], page_hashes=page_hash_table(pe, wrong=True)))
    add('page_hashes_cut', signed(pe, leaf, [inter], page_hashes=page_hash_table(pe)[:-3]))
    # signify accepts more than one table and an offset that does not grow (indirect_data.py:157-170,
    # 194-217); the engine keeps that and bounds the total work instead. No asserted status.
    add('page_hashes_two_tables',
        signed(pe, leaf, [inter], page_hashes=[page_hash_table(pe), page_hash_table(pe)]))
    add('page_hashes_offset_repeated',
        signed(pe, leaf, [inter], page_hashes=page_hash_entries(pe, [(0, 0x200), (0x200, 0x200), (0x200, 0x400)])))
    add('page_hashes_offset_decreasing',
        signed(pe, leaf, [inter], page_hashes=struct.pack('<I', 0x200) + bytes(32) + struct.pack('<I', 0) + bytes(32)))

    # reviewer's condition 6: other key types, MD5, nested signatures, lifetime signing. No asserted
    # status (the reference's answer is not known from reading): compared with the reference only.
    # A case that cannot even be built here is printed as NOT RUN, with the reason.
    def extra(name, build):
        try:
            add(name, build())
        except Exception as e:  # noqa: BLE001
            print(f'NOT RUN  {name}: cannot be built here ({type(e).__name__}: {e})')

    def with_key(key):
        return make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=code, key=key)

    extra('signer_dsa_2048', lambda: signed(pe, with_key(dsa.generate_private_key(key_size=2048)), [inter]))
    extra('signer_ecdsa_p256', lambda: signed(pe, with_key(ec.generate_private_key(ec.SECP256R1())), [inter]))
    extra('signer_ecdsa_p384', lambda: signed(pe, with_key(ec.generate_private_key(ec.SECP384R1())), [inter]))
    extra('digest_md5', lambda: signed(pe, leaf, [inter], digest='md5'))
    inner = authenticode_blob(pe, leaf, [inter], digest='sha1')
    extra('nested_one_level', lambda: signed(pe, leaf, [inter], nested=[inner]))
    extra('nested_two_levels', lambda: signed(
        pe, leaf, [inter], nested=[authenticode_blob(pe, leaf, [inter], digest='sha1', nested=[inner])]))
    extra('nested_two_side_by_side', lambda: signed(pe, leaf, [inter], nested=[inner, inner]))
    extra('nested_untrusted', lambda: signed(
        pe, leaf, [inter], nested=[authenticode_blob(pe, untrusted_leaf, [other_inter, other_root])]))
    extra('nested_not_signed_data', lambda: signed(pe, leaf, [inter], nested=[garbage]))
    lifetime = code + [x509.ObjectIdentifier(OID_LIFETIME_SIGNING)]
    extra('lifetime_no_stamp', lambda: signed(
        pe, make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=lifetime), [inter]))
    extra('lifetime_with_stamp', lambda: signed(
        pe, make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=lifetime), [inter],
        timestamp='rfc3161', tsa=tsa, stamp_time=NOW - 10 * DAY))

    def lifetime_expired():
        return make_identity('Test Publisher', issuer=inter, org='Test Publisher', eku=lifetime,
                             not_before=NOW - 800 * DAY, not_after=NOW - 400 * DAY)
    extra('lifetime_expired_no_stamp', lambda: signed(pe, lifetime_expired(), [inter]))
    extra('lifetime_expired_stamp_rfc3161', lambda: signed(
        pe, lifetime_expired(), [inter], timestamp='rfc3161', tsa=tsa, stamp_time=mid))
    extra('lifetime_expired_stamp_authenticode', lambda: signed(
        pe, lifetime_expired(), [inter], timestamp='authenticode', tsa=tsa, stamp_time=mid))

    # not signed at all
    add('unsigned', pe, 'unsigned', False)
    add('unsigned_pe32', pe32, 'unsigned', False)
    add('not_an_executable', b'hello, this is a text file\n' * 20, 'invalid', False)
    add('empty', b'', 'invalid', False)
    add('short_header', pe[:0x90], 'invalid', False)

    # randomly damaged variants of three signed files (fixed seed)
    rng = random.Random(SEED)
    variants = []
    mutations = {}
    for base_name, base in (('valid_sha256', good), ('valid_stamp_authenticode', stamped_a),
                            ('valid_stamp_rfc3161', stamped_r)):
        for index in range(120):
            data = bytearray(base)
            where = rng.randrange(table_at, len(data)) if index % 6 else rng.randrange(0, table_at)
            kind = rng.randrange(3)
            if kind == 0:
                data[where] ^= 1 << rng.randrange(8)
            elif kind == 1:
                data[where] = rng.randrange(256)
            else:
                length = rng.randrange(1, 9)
                data[where:where + length] = bytes(rng.randrange(256) for _ in range(length))[:len(data) - where]
            name = f'v_{base_name}_{index:03d}'
            variants.append((name, bytes(data)))
            mutations[name] = describe_mutation(base, bytes(data), where, ('bit flip', 'byte set', 'bytes overwritten')[kind],
                                                table_at)
    return cases, variants, roots_pem, policy, mutations


# ----------------------------------------------------------------------------- comparison
def reference_result(ref, data, roots_path, pinned, policy):
    return ref.verify_portable('unused', store_path=roots_path, pinned_sha256=pinned, data=data,
                               policy=policy, timeout=120.0)


def error_class(detail):
    for prefix in ('signify: ', 'verification error: '):
        if detail.startswith(prefix):
            return detail[len(prefix):].split(':', 1)[0]
    return None


def own_text(detail):
    """True if the whole text is the reference's own and must be equal."""
    return error_class(detail) is None and 'not valid at' not in detail


def engine_part(ref, inputs, tmp, roots_path, pinned, policy):
    """Reviewer's condition 5 (board B-3630): does the reference ENGINE give another score, verdict
    or finding for a signature that is 'invalid' than for one that is 'unavailable' or 'unsigned'?
    Part 1 scans named cases with the real check (throwaway store). Part 2 scans ONE file with
    the signature step forced to each answer in turn, so that nothing but the answer differs.
    Returns the lines that must fail the test."""
    from dexmond_mie.core import Engine
    failures = []
    work = os.path.join(tmp, 'engine')
    os.mkdir(work)
    rules_copy = os.path.join(work, 'rules')
    shutil.copytree(os.path.join(REPO, 'rules'), rules_copy)
    rep_copy = os.path.join(work, 'reputation.json')
    shutil.copy(os.path.join(REPO, 'data', 'reputation.json'), rep_copy)

    def scan(name, verifier):
        engine = Engine(rules_dir=rules_copy, reputation_db=rep_copy, use_reputation=False, auto_evolution=False,
                        signature_verifier=verifier, trusted_publishers=policy['publishers'])
        path = os.path.join(work, name + '.exe')
        with open(path, 'wb') as f:
            f.write(inputs[name])
        result = engine.scan_file(path)
        signature = (result.get('details') or {}).get('signature')
        view = {'score': result.get('score'), 'verdict': result.get('verdict'),
                'findings': sorted((f.get('category', ''), f.get('weight'), f.get('description', ''))
                                   for f in result.get('findings', []))}
        return view, signature

    def real(path, data=None, scanned_stat=None):
        return ref.verify_portable(path, store_path=roots_path, pinned_sha256=pinned, data=data,
                                   scanned_stat=scanned_stat, policy=policy, timeout=120.0)

    print('--- the reference ENGINE on named cases (real signature check, throwaway store) ---')
    reached = False
    for name in ('valid_sha256', 'publisher_not_listed', 'digest_mismatch', 'bytes_appended', 'untrusted_root',
                 'second_entry_not_signed_data', 'unsigned'):
        if name not in inputs:
            continue
        view, signature = scan(name, real)
        reached = reached or signature is not None
        status = signature.get('status') if signature else 'SIGNATURE STEP NOT REACHED (the executable did not parse)'
        print(f"ENGINE {name}: signature {status}; score {view['score']} {view['verdict']!r}; "
              f"findings {json.dumps(view['findings'])}")

    print('--- the reference ENGINE on ONE file with the signature answer forced ---')
    forced = {}
    for label, answer in (
            ('invalid', {'status': 'invalid', 'publisher': None, 'detail': 'forced A'}),
            ('invalid, other text', {'status': 'invalid', 'publisher': None, 'detail': 'signify: X: forced B'}),
            ('unavailable', {'status': 'unavailable', 'publisher': None, 'detail': 'verification error: forced C'}),
            ('unsigned', {'status': 'unsigned', 'publisher': None, 'detail': 'forced D'}),
            ('valid, publisher not allowed', {'status': 'valid', 'publisher': policy['publishers'][0],
                                              'publisher_allowed': False, 'detail': 'forced E'}),
            ('valid, publisher allowed', {'status': 'valid', 'publisher': policy['publishers'][0],
                                          'publisher_allowed': True, 'detail': 'forced F'})):
        view, signature = scan('digest_mismatch', lambda path, data=None, scanned_stat=None, a=answer: dict(a))
        forced[label] = view
        print(f"FORCED {label}: step reached: {signature is not None}; score {view['score']} {view['verdict']!r}; "
              f"findings {json.dumps(view['findings'])}")
        reached = reached and signature is not None
    if not reached:
        print('NOT RUN  the engine never reached its signature step on these files; the question is not answered')
        failures.append('engine part: the reference engine did not reach its signature step')
        return failures
    base = forced['invalid']
    for label in ('invalid, other text', 'unavailable', 'unsigned', 'valid, publisher not allowed'):
        same = forced[label] == base
        print(f"{'PASS' if same else 'FAIL'}  engine result for '{label}' equals the result for 'invalid': {same}")
        if not same:
            failures.append(f"engine part: '{label}' gives {forced[label]!r}, 'invalid' gives {base!r}: "
                            f'the split between these answers changes the result and must be reproduced')
    return failures


def main():
    from dexmond_mie import signature as ref
    cases, variants, roots_pem, policy, mutations = build_cases()
    hard, soft, classes = [], 0, 0
    with tempfile.TemporaryDirectory(prefix='mie-sig-') as tmp:
        roots_path = os.path.join(tmp, 'test_roots.pem')
        with open(roots_path, 'wb') as f:
            f.write(roots_pem)
        pinned = hashlib.sha256(roots_pem).hexdigest()
        policy_path = os.path.join(tmp, 'policy.json')
        with open(policy_path, 'w', encoding='utf-8') as f:
            json.dump(policy, f)
        loaded_policy = ref.load_policy(policy_path)
        files = os.path.join(tmp, 'files')
        os.mkdir(files)
        named = {name for name, _, _, _ in cases}
        expected = {name: (status, cap) for name, _, status, cap in cases}
        inputs = [(name, data) for name, data, _, _ in cases] + variants
        for name, data in inputs:
            with open(os.path.join(files, name + '.bin'), 'wb') as f:
                f.write(data)

        done = subprocess.run([PROBE, roots_path, pinned, policy_path, files, 'parity'], capture_output=True, timeout=1800)
        if done.returncode != 0:
            print('FAIL  the probe ended with code', done.returncode, done.stderr.decode('utf-8', 'replace')[-2000:])
            return 1
        cpp = {}
        for raw in done.stdout.split(b'\n'):
            if raw.strip():
                line = json.loads(raw.decode('ascii'))
                cpp[line['file'][:-4]] = line

        counts = {}
        for name, data in inputs:
            r = reference_result(ref, data, roots_path, pinned, loaded_policy)
            c = cpp.get(name)
            if c is None:
                hard.append(f'{name}: no line from the probe')
                continue
            r_cap = r.get('status') == 'valid' and r.get('publisher_allowed') is True
            c_cap = c['status'] == 'valid' and c['publisher_allowed'] is True
            counts[r['status']] = counts.get(r['status'], 0) + 1
            problems = []
            if name in named:
                want_status, want_cap = expected[name]
                if want_status is not None and r['status'] != want_status:
                    problems.append(f"the REFERENCE gives {r['status']!r} ({r['detail']!r}), the case expects {want_status!r}")
                if want_cap is not None and r_cap != want_cap:
                    problems.append(f'the REFERENCE gives cap {r_cap}, the case expects {want_cap}')
            if r_cap != c_cap:
                problems.append(f'cap: reference {r_cap}, C++ {c_cap}')
            if r['status'] != c['status']:
                both_no_cap = {r['status'], c['status']} == {'invalid', 'unavailable'}
                if both_no_cap and name not in named:
                    soft += 1
                    print(f"NOTE  {name}: reference {r['status']} ({r['detail'][:120]!r}), C++ {c['status']} "
                          f"({c['detail'][:120]!r})")
                else:
                    problems.append(f"status: reference {r['status']!r} ({r['detail']!r}), C++ {c['status']!r} ({c['detail']!r})")
            else:
                for key in ('publisher', 'publisher_allowed', 'issuer', 'issuer_spki_sha256', 'timestamp'):
                    if r.get(key) != c.get(key):
                        problems.append(f'{key}: reference {r.get(key)!r}, C++ {c.get(key)!r}')
                if own_text(r['detail']):
                    if r['detail'] != c['detail']:
                        problems.append(f"detail: reference {r['detail']!r}, C++ {c['detail']!r}")
                elif 'not valid at' in r['detail']:
                    if r['detail'].split('(')[0] != c['detail'].split('(')[0]:
                        problems.append(f"detail: reference {r['detail']!r}, C++ {c['detail']!r}")
                elif error_class(r['detail']) != c['error_class']:
                    classes += 1
                    print(f"CLASS {name}: reference {r['detail'][:160]!r}, C++ {c['detail'][:160]!r}")
            if problems and name in mutations:
                print(f'MUTATION {name}: {mutations[name]}')
            for problem in problems:
                hard.append(f'{name}: {problem}')
            if name in named:
                print(f"{'FAIL' if problems else 'PASS'}  {name}: reference {r['status']} cap={r_cap} "
                      f"{r['detail'][:110]!r}")

        # store states: unprovisioned, missing, wrong hash (the probe is run again for each)
        good_only = os.path.join(tmp, 'one')
        os.mkdir(good_only)
        good_data = dict(inputs)['valid_sha256']
        with open(os.path.join(good_only, 'valid_sha256.bin'), 'wb') as f:
            f.write(good_data)
        for label, store, pin in (('store not provisioned', roots_path, None),
                                  ('store missing', os.path.join(tmp, 'absent.pem'), pinned),
                                  ('store hash wrong', roots_path, '0' * 64)):
            r = ref.verify_portable('unused', store_path=store, pinned_sha256=pin, data=good_data,
                                    policy=loaded_policy, timeout=120.0)
            done = subprocess.run([PROBE, store, pin or '-', policy_path, good_only, 'parity'], capture_output=True, timeout=300)
            c = json.loads(done.stdout.split(b'\n')[0].decode('ascii')) if done.returncode == 0 and done.stdout.strip() else {}
            same_text = r['detail'] == c.get('detail') or label == 'store missing'  # the OS error text differs
            ok = r['status'] == 'unavailable' and c.get('status') == 'unavailable' and same_text
            print(f"{'PASS' if ok else 'FAIL'}  {label}: reference {r['status']} {r['detail']!r}, "
                  f"C++ {c.get('status')} {c.get('detail')!r}")
            if not ok:
                hard.append(f'{label}: reference {r!r}, C++ {c!r}')

        hard.extend(engine_part(ref, dict(inputs), tmp, roots_path, pinned, loaded_policy))

    print(f'seed {SEED}; named cases {len(cases)}; damaged variants {len(variants)}')
    print('reference statuses over all inputs:', json.dumps(counts, sort_keys=True))
    print(f'hard differences: {len(hard)}')
    for line in hard:
        print('  DIFF', line)
    print(f'invalid/unavailable differences on damaged variants (both no cap): {soft}')
    print(f'exception-class differences (same status): {classes}')
    print('signature_parity:', 'FAIL' if hard else 'PASS')
    return 1 if hard else 0


if __name__ == '__main__':
    sys.exit(main())
