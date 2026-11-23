#!/usr/bin/env python3
"""CI test: the C++ zip and tar readers give what the Python reference gives (reviewer's
ruling M-4c, board B-3619).

Usage: archive_parity.py <path to mie-archive-probe> <repository root>

Reference side: an Engine built as engine/tools/parity/run_reference.py builds it (copies of
rules/ and data/reputation.json), then for every input, as Engine._scan_archive does:
    engine._is_archive(path)
    engine._extract_safely(path, <fresh temp folder>, {'members': 200, 'bytes': 512 MiB})
C++ side: mie-archive-probe over the same folder (parity profile, a fresh budget per file).
Compared per input: is_archive; the member list in order (name, the path below the temp
folder, size, SHA-256 of the extracted bytes); the coverage reasons in order; complete.
Names and reasons are compared as bytes (hex), text encoded as UTF-8 with surrogateescape.

Inputs, all generated here (harmless text and filler; no code, no malware):
  - every file of parity set S (engine/tools/parity/make_set_s.py, the --no-large set),
  - archives built here by hand, one per behaviour named in ARCHIVE_SPEC.md (see zip_bases,
    tar_bases, compressed_bases, other_bases),
  - damaged variants of all of them with the seed printed below: byte flips near the start,
    near the end and anywhere, extreme values, truncations (also at 512-byte borders), bytes
    added in front and behind, zeroed windows, repeated pieces. At least 2,000 variants.

The reference writes real files, so "which path a member lands on" is a fact of the file
system. That part is defined on Linux (ARCHIVE_SPEC.md section 7). On other systems this
test compares is_archive only and checks that the probe gives one valid line per input.

Exit code 1 on any difference. Known differences are listed in ARCHIVE_SPEC.md; this test
does not hide them.

Settings (environment):
  MIE_ARCHIVE_SEED       seed of the generator (default 20261123)
  MIE_ARCHIVE_VARIANTS   least number of damaged variants in all (default 2000)
"""
import bz2
import gc
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import zlib

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'engine', 'tools', 'parity'))
SEED = int(os.environ.get('MIE_ARCHIVE_SEED', '20261123'))
MIN_VARIANTS = int(os.environ.get('MIE_ARCHIVE_VARIANTS', '2000'))
BATCH_FILES = 300
LINUX = sys.platform.startswith('linux')
FIELDS = ('is_archive', 'members', 'reasons_hex', 'complete')
TEXT = b'The garden needs water on Tuesday.\r\n' * 8
MIB = 1024 * 1024


# ---- zip, written by hand so that every field can be set ------------------------------------

def pack_member(method, data):
    if method == 8:
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        return c.compress(data) + c.flush()
    if method == 12:
        return bz2.compress(data)
    if method == 14:
        c = zipfile.LZMACompressor()
        return c.compress(data) + c.flush()
    return data


def zip_file(entries, comment=b'', zip64=False, gap=b'', comment_length=None):
    """entries: dicts with name, data and optional method, flags, local_flags, version,
    local_name, extra, local_extra, comment, crc, csize, usize, offset, descriptor, packed."""
    body, central = bytearray(), bytearray()
    for e in entries:
        name, data, method = e['name'], e.get('data', b''), e.get('method', 0)
        packed = e.get('packed', None)
        packed = pack_member(method, data) if packed is None else packed
        crc = e.get('crc', zlib.crc32(data) & 0xFFFFFFFF)
        csize, usize = e.get('csize', len(packed)), e.get('usize', len(data))
        flags, version = e.get('flags', 0), e.get('version', 20)
        local_name, local_extra = e.get('local_name', name), e.get('local_extra', b'')
        offset = len(body)
        body += struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', version, e.get('local_flags', flags), method, 0, 0x5B77,
                            crc, csize & 0xFFFFFFFF, usize & 0xFFFFFFFF, len(local_name), len(local_extra))
        body += local_name + local_extra + packed
        if e.get('descriptor'):
            body += struct.pack('<4sIII', b'PK\x07\x08', crc, csize & 0xFFFFFFFF, usize & 0xFFFFFFFF)
        body += gap
        extra, member_comment = e.get('extra', b''), e.get('comment', b'')
        central += struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', version | (3 << 8), version, flags, method, 0,
                               0x5B77, crc, csize & 0xFFFFFFFF, usize & 0xFFFFFFFF, len(name), len(extra),
                               len(member_comment), 0, 0, 0o644 << 16, e.get('offset', offset) & 0xFFFFFFFF)
        central += name + extra + member_comment
    count, cd_offset = len(entries), len(body)
    out = bytes(body) + bytes(central)
    if zip64:
        record_at = len(out)
        out += struct.pack('<4sQHHIIQQQQ', b'PK\x06\x06', 44, 45, 45, 0, 0, count, count, len(central), cd_offset)
        out += struct.pack('<4sIQI', b'PK\x06\x07', 0, record_at, 1)
        out += struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, len(comment))
    else:
        out += struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, count & 0xFFFF, count & 0xFFFF, len(central),
                           cd_offset, len(comment) if comment_length is None else comment_length)
    return out + comment


def E(name, data=TEXT, **more):
    entry = {'name': name if isinstance(name, bytes) else name.encode('utf-8'), 'data': data}
    entry.update(more)
    return entry


def zip_bases():
    other = b'A second text, different from the first.\r\n' * 5
    deflated = pack_member(8, TEXT * 40)
    spoiled = bytearray(deflated)
    spoiled[len(spoiled) // 2] ^= 0x55
    crc_name = zlib.crc32(b'plain.txt') & 0xFFFFFFFF
    unicode_path = lambda payload, crc=crc_name: struct.pack('<HHBI', 0x7075, 5 + len(payload), 1, crc) + payload
    zip64_extra = struct.pack('<HHQQ', 1, 16, len(TEXT), len(TEXT))
    bases = {
        'stored': zip_file([E('a.txt'), E('dir/b.txt', other)]),
        'deflated': zip_file([E('a.txt', TEXT * 40, method=8), E('b.txt', other, method=8)]),
        'bzip2': zip_file([E('a.txt', TEXT * 40, method=12), E('b.txt', other, method=12)]),
        'lzma': zip_file([E('a.txt', TEXT * 40, method=14, flags=2), E('b.txt', other, method=14)]),
        'mixed_methods': zip_file([E('a', method=0), E('b', method=8), E('c', method=12), E('d', method=14)]),
        'no_entries': zip_file([]),
        'empty_member': zip_file([E('empty.txt', b''), E('a.txt')]),
        'empty_member_deflated': zip_file([E('empty.txt', b'', method=8)]),
        'folders': zip_file([E('dir/', b''), E('dir/a.txt'), E('other/', b'')]),
        'folder_with_data': zip_file([E('dir/', TEXT)]),
        'same_name_twice': zip_file([E('a.txt', TEXT), E('a.txt', other)]),
        'same_name_three': zip_file([E('a.txt', TEXT), E('b.txt', other), E('a.txt', b'third'), E('a.txt', other)]),
        'same_file_other_spelling': zip_file([E('x.txt', TEXT), E('a/../x.txt', other), E('./x.txt', b'3'),
                                              E('a//b.txt', TEXT), E('a/b.txt', other)]),
        'same_name_last_fails': zip_file([E('a.txt', TEXT), E('a.txt', other, crc=1)]),
        'climbs_out': zip_file([E('../evil.txt'), E('a/../../evil.txt'), E('ok.txt', other)]),
        'absolute': zip_file([E('/etc/evil.txt'), E('ok.txt', other)]),
        'empty_name': zip_file([E(b''), E('ok.txt', other)]),
        'dot_names': zip_file([E('.'), E('a/.', other), E('a/..', other), E('ok.txt', other)]),
        'file_then_folder': zip_file([E('a'), E('a/b.txt', other)]),
        'folder_then_file': zip_file([E('a/b.txt'), E('a', other)]),
        'file_above_two_folders': zip_file([E('a'), E('a/b/c.txt', other)]),
        'name_255': zip_file([E('n' * 255), E('m' * 255 + '/x.txt', other)]),
        'name_256': zip_file([E('n' * 256), E('m' * 256 + '/x.txt', other), E('ok.txt')]),
        'path_too_long': zip_file([E('/'.join(['d' * 200] * 21) + '/x.txt'), E('/'.join(['e' * 200] * 20) + '/y.txt'),
                                   E('ok.txt')]),
        'nul_in_name': zip_file([E(b'a\x00b.txt'), E(b'\x00hidden', other)]),
        'cp437_name': zip_file([E(bytes(range(0x80, 0x100)) + b'.txt'), E(b'caf\x82.txt', other)]),
        'utf8_name': zip_file([E('café/日本.txt', flags=0x800)]),
        'utf8_name_invalid': zip_file([E('ok.txt'), E(b'bad\xff\xfe.txt', flags=0x800)]),
        'utf8_name_cut': zip_file([E(b'bad\xe6\x97', flags=0x800)]),
        'utf8_local_invalid': zip_file([E(b'bad\xc3\x28.txt', local_flags=0x800), E('ok.txt')]),
        'local_name_differs': zip_file([E('a.txt', local_name=b'b.txt'), E('ok.txt', other)]),
        'unicode_path_field': zip_file([E('plain.txt', extra=unicode_path('real/über.txt'.encode('utf-8')))]),
        'unicode_path_wrong_crc': zip_file([E('plain.txt', extra=unicode_path(b'other.txt', 7))]),
        'unicode_path_invalid': zip_file([E('plain.txt', extra=unicode_path(b'\xff\xff'))]),
        'unicode_path_short': zip_file([E('plain.txt', extra=struct.pack('<HHB', 0x7075, 1, 1))]),
        'zip64': zip_file([E('a.txt', extra=zip64_extra, csize=0xFFFFFFFF, usize=0xFFFFFFFF), E('b.txt', other)],
                          zip64=True),
        'zip64_field_missing': zip_file([E('a.txt', extra=struct.pack('<HHQ', 1, 8, len(TEXT)), csize=0xFFFFFFFF,
                                           usize=0xFFFFFFFF)]),
        'extra_runs_out': zip_file([E('a.txt', extra=struct.pack('<HH', 0x9999, 50) + b'xy')]),
        'comment': zip_file([E('a.txt')], comment=b'An archive comment.'),
        'comment_holds_end_signature': zip_file([E('a.txt')], comment=b'xxPK\x05\x06' + b'\x00' * 30),
        'comment_longer_than_said': zip_file([E('a.txt')], comment=b'c' * 40, comment_length=10),
        'many_extras': zip_file([E(f'f{i}.txt', extra=struct.pack('<HH', 0x9999, 600) + b'e' * 600,
                                   comment=b'c' * 300) for i in range(6)]),
        'descriptor': zip_file([E('a.txt', flags=8, descriptor=True), E('b.txt', other, flags=8, descriptor=True)]),
        'gap_between_members': zip_file([E('a.txt'), E('b.txt', other)], gap=b'gap!'),
        'after_other_data': b'#!/bin/sh\necho stub\n' * 30 + zip_file([E('a.txt'), E('b.txt', other)]),
        'data_behind': zip_file([E('a.txt')]) + b'trailing bytes after the end record',
        'encrypted': zip_file([E('a.txt', flags=1), E('ok.txt', other)]),
        'flag_bit_5': zip_file([E('a.txt', flags=0x20), E('ok.txt', other)]),
        'flag_bit_6': zip_file([E('a.txt', flags=0x40), E('ok.txt', other)]),
        'method_9': zip_file([E('a.txt', method=9), E('ok.txt', other)]),
        'method_99': zip_file([E('a.txt', method=99), E('ok.txt', other)]),
        'version_64': zip_file([E('ok.txt', other), E('a.txt', version=64)]),
        'crc_wrong': zip_file([E('a.txt', crc=0x12345678), E('ok.txt', other)]),
        'size_said_smaller': zip_file([E('a.txt', usize=10, crc=zlib.crc32(TEXT[:10])), E('b.txt', TEXT, method=8,
                                         usize=10, crc=zlib.crc32(TEXT[:10]))]),
        'size_said_larger': zip_file([E('a.txt', usize=len(TEXT) + 50), E('b.txt', TEXT, method=8,
                                        usize=len(TEXT) + 50)]),
        'compressed_size_past_end': zip_file([E('a.txt', csize=10 ** 6)]),
        'member_over_size_limit': zip_file([E('big.bin', usize=65 * MIB), E('ok.txt', other)]),
        'members_201': zip_file([E(f'f{i:03d}.txt', b'line\r\n') for i in range(201)]),
        'two_entries_one_header': zip_file([E('a.txt'), E('a.txt', offset=0)]),
        'entry_inside_another': zip_file([E('a.txt', TEXT * 4), E('b.txt', other, offset=40)]),
        'offset_past_end': zip_file([E('a.txt', offset=10 ** 7), E('ok.txt', other)]),
        'deflate_spoiled': zip_file([E('a.txt', TEXT * 40, method=8, packed=bytes(spoiled)), E('ok.txt', other)]),
        'deflate_then_more': zip_file([E('a.txt', TEXT * 40, method=8, packed=deflated + b'more bytes')]),
        'deflate_cut': zip_file([E('a.txt', TEXT * 40, method=8, packed=deflated[:len(deflated) // 2])]),
        'bzip2_cut': zip_file([E('a.txt', TEXT * 40, method=12, packed=pack_member(12, TEXT * 40)[:40])]),
        'lzma_bad_properties': zip_file([E('a.txt', method=14, packed=b'\x09\x04\x05\x00\xff\xff\xff\xff\xff' + b'x' * 20)]),
        'lzma_header_only': zip_file([E('a.txt', method=14, packed=b'\x09\x04\x05')]),
        'no_size_but_data': zip_file([E('a.txt', usize=0, crc=0), E('b.txt', TEXT, method=8, usize=0, crc=0)]),
        'zip_inside_zip': zip_file([E('inner.zip', zip_file([E('a.txt')])), E('inner.tar', b'\x00' * 1024)]),
    }
    return {'zip_' + key: value for key, value in bases.items()}


# ---- tar, written by hand ---------------------------------------------------------------------

def tar_header(name=b'file.txt', size=0, kind=b'0', prefix=b'', link=b'', size_field=None, checksum=None,
               magic=b'ustar\x0000', signed=False):
    if not isinstance(name, bytes):
        name = name.encode('utf-8')
    head = bytearray(512)
    head[0:len(name[:100])] = name[:100]
    head[100:108], head[108:116], head[116:124] = b'0000644\x00', b'0000000\x00', b'0000000\x00'
    head[124:136] = size_field if size_field is not None else b'%011o\x00' % size
    head[136:148] = b'14707023200\x00'
    head[156:157] = kind
    head[157:157 + len(link[:100])] = link[:100]
    head[257:265] = magic
    head[345:345 + len(prefix[:155])] = prefix[:155]
    head[148:156] = b' ' * 8
    total = sum(b - 256 if (signed and b > 127) else b for b in head)
    head[148:156] = (b'%06o\x00 ' % (total & 0o777777)) if checksum is None else checksum
    return bytes(head)


def blocks(data):
    return data + b'\x00' * ((-len(data)) % 512)


def member(name, data=TEXT, **more):
    return tar_header(name, len(data), **more) + blocks(data)


END = b'\x00' * 1024


def pax(records, kind=b'x'):
    body = b''
    for key, value in records:
        key = key if isinstance(key, bytes) else key.encode('utf-8')
        value = value if isinstance(value, bytes) else value.encode('utf-8')
        length = len(key) + len(value) + 3
        length += len(str(length + len(str(length))))
        body += b'%d %s=%s\n' % (length, key, value)
    return tar_header(b'././@PaxHeader', len(body), kind) + blocks(body)


def long_name(name, kind=b'L'):
    data = name + b'\x00'
    return tar_header(b'././@LongLink', len(data), kind, magic=b'ustar  \x00') + blocks(data)


def python_tar(fmt, names):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=fmt) as tf:
        for index, name in enumerate(names):
            info = tarfile.TarInfo(name)
            data = TEXT * (index + 1)
            info.size, info.mtime, info.mode = len(data), 1763856000, 0o644
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def tar_bases():
    other = b'A second text, different from the first.\r\n' * 5
    sparse_text = b'%d\n%d\n%d\n' % (1, 0, len(TEXT))
    old_sparse = bytearray(tar_header(b'sparse.bin', len(TEXT), b'S', magic=b'ustar  \x00'))
    old_sparse[386:398], old_sparse[398:410] = b'%011o\x00' % 512, b'%011o\x00' % len(TEXT)
    old_sparse[483:495] = b'%011o\x00' % (512 + len(TEXT))
    old_sparse[148:156] = b' ' * 8
    old_sparse[148:156] = b'%06o\x00 ' % sum(old_sparse)
    bases = {
        'ustar': python_tar(tarfile.USTAR_FORMAT, ['a.txt', 'dir/b.txt', 'dir/sub/c.txt']),
        'pax_format': python_tar(tarfile.PAX_FORMAT, ['a.txt', 'long/' + 'n' * 150 + '.txt', 'café/日本.txt']),
        'gnu_format': python_tar(tarfile.GNU_FORMAT, ['a.txt', 'long/' + 'n' * 150 + '.txt']),
        'empty': END,
        'one_zero_block': b'\x00' * 512,
        'zero_block_then_data': b'\x00' * 512 + member('a.txt') + END,
        'zero_block_then_text': b'\x00' * 512 + TEXT,
        'zeros_over_limit': b'\x00' * (MIB + 2048),
        'no_end_blocks': member('a.txt') + member('b.txt', other),
        'one_end_block': member('a.txt') + b'\x00' * 512,
        'kinds': (tar_header('d/', 0, b'5') + member('d/a.txt') + tar_header('link', 0, b'2', link=b'd/a.txt') +
                  tar_header('hard', 0, b'1', link=b'd/a.txt') + tar_header('pipe', 0, b'6') +
                  tar_header('dev', 0, b'3') + member('contiguous', other, kind=b'7') +
                  member('unknown', other, kind=b'Z') + END),
        'link_with_size': tar_header('link', 700, b'2', link=b'x') + member('after.txt') + END,
        'same_name_twice': member('a.txt') + member('a.txt', other) + END,
        'same_name_other_spelling': member('x.txt') + member('./x.txt', other) + member('a/../x.txt', b'3') + END,
        'file_then_folder': member('a') + member('a/b.txt', other) + END,
        'folder_then_file': member('a/b.txt') + member('a', other) + END,
        'file_above_two_folders': member('a') + member('a/b/c.txt', other) + END,
        'climbs_out': member('../evil.txt') + member('a/../../evil.txt') + member('ok.txt', other) + END,
        'absolute': member('/etc/evil.txt') + member('ok.txt', other) + END,
        'empty_name': member(b'') + member('ok.txt', other) + END,
        'dot_names': member('.') + member('a/.', other) + member('ok.txt', other) + END,
        'old_folder_form': tar_header('olddir/', 0, b'\x00', magic=b'\x00' * 8) + member('olddir/a.txt') + END,
        'file_name_ends_in_slash': member('a/') + member('b//', other) + END,
        'prefix_field': member('name.txt', prefix=b'pre/fix') + member('n2.txt', other, prefix=b'p' * 155) + END,
        'name_100': member('n' * 100) + member('m' * 99, other) + END,
        'name_256_parts': member('n' * 100, prefix=b'p' * 155) + member('ok.txt') + END,
        'padding_not_zero': tar_header('a.txt', len(TEXT)) + TEXT + b'X' * ((-len(TEXT)) % 512) + END,
        'data_behind': member('a.txt') + END + b'bytes after the end blocks',
        'member_cut': (member('a.txt') + member('b.txt', other * 30))[:-700],
        'header_cut': member('a.txt') + member('b.txt', other)[:300],
        'checksum_wrong_second': member('a.txt') + member('b.txt', other, checksum=b'0000000\x00') + member('c.txt') + END,
        'checksum_wrong_first': member('a.txt', checksum=b'0000000\x00') + END,
        'checksum_signed': member(b'caf\xe9\xff.txt', signed=True) + member('ok.txt', other) + END,
        'raw_bytes_in_names': member(b'\xff\xfe\x80name.txt') + member(b'dir\xc3/\xe6\x97.txt', other) + END,
        'size_base_256': tar_header('a.txt', size_field=b'\x80' + (len(TEXT)).to_bytes(11, 'big')) + blocks(TEXT) + END,
        'size_base_256_negative': member('a.txt') + tar_header('neg.txt', size_field=b'\xff' * 12) + END,
        'size_base_256_huge': member('a.txt') + tar_header('huge.txt', size_field=b'\x80' + b'\x7f' * 11) + END,
        'size_forms': (tar_header('a.txt', size_field=b'   440     \x00') + blocks(TEXT) +
                       tar_header('b.txt', size_field=b'0o440\x00\x00\x00\x00\x00\x00\x00') + blocks(TEXT) +
                       tar_header('c.txt', size_field=b'4_4_0\x00\x00\x00\x00\x00\x00\x00') + blocks(TEXT) + END),
        'size_not_a_number': member('a.txt') + tar_header('b.txt', size_field=b'12x45\x00\x00\x00\x00\x00\x00\x00') + END,
        'size_empty': tar_header('a.txt', size_field=b'\x00' * 12) + member('b.txt') + END,
        'member_over_size_limit': tar_header('big.bin', 65 * MIB) + blocks(TEXT) + END,
        'members_205': b''.join(member(f'f{i:03d}.txt', b'line\r\n') for i in range(205)) + END,
        'gnu_long_name': long_name(b'long/' + b'n' * 300 + b'.txt') + member('short') + END,
        'gnu_long_folder': long_name(b'longdir/' + b'd' * 200 + b'//') + tar_header('x', 0, b'5') + member('ok.txt') + END,
        'gnu_long_link': long_name(b'target' * 30, b'K') + member('a.txt') + END,
        'gnu_long_then_end': long_name(b'n' * 200) + END,
        'gnu_long_then_junk': long_name(b'n' * 200) + b'J' * 512 + END,
        'pax_path': pax([('path', 'real/name.txt')]) + member('short') + member('next.txt', other) + END,
        'pax_path_slashes': pax([('path', 'real/name///')]) + member('short') + END,
        'pax_path_nul': member('first.txt') + pax([('path', b'bad\x00name')]) + member('short') + member('never.txt') + END,
        'pax_path_raw_bytes': pax([('path', b'raw\xff\xfe/n.txt')]) + member('short') + END,
        'pax_size_smaller': pax([('size', '10')]) + member('a.txt') + member('b.txt', other) + END,
        'pax_size_larger': pax([('size', str(len(TEXT) + 600))]) + member('a.txt') + member('b.txt', other) + END,
        'pax_size_not_a_number': pax([('size', 'abc')]) + member('a.txt') + member('b.txt', other) + END,
        'pax_size_negative': member('first.txt') + pax([('size', '-5')]) + member('a.txt') + END,
        'pax_global_path': pax([('path', 'same.txt')], b'g') + member('a.txt') + member('b.txt', other) + END,
        'pax_global_size': pax([('size', '7')], b'g') + member('a.txt') + member('b.txt', other) + END,
        'pax_record_bad_length': member('first.txt') + tar_header(b'p', 12, b'x') + blocks(b'99 path=a\n\x00\x00') + member('a.txt') + END,
        'pax_record_no_equals': member('first.txt') + tar_header(b'p', 8, b'x') + blocks(b'8 pathx\n') + member('a.txt') + END,
        'pax_overhead': pax([('comment', 'c' * 5000)]) + member('a.txt') + END,
        'pax_then_end': member('first.txt') + pax([('path', 'x')]) + END,
        'pax_then_pax': pax([('path', 'one')]) + pax([('path', 'two')]) + member('a.txt') + END,
        'pax_charset_binary': pax([('hdrcharset', 'BINARY'), ('path', b'bin\xff.txt')]) + member('a.txt') + END,
        'pax_solaris': pax([('path', 'sol.txt')], b'X') + member('a.txt') + END,
        'sparse_1_0': (pax([('GNU.sparse.major', '1'), ('GNU.sparse.minor', '0'), ('GNU.sparse.name', 'sparse10.bin'),
                            ('GNU.sparse.realsize', str(len(TEXT)))]) +
                       tar_header('x', 512 + len(TEXT)) + blocks(sparse_text) + blocks(TEXT) + member('after.txt') + END),
        'sparse_0_1': (pax([('GNU.sparse.map', '0,100,300,%d' % (len(TEXT) - 100)), ('GNU.sparse.size', '500'),
                            ('GNU.sparse.name', 'sparse01.bin')]) + member('x') + member('after.txt') + END),
        'sparse_0_0': (pax([('GNU.sparse.size', '400'), ('GNU.sparse.numblocks', '1'), ('GNU.sparse.offset', '100'),
                            ('GNU.sparse.numbytes', '200')]) + member('sparse00.bin') + member('after.txt') + END),
        'sparse_old_gnu': bytes(old_sparse) + blocks(TEXT) + member('after.txt') + END,
        'sparse_map_not_numbers': member('first.txt') + pax([('GNU.sparse.map', '1,x')]) + member('a.txt') + END,
        'sparse_size_not_a_number': member('first.txt') + pax([('GNU.sparse.size', 'zz')]) + member('a.txt') + END,
        'sparse_1_0_no_map': member('first.txt') + pax([('GNU.sparse.major', '1'), ('GNU.sparse.minor', '0')]) + member('a.txt', b'no newline here') + END,
        'tar_inside_tar': member('inner.tar', member('a.txt') + END) + member('inner.zip', zip_file([E('a.txt')])) + END,
    }
    return {'tar_' + key: value for key, value in bases.items()}


def gzip_with(data, flags=0, extra=b'', name=b'', comment=b'', crc=None, size=None):
    head = b'\x1f\x8b\x08' + bytes([flags]) + b'\x00\x00\x00\x00\x02\xff'
    if flags & 4:
        head += struct.pack('<H', len(extra)) + extra
    if flags & 8:
        head += name + b'\x00'
    if flags & 16:
        head += comment + b'\x00'
    if flags & 2:
        head += b'\x12\x34'
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return head + c.compress(data) + c.flush() + struct.pack(
        '<II', zlib.crc32(data) if crc is None else crc, (len(data) if size is None else size) & 0xFFFFFFFF)


def compressed_bases(rng):
    other = b'A second text, different from the first.\r\n' * 5
    small = member('a.txt') + member('dir/b.txt', other) + END
    big = member('first.txt') + member('random.bin', rng.randbytes(300 * 1024)) + member('last.txt', other) + END
    half = len(small) // 2 // 512 * 512
    gz, bz, xz = gzip.compress(small, mtime=0), bz2.compress(small), lzma.compress(small)
    big_gz, big_bz, big_xz = gzip.compress(big, mtime=0), bz2.compress(big), lzma.compress(big)
    spoiled = bytearray(big_gz)
    spoiled[len(spoiled) // 2] ^= 0x01
    bases = {
        'gz': gz, 'bz2': bz, 'xz': xz, 'lzma_alone': lzma.compress(small, format=lzma.FORMAT_ALONE),
        'gz_big': big_gz, 'bz2_big': big_bz, 'xz_big': big_xz,
        'gz_two_members': gzip.compress(small[:half], mtime=0) + gzip.compress(small[half:], mtime=0),
        'bz2_two_streams': bz2.compress(small[:half]) + bz2.compress(small[half:]),
        'xz_two_streams': lzma.compress(small[:half]) + lzma.compress(small[half:]),
        'gz_zero_bytes_behind': gz + b'\x00' * 700,
        'gz_zero_bytes_between': gzip.compress(small[:half], mtime=0) + b'\x00' * 9 + gzip.compress(small[half:], mtime=0),
        'gz_text_behind': gz + b'not a gzip member',
        'bz2_text_behind': bz + b'not a bzip2 stream',
        'xz_text_behind': xz + b'not an xz stream',
        'xz_zero_bytes_behind': xz + b'\x00' * 8,
        'xz_zero_bytes_behind_7': xz + b'\x00' * 7,
        'bz2_zero_bytes_behind': bz + b'\x00' * 8,
        'gz_header_fields': gzip_with(small, flags=4 | 8 | 16 | 2, extra=b'extra!', name=b'a.tar', comment=b'hello'),
        'gz_name_runs_to_end': b'\x1f\x8b\x08\x08\x00\x00\x00\x00\x02\xffname without end',
        'gz_crc_wrong': gzip_with(small, crc=1),
        'gz_size_wrong': gzip_with(small, size=5),
        'gz_two_bytes': b'\x1f\x8b',
        'gz_method_wrong': b'\x1f\x8b\x07' + gz[3:],
        'gz_of_empty_tar': gzip.compress(END, mtime=0),
        'gz_of_nothing': gzip.compress(b'', mtime=0),
        'gz_of_text': gzip.compress(TEXT * 30, mtime=0),
        'gz_of_zero_block_then_text': gzip.compress(b'\x00' * 512 + TEXT, mtime=0),
        'gz_data_behind_tar': gzip.compress(small + b'bytes after the end blocks', mtime=0),
        'gz_spoiled_middle': bytes(spoiled),
        'gz_stored_blocks': __import__('make_set_s').gzip_stored(small),
        'bz2_of_text': bz2.compress(TEXT * 30),
        'xz_of_text': lzma.compress(TEXT * 30),
        'gz_of_zip': gzip.compress(zip_file([E('a.txt')]), mtime=0),
    }
    for label, data in (('gz', gz), ('bz2', bz), ('xz', xz), ('gz_big', big_gz), ('bz2_big', big_bz), ('xz_big', big_xz)):
        for cut in (5, 12, len(data) // 3, len(data) // 2, len(data) - 9, len(data) - 4, len(data) - 1):
            bases[f'{label}_cut_at_{cut}'] = data[:cut]
    for cut in (128 * 1024, 128 * 1024 + 10, 2 * 128 * 1024 + 10):
        bases[f'gz_big_cut_at_{cut}'] = big_gz[:cut]
    return {'packed_' + key: value for key, value in bases.items()}


def other_bases(rng):
    return {
        'other_empty': b'', 'other_text': TEXT * 10, 'other_random': rng.randbytes(3000),
        'other_511_zero_bytes': b'\x00' * 511, 'other_pk_only': b'PK\x05\x06', 'other_end_record_only': zip_file([]),
        'other_21_bytes': b'PK\x05\x06' + b'\x00' * 17, 'other_tar_magic_only': b'ustar\x00' * 100,
    }


# ---- damage -------------------------------------------------------------------------------------

def damaged(rng, data):
    """One damaged copy of data, and what was done."""
    out = bytearray(data)
    size = len(out)
    kind = rng.randrange(12)
    if size == 0:
        return bytes(rng.randbytes(rng.randrange(1, 40))), 'random bytes'
    if kind == 0:
        at = rng.randrange(min(size, 600))
        out[at] ^= 1 << rng.randrange(8)
        return bytes(out), f'bit flip at {at}'
    if kind == 1:
        at = size - 1 - rng.randrange(min(size, 120))
        out[at] ^= 1 << rng.randrange(8)
        return bytes(out), f'bit flip at {at}'
    if kind == 2:
        at = rng.randrange(size)
        out[at] = rng.randrange(256)
        return bytes(out), f'byte set at {at}'
    if kind == 3:
        at = rng.randrange(size)
        value = rng.choice([b'\xff\xff\xff\xff', b'\x00\x00\x00\x00', b'\xff\xff\xff\x7f', b'\x00\x00\x00\x80', b'7777', b'\x80\x00'])
        out[at:at + len(value)] = value
        return bytes(out[:max(size, at + len(value))]), f'extreme value at {at}'
    if kind == 4:
        cut = rng.randrange(size)
        return bytes(out[:cut]), f'cut at {cut}'
    if kind == 5:
        cut = rng.randrange(size // 512 + 1) * 512
        return bytes(out[:cut]), f'cut at {cut}'
    if kind == 6:
        extra = rng.choice([b'\x00' * rng.randrange(1, 2000), rng.randbytes(rng.randrange(1, 600)), b'PK\x05\x06' + b'\x00' * 18])
        return bytes(out) + extra, f'{len(extra)} bytes added behind'
    if kind == 7:
        extra = rng.choice([b'\x00' * 512, rng.randbytes(rng.randrange(1, 600)), b'\x00' * rng.randrange(1, 30)])
        return extra + bytes(out), f'{len(extra)} bytes added in front'
    if kind == 8:
        at, length = rng.randrange(size), rng.randrange(1, 600)
        out[at:at + length] = b'\x00' * len(out[at:at + length])
        return bytes(out), f'zeroed {length} at {at}'
    if kind == 9:
        at, length = rng.randrange(size), rng.choice([512, 1024, rng.randrange(1, 300)])
        return bytes(out[:at] + out[at:at + length] + out[at:]), f'piece of {length} at {at} repeated'
    if kind == 10:
        at, length = rng.randrange(size), rng.choice([512, rng.randrange(1, 300)])
        return bytes(out[:at] + out[at + length:]), f'piece of {length} at {at} removed'
    at = rng.randrange(min(size, 600))
    out[at] = rng.choice([0x00, 0xFF, 0x80, 0x2F, 0x2E, 0x30, 0x37, 0x4C, 0x78, 0x67, 0x53])
    return bytes(out), f'special byte at {at}'


# ---- the two sides ------------------------------------------------------------------------------

def build_engine(work):
    from dexmond_mie.core import Engine
    rules_copy = os.path.join(work, 'rules')
    shutil.copytree(os.path.join(REPO, 'rules'), rules_copy)
    rep_copy = os.path.join(work, 'reputation.json')
    shutil.copy(os.path.join(REPO, 'data', 'reputation.json'), rep_copy)
    return Engine(rules_dir=rules_copy, reputation_db=rep_copy, use_reputation=False, auto_evolution=False)


def as_hex(text):
    return text.encode('utf-8', 'surrogateescape').hex()


def reference_view(engine, core, path, temp_parent):
    """What the reference says about one file, in the probe's format."""
    view = {'is_archive': bool(engine._is_archive(path))}
    if not LINUX:
        return view
    tmpdir = tempfile.mkdtemp(prefix='dexmond_arc_', dir=temp_parent)
    try:
        budget = {'members': core.MAX_ARCHIVE_MEMBERS, 'bytes': core.MAX_ARCHIVE_TOTAL_BYTES}
        members, coverage = engine._extract_safely(path, tmpdir, budget)
        real = os.path.realpath(tmpdir)
        listed = []
        for name, member_path in members:
            with open(member_path, 'rb') as f:
                data = f.read()
            listed.append({'name_hex': as_hex(name), 'path_hex': os.fsencode(os.path.relpath(member_path, real)).hex(),
                           'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        view.update({'members': listed, 'reasons_hex': [as_hex(r) for r in coverage['reasons']],
                     'complete': not coverage['reasons']})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return view


def run_probe(case_dir, temp_dir_length):
    """{file name: record}, the number of unreadable lines, the exit code. Lines are split on
    line feeds only (never str.splitlines)."""
    done = subprocess.run([PROBE, case_dir, '--temp-dir-length', str(temp_dir_length)], capture_output=True, timeout=3000)
    records, unreadable = {}, 0
    for line in done.stdout.split(b'\n'):
        if not line.strip():
            continue
        try:
            record = json.loads(line.decode('ascii'))
            records[record['file']] = record
        except (ValueError, KeyError):
            unreadable += 1
    return records, unreadable, done.returncode


def show(view):
    if view is None:
        return 'no line'
    text = {'is_archive': view.get('is_archive'), 'complete': view.get('complete')}
    text['reasons'] = [bytes.fromhex(r).decode('utf-8', 'backslashreplace') for r in view.get('reasons_hex', [])]
    text['members'] = [(bytes.fromhex(m['name_hex']).decode('utf-8', 'backslashreplace'),
                        bytes.fromhex(m['path_hex']).decode('utf-8', 'backslashreplace'), m['size'], m['sha256'][:12])
                       for m in view.get('members', [])]
    return json.dumps(text, ensure_ascii=True)


def all_cases(rng):
    """Yields (name, bytes, note): set S, the bases, then the damaged variants."""
    import make_set_s
    bases = []
    for name, data, _ in make_set_s.build_files(random.Random(make_set_s.SEED), False):
        if isinstance(data, bytes):
            bases.append(('setS_' + name, data))
    for group in (zip_bases(), tar_bases(), compressed_bases(rng), other_bases(rng)):
        bases.extend(sorted(group.items()))
    index = 0
    for label, data in bases:
        yield f'{index:05d}_{label[:60]}.bin', data, 'base'
        index += 1
    per_base = max(1, -(-MIN_VARIANTS // len(bases)))
    print(f'seed {SEED}; {len(bases)} base files; {per_base} damaged variants of each = {per_base * len(bases)} variants')
    for label, data in bases:
        if len(data) > 8 * MIB:
            continue
        for _ in range(per_base):
            changed, what = damaged(rng, data)
            yield f'{index:05d}_{label[:40]}_v.bin', changed, f'{label}: {what}'
            index += 1


def main():
    rng = random.Random(SEED)
    counts = {field: [0, 0] for field in FIELDS}
    tally = {'inputs': 0, 'archive for the reference': 0, 'archive for C++': 0, 'inputs with a difference': 0,
             'no line from the probe': 0, 'unreadable lines': 0, 'probe failures': 0}
    shown = 0
    with tempfile.TemporaryDirectory(prefix='mie-arc-') as work:
        engine = build_engine(work)
        from dexmond_mie import core
        case_dir, temp_parent = os.path.join(work, 'cases'), os.path.join(work, 't')
        os.mkdir(case_dir)
        os.mkdir(temp_parent)
        sample = tempfile.mkdtemp(prefix='dexmond_arc_', dir=temp_parent)
        temp_dir_length = len(os.fsencode(os.path.realpath(sample)))
        os.rmdir(sample)
        if not LINUX:
            print('not Linux: only is_archive is compared (the path rules are defined on Linux)')

        def compare(batch):
            nonlocal shown
            got, unreadable, code = run_probe(case_dir, temp_dir_length)
            tally['unreadable lines'] += unreadable
            if code != 0:
                tally['probe failures'] += 1
                print(f'FAIL  the probe ended with exit code {code} on the batch starting at {batch[0][0]}')
            for name, note in batch:
                path = os.path.join(case_dir, name)
                want = reference_view(engine, core, path, temp_parent)
                have = got.get(name)
                tally['inputs'] += 1
                tally['archive for the reference'] += 1 if want['is_archive'] else 0
                tally['archive for C++'] += 1 if have and have.get('is_archive') else 0
                if have is None:
                    tally['no line from the probe'] += 1
                different = have is None
                for field in FIELDS:
                    if field not in want:
                        continue
                    counts[field][0] += 1
                    if have is None or want[field] != have.get(field):
                        counts[field][1] += 1
                        different = True
                if different:
                    tally['inputs with a difference'] += 1
                    if shown < 20:
                        shown += 1
                        print(f'DIFF  {name} ({note})\n      reference: {show(want)}\n      C++:       {show(have)}')
                os.remove(path)
            gc.collect()

        batch = []
        for name, data, note in all_cases(rng):
            with open(os.path.join(case_dir, name), 'wb') as f:
                f.write(data)
            batch.append((name, note))
            if len(batch) >= BATCH_FILES:
                compare(batch)
                batch = []
        if batch:
            compare(batch)

    for field in FIELDS:
        print(f'{field}: compared {counts[field][0]}, different {counts[field][1]}')
    for key, value in tally.items():
        print(f'{key}: {value}')
    failed = (tally['inputs with a difference'] or tally['unreadable lines'] or tally['probe failures'] or
              tally['inputs'] == 0)
    print('archive_parity: FAIL' if failed else 'archive_parity: ok')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
