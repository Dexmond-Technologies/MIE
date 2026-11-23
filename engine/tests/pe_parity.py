#!/usr/bin/env python3
# Compares MIE's executable reader, which follows pefile 2024.8.26 (MIT; notice in THIRD-PARTY-
# NOTICES), with pefile itself. This test contains no pefile code. Apache License 2.0, Copyright
# 2026 Dexmond Technologies.
#
"""CI test: the C++ PE reader reports what pefile 2024.8.26 and the reference's PEAnalyzer
report, field by field (reviewer's condition M-4b.3, board B-3608).

Usage: pe_parity.py <path to mie-pe-probe> <repository root>

Inputs, all generated here (harmless: headers, tables and filler; no code, no malware):
  - the executables of parity set S (engine/tools/parity/make_set_s.py --no-large),
  - executables built here for what set S lacks (reviewer, board B-3620): resource trees of
    several shapes (types and ids by number and by name, several languages, deep nesting, a
    large entry, entries that point outside their section, a string table, a version entry),
    delay imports in both formats, imports by ordinal from the three DLLs pefile names from
    its own tables, sections that overlap in virtual address together with an export and a
    debug directory, and a 64-bit (PE32+) file with imports and TLS,
  - damaged variants of all of them, generated with the seed printed below:
    byte flips and extreme values in the headers, the section table, and the import, TLS,
    resource and security areas; truncations at structure boundaries and at random places;
    zeroed windows; non-ASCII and unterminated names; overlapping and out-of-file ranges.
Compared: "parses or not" (the reference treats ANY exception of pefile as "does not parse"),
and for files that parse on both sides every field the engine uses.
Exit code 1 on any difference. Known, documented differences are listed in
PE_READER_SPEC.md; this test does not hide them: they show here as differences.

Settings (environment), for the nightly run on a cluster node:
  MIE_PE_VARIANTS_PER_BASE  damaged variants per base file (default 100, the per-push number)
  MIE_PE_TOTAL_VARIANTS     if set: at least this many variants in all (spread over the base files)
  MIE_PE_SEED               seed of the generator (default 20261123; the nightly run passes the date)
Files are written, compared and removed in batches, so a large run needs little memory and disk.
"""
import hashlib
import itertools
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import time

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'engine', 'tools', 'parity'))
SEED = int(os.environ.get('MIE_PE_SEED', '20261123'))
VARIANTS_PER_BASE = int(os.environ.get('MIE_PE_VARIANTS_PER_BASE', '100'))
TOTAL_VARIANTS = int(os.environ.get('MIE_PE_TOTAL_VARIANTS', '0'))
BATCH_FILES = 400
BATCH_BYTES = 64 * 1024 * 1024
PE32_DIRS = 0x80 + 24 + 96        # file offset of the data directories in the files build_pe makes
PE32_SECTIONS = 0x80 + 24 + 0xE0  # file offset of their section table


# Nightly wall-time cap (MIE_PARITY_DEADLINE_UNIX, seconds since 1970, UTC): when it has passed, no
# new batch is started; what was compared is reported, with the count, and the test ends with
# exit code 3 ("stopped at the deadline") unless something differed or failed (then 1).
DEADLINE = float(os.environ.get('MIE_PARITY_DEADLINE_UNIX', '0') or 0)


def deadline_passed():
    return DEADLINE > 0 and time.time() >= DEADLINE


def deadline_text():
    return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(DEADLINE))


def variants_per_base(base_count):
    """How many damaged variants each base file gets."""
    if TOTAL_VARIANTS > 0:
        return max(VARIANTS_PER_BASE, -(-TOTAL_VARIANTS // max(base_count, 1)))
    return VARIANTS_PER_BASE


def set_directory(image, index, rva, size):
    struct.pack_into('<II', image, PE32_DIRS + 8 * index, rva, size)


def resource_tree(base_rva, tree):
    """Builds a resource section from a nested description.
    tree: list of (key, child). key: an int (id) or a str (a name, stored as a length-prefixed
    UTF-16 string). child: a list (a sub-directory), bytes (a data entry whose payload is placed
    in the section), or a tuple (rva, size) (a data entry pointing wherever it says).
    Well-formed layout: directories first, then the name strings, then the data entries, then
    the payloads; in every directory the named entries come first, sorted, then the ids."""
    directories = []                    # each: list of (key, child), in final order

    def collect(entries):
        ordered = sorted((e for e in entries if isinstance(e[0], str)), key=lambda e: e[0].upper()) + \
                  sorted((e for e in entries if not isinstance(e[0], str)), key=lambda e: e[0])
        index = len(directories)
        directories.append(ordered)
        return index

    queue, at, dir_index = [tree], 0, {}
    order = []
    while at < len(queue):                               # breadth first
        entries = queue[at]
        index = collect(entries)
        dir_index[id(entries)] = index
        order.append(entries)
        for _, child in directories[index]:
            if isinstance(child, list):
                queue.append(child)
        at += 1
    dir_offsets, offset = [], 0
    for ordered in directories:
        dir_offsets.append(offset)
        offset += 16 + 8 * len(ordered)
    name_offsets, strings = {}, b''
    for ordered in directories:
        for key, _ in ordered:
            if isinstance(key, str) and key not in name_offsets:
                name_offsets[key] = offset + len(strings)
                strings += struct.pack('<H', len(key)) + key.encode('utf-16le')
                strings += b'\x00' * (len(strings) % 2)
    offset += len(strings)
    leaves = [child for ordered in directories for _, child in ordered if not isinstance(child, list)]
    entry_offsets = {}
    for i, child in enumerate(leaves):
        entry_offsets[i] = offset + 16 * i
    offset += 16 * len(leaves)
    payloads, payload_at = b'', {}
    for i, child in enumerate(leaves):
        if isinstance(child, bytes):
            payload_at[i] = (base_rva + offset + len(payloads), len(child))
            payloads += child + b'\x00' * (-len(child) % 4)
        else:
            payload_at[i] = child
    blob, leaf_number = b'', 0
    for d, ordered in enumerate(directories):
        named = sum(1 for key, _ in ordered if isinstance(key, str))
        blob += struct.pack('<IIHHHH', 0, 0, 0, 0, named, len(ordered) - named)
        for key, child in ordered:
            name_field = (0x80000000 | name_offsets[key]) if isinstance(key, str) else key
            if isinstance(child, list):
                target = 0x80000000 | dir_offsets[dir_index[id(child)]]
            else:
                target = entry_offsets[leaf_number]
                leaf_number += 1
            blob += struct.pack('<II', name_field, target)
    blob += strings
    for i in range(len(leaves)):
        blob += struct.pack('<IIII', payload_at[i][0], payload_at[i][1], 0, 0)
    return blob + payloads


def thunk_blob(rva, libraries, wide=False):
    """An import directory for [(dll, [name or int ordinal, ...])] placed at `rva`; 32-bit
    thunks, or 64-bit ones with wide=True. Returns (bytes, size of the descriptor table)."""
    size, flag, fmt = (8, 1 << 63, '<Q') if wide else (4, 1 << 31, '<I')
    desc_size = (len(libraries) + 1) * 20
    pos, layout = desc_size, []
    for dll, symbols in libraries:
        thunks = (len(symbols) + 1) * size
        layout.append((dll, symbols, pos, pos + thunks))
        pos += thunks * 2
    strings, where = b'', {}
    for n, (dll, symbols, _, _) in enumerate(layout):
        for symbol in symbols:
            if isinstance(symbol, str):
                where[(n, symbol)] = rva + pos + len(strings)
                strings += b'\x00\x00' + symbol.encode('ascii') + b'\x00'
                strings += b'\x00' * (len(strings) % 2)
        where[(n, None)] = rva + pos + len(strings)
        strings += dll.encode('ascii') + b'\x00'
        strings += b'\x00' * (len(strings) % 2)
    out = b''
    for n, (dll, symbols, ilt, iat) in enumerate(layout):
        out += struct.pack('<IIIII', rva + ilt, 0, 0, where[(n, None)], rva + iat)
    out += b'\x00' * 20
    for n, (dll, symbols, _, _) in enumerate(layout):
        table = b''.join(struct.pack(fmt, where[(n, s)] if isinstance(s, str) else (flag | s)) for s in symbols)
        table += b'\x00' * size
        out += table + table
    return out + strings, desc_size


def delay_blob(rva, libraries, image_base=0):
    """A delay-import directory for [(dll, [name or int ordinal, ...])] placed at `rva`.
    image_base == 0: the current format (attributes 1, every field an RVA). Otherwise the old
    format: attributes 0 and every field a virtual address (image base + RVA)."""
    add = image_base
    desc_size = (len(libraries) + 1) * 32
    pos, layout = desc_size, []
    for dll, symbols in libraries:
        thunks = (len(symbols) + 1) * 4
        layout.append((dll, symbols, pos, pos + thunks))
        pos += thunks * 2
    strings, where = b'', {}
    for n, (dll, symbols, _, _) in enumerate(layout):
        for symbol in symbols:
            if isinstance(symbol, str):
                where[(n, symbol)] = rva + pos + len(strings)
                strings += b'\x00\x00' + symbol.encode('ascii') + b'\x00'
                strings += b'\x00' * (len(strings) % 2)
        where[(n, None)] = rva + pos + len(strings)
        strings += dll.encode('ascii') + b'\x00'
        strings += b'\x00' * (len(strings) % 2)
        where[(n, 'handle')] = rva + pos + len(strings)
        strings += b'\x00' * 4
    out = b''
    for n, (dll, symbols, names_at, iat_at) in enumerate(layout):
        out += struct.pack('<IIIIIIII', 0 if image_base else 1, add + where[(n, None)], add + where[(n, 'handle')],
                           add + rva + iat_at, add + rva + names_at, 0, 0, 0)
    out += b'\x00' * 32
    for n, (dll, symbols, _, _) in enumerate(layout):
        table = b''.join(struct.pack('<I', (add + where[(n, s)]) if isinstance(s, str) else (0x80000000 | s))
                         for s in symbols) + b'\x00' * 4
        out += table + table
    return out + strings, desc_size


def build_pe64(sections, libraries, tls=True):
    """A minimal well-formed PE32+ (64-bit) file: the given sections, an import section with
    64-bit thunks, and a TLS directory with one callback address. No code."""
    image_base, file_align, sect_align = 0x140000000, 0x200, 0x1000
    laid, rva = [], sect_align
    for name, data, chars in sections:
        laid.append([name, data, chars, rva])
        rva += -(-max(len(data), 1) // sect_align) * sect_align
    dirs = [(0, 0)] * 16
    blob, desc_size = thunk_blob(rva, libraries, wide=True)
    dirs[1] = (rva, desc_size)
    laid.append(['.idata', blob, 0x40000040, rva])
    rva += -(-len(blob) // sect_align) * sect_align
    if tls:
        tls_blob = struct.pack('<QQQQII', image_base + rva + 64, image_base + rva + 72, image_base + rva + 72,
                               image_base + rva + 40, 0, 0)
        tls_blob += struct.pack('<QQ', image_base + laid[0][3], 0) + b'\x00' * 24
        dirs[9] = (rva, 40)
        laid.append(['.tls', tls_blob, 0xC0000040, rva])
        rva += sect_align
    headers_size, pointer, table, body = 0x400, 0x400, b'', b''
    for name, data, chars, vaddr in laid:
        raw = -(-len(data) // file_align) * file_align
        table += struct.pack('<8sIIIIIIHHI', name.encode('ascii'), len(data), vaddr, raw, pointer, 0, 0, 0, 0, chars)
        body += data + b'\x00' * (raw - len(data))
        pointer += raw
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    coff = struct.pack('<HHIIIHH', 0x8664, len(laid), 0x60000000, 0, 0, 0xF0, 0x0022)
    optional = struct.pack('<HBBIIIII', 0x20B, 14, 0, 0x200, 0, 0, laid[0][3], sect_align)
    optional += struct.pack('<QIIHHHHHHIIIIHHQQQQII', image_base, sect_align, file_align, 6, 0, 0, 0, 6, 0, 0, rva,
                            headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b''.join(struct.pack('<II', a, b) for a, b in dirs)
    assert len(optional) == 0xF0, len(optional)
    headers = bytes(dos) + b'PE\x00\x00' + coff + optional + table
    return headers + b'\x00' * (headers_size - len(headers)) + body


def resource_blob(base_rva, loop=False):
    """A three-level resource tree with two data entries; with loop=True one entry points back."""
    def directory(ids):
        return struct.pack('<IIHHHH', 0, 0, 0, 0, 0, len(ids))
    root = directory([1, 2])                       # at 0
    type1 = directory([1])                         # at 32
    type2 = directory([1])                         # at 56
    lang1 = directory([0x409])                     # at 80
    lang2 = directory([0x409])                     # at 104
    data1_at, data2_at, payload_at = 128, 144, 160
    blob = root + struct.pack('<IIII', 1, 0x80000000 | 32, 2, 0x80000000 | 56)
    blob += type1 + struct.pack('<II', 1, 0x80000000 | 80)
    blob += type2 + struct.pack('<II', 1, 0x80000000 | (0 if loop else 104))
    blob += lang1 + struct.pack('<II', 0x409, data1_at)
    blob += lang2 + struct.pack('<II', 0x409, data2_at)
    blob += struct.pack('<IIII', base_rva + payload_at, 64, 0, 0)
    blob += struct.pack('<IIII', base_rva + payload_at + 64, 32, 0, 0)
    return blob + bytes(range(96)) + bytes(0x200 - (len(blob) + 96))


def base_files(tmp):
    import make_set_s
    made = subprocess.run([sys.executable, os.path.join(REPO, 'engine', 'tools', 'parity', 'make_set_s.py'),
                           '--out', os.path.join(tmp, 'set_s'), '--no-large'], capture_output=True, text=True)
    if made.returncode != 0:
        raise SystemExit('set S could not be generated: ' + made.stderr)
    files_dir = os.path.join(tmp, 'set_s', 'files')
    bases = {}
    for name in sorted(os.listdir(files_dir)):
        with open(os.path.join(files_dir, name), 'rb') as f:
            data = f.read()
        if data[:2] == b'MZ' and len(data) < 4 * 1024 * 1024:
            bases[name] = data
    code = make_set_s.filler_code()
    plain = [('.text', code, make_set_s.SEC_CODE), ('.data', bytes(0x200), make_set_s.SEC_DATA)]
    for label, loop in (('r01_resources.exe', False), ('r02_resources_loop.exe', True)):
        image = bytearray(make_set_s.build_pe(
            plain + [('.rsrc', resource_blob(0x3000, loop), make_set_s.SEC_RDATA)], make_set_s.BENIGN_IMPORTS))
        set_directory(image, 2, 0x3000, 0x200)
        bases[label] = bytes(image)

    # ---- more resource trees (the third section starts at RVA 0x3000) ----
    filler = random.Random(SEED ^ 0x5EED)
    noise = filler.randbytes(0x3000)
    lang = lambda payload: [(0x409, payload)]                      # noqa: E731
    string_table = b''.join(struct.pack('<H', len(s)) + s.encode('utf-16le')
                            for s in ['one', 'two', '', 'four'] + [''] * 12)
    trees = {
        'r03_res_types_by_id_and_name.exe': [
            ('CUSTOM', [(1, lang(b'custom payload ' * 8))]),
            (3, [(1, [(0x409, b'icon one' * 16), (0x407, b'icon eins' * 16)]), (2, lang(b'icon two' * 16))]),
            (10, [(100, lang(b'raw data' * 32))])],
        'r04_res_named_everything.exe': [
            ('ALPHA', [('ITEM_ONE', lang(b'a' * 100)), ('ITEM_TWO', lang(b'b' * 100))]),
            ('BETA', [('X', [(0x409, b'c' * 64), (0x40C, b'd' * 64)])]),
            ('GAMMA_WITH_A_LONGER_NAME', [('Y', lang(b'e' * 32))])],
        'r05_res_many_entries.exe': [
            (t, [(i, [(0x409, bytes([t, i]) * 24), (0x809, bytes([i, t]) * 24)]) for i in (1, 2, 3)])
            for t in (2, 3, 5, 6, 9, 14)],
        'r06_res_large_and_random.exe': [
            (10, [(1, lang(b'large low-entropy entry. ' * 500)), (2, lang(noise))])],
        'r07_res_data_outside.exe': [
            (10, [(1, lang((0x1000, 0x100))),            # points into the first section
                  (2, lang((0x00900000, 0x40))),         # beyond the image
                  (3, lang((0x3000, 0xFFFFFFF0))),       # a size far beyond the file
                  (4, lang((0, 0))),
                  (5, lang(b'inside'))])],
        'r08_res_string_table.exe': [(6, [(1, lang(string_table))]), (10, [(1, lang(b'x' * 40))])],
        'r09_res_version_entry.exe': [(16, [(1, lang(bytes(0x60)))]), (10, [(1, lang(b'y' * 40))])],
        'r10_res_odd_depths.exe': [
            (1, b'data directly under the root'),
            (2, [(1, b'data at the second level')]),
            (3, [(1, [(0x409, [(7, [(8, b'data at the fifth level')])])])])],
    }
    for label, tree in trees.items():
        blob = resource_tree(0x3000, tree)
        image = bytearray(make_set_s.build_pe(plain + [('.rsrc', blob, make_set_s.SEC_RDATA)],
                                              make_set_s.BENIGN_IMPORTS))
        set_directory(image, 2, 0x3000, len(blob))
        bases[label] = bytes(image)

    # ---- imports by ordinal from the three DLLs pefile names from its tables ----
    ordinal_libraries = [
        ('ws2_32.dll', [1, 2, 3, 115, 9999, 'send', 0x1F4]),       # in the table, outside it, by name
        ('WS2_32.DLL', [116, 23]),                                 # the same DLL again, other case
        ('oleaut32.dll', [2, 6, 500, 1000]),
        ('WSOCK32.dll', [1, 1142, 30000]),
        ('other.dll', [5, 'NamedFunction', 77]),                   # not a DLL pefile has a table for
        ('KERNEL32.dll', ['ExitProcess', 'GetLastError', 'Sleep', 'CloseHandle', 'GetTickCount']),
    ]
    blob, desc_size = thunk_blob(0x3000, ordinal_libraries)
    image = bytearray(make_set_s.build_pe(plain + [('.idat2', blob, make_set_s.SEC_RDATA)]))
    set_directory(image, 1, 0x3000, desc_size)
    bases['o01_imports_by_ordinal.exe'] = bytes(image)

    # ---- delay imports, in the current format (RVAs) and the old one (virtual addresses) ----
    delay_libraries = [('urlmon.dll', ['URLDownloadToFileW', 'CoInternetCreateZoneManager']),
                       ('shell32.dll', ['ShellExecuteW']), ('ws2_32.dll', [115, 'recv', 3])]
    for label, base in (('d01_delay_imports.exe', 0), ('d02_delay_imports_old_format.exe', make_set_s.IMAGE_BASE)):
        blob, desc_size = delay_blob(0x3000, delay_libraries, base)
        image = bytearray(make_set_s.build_pe(plain + [('.didat', blob, make_set_s.SEC_DATA)],
                                              make_set_s.BENIGN_IMPORTS))
        set_directory(image, 13, 0x3000, desc_size)
        bases[label] = bytes(image)

    # ---- sections that overlap in virtual address, with an export and a debug directory ----
    exports = bytearray(0x200)
    names = [b'ExportedOne', b'ExportedTwo']
    struct.pack_into('<IIHHIIIIIII', exports, 0, 0, 0x60000000, 0, 0, 0x4000 + 0x80, 1, 2, 2,
                     0x4000 + 0x40, 0x4000 + 0x50, 0x4000 + 0x60)
    struct.pack_into('<II', exports, 0x40, 0x1000, 0x1010)                       # function addresses
    struct.pack_into('<II', exports, 0x50, 0x4000 + 0x90, 0x4000 + 0xA0)         # name addresses
    struct.pack_into('<HH', exports, 0x60, 0, 1)                                 # name ordinals
    exports[0x80:0x80 + 9] = b'base.dll\x00'
    exports[0x90:0x90 + len(names[0])] = names[0]
    exports[0xA0:0xA0 + len(names[1])] = names[1]
    codeview = b'RSDS' + bytes(range(16)) + struct.pack('<I', 1) + b'c:\\build\\base.pdb\x00'
    struct.pack_into('<IIHHIIII', exports, 0x100, 0, 0x60000000, 0, 0, 2, len(codeview), 0x4000 + 0x140, 0)
    exports[0x140:0x140 + len(codeview)] = codeview
    image = bytearray(make_set_s.build_pe(
        plain + [('.data2', b'second data section ' * 20, make_set_s.SEC_DATA),
                 ('.edata', bytes(exports), make_set_s.SEC_RDATA)], make_set_s.BENIGN_IMPORTS))
    set_directory(image, 0, 0x4000, 40)
    set_directory(image, 6, 0x4000 + 0x100, 28)
    edata_pointer = struct.unpack_from('<I', image, PE32_SECTIONS + 40 * 3 + 20)[0]
    struct.pack_into('<I', image, edata_pointer + 0x100 + 24, edata_pointer + 0x140)   # debug: file pointer
    bases['x01_export_and_debug.exe'] = bytes(image)
    struct.pack_into('<I', image, PE32_SECTIONS + 40 * 2 + 12, 0x2000)   # .data2 now starts where .data does
    bases['x02_overlapping_sections_export_debug.exe'] = bytes(image)
    struct.pack_into('<I', image, PE32_SECTIONS + 40 * 2 + 12, 0x1800)   # ... and now inside .text
    bases['x03_overlapping_sections_inside_text.exe'] = bytes(image)

    # ---- a 64-bit (PE32+) file with imports (by name and by ordinal) and TLS ----
    bases['q01_pe32plus_imports_tls.exe'] = build_pe64(
        [('.text', code, 0x60000020), ('.data', bytes(0x200), 0xC0000040)],
        [('KERNEL32.dll', ['ExitProcess', 'VirtualProtect', 'LoadLibraryW', 'GetProcAddress']),
         ('ws2_32.dll', [115, 'connect', 4000]), ('ADVAPI32.dll', ['RegSetValueExW', 'OpenProcessToken'])])
    bases['q02_pe32plus_no_tls.exe'] = build_pe64(
        [('.text', code, 0x60000020)], [('KERNEL32.dll', ['ExitProcess', 'CreateProcessW'])], tls=False)
    return bases


def variants(name, data, rng, count=None):
    """The damaged variants of one base file, as a list (kept for callers that want a list)."""
    return list(iter_variants(name, data, rng, VARIANTS_PER_BASE if count is None else count))


def iter_variants(name, data, rng, count):
    """Yields `count` damaged variants: first a cut at every structure boundary, then random damage."""
    produced = 0
    lfanew = struct.unpack_from('<I', data, 0x3C)[0] if len(data) >= 0x40 else 0
    opt = lfanew + 24
    nsec = struct.unpack_from('<H', data, lfanew + 6)[0] if len(data) >= lfanew + 8 else 0
    table = opt + (struct.unpack_from('<H', data, lfanew + 20)[0] if len(data) >= lfanew + 22 else 0)
    dirs = opt + 96
    extremes = (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, len(data), max(len(data) - 1, 0), 0x1000, 0x200, 0x10000001)
    regions = [(0, 0x40), (lfanew, lfanew + 24), (opt, dirs), (dirs, dirs + 128), (table, table + 40 * max(nsec, 1))]
    section_starts = []
    for i in range(min(nsec, 16)):
        at = table + 40 * i
        if at + 40 <= len(data):
            pointer, size = struct.unpack_from('<I', data, at + 20)[0], struct.unpack_from('<I', data, at + 16)[0]
            if 0 < pointer < len(data):
                section_starts.append((pointer, min(pointer + max(size, 1), len(data))))
    boundaries = sorted({0, 1, 0x3F, 0x40, lfanew, lfanew + 3, lfanew + 4, lfanew + 23, lfanew + 24, opt + 68, opt + 69,
                         opt + 95, opt + 96, dirs + 8, dirs + 64, dirs + 127, dirs + 128, table, table + 1, table + 39,
                         table + 40, table + 40 * nsec, len(data) - 1}
                        | {a for a, _ in section_starts} | {b for _, b in section_starts})
    for cut in boundaries:
        if 0 <= cut < len(data) and produced < count:
            produced += 1
            yield data[:cut]
    while produced < count:
        b = bytearray(data)
        kind = rng.randrange(8)
        if kind == 0:                                   # one or a few byte flips in a header region
            lo, hi = rng.choice(regions)
            for _ in range(rng.randint(1, 4)):
                at = rng.randrange(lo, max(hi, lo + 1))
                if at < len(b):
                    b[at] ^= 1 << rng.randrange(8)
        elif kind == 1:                                 # an extreme 32-bit value in a header field
            lo, hi = rng.choice(regions[1:])
            at = lo + 4 * rng.randrange(max((hi - lo) // 4, 1))
            if at + 4 <= len(b):
                struct.pack_into('<I', b, at, rng.choice(extremes))
        elif kind == 2 and section_starts:              # damage at the start of a section's data
            lo, hi = rng.choice(section_starts)
            for _ in range(rng.randint(1, 8)):
                at = lo + rng.randrange(min(hi - lo, 256))
                b[at] = rng.choice((0, 0xFF, 0x80, 0x41, rng.randrange(256)))
        elif kind == 3 and section_starts:              # an extreme 32-bit value inside a section
            lo, hi = rng.choice(section_starts)
            at = lo + 4 * rng.randrange(max(min(hi - lo, 256) // 4, 1))
            if at + 4 <= len(b):
                struct.pack_into('<I', b, at, rng.choice(extremes))
        elif kind == 4:                                 # a random truncation
            b = b[:rng.randrange(len(b))]
        elif kind == 5:                                 # a zeroed window
            at = rng.randrange(len(b))
            b[at:at + rng.choice((4, 8, 16, 40))] = bytes(min(rng.choice((4, 8, 16, 40)), len(b) - at))
        elif kind == 6 and nsec:                        # a section name with odd bytes, or overlapping sections
            at = table + 40 * rng.randrange(nsec)
            if at + 40 <= len(b):
                if rng.random() < 0.5:
                    b[at:at + 8] = bytes(rng.choice((0, 0x41, 0xC3, 0xA9, 0xE2, 0x82, 0xFF, 0x80)) for _ in range(8))
                else:
                    other = table + 40 * rng.randrange(nsec)
                    b[at + 12:at + 16] = b[other + 12:other + 16]        # same virtual address as another
        else:                                           # a few random bytes anywhere
            for _ in range(rng.randint(1, 3)):
                b[rng.randrange(len(b))] = rng.randrange(256)
        produced += 1
        yield bytes(b)


def case_batches(bases, rng, case_dir, per_base):
    """Yields lists of (kind, name, data): every base file followed by its damaged variants.
    The files of a batch exist in `case_dir` while the caller works on the batch and are
    removed before the next one, so a run of any size needs little memory and disk."""
    def flush(batch):
        for _, name, data in batch:
            with open(os.path.join(case_dir, name), 'wb') as f:
                f.write(data)
        yield batch
        for _, name, _ in batch:
            try:
                os.remove(os.path.join(case_dir, name))
            except OSError:
                pass

    batch, size = [], 0
    for base_name, data in bases.items():
        items = itertools.chain(
            [('base', base_name, data)],
            (('variant', f'{base_name}.v{index:03d}', variant)
             for index, variant in enumerate(iter_variants(base_name, data, rng, per_base))))
        for item in items:
            batch.append(item)
            size += len(item[2])
            if len(batch) >= BATCH_FILES or size >= BATCH_BYTES:
                yield from flush(batch)
                batch, size = [], 0
    if batch:
        yield from flush(batch)


def run_probe(args, timeout=540):
    """Runs a probe and returns ({file name: record}, number of unreadable lines, exit code).
    Lines are split on line feeds only: str.splitlines() also splits at characters such as
    U+0085 or U+2028, which can occur inside a damaged name and would cut a JSON line in two."""
    out = subprocess.run(args, capture_output=True, timeout=timeout)
    got, unreadable = {}, 0
    for raw in out.stdout.split(b'\n'):
        if not raw.strip():
            continue
        try:
            record = json.loads(raw.decode('utf-8', 'replace'))
            got[record['file']] = record
        except (ValueError, KeyError):
            unreadable += 1
    return got, unreadable, out.returncode


_OPENED = []


def reference_view(path):
    """What the reference side sees, in the shape of the probe's JSON line. The reference's
    analyser never closes pefile's handle on the file (review finding W-2); on Windows that keeps
    the file locked, so it is closed here once the view has been built."""
    try:
        return _reference_view(path)
    finally:
        for opened in _OPENED:
            try:
                opened.close()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass
        _OPENED.clear()


def _reference_view(path):
    from dexmond_mie.pe_analyzer import PEAnalyzer
    analyzer = PEAnalyzer(path)
    if not analyzer.is_valid():
        return {'parsed': False}
    pe = analyzer.pe
    _OPENED.append(pe)
    with open(path, 'rb') as f:
        data = f.read()

    def libraries(entries):
        out = []
        for entry in entries or []:
            symbols = []
            for imp in entry.imports:
                by_ordinal = bool(imp.import_by_ordinal)
                # an import by ordinal has a name only where pefile took one from its own tables
                symbols.append({'name': (imp.name or b'').decode('latin-1'),
                                'by_ordinal': by_ordinal, 'ordinal': imp.ordinal if by_ordinal else 0,
                                'name_offset': None if by_ordinal else imp.name_offset})
            out.append({'dll': (entry.dll or b'').decode('latin-1'), 'symbols': symbols})
        return out

    imports = libraries(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None))
    tls = getattr(pe, 'DIRECTORY_ENTRY_TLS', None)
    has_callbacks = analyzer.has_tls_callbacks()
    cert = analyzer.parse_certificate_table()
    res = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
    return {
        'parsed': True,
        'machine': pe.FILE_HEADER.Machine, 'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'characteristics': pe.FILE_HEADER.Characteristics, 'magic': pe.OPTIONAL_HEADER.Magic,
        'pe32_plus': getattr(pe, 'PE_TYPE', None) == 0x20B,
        'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint, 'image_base': pe.OPTIONAL_HEADER.ImageBase,
        'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment, 'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
        'size_of_image': pe.OPTIONAL_HEADER.SizeOfImage, 'size_of_headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
        'directories': [[d.VirtualAddress, d.Size] for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY],
        'sections': [{'raw_name': bytes(s.Name).hex(), 'name': analyzer._section_name(s),
                      'virtual_size': s.Misc_VirtualSize, 'virtual_address': s.VirtualAddress,
                      'raw_size': s.SizeOfRawData, 'raw_pointer': s.PointerToRawData,
                      'characteristics': s.Characteristics,
                      'data_sha256': hashlib.sha256(bytes(s.get_data())).hexdigest()} for s in pe.sections],
        'has_imports': hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'), 'imports': imports,
        'has_delay_imports': hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'),
        'delay_imports': libraries(getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', None)),
        # the reference's own view (pe_analyzer._get_imports), ordinal names included
        'reference_imports': [[k, v] for k, v in analyzer._get_imports().items()],
        'tls': {'present': bool(tls), 'address_of_callbacks': tls.struct.AddressOfCallBacks if tls else 0,
                'has_callbacks': has_callbacks},
        'has_resources': res is not None, 'resource_root_has_entries': bool(getattr(res, 'entries', None)),
        'resource_data': [list(r) for r in analyzer.get_resource_data_ranges()],
        'certificates': {'present': cert['present'], 'valid': cert['valid'], 'offset': cert.get('offset', 0),
                         'declared_size': cert.get('declared_size', 0), 'parsed_size': cert['parsed_size'],
                         'entries': cert.get('entries', 0), 'spans': [list(s) for s in cert['spans']],
                         'problems': cert['problems']},
        '_data': data,
    }


def compare(name, want, got, counts, shown):
    def differ(field, a, b):
        counts[field] = counts.get(field, [0, 0])
        counts[field][0] += 1
        if a != b:
            counts[field][1] += 1
            if shown[0] < 20:
                shown[0] += 1
                print(f'DIFFERENT {name}: {field}: reference {str(a)[:300]}  C++ {str(b)[:300]}')
            return True
        return False

    if differ('parsed', want['parsed'], got.get('parsed')) or not want['parsed']:
        return
    data = want.pop('_data')
    for field, value in want.items():
        if field == 'sections':
            mine = [dict(s, data_sha256=hashlib.sha256(data[s['data'][0]:s['data'][1]]).hexdigest())
                    for s in got.get('sections', [])]
            for s in mine:
                s.pop('data')
            differ('sections', value, mine)
        elif field == 'tls':
            theirs = got.get('tls', {})
            differ('tls', value, {k: theirs.get(k) for k in value})
        else:
            differ(field, value, got.get(field))


def main():
    rng = random.Random(SEED)
    counts, shown = {}, [0]
    tally = {'bases': 0, 'variants': 0, 'both': 0, 'lines': 0, 'unreadable': 0, 'ordinal_named': 0}
    stopped = False
    with tempfile.TemporaryDirectory(prefix='mie-pe-') as tmp:
        bases = base_files(tmp)
        per_base = variants_per_base(len(bases))
        print(f'seed {SEED}; {per_base} damaged variants per base file; {len(bases)} base files')
        case_dir = os.path.join(tmp, 'cases')
        os.mkdir(case_dir)
        for batch in case_batches(bases, rng, case_dir, per_base):
            if deadline_passed():
                stopped = True
                break
            got, unreadable, code = run_probe([PROBE, case_dir])
            tally['lines'] += len(got)
            tally['unreadable'] += unreadable
            if code != 0:
                print(f'FAIL  the probe ended with exit code {code} on a batch starting at {batch[0][1]}')
                counts['probe exit code'] = [counts.get('probe exit code', [0, 0])[0] + 1,
                                             counts.get('probe exit code', [0, 0])[1] + 1]
            for kind, name, _ in batch:
                tally['bases' if kind == 'base' else 'variants'] += 1
                want = reference_view(os.path.join(case_dir, name))
                have = got.get(name, {'parsed': None})
                if want['parsed'] and have.get('parsed'):
                    tally['both'] += 1
                    if any(s['by_ordinal'] and s['name'] for lib in want['imports'] + want['delay_imports']
                           for s in lib['symbols']):
                        tally['ordinal_named'] += 1
                compare(name, want, have, counts, shown)
    print(f"probe: {tally['lines']} lines read, {tally['unreadable']} unreadable")
    print(f"{tally['bases']} base files, {tally['variants']} damaged variants, {tally['both']} parse on both sides")
    print(f"files where pefile names an import by ordinal from its tables: {tally['ordinal_named']}")
    total_different = 0
    for field in sorted(counts):
        compared, different = counts[field]
        total_different += different
        print(f'{field}: {compared} compared, {different} different')
    problems = []
    if tally['unreadable']:
        problems.append(f"{tally['unreadable']} probe lines could not be read")
    if stopped:
        print(f"pe_parity: STOPPED AT THE DEADLINE ({deadline_text()}) after {tally['variants']} damaged variants "
              f"of {per_base * len(bases)} planned; coverage checks NOT DONE")
    elif tally['ordinal_named'] == 0:
        problems.append('no file with an import by ordinal named from pefile\'s tables: the tables were not exercised')
    for problem in problems:
        print('FAIL  ' + problem)
    print(f"pe_parity: compared {tally['variants']} damaged variants")
    print(f'pe_parity: {total_different} differences')
    if total_different or problems:
        return 1
    return 3 if stopped else 0


if __name__ == '__main__':
    sys.exit(main())
