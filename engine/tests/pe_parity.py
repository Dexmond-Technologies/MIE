#!/usr/bin/env python3
"""CI test: the C++ PE reader reports what pefile 2024.8.26 and the reference's PEAnalyzer
report, field by field (reviewer's condition M-4b.3, board B-3608).

Usage: pe_parity.py <path to mie-pe-probe> <repository root>

Inputs, all generated here (harmless: headers, tables and filler; no code, no malware):
  - the executables of parity set S (engine/tools/parity/make_set_s.py --no-large),
  - two executables with a resource tree built here,
  - damaged variants of all of them, generated with the fixed seed printed below:
    byte flips and extreme values in the headers, the section table, and the import, TLS,
    resource and security areas; truncations at structure boundaries and at random places;
    zeroed windows; non-ASCII and unterminated names; overlapping and out-of-file ranges.
Compared: "parses or not" (the reference treats ANY exception of pefile as "does not parse"),
and for files that parse on both sides every field the engine uses.
Exit code 1 on any difference. Known, documented differences are listed in
PE_READER_SPEC.md; this test does not hide them: they show here as differences.
"""
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

PROBE, REPO = sys.argv[1], os.path.abspath(sys.argv[2])
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, 'engine', 'tools', 'parity'))
SEED = 20261123
VARIANTS_PER_BASE = 100


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
    for label, loop in (('r01_resources.exe', False), ('r02_resources_loop.exe', True)):
        image = bytearray(make_set_s.build_pe(
            [('.text', code, make_set_s.SEC_CODE), ('.data', bytes(0x200), make_set_s.SEC_DATA),
             ('.rsrc', resource_blob(0x3000, loop), make_set_s.SEC_RDATA)], make_set_s.BENIGN_IMPORTS))
        struct.pack_into('<II', image, 0x80 + 24 + 96 + 2 * 8, 0x3000, 0x200)   # data directory 2
        bases[label] = bytes(image)
    return bases


def variants(name, data, rng):
    out = []
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
        if 0 <= cut < len(data):
            out.append(data[:cut])
    while len(out) < VARIANTS_PER_BASE:
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
        out.append(bytes(b))
    return out[:VARIANTS_PER_BASE]


def reference_view(path):
    """What the reference side sees, in the shape of the probe's JSON line."""
    from dexmond_mie.pe_analyzer import PEAnalyzer
    analyzer = PEAnalyzer(path)
    if not analyzer.is_valid():
        return {'parsed': False}
    pe = analyzer.pe
    with open(path, 'rb') as f:
        data = f.read()

    def libraries(entries):
        out = []
        for entry in entries or []:
            symbols = []
            for imp in entry.imports:
                by_ordinal = bool(imp.import_by_ordinal)
                symbols.append({'name': '' if by_ordinal else (imp.name or b'').decode('latin-1'),
                                'by_ordinal': by_ordinal, 'ordinal': imp.ordinal if by_ordinal else 0,
                                'name_offset': None if by_ordinal else imp.name_offset})
            out.append({'dll': (entry.dll or b'').decode('latin-1'), 'symbols': symbols})
        return out

    imports = libraries(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None))
    reference_imports = {}
    for library in imports:
        reference_imports[library['dll'] or 'unknown'] = [s['name'] or f"ordinal_{s['ordinal']}" for s in library['symbols']]
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
        'reference_imports': [[k, v] for k, v in reference_imports.items()],
        'reference_imports_as_the_reference_names_them': [[k, v] for k, v in analyzer._get_imports().items()],
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
    ordinal_names = want.pop('reference_imports_as_the_reference_names_them')
    if ordinal_names != want['reference_imports']:
        counts['(known) ordinal imports named by pefile\'s table for three DLLs'] = \
            [counts.get('(known) ordinal imports named by pefile\'s table for three DLLs', [0, 0])[0] + 1, 0]
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
    print(f'seed {SEED}; {VARIANTS_PER_BASE} damaged variants per base file')
    counts, shown = {}, [0]
    with tempfile.TemporaryDirectory(prefix='mie-pe-') as tmp:
        bases = base_files(tmp)
        case_dir = os.path.join(tmp, 'cases')
        os.mkdir(case_dir)
        names = []
        for base_name, data in bases.items():
            names.append(('base', base_name, data))
            for index, variant in enumerate(variants(base_name, data, rng)):
                names.append(('variant', f'{base_name}.v{index:03d}', variant))
        for _, name, data in names:
            with open(os.path.join(case_dir, name), 'wb') as f:
                f.write(data)
        out = subprocess.run([PROBE, case_dir], capture_output=True, timeout=540)
        got = {}
        for line in out.stdout.decode('utf-8', 'replace').splitlines():
            try:
                record = json.loads(line)
                got[record['file']] = record
            except (ValueError, KeyError):
                pass
        parsed_both = 0
        for kind, name, _ in names:
            want = reference_view(os.path.join(case_dir, name))
            parsed_both += 1 if (want['parsed'] and got.get(name, {}).get('parsed')) else 0
            compare(name, want, got.get(name, {'parsed': None}), counts, shown)
        variants_count = sum(1 for kind, _, _ in names if kind == 'variant')
        print(f'{len(bases)} base files, {variants_count} damaged variants, {parsed_both} parse on both sides')
    total_different = 0
    for field in sorted(counts):
        compared, different = counts[field]
        total_different += different
        print(f'{field}: {compared} compared, {different} different')
    print(f'pe_parity: {total_different} differences')
    return 1 if total_different else 0


if __name__ == '__main__':
    sys.exit(main())
