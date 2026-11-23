#!/usr/bin/env python3
"""Builds parity set "S": harmless synthetic files that make the Python reference use its
scoring table (reviewer's condition M-1, board B-3484).

    make_set_s.py --out DIR [--no-large]

Everything is generated here, deterministically (fixed seed): text files, random bytes,
hand-built Windows executables that contain no code (they are headers, tables and filler,
and cannot run anything), and zip/tar archives of those. NO malware and NO EICAR file is
used or generated. A text file that contains words a rule looks for (for example the names
of well-known tools) is still only text.

Written beside the files:
  set_s.intent.json       per file: what it is meant to trigger (the reference's own output
                          decides what it really triggers; see set_s_coverage.py)
  set_s.reputation.json   the reference's reputation list plus two entries of this set:
                          one generated file listed as known-bad, one as trusted. The
                          reference is run with this list, so the reputation rows are
                          exercised without any real sample.

--no-large leaves out the files above 32 MiB (the oversize and blind-zone cases); they are
part of the set and are generated in CI.
"""
import argparse
import hashlib
import io
import json
import os
import random
import struct
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SEED = 20261123
MIB = 1024 * 1024


# ---------------------------------------------------------------------------------------
# A minimal PE32 writer. The result is a well-formed file for a parser; it holds no code.
# ---------------------------------------------------------------------------------------
SEC_CODE = 0x60000020       # code, execute, read
SEC_DATA = 0xC0000040       # initialised data, read, write
SEC_RDATA = 0x40000040      # initialised data, read
SEC_WX = 0xE0000020         # code, execute, read, write
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x400000


def _align(value, to):
    return (value + to - 1) // to * to


def _import_blob(imports, rva):
    """Import directory for {dll: [names]} placed at `rva`. Returns (bytes, dir_size)."""
    dlls = list(imports.items())
    desc_size = (len(dlls) + 1) * 20
    pos = desc_size
    layout = []
    for dll, names in dlls:
        thunks = (len(names) + 1) * 4
        ilt, iat = pos, pos + thunks
        pos += thunks * 2
        layout.append((dll, names, ilt, iat))
    strings = b''
    string_base = pos
    name_rvas, dll_rvas = {}, {}
    for dll, names, _, _ in layout:
        for name in names:
            name_rvas[(dll, name)] = rva + string_base + len(strings)
            entry = b'\x00\x00' + name.encode('ascii') + b'\x00'
            if len(entry) % 2:
                entry += b'\x00'
            strings += entry
        dll_rvas[dll] = rva + string_base + len(strings)
        strings += dll.encode('ascii') + b'\x00'
        if len(strings) % 2:
            strings += b'\x00'
    out = b''
    for dll, names, ilt, iat in layout:
        out += struct.pack('<IIIII', rva + ilt, 0, 0, dll_rvas[dll], rva + iat)
    out += b'\x00' * 20
    for dll, names, _, _ in layout:
        table = b''.join(struct.pack('<I', name_rvas[(dll, n)]) for n in names) + b'\x00\x00\x00\x00'
        out += table + table
    out += strings
    return out, desc_size


def build_pe(sections, imports=None, entry='first', tls=False, overlay=b'', cert=None,
             timestamp=0x60000000):
    """sections: list of (name, data, characteristics[, virtual_size]). A section whose data is
    empty has no raw data (as a packer's first section). imports: {dll: [function names]},
    put into an extra read-only section `.idata`. entry: 'first' = start of the first section,
    'zero' = 0, or ('section', index). tls: adds a TLS directory with one callback address.
    cert: bytes appended as the certificate table (data directory 4)."""
    sections = [tuple(s) + ((None,) if len(s) == 3 else ()) for s in sections]
    dirs = [(0, 0)] * 16

    # lay out virtual addresses
    laid = []
    rva = SECT_ALIGN
    for name, data, chars, vsize in sections:
        vsize = vsize if vsize is not None else max(len(data), 1)
        laid.append([name, data, chars, vsize, rva])
        rva += _align(vsize, SECT_ALIGN)

    if imports:
        blob, desc_size = _import_blob(imports, rva)
        dirs[1] = (rva, desc_size)
        laid.append(['.idata', blob, SEC_RDATA, len(blob), rva])
        rva += _align(len(blob), SECT_ALIGN)

    if tls:
        # IMAGE_TLS_DIRECTORY32 (24 bytes) followed by the callback array (one entry, then 0)
        tls_rva = rva
        callbacks_va = IMAGE_BASE + tls_rva + 24
        callback_target = IMAGE_BASE + laid[0][4]
        blob = struct.pack('<IIIIII', IMAGE_BASE + tls_rva + 40, IMAGE_BASE + tls_rva + 44,
                           IMAGE_BASE + tls_rva + 44, callbacks_va, 0, 0)
        blob += struct.pack('<II', callback_target, 0) + b'\x00' * 16
        dirs[9] = (tls_rva, 24)
        laid.append(['.tls', blob, SEC_DATA, len(blob), rva])
        rva += _align(len(blob), SECT_ALIGN)

    size_of_image = rva
    headers_size = 0x400
    raw_ptr = headers_size
    table = b''
    body = b''
    for name, data, chars, vsize, vaddr in laid:
        raw_size = _align(len(data), FILE_ALIGN) if data else 0
        pointer = raw_ptr if raw_size else 0
        table += struct.pack('<8sIIIIIIHHI', name.encode('ascii')[:8], vsize, vaddr, raw_size, pointer,
                             0, 0, 0, 0, chars)
        if raw_size:
            body += data + b'\x00' * (raw_size - len(data))
            raw_ptr += raw_size

    if entry == 'zero':
        entry_rva = 0
    elif entry == 'first':
        entry_rva = laid[0][4]
    else:
        entry_rva = laid[entry[1]][4]

    cert_blob = b''
    if cert is not None:
        cert_offset = headers_size + len(body) + len(overlay)
        dirs[4] = (cert_offset, len(cert))
        cert_blob = cert

    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x80)
    coff = struct.pack('<HHIIIHH', 0x14C, len(laid), timestamp, 0, 0, 0xE0, 0x0102)
    code_size = sum(_align(len(d), FILE_ALIGN) for _, d, c, _, _ in laid if c & 0x20)
    optional = struct.pack('<HBBIIIIII', 0x10B, 14, 0, code_size, 0, 0, entry_rva, SECT_ALIGN, SECT_ALIGN)
    optional += struct.pack('<IIIHHHHHHIIIIHHIIIIII', IMAGE_BASE, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
                            size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b''.join(struct.pack('<II', a, b) for a, b in dirs)
    assert len(optional) == 0xE0, len(optional)
    headers = bytes(dos) + b'PE\x00\x00' + coff + optional + table
    assert len(headers) <= headers_size, 'too many sections for the header area'
    headers += b'\x00' * (headers_size - len(headers))
    return headers + body + overlay + cert_blob


# ---------------------------------------------------------------------------------------
# File contents
# ---------------------------------------------------------------------------------------
def filler_code(size=0x600):
    """Low-entropy filler for a 'code' section: not instructions anyone runs."""
    return (b'\xCC' * 16 + b'\x90' * 48) * (size // 64)


BENIGN_IMPORTS = {'KERNEL32.dll': ['ExitProcess', 'GetModuleHandleA', 'GetCommandLineA', 'GetLastError',
                                   'CloseHandle', 'Sleep', 'GetTickCount', 'GetCurrentProcessId']}


def with_benign(extra):
    """Benign imports plus the given ones (more than 5 in total, so the import table is not 'tiny')."""
    merged = {k: list(v) for k, v in BENIGN_IMPORTS.items()}
    for dll, names in extra.items():
        merged.setdefault(dll, [])
        merged[dll] += names
    return merged


def text(*lines):
    return ('\r\n'.join(lines) + '\r\n').encode('ascii')


def gzip_stored(data):
    """A gzip file whose deflate stream uses stored (uncompressed) blocks only, so the bytes
    do not depend on the version of the compression library."""
    import zlib
    out = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff'
    blocks = [data[i:i + 0xFFFF] for i in range(0, len(data), 0xFFFF)] or [b'']
    for index, block in enumerate(blocks):
        last = 1 if index == len(blocks) - 1 else 0
        out += struct.pack('<BHH', last, len(block), len(block) ^ 0xFFFF) + block
    return out + struct.pack('<II', zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)


def make_zip(members, stored=True):
    # Stored (uncompressed) members: the archive's bytes, and so its hash in the manifest,
    # do not depend on the version of the compression library.
    buffer = io.BytesIO()
    kind = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buffer, 'w', kind) as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 23, 0, 0, 0))
            info.compress_type = kind
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buffer.getvalue()


def make_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1763856000
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def build_files(rng, large):
    """Returns [(name, bytes or ('sparse', size, head, tail), intent)]."""
    files = []

    def add(name, data, intent):
        files.append((name, data, intent))

    random_64k = rng.randbytes(64 * 1024)

    # ---- text and data files: string indicators, rules, entropy ----
    clean = text('Meeting notes', 'The garden needs water on Tuesday.', 'Buy bread and milk.') * 20
    add('t01_clean.txt', clean, 'score 0, CLEAN')
    add('t02_shell_word.txt', text('To list files, start powershell and type dir.') * 3,
        'suspicious_string (5): lowest non-zero score')
    add('t03_obfuscated.txt', text('var bytes = Convert.FromBase64String(payloadText);') * 2,
        'obfuscated_script (25): highest reachable score below the MEDIUM line')
    add('t04_b64_marker.txt', text('blob = "TVqQAAMAAAA4A' + 'A' * 120 + '"'),
        'b64_executable (30): exactly the MEDIUM line')
    critical_words = text('Glossary of tool names seen in reports:', 'mimikatz', 'sekurlsa', 'gentilkiwi',
                          'This file is a word list.')
    add('t05_critical_words.txt', critical_words, 'critical_yara (70): exactly the MALICIOUS line')
    add('t06_rule_high.txt', text('Set x = CreateObject("MSXML2.XMLHTTP")', 'rem ADODB.Stream'),
        'yara_match, severity high (20)')
    add('t07_rule_medium.txt', text('rem vssadmin delete shadows', 'rem bcdedit /set', 'rem reg add'),
        'yara_match, severity medium (10)')
    # The next lines are TEXT written into a test file: words that three rules look for.
    # Nothing here is evaluated or executed, in this script or anywhere else.
    three_high = text('eval( unescape( fromCharCode ActiveXObject',
                      'CreateObject MSXML2.XMLHTTP ADODB.Stream',
                      'meterpreter metsrv.dll stdapi_')
    add('t08_rule_cap.txt', three_high, 'yara family above its cap of 40 (three high rules = 60)')
    add('t09_just_below_malicious.txt', three_high + text('x = FromBase64String(y)'),
        'yara cap 40 + obfuscated_script 25 = 65: highest reachable score below the MALICIOUS line')
    add('t10_clamp.txt', critical_words + three_high + text('x = FromBase64String(y)',
                                                            'z = "TVqQAAMAAAA4A' + 'B' * 120 + '"'),
        'sum above 100: clamp at 100')
    add('t11_random.bin', random_64k, 'non-PE whole-file entropy above 7.2: high_entropy (15)')
    add('t12_pockets.bin', bytes(60 * 1024) + rng.randbytes(40 * 1024),
        'entropy at most 7.2 but more than a quarter of the windows high: sliding_entropy_spike (10)')
    add('t13_gzip_magic_random.bin', b'\x1f\x8b\x08\x00' + rng.randbytes(64 * 1024),
        'compressed-format magic with high entropy, not an archive: entropy at reduced weight (5)')
    add('t14_png_magic_random.bin', b'\x89PNG\r\n\x1a\n' + rng.randbytes(64 * 1024),
        'compressed-format magic (png) with high entropy: entropy at reduced weight (5)')

    # ---- reputation rows (hashes are put into set_s.reputation.json) ----
    add('r01_listed_bad.txt', text('This harmless file is listed as known-bad in the list of set S.'),
        'reputation_malicious (70) and the floor of 70')
    add('r02_listed_trusted.txt', critical_words + text('listed as trusted in the list of set S'),
        'trusted hash: CLEAN at once, although a critical rule would match')

    # ---- archives ----
    add('a01_zip_clean.zip', make_zip([('notes.txt', clean), ('more/notes2.txt', clean)]),
        'archive fully covered by scanned members: no entropy score, CLEAN')
    add('a02_zip_critical_member.zip', make_zip([('notes.txt', clean), ('words.txt', critical_words)]),
        'archive takes its worst member\'s score as a floor (archive_member, 70)')
    add('a03_tar_medium_member.tar', make_tar([('notes.txt', clean), ('blob.txt', files[3][1])]),
        'tar archive with a member at 30: floor 30')
    inner = make_zip([('words.txt', critical_words)])
    for _ in range(3):
        inner = make_zip([('inner.zip', inner)])
    add('a04_zip_nested_4_deep.zip', inner, 'nesting deeper than 3: the innermost archive is not unpacked')
    add('a05_zip_201_members.zip', make_zip([(f'f{i:03d}.txt', b'line\r\n') for i in range(201)]),
        'more than 200 members: member limit')
    add('a06_targz_low_member.tar.gz', gzip_stored(make_tar([('shell.txt', files[1][1])])),
        'compressed tar with a member at 5')

    # ---- files that start with MZ but are not valid executables ----
    add('m01_mz_packer_markers.bin', b'MZ' + bytes(62) + b'UPX0 UPX1 UPX! ' + bytes(200),
        'packer rule on a file that does not parse as PE: packer_detected (15)')
    fake = bytearray(0x200)
    fake[0:2] = b'MZ'
    struct.pack_into('<I', fake, 0x3C, 0x1F0)
    fake[0x1F0:0x1F4] = b'PE\x00\x00'
    add('m02_pe_signature_only.bin', bytes(fake),
        'PE signature present but headers cut off: malformed_pe (10)')

    # ---- hand-built executables (no code) ----
    code = filler_code()
    plain = [('.text', code, SEC_CODE), ('.data', bytes(0x200), SEC_DATA)]
    add('p01_plain.exe', build_pe(plain, BENIGN_IMPORTS), 'well-formed executable, nothing to report')
    add('p02_suspicious_import.exe', build_pe(plain, with_benign({'KERNEL32.dll': ['WinExec']})),
        'suspicious_import (10)')
    add('p03_injection_chain.exe', build_pe(plain, with_benign(
        {'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']})),
        'api_chain (35) + suspicious_import (10) + an imports-category rule: imports family above its cap of 35')
    add('p04_dynamic_resolution.exe', build_pe(plain, with_benign(
        {'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect']})),
        'dynamic_resolution_chain (15)')
    add('p05_persistence.exe', build_pe(plain, with_benign(
        {'ADVAPI32.dll': ['RegSetValueExA'], 'KERNEL32.dll': ['CreateProcessA']})),
        'api_chain_minor (15)')
    add('p06_wx_section.exe', build_pe([('.text', code, SEC_WX), ('.data', bytes(0x200), SEC_DATA)],
                                       BENIGN_IMPORTS), 'wx_section (10)')
    add('p07_entry_zero.exe', build_pe(plain, BENIGN_IMPORTS, entry='zero'), 'anomaly (10): entry point is zero')
    add('p08_high_entropy_section.exe',
        build_pe(plain + [('.blob', rng.randbytes(0x4000), SEC_RDATA)], BENIGN_IMPORTS),
        'high_entropy (15) on a section')
    add('p09_big_overlay.exe', build_pe(plain, BENIGN_IMPORTS, overlay=(b'overlay text line\r\n' * 64000)),
        'pe_overlay (15): more than 1 MiB after the last section, low entropy')
    add('p10_random_overlay.exe', build_pe(plain, BENIGN_IMPORTS, overlay=rng.randbytes(8192)),
        'overlay_high_entropy (5)')
    add('p11_tls_with_entropy.exe',
        build_pe(plain + [('.blob', rng.randbytes(0x4000), SEC_RDATA)], BENIGN_IMPORTS, tls=True),
        'tls_callback (5), scored because an entropy signal is present')
    add('p12_tls_alone.exe', build_pe(plain, BENIGN_IMPORTS, tls=True),
        'TLS callback without any packer or entropy signal: reported, not scored')
    add('p13_entropy_cap.exe',
        build_pe(plain + [('.blob1', rng.randbytes(0x4000), SEC_RDATA), ('.blob2', rng.randbytes(0x4000), SEC_RDATA)],
                 BENIGN_IMPORTS, overlay=rng.randbytes(8192)),
        'entropy family above its cap of 15 (two sections and the overlay)')
    add('p14_bad_certificate_table.exe', build_pe(plain, BENIGN_IMPORTS, cert=b'\xff' * 64),
        'malformed_certificate_table (10)')
    upx_layout = [('UPX0', b'', SEC_WX, 0x4000), ('UPX1', b'UPX!' + rng.randbytes(0x3FFC), SEC_WX)]
    add('p15_packer_confirmed.exe', build_pe(upx_layout, BENIGN_IMPORTS, entry=('section', 1)),
        'confirmed packer layout: packing family above its cap of 25')
    add('p16_packer_section_name.exe', build_pe(plain + [('.aspack', bytes(0x200), SEC_RDATA)], BENIGN_IMPORTS),
        'packer_detected (15) by section name')
    add('p17_download_exec_chain.exe', build_pe(plain, with_benign(
        {'URLMON.dll': ['URLDownloadToFileA'], 'SHELL32.dll': ['ShellExecuteA']})),
        'api_chain (35), second chain')
    add('p18_hook_chain.exe', build_pe(plain, with_benign(
        {'USER32.dll': ['SetWindowsHookExA', 'GetAsyncKeyState']})), 'api_chain (35), third chain')
    add('p19_tiny_import_table.exe', build_pe(plain, {'KERNEL32.dll': ['LoadLibraryA', 'GetProcAddress']}),
        'dynamic_resolution_chain (15) through the tiny import table rule')
    add('p20_privilege_chain.exe', build_pe(plain, with_benign(
        {'ADVAPI32.dll': ['OpenProcessToken', 'AdjustTokenPrivileges', 'LookupPrivilegeValueA']})),
        'api_chain_minor (15), privilege chain')
    add('p21_antidebug.exe', build_pe(plain, with_benign(
        {'KERNEL32.dll': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent']})),
        'anti-debug chain and the anti-debug rule (medium, 10)')
    add('p22_many_signals.exe', build_pe(
        [('.text', code, SEC_WX), ('.blob', rng.randbytes(0x4000), SEC_RDATA)],
        with_benign({'KERNEL32.dll': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'WinExec'],
                     'URLMON.dll': ['URLDownloadToFileA']}),
        entry='zero', tls=True, overlay=rng.randbytes(8192)),
        'many heuristic families at once (no critical rule)')
    add('a07_zip_with_executable.zip', make_zip([('tool.exe', files[-1][1]), ('notes.txt', clean)]),
        'archive whose worst member is an executable')

    # ---- large files (generated in CI) ----
    if large:
        add('L1_oversize_nothing.bin', ('sparse', 257 * MIB, b'', b''),
            'above 256 MiB with nothing found: oversize_partial_scan (5) and the partial-scan verdict text')
        add('L2_oversize_with_indicator.bin',
            ('sparse', 257 * MIB, text('x = FromBase64String(y)'), text('end of file')),
            'above 256 MiB with an indicator in the first window: oversize_partial_scan + obfuscated_script')
        add('L3_blind_zone_tail.bin', ('sparse', 33 * MIB, b'', text('x = FromBase64String(y)')),
            'between 32 and 256 MiB with an indicator only after the first 32 MiB: the blind zone (R-5); '
            'the reference is expected NOT to report it')
        add('L4_blind_zone_head.bin', ('sparse', 33 * MIB, text('x = FromBase64String(y)'), b''),
            'between 32 and 256 MiB with the indicator in the first 32 MiB: reported')
    return files


def write_file(path, data):
    """Writes the file and returns (sha256, size)."""
    h = hashlib.sha256()
    if isinstance(data, tuple):
        _, size, head, tail = data
        with open(path, 'wb') as f:
            f.write(head)
            f.truncate(size - len(tail))
            f.seek(size - len(tail))
            f.write(tail)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(MIB), b''):
                h.update(chunk)
        return h.hexdigest(), size
    with open(path, 'wb') as f:
        f.write(data)
    h.update(data)
    return h.hexdigest(), len(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', required=True)
    parser.add_argument('--no-large', action='store_true')
    args = parser.parse_args()

    files_dir = os.path.join(args.out, 'files')
    os.makedirs(files_dir, exist_ok=True)
    rng = random.Random(SEED)
    intent = {}
    for name, data, why in build_files(rng, not args.no_large):
        sha, size = write_file(os.path.join(files_dir, name), data)
        intent[name] = {'sha256': sha, 'size': size, 'intent': why}

    with open(os.path.join(REPO, 'data', 'reputation.json'), encoding='utf-8') as f:
        reputation = json.load(f)
    reputation.setdefault('malicious', {})[intent['r01_listed_bad.txt']['sha256']] = 'set S: listed known-bad (harmless text)'
    reputation.setdefault('trusted', {})[intent['r02_listed_trusted.txt']['sha256']] = 'set S: listed trusted'
    with open(os.path.join(args.out, 'set_s.reputation.json'), 'w', encoding='utf-8') as f:
        json.dump(reputation, f, indent=2, sort_keys=True)
    with open(os.path.join(args.out, 'set_s.intent.json'), 'w', encoding='utf-8') as f:
        json.dump({'seed': SEED, 'files': intent}, f, indent=2, sort_keys=True)
    print(f'make_set_s: {len(intent)} files in {files_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
