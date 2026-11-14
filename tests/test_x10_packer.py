'''X10: packing is a property, not malice. One packer signal at most (YARA
or section names), weight 15; a benign UPX file with all the signals packing
causes stays at most SUSPICIOUS (LOW). Extra, independent evidence still
adds. (Stand-in PE parser and YARA results: PASS UNDER MOCK.)'''
import struct

from fakepe import FakeSection, patch_engine_pe

UPX_YARA = {'rule': 'Packer_UPX', 'namespace': 'packers', 'tags': [], 'strings': 3,
            'meta': {'description': 'UPX packed executable', 'severity': 'medium',
                     'category': 'packer'}}
# The layout UPX really writes: UPX0 empty on disk (virtual only), UPX1 with
# the packed data and the entry point, both RWX; TLS callback inside UPX1.
UPX_PE = dict(
    sections=[FakeSection('UPX0', 0.0, 'RWX', raw_size=0, vsize=0x10000, va=0x1000),
              FakeSection('UPX1', 7.9, 'RWX', raw_size=0x8000, va=0x11000),
              FakeSection('.rsrc', 4.0, 'R', raw_size=0x1000, va=0x19000)],
    entry=0x12000,
    imports={'KERNEL32.DLL': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect',
                              'VirtualAlloc', 'VirtualFree', 'ExitProcess']},
    tls_callbacks=[0x400000 + 0x12100])


def _pe_file(tmp_path):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    p = tmp_path / 'packed.exe'
    p.write_bytes(bytes(hdr) + b'\0' * 4096)
    return str(p)


def _scan(tmp_path, make_engine, monkeypatch, yara=(UPX_YARA,), **pe):
    patch_engine_pe(monkeypatch, **(pe or UPX_PE))
    engine = make_engine()
    monkeypatch.setattr(engine.yara_engine, 'scan', lambda path: [dict(m) for m in yara])
    return engine.scan_file(_pe_file(tmp_path))


def test_benign_upx_is_at_most_low(tmp_path, make_engine, monkeypatch):
    '''B3 class: a real UPX layout with the Packer_UPX rule stays below MEDIUM.'''
    results = _scan(tmp_path, make_engine, monkeypatch)
    assert results['details']['packer_confirmed'] == ['UPX0', 'UPX1']
    cats = [f['category'] for f in results['findings']]
    assert cats.count('packer_detected') == 1          # YARA + sections = one signal
    assert 'yara_match' not in cats
    assert results['score'] < 30, results['findings']
    assert results['verdict'] in ('SUSPICIOUS (LOW)', 'CLEAN')


def test_packer_weight_is_15(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch, entry=0x1100,
                    sections=[FakeSection('UPX0', 0.0, 'R'), FakeSection('UPX1', 5.0, 'R')])
    packer = [f for f in results['findings'] if f['category'] == 'packer_detected']
    assert len(packer) == 1 and packer[0]['weight'] == 15
    assert results['score'] == 15


def test_packed_plus_injection_still_scores_above_low(tmp_path, make_engine, monkeypatch):
    pe = dict(UPX_PE)
    pe['imports'] = {'KERNEL32.DLL': UPX_PE['imports']['KERNEL32.DLL'] +
                     ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']}
    results = _scan(tmp_path, make_engine, monkeypatch, **pe)
    assert results['score'] >= 30, results['findings']


def test_fake_upx_marker_folds_nothing(tmp_path, make_engine, monkeypatch):
    '''A UPX string (YARA hit) without the UPX layout, plus an RWX
    non-packer section and a dynamic-resolution import chain: every item
    keeps its full weight outside the packing cap.'''
    pe = dict(sections=[FakeSection('.text', 6.0, 'RX', va=0x1000),
                        FakeSection('.evil', 7.9, 'RWX', va=0x3000)],
              entry=0x1100,
              imports=UPX_PE['imports'])
    results = _scan(tmp_path, make_engine, monkeypatch, **pe)
    assert 'packer_confirmed' not in results['details']
    by_cat = {f['category']: f for f in results['findings']}
    assert by_cat['packer_detected']['weight'] == 15
    assert by_cat['wx_section']['weight'] == 10 and 'family' not in by_cat['wx_section']
    assert by_cat['dynamic_resolution_chain']['weight'] == 15
    assert 'family' not in by_cat['dynamic_resolution_chain']
    assert by_cat['high_entropy']['weight'] == 15 and 'family' not in by_cat['high_entropy']
    # 15 packer + 10 wx + 15 chain + 15 entropy = 55, nothing capped
    assert results['score'] >= 55, results['findings']


def test_upx_names_without_yara_confirm_nothing(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch, yara=())
    assert 'packer_confirmed' not in results['details']
    assert results['score'] >= 30
