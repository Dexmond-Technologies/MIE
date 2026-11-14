'''X10: packing is a property, not malice. One packer signal at most (YARA
or section names), weight 15; a benign UPX file with all the signals packing
causes stays at most SUSPICIOUS (LOW). Extra, independent evidence still
adds. (Stand-in PE parser and YARA results: PASS UNDER MOCK.)'''
import struct

from fakepe import FakeSection, patch_engine_pe

UPX_YARA = {'rule': 'Packer_UPX', 'namespace': 'packers', 'tags': [], 'strings': 3,
            'meta': {'description': 'UPX packed executable', 'severity': 'medium',
                     'category': 'packer'}}
UPX_PE = dict(
    sections=[FakeSection('UPX0', 0.0, 'RWX'), FakeSection('UPX1', 7.9, 'RWX'),
              FakeSection('.rsrc', 4.0, 'R')],
    imports={'KERNEL32.DLL': ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect',
                              'VirtualAlloc', 'VirtualFree', 'ExitProcess']},
    tls_callbacks=[0x401000])


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
    results = _scan(tmp_path, make_engine, monkeypatch)
    cats = [f['category'] for f in results['findings']]
    assert cats.count('packer_detected') == 1          # YARA + sections = one signal
    assert 'yara_match' not in cats
    assert results['score'] < 30, results['findings']
    assert results['verdict'] in ('SUSPICIOUS (LOW)', 'CLEAN')


def test_packer_weight_is_15(tmp_path, make_engine, monkeypatch):
    results = _scan(tmp_path, make_engine, monkeypatch,
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
