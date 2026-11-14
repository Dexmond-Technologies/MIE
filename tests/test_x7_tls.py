'''X7: a TLS directory alone (mingw/MSVC/Go) is not a finding; a non-empty
callback array scores 5, and only together with packer/entropy signals.
(Stand-in PE parser: PASS UNDER MOCK.)'''
import struct

from fakepe import FakeSection, analyzer, patch_engine_pe
from dexmond_mie.scoring import Scorer


def _pe_file(tmp_path):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    p = tmp_path / 'app.exe'
    p.write_bytes(bytes(hdr) + b'\0' * 4096)
    return str(p)


def _cats(results):
    return [f['category'] for f in results['findings']]


def test_tls_directory_without_callbacks_is_not_tls_callback():
    assert not analyzer(tls_callbacks=[]).has_tls_callbacks()
    assert not analyzer(tls_callbacks=None).has_tls_callbacks()
    assert analyzer(tls_callbacks=[0x401000]).has_tls_callbacks()
    assert analyzer(tls_callbacks=[0x140001000], is_64=True,
                    image_base=0x140000000).has_tls_callbacks()


def test_tls_callbacks_alone_not_scored(tmp_path, make_engine, monkeypatch):
    patch_engine_pe(monkeypatch, tls_callbacks=[0x401000])
    results = make_engine().scan_file(_pe_file(tmp_path))
    assert results['details']['pe_info']['tls_callbacks'] is True
    assert 'tls_callback' not in _cats(results)
    assert results['verdict'] == 'CLEAN'


def test_tls_callbacks_with_packer_scored_5(tmp_path, make_engine, monkeypatch):
    patch_engine_pe(monkeypatch, tls_callbacks=[0x401000],
                    sections=[FakeSection('UPX0', 0.0, 'RWX'), FakeSection('UPX1', 7.8, 'RWX')])
    results = make_engine().scan_file(_pe_file(tmp_path))
    tls = [f for f in results['findings'] if f['category'] == 'tls_callback']
    assert len(tls) == 1 and tls[0]['weight'] == 5
    assert Scorer.WEIGHTS['tls_callback'] == 5


def test_tls_gate_opened_by_resource_slack_entropy(tmp_path, make_engine, monkeypatch):
    '''Old semantics restored: ANY entropy warning (here: high entropy
    outside the resource data entries) opens the TLS-callback gate.'''
    import os
    rsrc = FakeSection('.rsrc', 7.9, 'R', va=0x3000, data=b'\0' * 512 + os.urandom(8192))
    patch_engine_pe(monkeypatch, tls_callbacks=[0x401000], resource_rva=0x3000,
                    resources=[(0x3000, 512)],
                    sections=[FakeSection('.text', 6.0, 'RX'), rsrc])
    results = make_engine().scan_file(_pe_file(tmp_path))
    assert any('outside its resource data entries' in w
               for w in results['details']['pe_info']['warnings'])
    assert 'tls_callback' in _cats(results)
