'''X4: the high-entropy-pocket finding no longer fires on PE resources or on
a few high-entropy windows; PE entropy is judged per section, .rsrc ignored.'''
import os
import struct

from fakepe import FakeSection, analyzer, patch_engine_pe, patch_engine_pe_fails
from dexmond_mie.scoring import Scorer
from dexmond_mie.utils import is_pe_data, detect_compressed_format


def _cats(results):
    return [f['category'] for f in results['findings']]


def _text(n):
    return (b'The quick brown fox jumps over the lazy dog. ' * (n // 45 + 1))[:n]


def _minimal_pe_header():
    hdr = bytearray(0x80)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    return bytes(hdr)


def test_weight_is_10():
    assert Scorer.WEIGHTS['sliding_entropy_spike'] == 10


def test_non_pe_small_pocket_does_not_fire(tmp_path, make_engine):
    # 1 random 8 KiB pocket in 64 KiB of text: < 25 % of windows high
    p = tmp_path / 'doc.bin'
    p.write_bytes(_text(28 * 1024) + os.urandom(8 * 1024) + _text(28 * 1024))
    results = make_engine().scan_file(str(p))
    assert 'sliding_entropy_spike' not in _cats(results)
    assert 'high_entropy' not in _cats(results)


def test_non_pe_large_share_fires_with_weight_10(tmp_path, make_engine):
    # half random, half text: > 25 % of windows high, whole-file entropy < 7.2
    p = tmp_path / 'blob.bin'
    p.write_bytes(_text(32 * 1024) + os.urandom(32 * 1024))
    results = make_engine().scan_file(str(p))
    spikes = [f for f in results['findings'] if f['category'] == 'sliding_entropy_spike']
    assert len(spikes) == 1 and spikes[0]['weight'] == 10


def test_valid_png_structure_is_exempt(tmp_path, make_engine):
    import struct
    import zlib
    ihdr = b'IHDR' + struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0)
    png = (b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + ihdr +
           struct.pack('>I', zlib.crc32(ihdr) & 0xffffffff))
    p = tmp_path / 'img.png'
    p.write_bytes(png + _text(32 * 1024) + os.urandom(32 * 1024))
    results = make_engine().scan_file(str(p))
    assert results['details']['compressed_format'] == {'format': 'png', 'structure_valid': True}
    assert 'sliding_entropy_spike' not in _cats(results)
    assert detect_compressed_format(p.read_bytes()) == 'png'


def _pe_file(tmp_path, body):
    data = _minimal_pe_header() + body
    assert is_pe_data(data)
    p = tmp_path / 'tool.exe'
    p.write_bytes(data)
    return str(p)


def test_parsed_pe_skips_whole_file_entropy(tmp_path, make_engine, monkeypatch):
    '''A PE that really parses: whole-file and sliding entropy are not used
    (PASS UNDER MOCK: the parser is a stand-in).'''
    patch_engine_pe(monkeypatch, sections=[FakeSection('.text', 6.0, 'RX')])
    results = make_engine().scan_file(_pe_file(tmp_path, os.urandom(64 * 1024)))
    assert 'sliding_entropy_spike' not in _cats(results)
    assert 'high_entropy' not in _cats(results)
    assert 'malformed_pe' not in _cats(results)


def test_malformed_pe_gets_non_pe_entropy_checks(tmp_path, make_engine, monkeypatch):
    '''PE signature present but the parser fails: no fail-open. The file gets
    the non-PE entropy checks plus a malformed_pe finding.'''
    patch_engine_pe_fails(monkeypatch)
    results = make_engine().scan_file(_pe_file(tmp_path, os.urandom(64 * 1024)))
    assert 'malformed_pe' in _cats(results)
    assert 'high_entropy' in _cats(results)


def test_pe_without_pefile_is_not_exempt(tmp_path, make_engine, monkeypatch):
    '''If pefile is missing the file is NOT treated as a parsed PE.'''
    from dexmond_mie import pe_analyzer
    monkeypatch.setattr(pe_analyzer, 'pefile', None)
    results = make_engine().scan_file(_pe_file(tmp_path, os.urandom(64 * 1024)))
    assert 'high_entropy' in _cats(results)
    assert results['details']['pe_analysis'].startswith('unavailable')


def test_overlay_entropy_measured_without_certificate(tmp_path, make_engine, monkeypatch):
    cert = b'\x30\x82' + bytes(range(256)) * 16          # stand-in cert blob
    overlay = cert + os.urandom(16 * 1024)
    patch_engine_pe(monkeypatch, overlay_data=overlay,
                    security=(0x2000, len(cert)))
    results = make_engine().scan_file(_pe_file(tmp_path, b'\0' * 1024))
    info = results['details']['pe_info']['overlay_entropy']
    assert info['certificate_excluded'] == len(cert)
    assert info['size'] == 16 * 1024
    assert 'overlay_high_entropy' in _cats(results)


def test_resource_section_found_by_directory_not_name():
    # real resource section (via data directory), not executable: exempt
    a = analyzer(sections=[FakeSection('.text', 6.0, 'RX', va=0x1000),
                           FakeSection('.rsrc', 7.9, 'R', va=0x3000)], resource_rva=0x3000)
    assert not any('entropy' in w for w in a._check_anomalies())
    # a section NAMED .rsrc that the resource directory does not point to
    b = analyzer(sections=[FakeSection('.text', 6.0, 'RX', va=0x1000),
                           FakeSection('.rsrc', 7.9, 'R', va=0x3000)], resource_rva=0)
    assert any('.rsrc' in w and 'entropy' in w for w in b._check_anomalies())
    # the resource directory points into an EXECUTABLE section: not exempt
    c = analyzer(sections=[FakeSection('.rsrc', 7.9, 'RX', va=0x3000)], resource_rva=0x3000)
    assert any('entropy' in w for w in c._check_anomalies())
    d = analyzer(sections=[FakeSection('.text', 7.6, 'RX')])
    assert any('.text' in w and 'entropy' in w for w in d._check_anomalies())


def test_fake_magic_does_not_switch_off_detector(tmp_path, make_engine):
    '''3 bytes of JPEG/LZMA/MP3 magic in front of random data: the finding is
    still reported, at the lower weight.'''
    for magic in (b'\xff\xd8\xff', b'\x5d\x00\x00', b'ID3', b'%PDF-1.7'):
        p = tmp_path / 'fake.bin'
        p.write_bytes(magic + _text(32 * 1024) + os.urandom(32 * 1024))
        results = make_engine().scan_file(str(p))
        spikes = [f for f in results['findings'] if f['category'] == 'sliding_entropy_spike']
        assert len(spikes) == 1 and spikes[0]['weight'] == 5, (magic, results['findings'])


def test_valid_gzip_structure_is_exempt(tmp_path, make_engine):
    import gzip
    p = tmp_path / 'data.gz'
    p.write_bytes(gzip.compress(os.urandom(64 * 1024)))
    results = make_engine().scan_file(str(p))
    assert results['details']['compressed_format'] == {'format': 'gzip', 'structure_valid': True}
    assert 'sliding_entropy_spike' not in _cats(results)


def test_is_pe_requires_pe_signature():
    assert not is_pe_data(b'MZ' + b'\0' * 100)
