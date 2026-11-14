'''X4: the high-entropy-pocket finding no longer fires on PE resources or on
a few high-entropy windows; PE entropy is judged per section, .rsrc ignored.'''
import os
import struct

from fakepe import FakeSection, analyzer
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


def test_known_compressed_format_does_not_fire(tmp_path, make_engine):
    p = tmp_path / 'img.png'
    p.write_bytes(b'\x89PNG\r\n\x1a\n' + _text(32 * 1024) + os.urandom(32 * 1024))
    results = make_engine().scan_file(str(p))
    assert 'sliding_entropy_spike' not in _cats(results)
    assert detect_compressed_format(p.read_bytes()) == 'png'


def test_pe_whole_file_entropy_not_used(tmp_path, make_engine):
    # a PE whose body is random (e.g. resources + signature): no whole-file
    # or sliding entropy finding; sections decide (needs pefile)
    data = _minimal_pe_header() + os.urandom(64 * 1024)
    assert is_pe_data(data)
    p = tmp_path / 'tool.exe'
    p.write_bytes(data)
    results = make_engine().scan_file(str(p))
    assert 'sliding_entropy_spike' not in _cats(results)
    assert not any(f['category'] == 'high_entropy' and 'overall' in f['description']
                   for f in results['findings'])


def test_rsrc_section_entropy_ignored():
    a = analyzer(sections=[FakeSection('.text', 6.0, 'RX'), FakeSection('.rsrc', 7.9, 'R')])
    assert not any('entropy' in w for w in a._check_anomalies())
    b = analyzer(sections=[FakeSection('.text', 7.6, 'RX')])
    assert any('.text' in w and 'entropy' in w for w in b._check_anomalies())


def test_is_pe_requires_pe_signature():
    assert not is_pe_data(b'MZ' + b'\0' * 100)
