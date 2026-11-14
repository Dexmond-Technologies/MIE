'''X8: a zero or out-of-range compile timestamp (reproducible builds) is
report-only: a note in pe_info, never a scored finding.
(Stand-in PE parser: PASS UNDER MOCK.)'''
import struct

import pytest

from fakepe import analyzer, patch_engine_pe


def _pe_file(tmp_path):
    hdr = bytearray(0x200)
    hdr[0:2] = b'MZ'
    hdr[0x3c:0x40] = struct.pack('<I', 0x40)
    hdr[0x40:0x44] = b'PE\0\0'
    p = tmp_path / 'repro.exe'
    p.write_bytes(bytes(hdr))
    return str(p)


@pytest.mark.parametrize('ts', [0, 0x80000000, 0xFFFFFFFF])
def test_timestamp_alone_not_flagged(tmp_path, make_engine, monkeypatch, ts):
    assert not any('timestamp' in w.lower() for w in analyzer(timestamp=ts)._check_anomalies())
    patch_engine_pe(monkeypatch, timestamp=ts)
    results = make_engine().scan_file(_pe_file(tmp_path))
    assert results['verdict'] == 'CLEAN', results['findings']
    assert any('timestamp' in n.lower() for n in results['details']['pe_info']['notes'])
