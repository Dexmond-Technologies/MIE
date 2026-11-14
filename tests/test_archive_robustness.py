'''Review follow-ups on archive coverage: crafted archives can never drop the
outer scan (fail-open), and bytes no member scan sees (zip extra fields and
comments, tar pax headers, non-zero tar padding) keep the entropy finding
at the reduced weight instead of a full exemption.'''
import io
import os
import tarfile
import zipfile

from dexmond_mie import core


def _he(results):
    return [f for f in results['findings'] if f['category'] == 'high_entropy']


def test_unexpected_exception_in_member_extraction_is_recorded(tmp_path, make_engine,
                                                              monkeypatch):
    p = tmp_path / 'a.zip'
    with zipfile.ZipFile(p, 'w') as zf:
        zf.writestr('blob.bin', os.urandom(48 * 1024))
    real_open = zipfile.ZipFile.open

    def boom(self, *a, **k):
        raise RuntimeError('crafted archive')
    monkeypatch.setattr(zipfile.ZipFile, 'open', boom)
    results = make_engine().scan_file(str(p))
    monkeypatch.setattr(zipfile.ZipFile, 'open', real_open)
    reasons = results['details']['archive']['coverage']['reasons']
    assert any('RuntimeError' in r for r in reasons)
    assert results['verdict'] != 'CLEAN'          # findings kept, reduced entropy finding
    assert _he(results)[0]['weight'] == 5


def test_unexpected_exception_in_member_scan_is_recorded(tmp_path, make_engine, monkeypatch):
    p = tmp_path / 'a.zip'
    with zipfile.ZipFile(p, 'w') as zf:
        zf.writestr('blob.bin', os.urandom(48 * 1024))
    real = core.Engine.scan_file

    def flaky(self, fp, _depth=0, _budget=None):
        if _depth > 0:
            raise NotImplementedError('crafted member')
        return real(self, fp, _depth, _budget)
    monkeypatch.setattr(core.Engine, 'scan_file', flaky)
    results = make_engine().scan_file(str(p))
    assert any('NotImplementedError' in r
               for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_zip_large_comment_is_uncovered(tmp_path, make_engine):
    p = tmp_path / 'c.zip'
    with zipfile.ZipFile(p, 'w') as zf:
        zf.writestr('blob.bin', os.urandom(48 * 1024))
        zf.comment = os.urandom(8 * 1024)
    results = make_engine().scan_file(str(p))
    assert any('extra fields/comments' in r
               for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_zip_large_extra_field_is_uncovered(tmp_path, make_engine):
    p = tmp_path / 'e.zip'
    info = zipfile.ZipInfo('blob.bin')
    payload = os.urandom(6000)
    info.extra = (0xCAFE).to_bytes(2, 'little') + len(payload).to_bytes(2, 'little') + payload
    with zipfile.ZipFile(p, 'w') as zf:
        zf.writestr(info, os.urandom(48 * 1024))
    results = make_engine().scan_file(str(p))
    assert any('extra fields/comments' in r
               for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_tar_pax_headers_over_limit_are_uncovered(tmp_path, make_engine):
    p = tmp_path / 'pax.tar'
    with tarfile.open(p, 'w', format=tarfile.PAX_FORMAT) as tf:
        blob = os.urandom(64 * 1024)
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        info.pax_headers = {'comment': os.urandom(4000).hex()}
        tf.addfile(info, io.BytesIO(blob))
    results = make_engine().scan_file(str(p))
    assert any('extended' in r for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_tar_non_zero_member_padding_is_uncovered(tmp_path, make_engine):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        blob = os.urandom(64 * 1024 + 100)        # 412 bytes of block padding follow
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))
    data = bytearray(buf.getvalue())
    data[512 + 64 * 1024 + 100: 512 + 64 * 1024 + 512] = os.urandom(412)
    p = tmp_path / 'pad.tar'
    p.write_bytes(bytes(data))
    results = make_engine().scan_file(str(p))
    assert any('padding' in r for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_small_pax_header_still_covered(tmp_path, make_engine):
    p = tmp_path / 'ok.tar'
    with tarfile.open(p, 'w', format=tarfile.PAX_FORMAT) as tf:
        blob = os.urandom(64 * 1024)
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        info.pax_headers = {'comment': 'built by ci'}
        tf.addfile(info, io.BytesIO(blob))
    results = make_engine().scan_file(str(p))
    assert results['details']['archive']['coverage']['complete'], \
        results['details']['archive']['coverage']
    assert _he(results) == []
