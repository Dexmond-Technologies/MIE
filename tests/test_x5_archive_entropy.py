'''X5 (and its review follow-ups): whole-file entropy is exempt ONLY for an
archive whose members were all unpacked and scanned and cover the whole
file. Every other compressed format, and any archive whose member scan was
incomplete, keeps the finding at the reduced weight (5). Archives are
recognised by content, not extension.'''
import bz2
import io
import os
import tarfile
import tracemalloc
import zipfile

from dexmond_mie import core


def _he(results):
    return [f for f in results['findings'] if f['category'] == 'high_entropy']


def _zip_bytes(members, method=zipfile.ZIP_STORED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', method) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(members, mode='w'):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_fully_covered_zip_is_exempt(tmp_path, make_engine):
    p = tmp_path / 'photos.zip'
    p.write_bytes(_zip_bytes([('a.bin', os.urandom(48 * 1024))]))
    results = make_engine().scan_file(str(p))
    assert results['details']['entropy'] > 7.2
    assert results['details']['archive']['coverage'] == {'complete': True, 'reasons': []}
    assert _he(results) == []
    # the member itself is still judged on its own: a random blob member
    assert results['details']['archive']['worst_score'] == 15


def test_zip_with_trailing_data_keeps_reduced_finding(tmp_path, make_engine):
    p = tmp_path / 'x.zip'
    p.write_bytes(_zip_bytes([('a.txt', b'hello')]) + os.urandom(64 * 1024))
    results = make_engine().scan_file(str(p))
    he = _he(results)
    assert len(he) == 1 and he[0]['weight'] == 5, results['findings']


def test_zip_with_data_before_first_member_keeps_reduced_finding(tmp_path, make_engine):
    p = tmp_path / 'sfx.zip'
    p.write_bytes(os.urandom(64 * 1024) + _zip_bytes([('a.txt', b'hello')]))
    results = make_engine().scan_file(str(p))
    he = _he(results)
    assert len(he) == 1 and he[0]['weight'] == 5, results['findings']


def test_zip_member_over_budget_keeps_reduced_finding(tmp_path, make_engine, monkeypatch):
    monkeypatch.setattr(core, 'MAX_ARCHIVE_MEMBERS', 1)
    p = tmp_path / 'two.zip'
    p.write_bytes(_zip_bytes([('a.bin', os.urandom(32 * 1024)), ('b.bin', os.urandom(32 * 1024))]))
    results = make_engine().scan_file(str(p))
    assert not results['details']['archive']['coverage']['complete']
    he = _he(results)
    assert len(he) == 1 and he[0]['weight'] == 5


def test_depth_limit_keeps_reduced_finding(tmp_path, make_engine, monkeypatch):
    monkeypatch.setattr(core, 'MAX_ARCHIVE_DEPTH', 1)
    inner = _zip_bytes([('blob.bin', os.urandom(48 * 1024))])
    p = tmp_path / 'outer.zip'
    p.write_bytes(_zip_bytes([('inner.zip', inner)]))
    results = make_engine().scan_file(str(p))
    reasons = results['details']['archive']['coverage']['reasons']
    assert any('depth' in r for r in reasons)
    he = _he(results)
    assert len(he) == 1 and he[0]['weight'] == 5


def test_tgz_fully_covered_is_exempt(tmp_path, make_engine):
    p = tmp_path / 'backup.tgz'
    p.write_bytes(_tar_bytes([('blob.bin', os.urandom(48 * 1024))], 'w:gz'))
    results = make_engine().scan_file(str(p))
    assert results['details']['archive']['coverage']['complete'], results['details']['archive']
    assert _he(results) == []


def test_plain_tar_fully_covered_is_exempt(tmp_path, make_engine):
    p = tmp_path / 'data.tar'
    p.write_bytes(_tar_bytes([('blob.bin', os.urandom(64 * 1024))]))
    results = make_engine().scan_file(str(p))
    assert results['details']['archive']['coverage']['complete']
    assert _he(results) == []


def test_tar_with_trailing_random_keeps_finding(tmp_path, make_engine):
    p = tmp_path / 'data.tar'
    p.write_bytes(_tar_bytes([('a.txt', b'hello')]) + os.urandom(64 * 1024))
    results = make_engine().scan_file(str(p))
    assert not results['details'].get('archive', {}).get('coverage', {}).get('complete')
    he = _he(results)
    assert len(he) == 1 and he[0]['weight'] == 5, results['findings']


def test_tar_with_non_regular_member_not_covered(tmp_path, make_engine):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        blob = os.urandom(64 * 1024)
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))
        link = tarfile.TarInfo('link')
        link.type = tarfile.SYMTYPE
        link.linkname = 'blob.bin'
        tf.addfile(link)
    p = tmp_path / 'links.tar'
    p.write_bytes(buf.getvalue())
    results = make_engine().scan_file(str(p))
    assert any('non-regular' in r for r in results['details']['archive']['coverage']['reasons'])
    assert _he(results)[0]['weight'] == 5


def test_archive_detected_by_content_not_extension(tmp_path, make_engine):
    p = tmp_path / 'renamed.dat'
    p.write_bytes(_zip_bytes([('a.txt', b'hello world')]))
    results = make_engine().scan_file(str(p))
    assert results['details']['archive']['members_scanned'] == 1


def test_fake_gzip_magic_keeps_reduced_finding(tmp_path, make_engine):
    p = tmp_path / 'fake.gz'
    p.write_bytes(b'\x1f\x8b\x08\x00' + os.urandom(64 * 1024))
    he = _he(make_engine().scan_file(str(p)))
    assert len(he) == 1 and he[0]['weight'] == 5


def test_random_blob_without_format_full_weight(tmp_path, make_engine):
    p = tmp_path / 'blob.dat'
    p.write_bytes(os.urandom(64 * 1024))
    he = _he(make_engine().scan_file(str(p)))
    assert len(he) == 1 and he[0]['weight'] == 15


def test_bz2_bomb_is_not_expanded(tmp_path, make_engine):
    '''No validator decompresses a stream any more; a 16 MiB-of-zeros bz2
    bomb must not be expanded in memory by the scan.'''
    p = tmp_path / 'bomb.bz2'
    p.write_bytes(bz2.compress(b'\0' * (16 * 1024 * 1024)))
    engine = make_engine()
    tracemalloc.start()
    engine.scan_file(str(p))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 8 * 1024 * 1024
