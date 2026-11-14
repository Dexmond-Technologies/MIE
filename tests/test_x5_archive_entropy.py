'''X5: whole-file high_entropy is not scored for recognised (structurally
valid) archive/compressed formats; a fake magic prefix is not enough.'''
import gzip
import io
import os
import tarfile
import zipfile


def _cats(results):
    return [f['category'] for f in results['findings']]


def test_stored_zip_of_random_data_no_high_entropy(tmp_path, make_engine):
    p = tmp_path / 'photos.zip'
    with zipfile.ZipFile(p, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr('a.jpg', os.urandom(48 * 1024))
    results = make_engine().scan_file(str(p))
    assert results['details']['entropy'] > 7.2
    assert 'high_entropy' not in _cats(results)
    assert results['details']['archive']['members_scanned'] == 1


def test_tgz_no_high_entropy(tmp_path, make_engine):
    p = tmp_path / 'backup.tgz'
    with tarfile.open(p, 'w:gz') as tf:
        blob = os.urandom(48 * 1024)
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))
    results = make_engine().scan_file(str(p))
    assert 'high_entropy' not in _cats(results)


def test_plain_tar_of_random_no_high_entropy(tmp_path, make_engine):
    p = tmp_path / 'data.tar'
    with tarfile.open(p, 'w') as tf:
        blob = os.urandom(64 * 1024)
        info = tarfile.TarInfo('blob.bin')
        info.size = len(blob)
        tf.addfile(info, io.BytesIO(blob))
    results = make_engine().scan_file(str(p))
    assert results['details']['compressed_format']['format'] == 'tar'
    assert 'high_entropy' not in _cats(results)


def test_fake_gzip_magic_keeps_lower_weight_finding(tmp_path, make_engine):
    p = tmp_path / 'fake.gz'
    p.write_bytes(b'\x1f\x8b\x08\x00' + os.urandom(64 * 1024))
    results = make_engine().scan_file(str(p))
    he = [f for f in results['findings'] if f['category'] == 'high_entropy']
    assert len(he) == 1 and he[0]['weight'] == 5


def test_random_blob_without_format_still_high_entropy(tmp_path, make_engine):
    p = tmp_path / 'blob.dat'
    p.write_bytes(os.urandom(64 * 1024))
    he = [f for f in make_engine().scan_file(str(p))['findings'] if f['category'] == 'high_entropy']
    assert len(he) == 1 and he[0]['weight'] == 15


def test_gzip_of_text_detected_valid():
    from dexmond_mie.utils import detect_compressed_format, validate_compressed_format
    data = gzip.compress(b'hello world ' * 1000)
    assert detect_compressed_format(data) == 'gzip'
    assert validate_compressed_format('gzip', data)
