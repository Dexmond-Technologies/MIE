'''X6: an archive's score is its worst member's score as a floor, labelled
archive_member, not added on top of the container's own findings.'''
import io
import os
import tarfile
import zipfile

from conftest import eicar_path


def _cats(results):
    return [f['category'] for f in results['findings']]


def test_benign_tgz_is_clean(tmp_path, make_engine):
    p = tmp_path / 'tgz_31.tgz'
    with tarfile.open(p, 'w:gz') as tf:
        for i in range(3):
            data = (f'line {i} of a benign changelog\n' * 200).encode()
            info = tarfile.TarInfo(f'docs/file{i}.txt')
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    results = make_engine().scan_file(str(p))
    assert results['verdict'] == 'CLEAN', results['findings']


def test_nested_benign_zip_is_clean(tmp_path, make_engine):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('readme.txt', 'hello world\n' * 100)
    p = tmp_path / 'nested.zip'
    with zipfile.ZipFile(p, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr('inner.zip', inner.getvalue())
    results = make_engine().scan_file(str(p))
    assert results['verdict'] == 'CLEAN', results['findings']


def test_member_score_not_added_to_container_score(tmp_path, make_engine):
    # member: random blob (high_entropy 15) + 'powershell' string (5) = 20;
    # stored zip shows the same string to the container scan (5).
    # Old logic: 5 + 20 = 25. New: max(5, 20) = 20.
    member = os.urandom(32 * 1024) + b' run powershell.exe now ' + os.urandom(32 * 1024)
    p = tmp_path / 'one.zip'
    with zipfile.ZipFile(p, 'w', zipfile.ZIP_STORED) as zf:
        zf.writestr('blob.bin', member)
    results = make_engine().scan_file(str(p))
    member_score = results['details']['archive']['worst_score']
    assert member_score == 20
    assert results['score'] == member_score
    assert 'archive_member' in _cats(results)
    assert 'yara_match' not in _cats(results) and 'critical_yara' not in _cats(results)


def test_eicar_zips_stay_malicious(make_engine):
    for name in ('eicar_com.zip', 'eicar_com2.zip'):
        results = make_engine().scan_file(eicar_path(name))
        assert results['verdict'] == 'MALICIOUS'
        assert 'archive_member' in _cats(results)
