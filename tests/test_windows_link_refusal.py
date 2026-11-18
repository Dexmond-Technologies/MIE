'''read_for_verify on a platform without O_NOFOLLOW (Windows), simulated on
any OS: links and junctions (name-surrogate reparse tags) are refused, while
ordinary files with other reparse tags (OneDrive cloud files, dedup) are
still read. PASS UNDER MOCK for the reparse tags; the real symlink case runs
on the Windows runner in test_x12_v2_authenticode.'''
import os
from types import SimpleNamespace

import pytest

from dexmond_mie import signature

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _windows_like(monkeypatch, tag):
    monkeypatch.delattr(signature.os, 'O_NOFOLLOW', raising=False)
    real_lstat = os.lstat

    def lstat(path):
        st = real_lstat(path)
        return SimpleNamespace(st_mode=st.st_mode, st_dev=st.st_dev, st_ino=st.st_ino,
                               st_file_attributes=FILE_ATTRIBUTE_REPARSE_POINT,
                               st_reparse_tag=tag)
    monkeypatch.setattr(signature.os, 'lstat', lstat)


@pytest.mark.parametrize('tag', [0x9000001A,   # IO_REPARSE_TAG_CLOUD (OneDrive)
                                 0x80000013])  # IO_REPARSE_TAG_DEDUP
def test_ordinary_reparse_files_are_read(tmp_path, monkeypatch, tag):
    p = tmp_path / 'a.exe'
    p.write_bytes(b'MZ' + b'\0' * 100)
    _windows_like(monkeypatch, tag)
    data, _ = signature.read_for_verify(str(p))
    assert data == b'MZ' + b'\0' * 100


@pytest.mark.parametrize('tag', [0xA000000C,   # IO_REPARSE_TAG_SYMLINK
                                 0xA0000003])  # IO_REPARSE_TAG_MOUNT_POINT (junction)
def test_links_and_junctions_are_refused(tmp_path, monkeypatch, tag):
    p = tmp_path / 'a.exe'
    p.write_bytes(b'MZ' + b'\0' * 100)
    _windows_like(monkeypatch, tag)
    with pytest.raises(OSError):
        signature.read_for_verify(str(p))


def test_replaced_file_is_refused(tmp_path, monkeypatch):
    p = tmp_path / 'a.exe'
    p.write_bytes(b'MZ' + b'\0' * 100)
    monkeypatch.delattr(signature.os, 'O_NOFOLLOW', raising=False)
    real_lstat = os.lstat

    def lstat(path):
        st = real_lstat(path)
        return SimpleNamespace(st_mode=st.st_mode, st_dev=st.st_dev, st_ino=st.st_ino + 1)
    monkeypatch.setattr(signature.os, 'lstat', lstat)
    with pytest.raises(OSError):
        signature.read_for_verify(str(p))
