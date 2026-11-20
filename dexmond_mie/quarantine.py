import os
import re
import json
import stat
import time
import errno
import hashlib
import logging
from typing import Dict, List, Optional

from . import paths

logger = logging.getLogger('DEXMOND_MIE')

# Stored files are XOR-ed with one fixed byte (obfuscation, NOT encryption:
# anyone with the file can undo it) so they are not run by accident and not
# re-flagged by scans while sitting in quarantine. Restore undoes it exactly.
XOR_KEY = 0xA5
CHUNK_SIZE = 1024 * 1024

# Quarantine IDs are locally generated 16-char hex digests. Validating the
# shape blocks path-traversal (e.g. "../../etc/passwd") through the id.
_QID_RE = re.compile(r'^[a-f0-9]{16}$')


class QuarantineManager:
    '''Moves a flagged file into the quarantine folder: writes a copy XOR-ed
    with XOR_KEY, deletes the original, keeps the metadata for restore.'''

    def __init__(self, quarantine_dir: str = './quarantine'):
        os.makedirs(quarantine_dir, exist_ok=True)
        self.dir = os.path.realpath(quarantine_dir)

    @staticmethod
    def _xor_copy_fd(src_fd: int, dst_fd: int) -> str:
        '''Streams bytes from src_fd to dst_fd XOR-ed with XOR_KEY and returns
        the plaintext SHA-256 hex digest.'''
        h = hashlib.sha256()
        with os.fdopen(src_fd, 'rb') as fin, os.fdopen(dst_fd, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
                fout.write(bytes(b ^ XOR_KEY for b in chunk))
        return h.hexdigest()

    @staticmethod
    def _open_regular_nofollow_rdonly(file_path: str) -> int:
        pre = os.lstat(file_path)
        if paths.is_symlink_or_junction_stat(pre):
            raise OSError(errno.ELOOP, 'Refusing to follow symbolic link or junction', file_path)
        if not stat.S_ISREG(pre.st_mode):
            raise OSError(errno.EINVAL, 'Not a regular file', file_path)
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        fd = os.open(file_path, flags)
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != (pre.st_dev, pre.st_ino) and pre.st_ino != 0:
                raise OSError(errno.ELOOP, 'File replaced during open', file_path)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(errno.EINVAL, 'Not a regular file', file_path)
            return fd
        except Exception:
            os.close(fd)
            raise

    def add(self, file_path: str, results: Optional[Dict] = None) -> Dict:
        file_path = os.path.abspath(file_path)
        results = results or {}
        expected_sha256 = (results.get('hashes', {}) or {}).get('sha256', '').lower()

        src_fd = self._open_regular_nofollow_rdonly(file_path)
        qid = hashlib.sha256(f'{file_path}|{time.time_ns()}'.encode()).hexdigest()[:16]
        data_path = os.path.join(self.dir, qid + '.qtn')
        dst_flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            dst_fd = os.open(data_path, dst_flags, 0o600)
        except Exception:
            os.close(src_fd)
            raise

        try:
            copied_sha256 = self._xor_copy_fd(src_fd, dst_fd)
            if expected_sha256 and copied_sha256 != expected_sha256:
                raise OSError(errno.EAGAIN,
                              'File contents changed between scan and quarantine (SHA-256 mismatch)',
                              file_path)
            if paths.is_symlink_or_junction(file_path):
                raise OSError(errno.ELOOP, 'File replaced by symbolic link before removal', file_path)
            try:
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
            os.remove(file_path)
        except Exception:
            try:
                if os.path.lexists(data_path):
                    os.unlink(data_path)
            except OSError:
                pass
            raise

        meta = {
            'id': qid,
            'filename': os.path.basename(file_path),
            'original_path': file_path,
            'quarantined_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'verdict': results.get('verdict', 'UNKNOWN'),
            'score': results.get('score', 0),
            'sha256': copied_sha256}
        with open(os.path.join(self.dir, qid + '.json'), 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2)
        logger.info(f'Quarantined {file_path} as {qid}')
        return meta

    def list(self) -> List[Dict]:
        items = []
        for name in os.listdir(self.dir):
            if name.endswith('.json'):
                try:
                    with open(os.path.join(self.dir, name), encoding='utf-8') as f:
                        items.append(json.load(f))
                except (OSError, json.JSONDecodeError):
                    continue
        return sorted(items, key=lambda x: x.get('quarantined_at', ''), reverse=True)

    def _safe_path(self, qid: str, suffix: str) -> str:
        '''Resolves a store path for qid, rejecting anything that escapes the dir.'''
        if not _QID_RE.match(qid):
            raise KeyError(qid)
        path = os.path.realpath(os.path.join(self.dir, qid + suffix))
        if os.path.commonpath([path, self.dir]) != self.dir:
            raise KeyError(qid)
        return path

    def _meta(self, qid: str) -> Dict:
        meta_path = self._safe_path(qid, '.json')
        if not os.path.isfile(meta_path):
            raise KeyError(qid)
        with open(meta_path, encoding='utf-8') as f:
            return json.load(f)

    @staticmethod
    def _choose_restore_dest(original_path: str) -> str:
        parent = os.path.dirname(os.path.abspath(original_path))
        if parent:
            if paths.is_symlink_or_junction(parent):
                raise OSError(errno.ELOOP, 'Refusing to restore into symbolic link or junction directory', parent)
            os.makedirs(parent, exist_ok=True)
        if not os.path.lexists(original_path):
            return original_path
        base, ext = os.path.splitext(original_path)
        candidate = f'{base}.restored{ext}'
        idx = 1
        while os.path.lexists(candidate):
            candidate = f'{base}.restored.{idx}{ext}'
            idx += 1
        return candidate

    def restore(self, qid: str) -> str:
        meta = self._meta(qid)
        qtn_path = self._safe_path(qid, '.qtn')
        src_fd = self._open_regular_nofollow_rdonly(qtn_path)
        dest = self._choose_restore_dest(meta['original_path'])
        dst_flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            dst_fd = os.open(dest, dst_flags, 0o600)
        except Exception:
            os.close(src_fd)
            raise
        self._xor_copy_fd(src_fd, dst_fd)
        self._remove(qid)
        logger.info(f'Restored quarantine item {qid} to {dest}')
        return dest

    def delete(self, qid: str):
        self._meta(qid)
        self._remove(qid)
        logger.info(f'Deleted quarantine item {qid}')

    def _remove(self, qid: str):
        for suffix in ('.qtn', '.json'):
            path = self._safe_path(qid, suffix)
            if os.path.isfile(path):
                os.remove(path)
