import os
import re
import json
import stat
import time
import hashlib
import logging
from typing import Dict, List, Optional

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
    def _xor_copy(src: str, dst: str):
        with open(src, 'rb') as fin, open(dst, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(bytes(b ^ XOR_KEY for b in chunk))

    def add(self, file_path: str, results: Optional[Dict] = None) -> Dict:
        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)
        qid = hashlib.sha256(f'{file_path}|{time.time()}'.encode()).hexdigest()[:16]
        data_path = os.path.join(self.dir, qid + '.qtn')
        self._xor_copy(file_path, data_path)
        if not os.path.islink(file_path):
            try:
                os.chmod(file_path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        os.remove(file_path)
        results = results or {}
        meta = {
            'id': qid,
            'filename': os.path.basename(file_path),
            'original_path': file_path,
            'quarantined_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'verdict': results.get('verdict', 'UNKNOWN'),
            'score': results.get('score', 0),
            'sha256': results.get('hashes', {}).get('sha256', '')}
        with open(os.path.join(self.dir, qid + '.json'), 'w') as f:
            json.dump(meta, f, indent=2)
        logger.info(f'Quarantined {file_path} as {qid}')
        return meta

    def list(self) -> List[Dict]:
        items = []
        for name in os.listdir(self.dir):
            if name.endswith('.json'):
                try:
                    with open(os.path.join(self.dir, name)) as f:
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
        with open(meta_path) as f:
            return json.load(f)

    def restore(self, qid: str) -> str:
        meta = self._meta(qid)
        dest = meta['original_path']
        if os.path.exists(dest):
            base, ext = os.path.splitext(dest)
            dest = f'{base}.restored{ext}'
        self._xor_copy(self._safe_path(qid, '.qtn'), dest)
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
