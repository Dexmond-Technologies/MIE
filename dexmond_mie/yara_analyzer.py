import os
import logging
from typing import Dict, List

try:
    import yara
except ImportError:
    yara = None

logger = logging.getLogger('DEXMOND_MIE')

SCAN_TIMEOUT = 60
# yara's match(file) maps the whole file; never hand it a file above this
# size (the engine applies the same limit and records the skip).
MAX_YARA_FILE_BYTES = 256 * 1024 * 1024


class YaraAnalyzer:
    '''Manages YARA rules and scanning.'''

    def __init__(self, rules_dir: str):
        self.rules = None
        self.rules_count = 0
        self.rules_dir = rules_dir
        self._compile_rules()

    def reload_rules(self):
        '''Recompiles rules dynamically when rules are updated or auto-generated.'''
        logger.info('Reloading and recompiling YARA rules...')
        self._compile_rules()

    def _compile_rules(self):
        '''Compiles all .yar files in the specified directory.'''
        if yara is None:
            logger.warning('yara-python is not installed; YARA scanning disabled')
            return
        filepaths = {}
        if not os.path.exists(self.rules_dir):
            logger.warning(f'YARA rules directory not found: {self.rules_dir}')
            return
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(('.yar', '.yara')):
                    full_path = os.path.join(root, file)
                    namespace = os.path.splitext(file)[0]
                    filepaths[namespace] = full_path
        if not filepaths:
            logger.warning(f'No YARA rules found in: {self.rules_dir}')
            return
        try:
            self.rules = yara.compile(filepaths=filepaths)
            self.rules_count = len(filepaths)
            logger.info(f'Compiled {len(filepaths)} YARA rule file(s)')
        except yara.Error as e:
            logger.error(f'Failed to compile YARA rules: {e}')

    def scan(self, file_path: str) -> List[Dict]:
        '''Scans a file with compiled rules.'''
        if not self.rules:
            return []
        try:
            size = os.path.getsize(file_path)
        except OSError as e:
            logger.error(f'YARA scan failed on {file_path}: {e}')
            return []
        if size > MAX_YARA_FILE_BYTES:
            logger.warning(f'YARA skipped on {file_path}: {size} bytes is over the size limit')
            return []
        try:
            matches = self.rules.match(file_path, timeout=SCAN_TIMEOUT)
        except yara.TimeoutError:
            logger.warning(f'YARA scan timed out on {file_path}')
            return []
        except yara.Error as e:
            logger.error(f'YARA scan failed on {file_path}: {e}')
            return []
        return self._to_dicts(matches)

    def scan_data(self, data: bytes, label: str = '<data>') -> List[Dict]:
        '''Scans an in-memory buffer (a bounded window of an oversize file).'''
        if not self.rules or not data:
            return []
        try:
            matches = self.rules.match(data=data, timeout=SCAN_TIMEOUT)
        except yara.TimeoutError:
            logger.warning(f'YARA scan timed out on {label}')
            return []
        except yara.Error as e:
            logger.error(f'YARA scan failed on {label}: {e}')
            return []
        return self._to_dicts(matches)

    @staticmethod
    def _to_dicts(matches) -> List[Dict]:
        results = []
        for match in matches:
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': list(match.tags),
                'meta': dict(match.meta),
                'strings': len(match.strings)})
        return results
