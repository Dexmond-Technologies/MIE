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


YARA_ON = 'ON'
YARA_DEGRADED = 'DEGRADED'   # some rule files failed to compile and are skipped
YARA_OFF = 'YARA-OFF'        # no rules loaded at all


class YaraAnalyzer:
    '''Manages YARA rules and scanning.

    F2: each rule file is compiled on its own first. A file that fails is
    skipped with a logged error (it cannot take the other files down); the
    good files are then compiled together. `status` is ON, DEGRADED or
    YARA-OFF and is shown in the CLI, the dashboard and the log.'''

    def __init__(self, rules_dir: str):
        self.rules = None
        self.rules_count = 0
        self.rules_dir = rules_dir
        self.status = YARA_OFF
        self.errors: List[Dict[str, str]] = []
        self._compile_rules()

    def reload_rules(self):
        '''Recompiles rules dynamically when rules are updated.'''
        logger.info('Reloading and recompiling YARA rules...')
        self._compile_rules()

    def _rule_files(self) -> Dict[str, str]:
        filepaths = {}
        for root, dirs, files in os.walk(self.rules_dir):
            # rules/proposed/ holds unreviewed auto-generated rules (F1):
            # never loaded
            dirs[:] = sorted(d for d in dirs if d != 'proposed')
            for file in sorted(files):
                if root == self.rules_dir and file == 'auto_generated.yar':
                    logger.warning('Not loading legacy unreviewed rules/auto_generated.yar; '
                                   'move it to rules/proposed/ and approve rules one by one')
                    continue
                if file.endswith(('.yar', '.yara')):
                    full_path = os.path.join(root, file)
                    rel = os.path.splitext(os.path.relpath(full_path, self.rules_dir))[0]
                    filepaths[rel.replace(os.sep, '_').replace('/', '_')] = full_path
        return filepaths

    def _set_off(self, reason: str):
        self.rules = None
        self.rules_count = 0
        self.status = YARA_OFF
        logger.error(f'YARA-OFF: {reason}')

    def _compile_rules(self):
        '''Compiles all .yar files in the rules directory, one by one.'''
        self.errors = []
        if yara is None:
            self._set_off('yara-python is not installed; YARA scanning disabled')
            return
        if not os.path.exists(self.rules_dir):
            self._set_off(f'YARA rules directory not found: {self.rules_dir}')
            return
        filepaths = self._rule_files()
        if not filepaths:
            self._set_off(f'No YARA rules found in: {self.rules_dir}')
            return
        good = {}
        for namespace, path in filepaths.items():
            try:
                yara.compile(filepath=path)
                good[namespace] = path
            except Exception as e:  # noqa: BLE001 - yara.SyntaxError, OSError, ...
                self.errors.append({'file': path, 'error': str(e)})
                logger.error(f'YARA rule file skipped (does not compile): {path}: {e}')
        if not good:
            self._set_off(f'all {len(filepaths)} YARA rule file(s) failed to compile')
            return
        try:
            self.rules = yara.compile(filepaths=good)
        except Exception as e:  # noqa: BLE001 - e.g. duplicate identifiers across files
            self.errors.append({'file': '(combined)', 'error': str(e)})
            self._set_off(f'combined compile of the valid rule files failed: {e}')
            return
        self.rules_count = len(good)
        self.status = YARA_DEGRADED if self.errors else YARA_ON
        if self.errors:
            logger.error(f'YARA DEGRADED: {len(good)} rule file(s) loaded, '
                         f'{len(self.errors)} skipped')
        else:
            logger.info(f'Compiled {len(good)} YARA rule file(s)')

    def status_info(self) -> Dict:
        return {'status': self.status, 'rule_files': self.rules_count,
                'errors': list(self.errors)}

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
