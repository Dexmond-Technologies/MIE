import os
import re
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger('DEXMOND_MIE')

# F1: auto-generated rules are PROPOSALS. They go to rules/proposed/, which
# the YARA loader never reads; a human approves a rule with
# `main.py rules approve <name>`, which validates it and moves it into the
# live file rules/auto_approved.yar. The feature is OFF by default
# (Engine(auto_evolution=True) or DEXMOND_AUTO_EVOLUTION=1 turns it on).
PROPOSED_DIR = 'proposed'
PROPOSED_FILE = 'auto_generated.yar'
APPROVED_FILE = 'auto_approved.yar'


def proposed_path(rules_dir: str) -> str:
    return os.path.join(rules_dir, PROPOSED_DIR, PROPOSED_FILE)


def auto_evolution_enabled_by_env() -> bool:
    return os.environ.get('DEXMOND_AUTO_EVOLUTION', '').strip() == '1'

COMMON_STRINGS = {
    'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ntdll.dll', 'shell32.dll',
    'ws2_32.dll', 'ole32.dll', 'oleaut32.dll', 'msvcrt.dll', 'gdi32.dll',
    'http', 'https', 'windows', 'system32', 'program files', 'microsoft'
}


class RuleSynthesizer:
    '''Automatically synthesizes YARA rules for unclassified malicious binaries.'''

    @staticmethod
    def extract_distinctive_strings(strings: List[str], max_count: int = 5) -> List[str]:
        '''Filters out generic strings and returns distinctive candidates for YARA rules.'''
        candidates = []
        for s in strings:
            cleaned = s.strip()
            if len(cleaned) < 8 or len(cleaned) > 128:
                continue
            lower = cleaned.lower()
            if any(common in lower for common in COMMON_STRINGS):
                continue
            # Keep strings with alphanumeric content
            if re.search(r'[A-Za-z0-9_]{6,}', cleaned):
                candidates.append(cleaned)
            if len(candidates) >= max_count:
                break
        return candidates

    @staticmethod
    def generate_yara_rule(file_path: str, results: Dict[str, Any], rules_dir: str) -> Optional[str]:
        '''Generates a new YARA rule from extracted signals if score >= 70 and 0 yara matches.'''
        score = results.get('score', 0)
        yara_matches = results.get('details', {}).get('yara_matches', [])
        if score < 70 or len(yara_matches) > 0:
            return None

        filename = results.get('filename', 'sample')
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', filename).strip('_')
        rule_name = f"auto_gen_{safe_name}_{int(time.time())}"

        strings_list = results.get('details', {}).get('iocs', {})
        raw_strings = []
        for v in strings_list.values():
            if isinstance(v, list):
                raw_strings.extend(v)

        candidates = RuleSynthesizer.extract_distinctive_strings(raw_strings)
        if not candidates:
            return None

        string_defs = []
        for i, s in enumerate(candidates):
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            string_defs.append(f'        $s{i} = "{escaped}" ascii wide')

        rule_body = f"""
rule {rule_name} {{
    meta:
        description = "Auto-generated signature for {filename}"
        author = "DEXMOND MIE Auto-Evolution Engine"
        date = "{time.strftime('%Y-%m-%d')}"
        severity = "critical"
        auto_generated = true
    strings:
{chr(10).join(string_defs)}
    condition:
        any of ($s*)
}}
"""
        target_rule_file = proposed_path(rules_dir)
        try:
            os.makedirs(os.path.dirname(target_rule_file), exist_ok=True)
            with open(target_rule_file, 'a', encoding='utf-8') as f:
                f.write(rule_body)
            logger.info(f'Auto-Evolution proposed YARA rule {rule_name} (NOT active until approved: '
                        f'main.py rules approve {rule_name})')
            return rule_name
        except OSError as e:
            logger.error(f'Failed to save auto-generated YARA rule: {e}')
            return None


class AutoEvolutionEngine:
    '''Orchestrates self-learning and automatic adaptation across scans.'''

    def __init__(self, rules_dir: str, enabled: bool = False):
        self.rules_dir = rules_dir
        self.enabled = enabled
        self.auto_rules_count = 0
        self._count_auto_rules()

    def _count_auto_rules(self):
        '''Counts PROPOSED rules (not active).'''
        self.auto_rules_count = len(list_proposed(self.rules_dir))

    def process_scan_result(self, file_path: str, results: Dict[str, Any], yara_engine=None) -> Optional[str]:
        '''Proposes a rule for review. Never reloads or changes the live rules.'''
        if not self.enabled:
            return None
        rule_name = RuleSynthesizer.generate_yara_rule(file_path, results, self.rules_dir)
        if rule_name:
            self._count_auto_rules()
        return rule_name

    @staticmethod
    def on_isolate(reputation_db, sha256: str, filename: str = ''):
        '''Called when a user isolates a file to train the reputation DB.'''
        if reputation_db and sha256:
            label = f'isolated-threat ({filename})' if filename else 'isolated-threat'
            reputation_db.add_malicious(sha256, label)
            logger.info(f'Known-hash list: added {sha256[:12]}... as known-bad (quarantined by the user)')

    @staticmethod
    def on_restore(reputation_db, sha256: str, filename: str = ''):
        '''Called when a user restores a file to whitelist it in reputation DB.'''
        if reputation_db and sha256:
            label = f'user-restored ({filename})' if filename else 'user-restored'
            reputation_db.add_trusted(sha256, label)
            logger.info(f'Known-hash list: added {sha256[:12]}... as trusted (restored by the user)')


def _split_rules(text: str) -> List[str]:
    '''Splits a generated-rules file into rule blocks.'''
    blocks, current = [], []
    for line in text.splitlines(keepends=True):
        if line.startswith('rule ') and current:
            blocks.append(''.join(current))
            current = []
        if line.startswith('rule ') or current:
            current.append(line)
    if current:
        blocks.append(''.join(current))
    return blocks


def _rule_name(block: str) -> str:
    return block.split()[1] if len(block.split()) > 1 else ''


def list_proposed(rules_dir: str) -> List[str]:
    path = proposed_path(rules_dir)
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8', errors='ignore') as f:
        return [_rule_name(b) for b in _split_rules(f.read())]


def approve_rule(rules_dir: str, rule_name: str, compiler=None) -> str:
    '''Human approval: validates the proposed rule on its own, appends it to
    the live rules/auto_approved.yar and removes it from proposed/.
    Raises ValueError if the rule is missing or does not compile.'''
    path = proposed_path(rules_dir)
    if not os.path.exists(path):
        raise ValueError('no proposed rules')
    with open(path, encoding='utf-8') as f:
        blocks = _split_rules(f.read())
    chosen = [b for b in blocks if _rule_name(b) == rule_name]
    if not chosen:
        raise ValueError(f'proposed rule not found: {rule_name}')
    block = chosen[0]
    if compiler is None:
        try:
            import yara
        except ImportError:
            raise ValueError('yara-python is not installed: cannot validate the rule, not approved')
        compiler = lambda source: yara.compile(source=source)  # noqa: E731
    try:
        compiler(block)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f'rule does not compile, not approved: {e}')
    with open(os.path.join(rules_dir, APPROVED_FILE), 'a', encoding='utf-8') as f:
        f.write('\n' + block.strip() + '\n')
    remaining = [b for b in blocks if _rule_name(b) != rule_name]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(''.join(remaining))
    logger.info(f'Approved auto-generated rule {rule_name} into {APPROVED_FILE}')
    return os.path.join(rules_dir, APPROVED_FILE)
