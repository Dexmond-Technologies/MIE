import os
import re
import time
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger('DEXMOND_MIE')

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
        target_rule_file = os.path.join(rules_dir, 'auto_generated.yar')
        try:
            os.makedirs(rules_dir, exist_ok=True)
            with open(target_rule_file, 'a', encoding='utf-8') as f:
                f.write(rule_body)
            logger.info(f'Auto-Evolution Engine synthesized new YARA rule: {rule_name}')
            return rule_name
        except OSError as e:
            logger.error(f'Failed to save auto-generated YARA rule: {e}')
            return None


class AutoEvolutionEngine:
    '''Orchestrates self-learning and automatic adaptation across scans.'''

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.auto_rules_count = 0
        self._count_auto_rules()

    def _count_auto_rules(self):
        auto_file = os.path.join(self.rules_dir, 'auto_generated.yar')
        if os.path.exists(auto_file):
            try:
                with open(auto_file, encoding='utf-8', errors='ignore') as f:
                    self.auto_rules_count = f.read().count('rule auto_gen_')
            except OSError:
                self.auto_rules_count = 0

    def process_scan_result(self, file_path: str, results: Dict[str, Any], yara_engine) -> Optional[str]:
        '''Evaluates scan results and triggers dynamic rule synthesis if needed.'''
        rule_name = RuleSynthesizer.generate_yara_rule(file_path, results, self.rules_dir)
        if rule_name and yara_engine:
            yara_engine.reload_rules()
            self._count_auto_rules()
        return rule_name

    @staticmethod
    def on_isolate(reputation_db, sha256: str, filename: str = ''):
        '''Called when a user isolates a file to train the reputation DB.'''
        if reputation_db and sha256:
            label = f'isolated-threat ({filename})' if filename else 'isolated-threat'
            reputation_db.add_malicious(sha256, label)
            logger.info(f'Auto-Evolution: Learned malicious hash {sha256[:12]}...')

    @staticmethod
    def on_restore(reputation_db, sha256: str, filename: str = ''):
        '''Called when a user restores a file to whitelist it in reputation DB.'''
        if reputation_db and sha256:
            label = f'user-restored ({filename})' if filename else 'user-restored'
            reputation_db.add_trusted(sha256, label)
            logger.info(f'Auto-Evolution: Learned trusted hash {sha256[:12]}...')
