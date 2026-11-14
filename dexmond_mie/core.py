import os
import time
import zipfile
import tarfile
import tempfile
import logging
from typing import Dict, Any

from .utils import (calculate_hashes, calculate_entropy, calculate_sliding_window_entropy,
                    detect_compressed_format, is_pe_data, StringExtractor)
from .pe_analyzer import PEAnalyzer
from .yara_analyzer import YaraAnalyzer
from .scoring import Scorer
from .reputation import ReputationDB
from .auto_evolution import AutoEvolutionEngine

logger = logging.getLogger('DEXMOND_MIE')

# Cap the amount of data loaded for entropy/string analysis
MAX_ANALYSIS_BYTES = 32 * 1024 * 1024
# Files larger than this are not mapped whole: YARA's match(file) and pefile
# both map the file, and a 1 GiB file peaked at 2.1 GiB RSS. Above the limit
# the engine does a bounded partial scan instead (X14): YARA on the first
# and last OVERSIZE_WINDOW_BYTES via match(data=...), strings/IOCs on the
# same windows, and the PE header + import table parsed from the head
# window. Padding a file past the limit therefore does not make it unseen.
MAX_SCAN_BYTES = 256 * 1024 * 1024
OVERSIZE_WINDOW_BYTES = 16 * 1024 * 1024
# Verdict when the partial scan finds nothing: a visible LOW, not CLEAN and
# not a silent skip. Kept out of auto-quarantine (see auto_quarantine_allowed).
PARTIAL_VERDICT = 'SUSPICIOUS (LOW): oversize, partially scanned'
# Non-PE files: the high-entropy-pocket finding needs more than this share of
# 4 KiB windows above 7.2 bits (one icon or embedded blob is not enough)
SLIDING_HIGH_SHARE = 0.25
# Archive scanning limits (guard against zip bombs)
MAX_ARCHIVE_MEMBERS = 200
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
# Nested archives (a zip inside a zip) are opened up to this depth. The member
# and byte limits above are a budget for the WHOLE scan, shared by all
# nesting levels, so nesting cannot multiply the work.
MAX_ARCHIVE_DEPTH = 3
# Score floor applied for a malicious reputation hit (forces MALICIOUS)
MALICIOUS_FLOOR = 70
ARCHIVE_EXTENSIONS = ('.zip', '.jar', '.apk', '.tar', '.tar.gz', '.tgz', '.tar.bz2')


class Engine:
    '''Orchestrates the malware inspection process.'''

    def __init__(self, rules_dir: str = './rules', reputation_db: str = './data/reputation.json',
                 use_reputation: bool = True, max_scan_bytes: int = None,
                 oversize_window_bytes: int = None):
        self.rules_dir = rules_dir
        self.max_scan_bytes = MAX_SCAN_BYTES if max_scan_bytes is None else max_scan_bytes
        self.oversize_window_bytes = (OVERSIZE_WINDOW_BYTES if oversize_window_bytes is None
                                      else oversize_window_bytes)
        # use_reputation=False is the measuring mode (CLI --no-reputation):
        # the known-hash list is not consulted, so detection by YARA and the
        # heuristics can be measured on its own.
        self.use_reputation = use_reputation
        self.yara_engine = YaraAnalyzer(rules_dir)
        self.reputation = ReputationDB(reputation_db)
        self.auto_evolution = AutoEvolutionEngine(rules_dir)

    def scan_file(self, file_path: str, _depth: int = 0, _budget: Dict[str, int] = None) -> Dict[str, Any]:
        '''Scans a single file and returns results.'''
        if _budget is None:
            _budget = {'members': MAX_ARCHIVE_MEMBERS, 'bytes': MAX_ARCHIVE_TOTAL_BYTES}
        start_time = time.time()
        logger.info(f'Scanning file: {file_path}')
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        results = {
            'filename': os.path.basename(file_path),
            'path': file_path,
            'size': os.path.getsize(file_path),
            'hashes': calculate_hashes(file_path),
            'scan_time': 0,
            'verdict': 'UNKNOWN',
            'score': 0,
            'details': {}}
        scorer = Scorer()

        # --- Reputation lookup ---
        # A malicious hit no longer returns early: the full pipeline still
        # runs so YARA and the heuristics are recorded next to it, and the
        # verdict is forced to MALICIOUS at the end (a floor that later caps
        # cannot lower). A trusted hit (user-restored hash) still returns
        # CLEAN at once.
        rep_malicious = None
        rep = self.reputation.lookup(results['hashes'].get('sha256', '')) if self.use_reputation else None
        if rep:
            results['details']['reputation'] = rep
            if rep['reputation'] == 'malicious':
                rep_malicious = rep
                logger.info(f"Reputation hit: MALICIOUS ({rep['label']})")
            elif rep['reputation'] == 'trusted':
                results['verdict'] = 'CLEAN'
                results['findings'] = []
                results['yara'] = []
                results['scan_time'] = round(time.time() - start_time, 3)
                logger.info(f"Reputation hit: TRUSTED ({rep['label']})")
                return results

        # --- Size limit: bounded partial scan, never blind, never CLEAN ---
        if results['size'] > self.max_scan_bytes:
            return self._scan_oversize(file_path, results, scorer, rep_malicious, start_time)

        try:
            with open(file_path, 'rb') as f:
                data = f.read(MAX_ANALYSIS_BYTES)
        except OSError as e:
            logger.error(f'Failed to read {file_path}: {e}')
            return {'error': str(e), 'path': file_path}

        # --- Entropy ---
        # PE files: entropy is judged per section in the PE analysis (with
        # .rsrc ignored; the Authenticode certificate table lies outside the
        # sections), not over the whole file, where resources, icons and
        # signatures raise it. Known compressed formats are skipped for the
        # sliding-window check.
        entropy = calculate_entropy(data)
        sliding_entropy = calculate_sliding_window_entropy(data)
        results['details']['entropy'] = round(entropy, 4)
        results['details']['sliding_entropy'] = sliding_entropy
        is_pe = is_pe_data(data)
        compressed_format = detect_compressed_format(data)
        if compressed_format:
            results['details']['compressed_format'] = compressed_format
        if not is_pe:
            high_share = (sliding_entropy['high_entropy_windows'] / sliding_entropy['total_windows']
                          if sliding_entropy['total_windows'] else 0)
            if entropy > 7.2:
                scorer.add_finding('high_entropy',
                                   f'File has very high overall entropy ({entropy:.2f}/8.00) - likely packed or encrypted')
            elif not compressed_format and high_share > SLIDING_HIGH_SHARE:
                scorer.add_finding('sliding_entropy_spike',
                                   f"{sliding_entropy['high_entropy_windows']} of {sliding_entropy['total_windows']} "
                                   f"windows have high entropy (peak {sliding_entropy['max']:.2f}/8.00)")

        # --- YARA ---
        yara_matches = self.yara_engine.scan(file_path)
        results['yara'] = [m['rule'] for m in yara_matches]
        if yara_matches:
            results['details']['yara_matches'] = yara_matches
        self._add_yara_findings(scorer, yara_matches)

        # --- PE analysis ---
        pe_analyzer = PEAnalyzer(file_path)
        if pe_analyzer.is_valid():
            pe_info = pe_analyzer.analyze()
            results['details']['pe_info'] = pe_info
            for warning in pe_info.get('warnings', []):
                if 'entropy' in warning:
                    scorer.add_finding('high_entropy', warning)
                elif 'TLS Callbacks' in warning:
                    scorer.add_finding('tls_callback', warning)
                elif 'overlay' in warning:
                    scorer.add_finding('pe_overlay', warning)
                else:
                    scorer.add_finding('anomaly', warning)
            for chain in pe_info.get('api_chains', []):
                scorer.add_finding('api_chain', f"Behavioral API Chain detected: {chain}")
            for chain in pe_info.get('minor_api_chains', []):
                scorer.add_finding('api_chain_minor', f"Behavioral API Chain detected: {chain}")
            suspicious_imports = pe_analyzer.get_suspicious_imports()
            if suspicious_imports:
                scorer.add_finding('suspicious_import',
                                   f"Suspicious API imports: {', '.join(suspicious_imports[:10])}")
            packer_sections = pe_analyzer.get_packer_sections()
            if packer_sections:
                scorer.add_finding('packer_detected',
                                   f"Packer section names detected: {', '.join(packer_sections)}")

        # --- Strings / IOCs ---
        strings, iocs = StringExtractor.extract_ascii_unicode(data, 5)
        results['details']['string_count'] = len(strings)
        if iocs:
            results['details']['iocs'] = iocs
        for key in ('powershell', 'suspicious_api'):
            if key in iocs:
                scorer.add_finding('suspicious_string',
                                   f"Suspicious strings ({key}): {', '.join(iocs[key][:5])}")
        if 'b64_executable' in iocs:
            scorer.add_finding('b64_executable',
                               f"Embedded Base64-encoded executable signature detected ({len(iocs['b64_executable'])} occurrence(s))")
        if 'obfuscated_script' in iocs:
            scorer.add_finding('obfuscated_script',
                               f"Obfuscated script pattern detected: {', '.join(iocs['obfuscated_script'][:3])}")

        # --- Archive inspection (scan contents of zips/tars) ---
        if _depth < MAX_ARCHIVE_DEPTH and self._is_archive(file_path):
            archive = self._scan_archive(file_path, _depth, _budget)
            if archive:
                results['details']['archive'] = archive
                worst = archive['worst_score']
                if worst > 0:
                    scorer.add_finding(
                        'critical_yara' if worst >= 70 else 'yara_match',
                        f"Archive contains a threat: {archive['worst_member']} "
                        f"({archive['worst_verdict']}, score {worst})",
                        weight_override=worst)

        if rep_malicious:
            scorer.add_finding('reputation_malicious',
                               f"Known malicious file (reputation: {rep_malicious['label']})")
            scorer.set_floor(MALICIOUS_FLOOR)

        results['findings'] = scorer.findings
        results['score'] = scorer.get_score()
        results['verdict'] = scorer.get_verdict()
        results['scan_time'] = round(time.time() - start_time, 3)

        if _depth == 0 and results['score'] >= 70:
            gen_rule = self.auto_evolution.process_scan_result(file_path, results, self.yara_engine)
            if gen_rule:
                results['details']['auto_generated_rule'] = gen_rule

        logger.info(f"Scan complete: {results['verdict']} (score {results['score']}) in {results['scan_time']}s")
        return results

    @staticmethod
    def _add_yara_findings(scorer: Scorer, yara_matches, where: str = ''):
        for match in yara_matches:
            severity = str(match['meta'].get('severity', '')).lower()
            description = match['meta'].get('description', match['rule'])
            if severity == 'critical':
                scorer.add_finding('critical_yara',
                                   f"Critical YARA match{where}: {match['rule']} ({description})")
            else:
                scorer.add_finding('yara_match',
                                   f"YARA match{where}: {match['rule']} ({description})")

    def _scan_oversize(self, file_path, results, scorer, rep_malicious, start_time):
        '''Bounded partial scan of a file over max_scan_bytes. Memory stays at
        about two windows (default 2 x 16 MiB) whatever the file size.'''
        size = results['size']
        window = min(self.oversize_window_bytes, self.max_scan_bytes)
        try:
            with open(file_path, 'rb') as f:
                head = f.read(window)
                f.seek(max(size - window, len(head)))
                tail = f.read(window)
        except OSError as e:
            logger.error(f'Failed to read {file_path}: {e}')
            return {'error': str(e), 'path': file_path}
        windows = [('head', head)] + ([('tail', tail)] if tail else [])
        results['details']['partial_scan'] = {
            'reason': 'size limit',
            'limit_bytes': self.max_scan_bytes,
            'window_bytes': window,
            'scanned': [name for name, _ in windows] + ['pe_header_imports'],
            'not_scanned': ['middle of file', 'entropy', 'archive members']}

        # YARA on each window (rules see the window, so filesize and offsets
        # are relative to it)
        yara_rules = []
        for name, chunk in windows:
            matches = self.yara_engine.scan_data(chunk, f'{file_path} [{name}]')
            for m in matches:
                m['window'] = name
            yara_rules.extend(m['rule'] for m in matches)
            if matches:
                results['details'].setdefault('yara_matches', []).extend(matches)
            self._add_yara_findings(scorer, matches, f' ({name} window)')
        results['yara'] = sorted(set(yara_rules))

        # PE header and import table from the head window only
        if is_pe_data(head):
            pe_analyzer = PEAnalyzer.from_data(head, file_path)
            if pe_analyzer.is_valid():
                results['details']['pe_info'] = {'is_pe': True, 'partial': True,
                                                 'imports': pe_analyzer._get_imports()}
                for chain in pe_analyzer.get_api_chains():
                    scorer.add_finding('api_chain', f"Behavioral API Chain detected: {chain}")
                for chain in pe_analyzer.get_minor_api_chains():
                    scorer.add_finding('api_chain_minor', f"Behavioral API Chain detected: {chain}")
                suspicious_imports = pe_analyzer.get_suspicious_imports()
                if suspicious_imports:
                    scorer.add_finding('suspicious_import',
                                       f"Suspicious API imports: {', '.join(suspicious_imports[:10])}")

        # Strings / IOCs on the windows
        for name, chunk in windows:
            _, iocs = StringExtractor.extract_ascii_unicode(chunk, 5)
            for key in ('b64_executable', 'obfuscated_script'):
                if key in iocs:
                    scorer.add_finding(key, f"{key} pattern in {name} window: "
                                            f"{', '.join(iocs[key][:3])[:200]}")

        scorer.add_finding('oversize_partial_scan',
                           f'File is {size} bytes, over the {self.max_scan_bytes}-byte limit: '
                           f'only the first and last {window} bytes and the PE header were scanned')
        if rep_malicious:
            scorer.add_finding('reputation_malicious',
                               f"Known malicious file (reputation: {rep_malicious['label']})")
            scorer.set_floor(MALICIOUS_FLOOR)
        results['findings'] = scorer.findings
        results['score'] = scorer.get_score()
        verdict = scorer.get_verdict()
        results['verdict'] = PARTIAL_VERDICT if verdict == 'SUSPICIOUS (LOW)' else verdict
        results['scan_time'] = round(time.time() - start_time, 3)
        logger.warning(f"Partial scan of {file_path}: {size} bytes is over the "
                       f"{self.max_scan_bytes}-byte limit -> {results['verdict']}")
        return results

    @staticmethod
    def _is_archive(file_path: str) -> bool:
        lower = file_path.lower()
        if lower.endswith(ARCHIVE_EXTENSIONS):
            return zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path)
        return False

    def _scan_archive(self, file_path: str, _depth: int = 0, _budget: Dict[str, int] = None) -> Dict[str, Any]:
        '''Extracts archive members to a temp dir and scans each one.'''
        summary = {'members_scanned': 0, 'threats': [], 'member_yara': [], 'worst_score': 0,
                   'worst_member': None, 'worst_verdict': 'CLEAN'}
        try:
            with tempfile.TemporaryDirectory(prefix='dexmond_arc_') as tmpdir:
                if _budget is None:
                    _budget = {'members': MAX_ARCHIVE_MEMBERS, 'bytes': MAX_ARCHIVE_TOTAL_BYTES}
                members = self._extract_safely(file_path, tmpdir, _budget)
                for member_name, member_path in members:
                    sub = self.scan_file(member_path, _depth=_depth + 1, _budget=_budget)
                    if 'error' in sub:
                        continue
                    summary['members_scanned'] += 1
                    member_rules = list(sub.get('yara', []))
                    for entry in sub.get('details', {}).get('archive', {}).get('member_yara', []):
                        member_rules.extend(entry['rules'])
                    if member_rules:
                        summary['member_yara'].append({'member': member_name,
                                                       'rules': sorted(set(member_rules))})
                    score = sub.get('score', 0)
                    if score >= 30:
                        summary['threats'].append({
                            'name': member_name,
                            'verdict': sub.get('verdict'),
                            'score': score})
                    if score > summary['worst_score']:
                        summary['worst_score'] = score
                        summary['worst_member'] = member_name
                        summary['worst_verdict'] = sub.get('verdict', 'UNKNOWN')
        except (OSError, zipfile.BadZipFile, tarfile.TarError) as e:
            logger.warning(f'Archive scan failed for {file_path}: {e}')
            return {}
        return summary

    @staticmethod
    def _extract_safely(file_path: str, dest_dir: str, budget: Dict[str, int] = None):
        '''Returns (name, extracted_path) for archive members, guarding against
        path traversal, zip bombs, and excessive member counts. The budget
        (members, bytes) is shared with nested archives and is decremented.'''
        if budget is None:
            budget = {'members': MAX_ARCHIVE_MEMBERS, 'bytes': MAX_ARCHIVE_TOTAL_BYTES}
        extracted = []
        dest_real = os.path.realpath(dest_dir)

        def _target(name):
            out = os.path.realpath(os.path.join(dest_dir, name))
            if os.path.commonpath([out, dest_real]) != dest_real:
                return None  # path traversal attempt
            return out

        def _take(size):
            '''Reserves one member of `size` bytes from the budget.'''
            if budget['members'] <= 0 or size > budget['bytes']:
                return False
            budget['members'] -= 1
            budget['bytes'] -= size
            return True

        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                    if info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    out = _target(info.filename)
                    if not out:
                        continue
                    if not _take(info.file_size):
                        break
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with zf.open(info) as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((info.filename, out))
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path) as tf:
                for member in tf:
                    if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    out = _target(member.name)
                    if not out:
                        continue
                    if not _take(member.size):
                        break
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file is None:
                        continue
                    with extracted_file as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((member.name, out))
        return extracted


def is_partial_scan(results: Dict[str, Any]) -> bool:
    '''True when the file was too large for a full scan (X14).'''
    return bool(results.get('details', {}).get('partial_scan'))


def needs_alert(results: Dict[str, Any], threshold: int = 30) -> bool:
    '''Real-time alert rule: score at or over the threshold, or a partial
    scan of an oversize file (which must be visible, not silent).'''
    return results.get('score', 0) >= threshold or is_partial_scan(results)


def auto_quarantine_allowed(results: Dict[str, Any]) -> bool:
    '''Auto-quarantine only confirmed MALICIOUS verdicts; an oversize file
    with nothing found in its partial scan is never auto-quarantined.'''
    verdict = results.get('verdict', '')
    if is_partial_scan(results) and verdict == PARTIAL_VERDICT:
        return False
    return verdict.startswith('MALICIOUS')
