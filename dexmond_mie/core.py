import os
import time
import zipfile
import tarfile
import tempfile
import logging
from typing import Dict, Any

from .utils import calculate_hashes, calculate_entropy, StringExtractor
from .pe_analyzer import PEAnalyzer
from .yara_analyzer import YaraAnalyzer
from .scoring import Scorer
from .reputation import ReputationDB

logger = logging.getLogger('DEXMOND_MIE')

# Cap the amount of data loaded for entropy/string analysis
MAX_ANALYSIS_BYTES = 32 * 1024 * 1024
# Archive scanning limits (guard against zip bombs)
MAX_ARCHIVE_MEMBERS = 200
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
ARCHIVE_EXTENSIONS = ('.zip', '.jar', '.apk', '.tar', '.tar.gz', '.tgz', '.tar.bz2')


class Engine:
    '''Orchestrates the malware inspection process.'''

    def __init__(self, rules_dir: str = './rules', reputation_db: str = './data/reputation.json'):
        self.yara_engine = YaraAnalyzer(rules_dir)
        self.reputation = ReputationDB(reputation_db)

    def scan_file(self, file_path: str, _depth: int = 0) -> Dict[str, Any]:
        '''Scans a single file and returns results.'''
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

        # --- Reputation lookup (instant verdict for known hashes) ---
        rep = self.reputation.lookup(results['hashes'].get('sha256', ''))
        if rep:
            results['details']['reputation'] = rep
            if rep['reputation'] == 'malicious':
                scorer.add_finding('critical_yara',
                                   f"Known malicious file (reputation: {rep['label']})")
                results['findings'] = scorer.findings
                results['score'] = scorer.get_score()
                results['verdict'] = scorer.get_verdict()
                results['scan_time'] = round(time.time() - start_time, 3)
                logger.info(f"Reputation hit: MALICIOUS ({rep['label']})")
                return results
            if rep['reputation'] == 'trusted':
                results['verdict'] = 'CLEAN'
                results['findings'] = []
                results['scan_time'] = round(time.time() - start_time, 3)
                logger.info(f"Reputation hit: TRUSTED ({rep['label']})")
                return results

        try:
            with open(file_path, 'rb') as f:
                data = f.read(MAX_ANALYSIS_BYTES)
        except OSError as e:
            logger.error(f'Failed to read {file_path}: {e}')
            return {'error': str(e), 'path': file_path}

        # --- Entropy ---
        entropy = calculate_entropy(data)
        results['details']['entropy'] = round(entropy, 4)
        if entropy > 7.2:
            scorer.add_finding('high_entropy',
                               f'File has very high entropy ({entropy:.2f}/8.00) - likely packed or encrypted')

        # --- YARA ---
        yara_matches = self.yara_engine.scan(file_path)
        if yara_matches:
            results['details']['yara_matches'] = yara_matches
        for match in yara_matches:
            severity = str(match['meta'].get('severity', '')).lower()
            description = match['meta'].get('description', match['rule'])
            if severity == 'critical':
                scorer.add_finding('critical_yara',
                                   f"Critical YARA match: {match['rule']} ({description})")
            else:
                scorer.add_finding('yara_match',
                                   f"YARA match: {match['rule']} ({description})")

        # --- PE analysis ---
        pe_analyzer = PEAnalyzer(file_path)
        if pe_analyzer.is_valid():
            pe_info = pe_analyzer.analyze()
            results['details']['pe_info'] = pe_info
            for warning in pe_info.get('warnings', []):
                if 'entropy' in warning:
                    scorer.add_finding('high_entropy', warning)
                else:
                    scorer.add_finding('anomaly', warning)
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

        # --- Archive inspection (scan contents of zips/tars) ---
        if _depth == 0 and self._is_archive(file_path):
            archive = self._scan_archive(file_path)
            if archive:
                results['details']['archive'] = archive
                worst = archive['worst_score']
                if worst > 0:
                    scorer.add_finding(
                        'critical_yara' if worst >= 70 else 'yara_match',
                        f"Archive contains a threat: {archive['worst_member']} "
                        f"({archive['worst_verdict']}, score {worst})",
                        weight_override=worst)

        results['findings'] = scorer.findings
        results['score'] = scorer.get_score()
        results['verdict'] = scorer.get_verdict()
        results['scan_time'] = round(time.time() - start_time, 3)
        logger.info(f"Scan complete: {results['verdict']} (score {results['score']}) in {results['scan_time']}s")
        return results

    @staticmethod
    def _is_archive(file_path: str) -> bool:
        lower = file_path.lower()
        if lower.endswith(ARCHIVE_EXTENSIONS):
            return zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path)
        return False

    def _scan_archive(self, file_path: str) -> Dict[str, Any]:
        '''Extracts archive members to a temp dir and scans each one.'''
        summary = {'members_scanned': 0, 'threats': [], 'worst_score': 0,
                   'worst_member': None, 'worst_verdict': 'CLEAN'}
        try:
            with tempfile.TemporaryDirectory(prefix='dexmond_arc_') as tmpdir:
                members = self._extract_safely(file_path, tmpdir)
                for member_name, member_path in members:
                    sub = self.scan_file(member_path, _depth=1)
                    if 'error' in sub:
                        continue
                    summary['members_scanned'] += 1
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
    def _extract_safely(file_path: str, dest_dir: str):
        '''Yields (name, extracted_path) for archive members, guarding against
        path traversal, zip bombs, and excessive member counts.'''
        extracted = []
        total = 0
        dest_real = os.path.realpath(dest_dir)

        def _target(name):
            out = os.path.realpath(os.path.join(dest_dir, name))
            if os.path.commonpath([out, dest_real]) != dest_real:
                return None  # path traversal attempt
            return out

        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
                    if info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    total += info.file_size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        break
                    out = _target(info.filename)
                    if not out:
                        continue
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with zf.open(info) as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((info.filename, out))
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path) as tf:
                count = 0
                for member in tf:
                    if count >= MAX_ARCHIVE_MEMBERS:
                        break
                    if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    total += member.size
                    if total > MAX_ARCHIVE_TOTAL_BYTES:
                        break
                    out = _target(member.name)
                    if not out:
                        continue
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file is None:
                        continue
                    with extracted_file as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((member.name, out))
                    count += 1
        return extracted
