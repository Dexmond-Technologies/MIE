import os
import re
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
from .auto_evolution import AutoEvolutionEngine, auto_evolution_enabled_by_env
from . import signature

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
# Entropy findings on a compressed/archive format keep this reduced weight.
# The ONLY full exemption: an archive whose members were all unpacked and
# scanned and whose members cover the whole file (archive coverage).
REDUCED_ENTROPY_WEIGHT = 5
# Trailing zero padding allowed after the last tar member
MAX_TAR_PADDING = 1024 * 1024
# Slack allowed after a zip member that uses a data descriptor
ZIP_DESCRIPTOR_SLACK = 24
# Bytes no member scan sees (zip extra fields + comments, tar pax/GNU
# extended headers): more than this and the archive is not fully covered
MAX_UNCOVERED_ZIP_BYTES = 4096
MAX_UNCOVERED_TAR_HEADER_BYTES = 4096
# Overlay (data past the last PE section, certificate cut out)
OVERLAY_ENTROPY_MIN_BYTES = 4096
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


class Engine:
    '''Orchestrates the malware inspection process.'''

    def __init__(self, rules_dir: str = './rules', reputation_db: str = './data/reputation.json',
                 use_reputation: bool = True, max_scan_bytes: int = None,
                 oversize_window_bytes: int = None, signature_verifier=None,
                 trusted_publishers=None, auto_evolution: bool = None):
        self.rules_dir = rules_dir
        # X12: real Authenticode verification (Windows WinVerifyTrust);
        # elsewhere it reports 'unavailable' and no cap is applied
        self.signature_verifier = signature_verifier or signature.verify_authenticode
        self.trusted_publishers = tuple(trusted_publishers if trusted_publishers is not None
                                        else signature.trusted_publishers())
        self.max_scan_bytes = MAX_SCAN_BYTES if max_scan_bytes is None else max_scan_bytes
        self.oversize_window_bytes = (OVERSIZE_WINDOW_BYTES if oversize_window_bytes is None
                                      else oversize_window_bytes)
        # use_reputation=False is the measuring mode (CLI --no-reputation):
        # the known-hash list is not consulted, so detection by YARA and the
        # heuristics can be measured on its own.
        self.use_reputation = use_reputation
        self.yara_engine = YaraAnalyzer(rules_dir)
        self.reputation = ReputationDB(reputation_db)
        # F1: off by default; proposals only, never loaded until approved
        if auto_evolution is None:
            auto_evolution = auto_evolution_enabled_by_env()
        self.auto_evolution = AutoEvolutionEngine(rules_dir, enabled=auto_evolution)

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
            'details': {'yara_status': self.yara_engine.status}}
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
                # read only what exists: read(n) allocates n bytes up front
                data = f.read(min(results['size'] + 1, MAX_ANALYSIS_BYTES))
                # fstat of the same descriptor: the signature check verifies
                # exactly these bytes and refuses if the file changed (TOCTOU)
                scanned_stat = signature.stat_key(os.fstat(f.fileno()))
        except OSError as e:
            logger.error(f'Failed to read {file_path}: {e}')
            return {'error': str(e), 'path': file_path}

        # --- PE parse (before entropy, so entropy can trust the result) ---
        # The bytes decide whether a file claims to be PE; the parser decides
        # whether it is one. Whole-file entropy is skipped only when pefile
        # really parsed the file (no parser differential / fail-open).
        claims_pe = is_pe_data(data)
        pe_analyzer = PEAnalyzer(file_path) if data[:2] == b'MZ' else None
        pe_parsed = pe_analyzer is not None and pe_analyzer.is_valid()
        if claims_pe and not pe_parsed:
            if pe_analyzer is not None and pe_analyzer.available:
                scorer.add_finding('malformed_pe',
                                   f'File has a PE signature but does not parse as PE '
                                   f'({pe_analyzer.parse_error})')
            else:
                results['details']['pe_analysis'] = 'unavailable (pefile not installed)'

        # --- Entropy (measured here, scored after the archive scan) ---
        entropy = calculate_entropy(data)
        sliding_entropy = calculate_sliding_window_entropy(data)
        results['details']['entropy'] = round(entropy, 4)
        results['details']['sliding_entropy'] = sliding_entropy
        compressed_format = detect_compressed_format(data)
        if compressed_format:
            results['details']['compressed_format'] = compressed_format

        # --- YARA ---
        yara_matches = self.yara_engine.scan(file_path)
        results['yara'] = [m['rule'] for m in yara_matches]
        if yara_matches:
            results['details']['yara_matches'] = yara_matches
        packer_yara = [m['rule'] for m in yara_matches if self._yara_category(m) == 'packer']
        self._add_yara_findings(scorer, [m for m in yara_matches
                                         if self._yara_category(m) != 'packer'])
        if packer_yara and not pe_parsed:
            scorer.add_finding('packer_detected', f"Packer detected: {', '.join(packer_yara)}")

        # --- PE analysis ---
        import_name_spans = set()
        if pe_parsed:
            pe_info = pe_analyzer.analyze()
            try:
                import_name_spans = pe_analyzer.scored_import_name_spans()
            except Exception as e:  # noqa: BLE001 - no spans = nothing suppressed
                logger.debug(f'Import name offsets unavailable for {file_path}: {e}')
            results['details']['pe_info'] = pe_info
            packer_sections = pe_analyzer.get_packer_sections()
            # Signals that packing itself causes are folded into the capped
            # 'packing' family ONLY when the packer is confirmed (YARA rule +
            # the packer's real section layout), and only for the packer's
            # OWN sections. A fake marker folds nothing: every other finding
            # keeps its own weight outside the cap.
            own = pe_analyzer.confirmed_upx_sections(packer_yara)   # section indices
            names = [pe_analyzer._section_name(sec) for sec in pe_analyzer.pe.sections]
            if own:
                results['details']['packer_confirmed'] = [names[i] for i in sorted(own)]
            pack = lambda in_packer: 'packing' if in_packer else None  # noqa: E731
            he_sections = pe_info.get('high_entropy_sections', [])
            for idx in he_sections:
                scorer.add_finding('high_entropy',
                                   f'Section {names[idx]} has very high entropy (packed/encrypted?)',
                                   family=pack(idx in own))
            wx = pe_info.get('wx_sections', [])
            for group, in_packer in (([i for i in wx if i in own], True),
                                     ([i for i in wx if i not in own], False)):
                if group:
                    scorer.add_finding('wx_section',
                                       f"Writable and executable section(s): "
                                       f"{', '.join(names[i] for i in group)}",
                                       family=pack(in_packer))
            any_entropy_warning = any('entropy' in w for w in pe_info.get('warnings', []))
            for warning in pe_info.get('warnings', []):
                if '(packed/encrypted?)' in warning or 'Writable and executable' in warning:
                    continue  # scored per section above
                if 'entropy' in warning:
                    scorer.add_finding('high_entropy', warning)
                elif 'TLS Callbacks' in warning:
                    # TLS callbacks are scored (weight 5) only together with a
                    # packer or any entropy signal; otherwise they are
                    # reported in pe_info.tls_callbacks only
                    if packer_sections or packer_yara or he_sections or any_entropy_warning:
                        scorer.add_finding('tls_callback', warning,
                                           family=pack(pe_info.get('tls_callback_section') in own))
                elif 'overlay' in warning:
                    scorer.add_finding('pe_overlay', warning)
                else:
                    scorer.add_finding('anomaly', warning)
            cert = pe_info.get('certificate', {})
            if cert.get('present') and not cert.get('valid'):
                scorer.add_finding('malformed_certificate_table',
                                   f"Authenticode certificate table is malformed or oversized: "
                                   f"{'; '.join(cert.get('problems', []))}")
            overlay = pe_info.get('overlay_entropy', {})
            if overlay.get('size', 0) >= OVERLAY_ENTROPY_MIN_BYTES and overlay.get('entropy', 0) > 7.2:
                scorer.add_finding('overlay_high_entropy',
                                   f"PE overlay ({overlay['size']} bytes, certificate excluded) has "
                                   f"high entropy ({overlay['entropy']:.2f}/8.00)")
            for chain in pe_info.get('api_chains', []):
                scorer.add_finding('api_chain', f"Behavioral API Chain detected: {chain}")
            for chain in pe_info.get('minor_api_chains', []):
                category = self._minor_chain_category(chain)
                # a confirmed UPX stub resolves its imports at run time
                scorer.add_finding(category, f"Behavioral API Chain detected: {chain}",
                                   family=pack(bool(own) and category == 'dynamic_resolution_chain'))
            suspicious_imports = pe_analyzer.get_suspicious_imports()
            if suspicious_imports:
                scorer.add_finding('suspicious_import',
                                   f"Suspicious API imports: {', '.join(suspicious_imports[:10])}")
            # Packing is one signal: YARA packer rules OR section names, never
            # both (X10)
            packer_evidence = list(packer_sections) + packer_yara
            if packer_evidence:
                scorer.add_finding('packer_detected',
                                   f"Packer detected: {', '.join(packer_evidence)}")

        # --- Authenticode signature (X12) ---
        if pe_parsed:
            if len(data) == results['size'] and scanned_stat[0] == len(data):
                sig = self.signature_verifier(file_path, data=data, scanned_stat=scanned_stat)
            else:
                sig = {'status': 'unavailable', 'publisher': None,
                       'detail': 'file is bigger than the analysed buffer; signature not checked',
                       'revocation': 'not checked (offline)'}
            results['details']['signature'] = sig
            # cap only for a VALID signature from an allowlisted publisher;
            # a valid signature from anyone else stays valid, without a cap
            if (sig.get('status') == 'valid' and sig.get('publisher_allowed') is True
                    and sig.get('publisher') in self.trusted_publishers):
                scorer.cap_heuristics()
                results['details']['signature']['heuristics_capped_at'] = Scorer.SIGNED_CAP

        # --- Strings / IOCs ---
        strings, iocs = StringExtractor.extract_ascii_unicode(data, 5)
        results['details']['string_count'] = len(strings)
        if import_name_spans and 'suspicious_api' in iocs:
            # Fix FA-1. A parsed PE's import hint/name table holds each
            # imported API name as a plain string; that occurrence IS the
            # import. When the import analysis above has scored that import
            # (a SUSPICIOUS_IMPORTS name, or part of a reported chain), the
            # same bytes are not scored a second time here. Suppression is by
            # file offset: only the string that starts and ends exactly at a
            # scored import's name entry is skipped. The same name anywhere
            # else in the file, any name the import analysis does not score
            # (e.g. ReflectiveLoader, or VirtualAlloc outside a chain), and
            # every non-PE file keep this finding.
            outside = _api_names_outside_spans(data, import_name_spans)
            if outside:
                iocs['suspicious_api'] = outside
            else:
                del iocs['suspicious_api']
                results['details']['api_strings_in_scored_imports_only'] = True
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

        # --- Archive inspection (by content, not extension) ---
        archive = None
        is_archive = self._is_archive(file_path)
        if is_archive and _depth >= MAX_ARCHIVE_DEPTH:
            results['details']['archive_not_unpacked'] = 'depth limit'
        if is_archive and _depth < MAX_ARCHIVE_DEPTH:
            archive = self._scan_archive(file_path, _depth, _budget)
            if archive:
                results['details']['archive'] = archive
                worst = archive['worst_score']
                if worst > 0:
                    # The archive's verdict is at least its worst member's
                    # (a floor), NOT the member score added on top of the
                    # container's own findings, and not labelled as YARA
                    # unless the member really had a YARA match.
                    scorer.add_floor_finding(
                        'archive_member',
                        f"Archive member {archive['worst_member']}: "
                        f"{archive['worst_verdict']} (score {worst})",
                        worst)

        # --- Entropy scoring ---
        # Parsed PE files: judged per section and overlay (PE analysis), not
        # over the whole file. Everything else, including a PE that fails to
        # parse, gets the whole-file and sliding-window checks:
        #   - an archive fully covered by scanned members: exempt (members
        #     were scanned on their own);
        #   - any other compressed/archive format (png, jpeg, pdf, gz, ...),
        #     or an archive whose member scan was incomplete: reduced weight;
        #   - everything else: full weight.
        if not pe_parsed:
            self._score_entropy(scorer, results, entropy, sliding_entropy,
                                compressed_format, is_archive, archive)

        if rep_malicious:
            scorer.add_finding('reputation_malicious',
                               f"Known malicious file (reputation: {rep_malicious['label']})")
            scorer.set_floor(MALICIOUS_FLOOR)

        results['findings'] = scorer.findings
        results['score'] = scorer.get_score()
        results['verdict'] = scorer.get_verdict()
        results['scan_time'] = round(time.time() - start_time, 3)

        if _depth == 0 and results['score'] >= 70:
            gen_rule = self.auto_evolution.process_scan_result(file_path, results)
            if gen_rule:
                results['details']['proposed_rule'] = {'name': gen_rule, 'active': False,
                                                       'approve_with': f'main.py rules approve {gen_rule}'}

        logger.info(f"Scan complete: {results['verdict']} (score {results['score']}) in {results['scan_time']}s")
        return results

    @staticmethod
    def _minor_chain_category(chain: str) -> str:
        # a packer stub resolves its imports at run time, so this chain is a
        # packing consequence when a packer is detected (scoring.py)
        if chain.startswith('Dynamic API Resolution'):
            return 'dynamic_resolution_chain'
        return 'api_chain_minor'

    @staticmethod
    def _yara_category(match) -> str:
        return str(match.get('meta', {}).get('category', '')).lower()

    @staticmethod
    def _add_yara_findings(scorer: Scorer, yara_matches, where: str = ''):
        '''YARA weight by severity (X13). A rule with meta category
        "imports" detects API names, the same evidence as the import
        analysis, so it scores in the capped 'imports' family.'''
        for match in yara_matches:
            severity = str(match['meta'].get('severity', '')).lower()
            description = match['meta'].get('description', match['rule'])
            if severity == 'critical':
                scorer.add_finding('critical_yara',
                                   f"Critical YARA match{where}: {match['rule']} ({description})")
            else:
                weight = Scorer.YARA_SEVERITY_WEIGHTS.get(severity, Scorer.WEIGHTS['yara_match'])
                family = 'imports' if Engine._yara_category(match) == 'imports' else None
                scorer.add_finding('yara_match',
                                   f"YARA match{where}: {match['rule']} ({description})",
                                   weight_override=weight, family=family)

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
            packer = [m['rule'] for m in matches if self._yara_category(m) == 'packer']
            if packer and not any(f['category'] == 'packer_detected' for f in scorer.findings):
                scorer.add_finding('packer_detected', f"Packer detected: {', '.join(packer)}")
            self._add_yara_findings(scorer, [m for m in matches if self._yara_category(m) != 'packer'],
                                    f' ({name} window)')
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
                    scorer.add_finding(self._minor_chain_category(chain),
                                       f"Behavioral API Chain detected: {chain}")
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
        # PARTIAL_VERDICT means "nothing found in the windows": only the
        # oversize finding itself. A window finding that scores LOW keeps the
        # normal LOW verdict, so the finding is not hidden behind the
        # partial-scan label (details.partial_scan still records the size
        # limit, so needs_alert() fires and auto-quarantine stays MALICIOUS-only).
        nothing_found = all(f['category'] == 'oversize_partial_scan' for f in scorer.findings)
        results['verdict'] = (PARTIAL_VERDICT if verdict == 'SUSPICIOUS (LOW)' and nothing_found
                              else verdict)
        results['scan_time'] = round(time.time() - start_time, 3)
        logger.warning(f"Partial scan of {file_path}: {size} bytes is over the "
                       f"{self.max_scan_bytes}-byte limit -> {results['verdict']}")
        return results

    @staticmethod
    def _score_entropy(scorer, results, entropy, sliding_entropy, compressed_format,
                       is_archive, archive):
        coverage = (archive or {}).get('coverage', {})
        if is_archive and archive and archive.get('members_scanned', 0) > 0 and coverage.get('complete'):
            if entropy > 7.2 or sliding_entropy['high_entropy_windows']:
                results['details']['entropy_note'] = ('entropy not scored: every member of this '
                                                      'archive was unpacked and scanned')
            return
        weight, note = None, ''
        if is_archive:
            weight = REDUCED_ENTROPY_WEIGHT
            reasons = ', '.join(coverage.get('reasons', [])) or results['details'].get(
                'archive_not_unpacked', 'archive not unpacked')
            note = f' (archive, member scan incomplete: {reasons})'
        elif compressed_format:
            weight = REDUCED_ENTROPY_WEIGHT
            note = f' ({compressed_format} format, contents not unpacked)'
        total = sliding_entropy['total_windows']
        high_share = sliding_entropy['high_entropy_windows'] / total if total else 0
        if entropy > 7.2:
            scorer.add_finding('high_entropy',
                               f'File has very high overall entropy ({entropy:.2f}/8.00) - '
                               f'likely packed or encrypted{note}', weight_override=weight)
        elif high_share > SLIDING_HIGH_SHARE:
            scorer.add_finding('sliding_entropy_spike',
                               f"{sliding_entropy['high_entropy_windows']} of {total} windows have "
                               f"high entropy (peak {sliding_entropy['max']:.2f}/8.00){note}",
                               weight_override=weight)

    @staticmethod
    def _is_archive(file_path: str) -> bool:
        '''Decided by content (zip central directory / tar header, plain or
        gz/bz2/xz compressed), not by file extension.'''
        try:
            return zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path)
        except Exception:
            return False

    def _scan_archive(self, file_path: str, _depth: int = 0, _budget: Dict[str, int] = None) -> Dict[str, Any]:
        '''Extracts archive members to a temp dir and scans each one.
        summary['coverage'] says whether every member was unpacked and
        scanned and the members cover the whole file. Any error (also an
        unexpected one from a crafted archive) is recorded as a coverage
        failure for that member; the rest of the scan carries on.'''
        summary = {'members_scanned': 0, 'threats': [], 'member_yara': [], 'worst_score': 0,
                   'worst_member': None, 'worst_verdict': 'CLEAN',
                   'coverage': {'complete': False, 'reasons': []}}
        reasons = summary['coverage']['reasons']
        if _budget is None:
            _budget = {'members': MAX_ARCHIVE_MEMBERS, 'bytes': MAX_ARCHIVE_TOTAL_BYTES}
        try:
            tmp = tempfile.TemporaryDirectory(prefix='dexmond_arc_')
        except OSError as e:
            reasons.append(f'no temp dir: {e}')
            return summary
        with tmp as tmpdir:
            members, coverage = self._extract_safely(file_path, tmpdir, _budget)
            reasons.extend(coverage['reasons'])
            for member_name, member_path in members:
                try:
                    sub = self.scan_file(member_path, _depth=_depth + 1, _budget=_budget)
                except Exception as e:  # noqa: BLE001 - never lose the outer scan
                    logger.warning(f'Member scan failed for {member_name} in {file_path}: {e}')
                    reasons.append(f'member scan failed: {member_name} ({type(e).__name__})')
                    continue
                if 'error' in sub:
                    reasons.append(f'member not scanned: {member_name}')
                    continue
                sub_details = sub.get('details', {})
                if sub_details.get('archive_not_unpacked'):
                    reasons.append(f'nested archive not unpacked (depth): {member_name}')
                elif sub_details.get('archive') and not sub_details['archive'].get(
                        'coverage', {}).get('complete'):
                    reasons.append(f'nested archive incomplete: {member_name}')
                summary['members_scanned'] += 1
                member_rules = list(sub.get('yara', []))
                for entry in sub_details.get('archive', {}).get('member_yara', []):
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
        summary['coverage']['complete'] = not reasons
        return summary

    @staticmethod
    def _zip_covers_file(file_path: str, zf: zipfile.ZipFile, infos) -> list:
        '''Returns reasons the zip members do NOT cover the file ([] = full
        coverage): local header at offset 0, members back to back up to the
        central directory, end record at the very end of the file, and at
        most MAX_UNCOVERED_ZIP_BYTES of extra fields and comments (bytes no
        member scan sees).'''
        reasons = []
        size = os.path.getsize(file_path)
        uncovered = len(zf.comment or b'')
        with open(file_path, 'rb') as f:
            if f.read(4) != b'PK\x03\x04':
                reasons.append('no local header at offset 0')
            pos, slack = 0, 0
            for info in sorted(infos, key=lambda i: i.header_offset):
                if not (pos <= info.header_offset <= pos + slack):
                    reasons.append(f'gap or overlap before member {info.filename}')
                    break
                f.seek(info.header_offset)
                lh = f.read(30)
                if len(lh) < 30 or lh[:4] != b'PK\x03\x04':
                    reasons.append(f'bad local header for {info.filename}')
                    break
                name_len = int.from_bytes(lh[26:28], 'little')
                extra_len = int.from_bytes(lh[28:30], 'little')
                uncovered += extra_len + len(info.extra or b'') + len(info.comment or b'')
                pos = info.header_offset + 30 + name_len + extra_len + info.compress_size
                slack = ZIP_DESCRIPTOR_SLACK if info.flag_bits & 0x08 else 0
            start_dir = getattr(zf, 'start_dir', None)
            if not reasons and (start_dir is None or not (pos <= start_dir <= pos + slack)):
                reasons.append('data between the last member and the central directory')
            eocd = size - 22 - len(zf.comment or b'')
            f.seek(max(eocd, 0))
            if eocd < 0 or f.read(4) != b'PK\x05\x06':
                reasons.append('data after the end-of-central-directory record')
        if uncovered > MAX_UNCOVERED_ZIP_BYTES:
            reasons.append(f'{uncovered} bytes of extra fields/comments not covered by members')
        return reasons

    @staticmethod
    def _extract_safely(file_path: str, dest_dir: str, budget: Dict[str, int] = None):
        '''Returns ([(name, extracted_path)], coverage) for archive members,
        guarding against path traversal, zip bombs, and excessive member
        counts. The budget (members, bytes) is shared with nested archives and
        is decremented. coverage['reasons'] lists every member that was NOT
        extracted and any file data the members do not account for. Errors,
        expected or not, are recorded per member and never raised.'''
        if budget is None:
            budget = {'members': MAX_ARCHIVE_MEMBERS, 'bytes': MAX_ARCHIVE_TOTAL_BYTES}
        extracted = []
        coverage = {'complete': False, 'reasons': []}
        reasons = coverage['reasons']
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

        try:
            is_zip = zipfile.is_zipfile(file_path)
        except Exception as e:  # noqa: BLE001
            reasons.append(f'zip check failed ({type(e).__name__})')
            is_zip = False
        try:
            if is_zip:
                Engine._extract_zip(file_path, _target, _take, extracted, reasons)
            elif tarfile.is_tarfile(file_path):
                Engine._extract_tar(file_path, _target, _take, extracted, reasons)
            else:
                reasons.append('not a zip or tar archive')
        except Exception as e:  # noqa: BLE001 - a crafted archive must not drop the scan
            logger.warning(f'Archive extraction failed for {file_path}: {e}')
            reasons.append(f'archive could not be read ({type(e).__name__}: {e})')
        return extracted, coverage

    @staticmethod
    def _extract_zip(file_path, _target, _take, extracted, reasons):
        with zipfile.ZipFile(file_path) as zf:
            infos = zf.infolist()
            try:
                reasons.extend(Engine._zip_covers_file(file_path, zf, infos))
            except Exception as e:  # noqa: BLE001
                reasons.append(f'zip coverage check failed ({type(e).__name__})')
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                reasons.append(f'more than {MAX_ARCHIVE_MEMBERS} members')
            for info in infos[:MAX_ARCHIVE_MEMBERS]:
                if info.is_dir():
                    continue
                if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    reasons.append(f'member over size limit: {info.filename}')
                    continue
                out = _target(info.filename)
                if not out:
                    reasons.append(f'unsafe member path: {info.filename}')
                    continue
                if not _take(info.file_size):
                    reasons.append('member/byte budget exhausted')
                    break
                try:
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with zf.open(info) as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((info.filename, out))
                except Exception as e:  # noqa: BLE001
                    reasons.append(f'member extraction failed: {info.filename} ({type(e).__name__})')

    @staticmethod
    def _extract_tar(file_path, _target, _take, extracted, reasons):
        header_overhead = 0
        with tarfile.open(file_path) as tf:
            stopped = False
            while True:
                try:
                    member = tf.next()
                except Exception as e:  # noqa: BLE001
                    reasons.append(f'tar header unreadable ({type(e).__name__})')
                    stopped = True
                    break
                if member is None:
                    break
                # pax / GNU long-name headers before the member's own header
                header_overhead += max(0, member.offset_data - member.offset - 512)
                if member.isdir():
                    continue
                if not member.isfile():
                    reasons.append(f'non-regular member: {member.name}')
                    continue
                if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                    reasons.append(f'member over size limit: {member.name}')
                    continue
                out = _target(member.name)
                if not out:
                    reasons.append(f'unsafe member path: {member.name}')
                    continue
                if not _take(member.size):
                    reasons.append('member/byte budget exhausted')
                    stopped = True
                    break
                try:
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    extracted_file = tf.extractfile(member)
                    if extracted_file is None:
                        reasons.append(f'member not readable: {member.name}')
                        continue
                    with extracted_file as src, open(out, 'wb') as dst:
                        dst.write(src.read(MAX_ARCHIVE_MEMBER_BYTES))
                    extracted.append((member.name, out))
                    # the block padding after the member's data must be zero
                    pad = (-member.size) % 512
                    if pad:
                        tf.fileobj.seek(member.offset_data + member.size)
                        if tf.fileobj.read(pad).count(0) != pad:
                            reasons.append(f'non-zero padding after member {member.name}')
                except Exception as e:  # noqa: BLE001
                    reasons.append(f'member extraction failed: {member.name} ({type(e).__name__})')
            if header_overhead > MAX_UNCOVERED_TAR_HEADER_BYTES:
                reasons.append(f'{header_overhead} bytes of extended (pax/GNU) headers not covered')
            if not stopped:
                # members + end padding must account for the whole
                # (decompressed) stream: only zero bytes may follow
                try:
                    tf.fileobj.seek(tf.offset)
                    rest = tf.fileobj.read(MAX_TAR_PADDING + 1)
                    if len(rest) > MAX_TAR_PADDING or rest.count(0) != len(rest):
                        reasons.append('data after the last tar member')
                except Exception as e:  # noqa: BLE001
                    reasons.append(f'tar end not readable ({type(e).__name__})')


def _api_names_outside_spans(data: bytes, spans) -> list:
    '''suspicious_api matches over the same ASCII and UTF-16 string runs as
    StringExtractor, except ASCII runs whose (start, end) file offsets are
    exactly one of `spans` (the name entries of scored imports). Fix FA-1.'''
    pattern = StringExtractor.PATTERNS['suspicious_api']
    found = set()
    for m in re.finditer(rb'[ -~]{5,}', data):
        if (m.start(), m.end()) not in spans:
            found.update(pattern.findall(m.group().decode('ascii', errors='ignore')))
    for m in re.finditer(rb'(?:[ -~]\x00){5,}', data):
        found.update(pattern.findall(m.group().decode('utf-16le', errors='ignore')))
    return sorted(found)


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
