import hashlib
import re
import logging
import math
from collections import Counter
from typing import List, Dict, Tuple

logger = logging.getLogger('DEXMOND_MIE')

CHUNK_SIZE = 1024 * 1024


def calculate_hashes(file_path: str) -> Dict[str, str]:
    '''Calculates MD5, SHA1, and SHA256 hashes of a file efficiently.'''
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()}
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                for h in hashes.values():
                    h.update(chunk)
    except OSError as e:
        logger.error(f'Failed to hash {file_path}: {e}')
        return {}
    return {name: h.hexdigest() for name, h in hashes.items()}


def calculate_entropy(data: bytes) -> float:
    '''Calculates Shannon entropy of data block.'''
    if not data:
        return 0
    entropy = 0.0
    length = len(data)
    for count in Counter(data).values():
        p_x = count / length
        entropy += -p_x * math.log(p_x, 2)
    return entropy


class StringExtractor:
    '''Extracts strings and identifies suspicious patterns.'''
    PATTERNS = {
        'ipv4': re.compile('\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'),
        'url': re.compile('https?://(?:[-\\w.]|(?:%[\\da-fA-F]{2}))+'),
        'email': re.compile('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'),
        'bitcoin': re.compile('\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b'),
        'base64': re.compile('(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
        'powershell': re.compile('powershell(?:\\.exe)?|pwsh(?:\\.exe)?|-enc|-encodedcommand', re.IGNORECASE),
        'suspicious_api': re.compile('(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|LdrLoadDll|ReflectiveLoader)', re.IGNORECASE)}

    @staticmethod
    def extract_ascii_unicode(data: bytes, min_length: int = 5) -> Tuple[List[str], Dict[str, List[str]]]:
        '''Extracts ASCII and Unicode strings, returns found IOCs.'''
        found_strings = []
        found_iocs = {key: [] for key in StringExtractor.PATTERNS}
        ascii_strings = re.findall(b'[ -~]{%d,}' % min_length, data)
        for s in ascii_strings:
            decoded = s.decode('ascii', errors='ignore')
            found_strings.append(decoded)
            StringExtractor._check_patterns(decoded, found_iocs)
        unicode_strings = re.findall(b'(?:[ -~]\x00){%d,}' % min_length, data)
        for s in unicode_strings:
            decoded = s.decode('utf-16le', errors='ignore')
            found_strings.append(decoded)
            StringExtractor._check_patterns(decoded, found_iocs)
        return (found_strings,
                {k: sorted(set(v)) for k, v in found_iocs.items() if v})

    @staticmethod
    def _check_patterns(text: str, iocs: Dict[str, List[str]]) -> None:
        for key, pattern in StringExtractor.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                iocs[key].extend(matches)
