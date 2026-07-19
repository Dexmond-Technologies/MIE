# Source Generated with Decompyle++
# File: utils.pyc (Python 3.10)

import hashlib
import re
import logging
import math
from typing import List, Dict, Set, Tuple
logger = logging.getLogger('DEXMOND_MIE')

def calculate_hashes(file_path = None):
    '''Calculates MD5, SHA1, and SHA256 hashes of a file efficiently.'''
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256() }
# WARNING: Decompyle incomplete


def calculate_entropy(data = None):
    '''Calculates Shannon entropy of data block.'''
    if not data:
        return 0
    entropy = None
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
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
        'suspicious_api': re.compile('(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|LdrLoadDll|ReflectiveLoader)', re.IGNORECASE) }
    
    def extract_ascii_unicode(data = None, min_length = None):
        '''Extracts ASCII and Unicode strings, returns found IOCs.'''
        found_strings = []
        found_iocs = (lambda .0: pass# WARNING: Decompyle incomplete
)(StringExtractor.PATTERNS)
        ascii_strings = re.findall(b'[ -~]{%d,}' % min_length, data)
        for s in ascii_strings:
            decoded = s.decode('ascii', 'ignore', **('errors',))
            found_strings.append(decoded)
            StringExtractor._check_patterns(decoded, found_iocs)
        unicode_strings = re.findall(b'(?:[ -~]\x00){%d,}' % min_length, data)
        for s in unicode_strings:
            decoded = s.decode('utf-16le', 'ignore', **('errors',))
            found_strings.append(decoded)
            StringExtractor._check_patterns(decoded, found_iocs)
        return (found_strings, (lambda .0: pass# WARNING: Decompyle incomplete
)(found_iocs.items()))

    extract_ascii_unicode = None(extract_ascii_unicode)
    
    def _check_patterns(text = None, iocs = None):
        for key, pattern in StringExtractor.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                iocs[key].extend(matches)

    _check_patterns = None(_check_patterns)

