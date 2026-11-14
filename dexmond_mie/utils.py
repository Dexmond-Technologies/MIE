import bz2
import tarfile
import hashlib
import lzma
import re
import struct
import zipfile
import zlib
import logging
import math
from collections import Counter
from typing import List, Dict, Tuple

logger = logging.getLogger('DEXMOND_MIE')

CHUNK_SIZE = 1024 * 1024

# Magic numbers of formats that are compressed (or hold compressed streams)
# by design, so high entropy in them is expected and says nothing about
# packing or encryption. (offset, magic, name)
COMPRESSED_MAGICS = (
    (0, b'PK\x03\x04', 'zip'), (0, b'PK\x05\x06', 'zip'), (0, b'PK\x07\x08', 'zip'),
    (0, b'\x1f\x8b', 'gzip'), (0, b'BZh', 'bzip2'), (0, b'\xfd7zXZ\x00', 'xz'),
    (0, b"7z\xbc\xaf\x27\x1c", '7z'), (0, b'Rar!\x1a\x07', 'rar'),
    (0, b'\x28\xb5\x2f\xfd', 'zstd'), (0, b'MSCF', 'cab'), (0, b'\x5d\x00\x00', 'lzma'),
    (0, b'\x89PNG\r\n\x1a\n', 'png'), (0, b'\xff\xd8\xff', 'jpeg'),
    (0, b'GIF87a', 'gif'), (0, b'GIF89a', 'gif'), (0, b'%PDF-', 'pdf'),
    (0, b'OggS', 'ogg'), (0, b'fLaC', 'flac'), (0, b'ID3', 'mp3'),
    (4, b'ftyp', 'mp4'), (0, b'wOFF', 'woff'), (0, b'wOF2', 'woff2'),
    (257, b'ustar', 'tar'))


def detect_compressed_format(data: bytes):
    '''Returns the name of a known compressed/archive format, or None.'''
    if data[:4] == b'RIFF' and data[8:12] in (b'WEBP', b'AVI ', b'WAVE'):
        return 'riff'
    for offset, magic, name in COMPRESSED_MAGICS:
        if data[offset:offset + len(magic)] == magic:
            return name
    return None


_VALIDATE_BYTES = 64 * 1024


def _gzip_ok(data: bytes) -> bool:
    if len(data) < 18 or data[2] != 8 or data[3] & 0xE0:
        return False
    try:
        out = zlib.decompressobj(31).decompress(data[:_VALIDATE_BYTES], 4096)
        return len(out) > 0 or len(data) < 64
    except zlib.error:
        return False


def _png_ok(data: bytes) -> bool:
    # IHDR must be the first chunk, 13 bytes long, with a correct CRC
    if len(data) < 33 or data[12:16] != b'IHDR' or struct.unpack('>I', data[8:12])[0] != 13:
        return False
    return zlib.crc32(data[12:29]) & 0xffffffff == struct.unpack('>I', data[29:33])[0]


def _jpeg_ok(data: bytes) -> bool:
    # walk the first few marker segments: FFxx + big-endian length
    pos, seen = 2, 0
    while pos + 4 <= len(data) and seen < 4:
        if data[pos] != 0xFF or data[pos + 1] in (0x00, 0xFF):
            return False
        marker = data[pos + 1]
        if marker == 0xDA:  # start of scan: header structure was valid
            return seen > 0
        length = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        if length < 2:
            return False
        pos += 2 + length
        seen += 1
    return seen >= 2


def _stream_ok(decompressor_factory, data: bytes) -> bool:
    try:
        out = decompressor_factory().decompress(data[:_VALIDATE_BYTES])
        return len(out) > 0
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        return False


def _pdf_ok(data: bytes) -> bool:
    return (re.match(rb'%PDF-[12]\.\d', data[:8]) is not None
            and re.search(rb'\d+\s+\d+\s+obj', data[:_VALIDATE_BYTES]) is not None)


def validate_compressed_format(fmt: str, data: bytes, path: str = None) -> bool:
    '''True only when the container STRUCTURE checks out, not just its magic
    bytes (which anyone can prepend to random data). Formats without a
    validator here return False, so they are reported at a lower weight
    instead of being exempt.'''
    try:
        if fmt == 'zip':
            return path is not None and zipfile.is_zipfile(path) and _zip_members_ok(path)
        if fmt == 'tar':
            return path is not None and _tar_ok(path)
        if fmt == 'gzip':
            return _gzip_ok(data)
        if fmt == 'bzip2':
            return _stream_ok(bz2.BZ2Decompressor, data)
        if fmt == 'xz':
            return _stream_ok(lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ), data)
        if fmt == 'png':
            return _png_ok(data)
        if fmt == 'jpeg':
            return _jpeg_ok(data)
        if fmt == 'pdf':
            return _pdf_ok(data)
    except Exception:
        return False
    return False


def _tar_ok(path: str) -> bool:
    with tarfile.open(path, 'r:') as tf:
        return tf.next() is not None


def _zip_members_ok(path: str) -> bool:
    '''The central directory parses and lists at least one member.'''
    with zipfile.ZipFile(path) as zf:
        return len(zf.infolist()) > 0


def is_pe_data(data: bytes) -> bool:
    '''True when data starts with an MZ header whose e_lfanew points to a PE
    signature. Decided from the bytes, so it does not depend on pefile.'''
    if len(data) < 0x40 or data[:2] != b'MZ':
        return False
    e_lfanew = int.from_bytes(data[0x3c:0x40], 'little')
    return data[e_lfanew:e_lfanew + 4] == b'PE\x00\x00'


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


def calculate_sliding_window_entropy(data: bytes, window_size: int = 4096, step: int = 2048) -> Dict[str, float]:
    '''Calculates sliding window entropy across data to detect hidden high-entropy pockets.'''
    if not data or len(data) < window_size:
        e = calculate_entropy(data)
        return {'max': round(e, 4), 'min': round(e, 4), 'avg': round(e, 4), 'high_entropy_windows': 1 if e > 7.2 else 0, 'total_windows': 1}
    
    entropies = []
    high_count = 0
    for i in range(0, len(data) - window_size + 1, step):
        window = data[i:i + window_size]
        e = calculate_entropy(window)
        entropies.append(e)
        if e > 7.2:
            high_count += 1
            
    if not entropies:
        e = calculate_entropy(data)
        return {'max': round(e, 4), 'min': round(e, 4), 'avg': round(e, 4), 'high_entropy_windows': 1 if e > 7.2 else 0, 'total_windows': 1}
        
    return {
        'max': round(max(entropies), 4),
        'min': round(min(entropies), 4),
        'avg': round(sum(entropies) / len(entropies), 4),
        'high_entropy_windows': high_count,
        'total_windows': len(entropies)
    }


class StringExtractor:
    '''Extracts strings and identifies suspicious patterns.'''
    PATTERNS = {
        'ipv4': re.compile('\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'),
        'url': re.compile('https?://(?:[-\\w.]|(?:%[\\da-fA-F]{2}))+'),
        'email': re.compile('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'),
        'bitcoin': re.compile('\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b'),
        'base64': re.compile('(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
        'powershell': re.compile('powershell(?:\\.exe)?|pwsh(?:\\.exe)?|-enc|-encodedcommand', re.IGNORECASE),
        'suspicious_api': re.compile('(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|LdrLoadDll|ReflectiveLoader)', re.IGNORECASE),
        'b64_executable': re.compile('TVqQAAMAAAA4A[A-Za-z0-9+/=]+'),
        'obfuscated_script': re.compile('(\\[char\\[\\]\\]|Invoke-Expression|iex\\s*\\(|FromBase64String|Bypass\\s+-noprofile)', re.IGNORECASE)}

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
