import datetime
import logging
import struct
from typing import Dict, Any, List

try:
    import pefile
except ImportError:
    pefile = None

from .utils import calculate_entropy

logger = logging.getLogger('DEXMOND_MIE')

DIR_RESOURCE = 2   # IMAGE_DIRECTORY_ENTRY_RESOURCE
DIR_SECURITY = 4   # IMAGE_DIRECTORY_ENTRY_SECURITY (file offset, not RVA)
MAX_OVERLAY_ENTROPY_BYTES = 32 * 1024 * 1024
WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
# resource-section bytes OUTSIDE the resource data entries that are enough
# to judge their entropy
MIN_RESOURCE_SLACK_BYTES = 1024
MAX_RESOURCE_ENTRIES = 10000

# Section names commonly left behind by executable packers
PACKER_SECTIONS = {
    'upx0', 'upx1', 'upx2', '.upx', '.aspack', '.adata', '.themida',
    '.vmp0', '.vmp1', '.vmp2', '.petite', '.nsp0', '.nsp1', '.mpress1',
    '.mpress2', '.enigma1', '.enigma2', '.fsg', '.mew', '.y0da'}

# APIs that are suspicious ON THEIR OWN. Routine APIs that every loader, UI
# tool or installer imports are not listed here (fix X3); they only count
# inside the behavioural chains of get_api_chains() / get_minor_api_chains().
SUSPICIOUS_IMPORTS = {
    'VirtualAllocEx', 'WriteProcessMemory',
    'ReadProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx',
    'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookExA', 'SetWindowsHookExW',
    'LdrLoadDll',
    'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'AdjustTokenPrivileges', 'CryptEncrypt', 'CryptDecrypt',
    'InternetOpenA', 'InternetOpenUrlA', 'URLDownloadToFileA', 'URLDownloadToFileW',
    'WinExec'}

# Removed from the single-import list in fix X3. Each one is still used by
# at least one chain (tests/test_x3_imports.py checks this):
#   LoadLibrary*, GetProcAddress, VirtualAlloc, VirtualProtect -> dynamic API
#     resolution chain (VirtualAlloc also in the injection chain)
#   RegSetValueEx*, ShellExecute*                             -> persistence
#     chain (ShellExecute* also in download-and-execute)
#   OpenProcessToken                                          -> privilege chain
#   IsDebuggerPresent                                         -> anti-debug chain
CHAIN_ONLY_IMPORTS = {
    'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'VirtualProtect', 'VirtualAlloc',
    'IsDebuggerPresent', 'OpenProcessToken', 'RegSetValueExA', 'RegSetValueExW',
    'ShellExecuteA', 'ShellExecuteW'}

_LOADLIB = ('LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW', 'LdrLoadDll')
_EXEC = ('ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
         'CreateProcessA', 'CreateProcessW', 'WinExec')
# OutputDebugString is NOT counted: nearly every program imports it
_ANTIDEBUG_EXTRA = ('CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
                    'ZwQueryInformationProcess', 'NtSetInformationThread')
# A loader stub (packer, shellcode loader) imports almost nothing else
TINY_IMPORT_TABLE = 5

class PEAnalyzer:
    '''Analyzes Portable Executable (PE) files.'''

    @classmethod
    def from_pe(cls, pe, file_path: str = ''):
        '''Wraps an already-parsed PE object (used by tests).'''
        obj = cls.__new__(cls)
        obj.file_path = file_path
        obj.pe = pe
        obj.available = True
        obj.parse_error = None
        return obj

    @classmethod
    def from_data(cls, data: bytes, file_path: str = ''):
        '''Parses only the headers and the import table from a bounded buffer
        (the head window of an oversize file). Never maps the file.'''
        obj = cls.__new__(cls)
        obj.file_path = file_path
        obj.pe = None
        obj.available = pefile is not None
        obj.parse_error = None
        if pefile is None:
            return obj
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            obj.pe = pe
        except Exception as e:
            logger.debug(f'Bounded PE parse failed for {file_path}: {e}')
        return obj

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.pe = None
        # available: pefile is installed; parse_error: why parsing failed
        self.available = pefile is not None
        self.parse_error = None
        if pefile is None:
            logger.warning('pefile is not installed; PE analysis disabled')
            return
        try:
            self.pe = pefile.PE(file_path, fast_load=False)
        except pefile.PEFormatError as e:
            self.parse_error = str(e) or 'PEFormatError'
            logger.debug(f'Not a valid PE file: {file_path}')
        except Exception as e:
            self.parse_error = str(e) or type(e).__name__
            logger.error(f'Failed to parse PE {file_path}: {e}')

    def is_valid(self) -> bool:
        return self.pe is not None

    def analyze(self) -> Dict[str, Any]:
        '''Performs static analysis on the PE file.'''
        if not self.pe:
            return {}
        results = {
            'is_pe': True,
            'machine_type': hex(self.pe.FILE_HEADER.Machine),
            'timestamp': str(datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)),
            'compile_time': self.pe.FILE_HEADER.TimeDateStamp,
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'imphash': self.get_imphash(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources(),
            'api_chains': self.get_api_chains(),
            'minor_api_chains': self.get_minor_api_chains(),
            'overlay': self.get_overlay_info(),
            'overlay_entropy': self.get_overlay_entropy(),
            'certificate': self.parse_certificate_table(),
            'tls_callbacks': self.has_tls_callbacks(),
            'warnings': self._check_anomalies()}
        return results

    def get_imphash(self) -> str:
        '''Returns PE import hash if available.'''
        if self.pe and hasattr(self.pe, 'get_imphash'):
            try:
                return self.pe.get_imphash()
            except Exception:
                pass
        return ''

    def get_suspicious_imports(self) -> List[str]:
        '''Returns imported API names commonly abused by malware.'''
        found = []
        for funcs in self._get_imports().values():
            for func in funcs:
                if func in SUSPICIOUS_IMPORTS:
                    found.append(func)
        return sorted(set(found))

    def get_api_chains(self) -> List[str]:
        '''Identifies combinations of API calls matching known attack behaviors.'''
        all_funcs = set()
        for funcs in self._get_imports().values():
            all_funcs.update(funcs)
        
        chains = []
        # Process Injection Chain
        if ('VirtualAllocEx' in all_funcs or 'VirtualAlloc' in all_funcs) and \
           ('WriteProcessMemory' in all_funcs or 'NtWriteVirtualMemory' in all_funcs) and \
           ('CreateRemoteThread' in all_funcs or 'NtCreateThreadEx' in all_funcs or 'QueueUserAPC' in all_funcs):
            chains.append('Process Injection Chain (VirtualAllocEx + WriteProcessMemory + Thread Creation)')
            
        # Remote Download & Execute Chain
        if any(f in all_funcs for f in ('URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenA', 'InternetOpenUrlA')) and \
           any(f in all_funcs for f in ('WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW')):
            chains.append('Remote Download & Exec Chain (Internet API + Execution)')

        # Hooking / Keylogging Chain
        if any(f in all_funcs for f in ('SetWindowsHookExA', 'SetWindowsHookExW')) and \
           any(f in all_funcs for f in ('GetAsyncKeyState', 'GetForegroundWindow')):
            chains.append('System Hooking / Keylogging Chain (SetWindowsHookEx + Input Capture)')

        return chains

    def get_minor_api_chains(self) -> List[str]:
        '''Weaker behavioural chains built from routine APIs (fix X3). Each
        scores as api_chain_minor (moderate weight), so one alone cannot
        reach MALICIOUS without other evidence.'''
        imports = self._get_imports()
        all_funcs = set()
        for funcs in imports.values():
            all_funcs.update(funcs)
        total = sum(len(funcs) for funcs in imports.values())
        has = lambda names: any(f in all_funcs for f in names)  # noqa: E731

        chains = []
        if has(_LOADLIB) and 'GetProcAddress' in all_funcs:
            if has(('VirtualAlloc', 'VirtualProtect')):
                chains.append('Dynamic API Resolution Chain (LoadLibrary + GetProcAddress + '
                              'VirtualAlloc/VirtualProtect)')
            elif total <= TINY_IMPORT_TABLE:
                chains.append(f'Dynamic API Resolution Chain (LoadLibrary + GetProcAddress, '
                              f'only {total} imports)')
        if has(('RegSetValueExA', 'RegSetValueExW')) and has(_EXEC):
            chains.append('Persistence Chain (RegSetValueEx + process execution)')
        if 'OpenProcessToken' in all_funcs and 'AdjustTokenPrivileges' in all_funcs:
            extra = ' + LookupPrivilegeValue' if has(('LookupPrivilegeValueA',
                                                       'LookupPrivilegeValueW')) else ''
            chains.append(f'Privilege Adjustment Chain (OpenProcessToken + AdjustTokenPrivileges{extra})')
        if 'IsDebuggerPresent' in all_funcs and has(_ANTIDEBUG_EXTRA):
            chains.append('Anti-Debug Chain (IsDebuggerPresent + a second anti-debug API)')
        return chains

    def get_overlay_info(self) -> Dict[str, Any]:
        '''Checks for PE overlay data appended past the last section.'''
        if not self.pe:
            return {'present': False, 'size': 0}
        try:
            offset = self.pe.get_overlay_data_offset()
            if offset is not None:
                file_size = len(self.pe.__data__) if hasattr(self.pe, '__data__') else 0
                overlay_size = file_size - offset if file_size > offset else 0
                return {'present': overlay_size > 0, 'size': overlay_size, 'offset': offset}
        except Exception:
            pass
        return {'present': False, 'size': 0}

    def _data_directory(self, index: int):
        try:
            dd = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
            return dd[index] if len(dd) > index else None
        except Exception:
            return None

    def get_resource_section(self):
        '''The section that holds a resource tree pefile really parsed, if
        that section is neither executable nor writable. Neither the section
        NAME nor the data-directory field alone is trusted.'''
        res = getattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        entry = self._data_directory(DIR_RESOURCE)
        if res is None or not getattr(res, 'entries', None) or entry is None or not entry.VirtualAddress:
            return None
        rva = entry.VirtualAddress
        for section in self.pe.sections:
            span = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if section.VirtualAddress <= rva < section.VirtualAddress + span:
                perms = self._get_section_permissions(section)
                if 'X' in perms or 'W' in perms:
                    return None
                return section
        return None

    def get_resource_data_ranges(self) -> List[tuple]:
        '''(rva, size) of every resource DATA entry pefile parsed.'''
        ranges = []
        res = getattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        stack = [(e, 0) for e in getattr(res, 'entries', []) or []]
        while stack and len(ranges) < MAX_RESOURCE_ENTRIES:
            node, depth = stack.pop()
            data = getattr(node, 'data', None)
            if data is not None and getattr(data, 'struct', None) is not None:
                ranges.append((data.struct.OffsetToData, data.struct.Size))
            directory = getattr(node, 'directory', None)
            if directory is not None and depth < 4:
                stack.extend((e, depth + 1) for e in getattr(directory, 'entries', []) or [])
        return ranges

    def resource_slack_entropy(self, section) -> Dict[str, Any]:
        '''Entropy of the resource section's bytes that are NOT inside a
        resource data entry (where a hidden payload would sit).'''
        raw = section.get_data()
        covered = []
        for rva, size in self.get_resource_data_ranges():
            start = max(rva - section.VirtualAddress, 0)
            end = min(rva - section.VirtualAddress + size, len(raw))
            if start < end:
                covered.append((start, end))
        pieces, pos = [], 0
        for start, end in sorted(covered):
            if start > pos:
                pieces.append(bytes(raw[pos:start]))
            pos = max(pos, end)
        pieces.append(bytes(raw[pos:]))
        slack = b''.join(pieces)
        return {'size': len(slack), 'entropy': calculate_entropy(slack) if slack else 0.0}

    def parse_certificate_table(self) -> Dict[str, Any]:
        '''Validates the Authenticode certificate table (WIN_CERTIFICATE
        entries) before any of it is excluded from entropy: dwLength in
        bounds, wRevision 0x0200, wCertificateType 0x0002 (PKCS#7 signed
        data), body starting as a DER SEQUENCE (30 82). This checks the
        structure only; it does NOT verify the signature.'''
        entry = self._data_directory(DIR_SECURITY)
        if entry is None or not entry.Size:
            return {'present': False, 'valid': False, 'parsed_size': 0, 'problems': []}
        data = self.pe.__data__
        flen = len(data)
        off, size = entry.VirtualAddress, entry.Size
        info = {'present': True, 'offset': off, 'declared_size': size, 'valid': False,
                'parsed_size': 0, 'entries': 0, 'problems': []}
        problems = info['problems']
        if off <= 0 or off >= flen:
            problems.append('certificate table offset outside the file')
            return info
        if off + size > flen:
            problems.append('certificate table runs past the end of the file')
        end = min(off + size, flen)
        pos = off
        while pos + 8 <= end:
            length, revision, cert_type = struct.unpack_from('<IHH', data, pos)
            if length < 10 or pos + length > end:
                problems.append(f'bad dwLength {length} at offset {pos}')
                break
            if revision != WIN_CERT_REVISION_2_0:
                problems.append(f'wRevision 0x{revision:04x} is not 0x0200')
                break
            if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
                problems.append(f'wCertificateType 0x{cert_type:04x} is not PKCS#7 (0x0002)')
                break
            if bytes(data[pos + 8:pos + 10]) != b'\x30\x82':
                problems.append('certificate body is not PKCS#7 DER')
                break
            info['entries'] += 1
            pos += (length + 7) & ~7
        if not problems and end - pos >= 8:
            problems.append(f'declared size is {end - pos} bytes larger than the certificates in it')
        if info['entries'] and not problems:
            info['valid'] = True
            info['parsed_size'] = min(pos, end) - off
        elif not info['entries'] and not problems:
            problems.append('no certificate entries')
        return info

    def get_overlay_entropy(self) -> Dict[str, Any]:
        '''Entropy of the data past the last section, measured on its own and
        with the Authenticode certificate table cut out.'''
        info = {'size': 0, 'entropy': 0.0, 'certificate_excluded': 0}
        try:
            offset = self.pe.get_overlay_data_offset()
        except Exception:
            offset = None
        if offset is None:
            return info
        data = self.pe.__data__
        end = len(data)
        pieces = [(offset, end)]
        # only a VALID certificate table is cut out, and only as far as its
        # parsed entries reach (never the declared Size)
        cert = self.parse_certificate_table()
        if cert['valid'] and cert['offset'] >= offset:
            c0 = cert['offset']
            c1 = min(c0 + cert['parsed_size'], end)
            pieces = [(offset, c0), (c1, end)]
            info['certificate_excluded'] = c1 - c0
        blob = b''.join(bytes(data[a:b]) for a, b in pieces if b > a)[:MAX_OVERLAY_ENTROPY_BYTES]
        info['size'] = sum(max(0, b - a) for a, b in pieces)
        info['entropy'] = round(calculate_entropy(blob), 4) if blob else 0.0
        return info

    def has_tls_callbacks(self) -> bool:
        '''Checks if binary uses TLS Callbacks to execute code before main entry point.'''
        # A TLS *directory* alone is normal (mingw, MSVC and Go binaries all
        # have one). Only a non-empty callback array counts: AddressOfCallBacks
        # must be set and its first entry must be a non-zero pointer.
        if not self.pe:
            return False
        tls = getattr(self.pe, 'DIRECTORY_ENTRY_TLS', None)
        if not tls:
            return False
        try:
            array_va = tls.struct.AddressOfCallBacks
            if not array_va:
                return False
            rva = array_va - self.pe.OPTIONAL_HEADER.ImageBase
            if getattr(self.pe, 'PE_TYPE', 0x10b) == 0x20b:
                first = self.pe.get_qword_at_rva(rva)
            else:
                first = self.pe.get_dword_at_rva(rva)
            return bool(first)
        except Exception:
            return False

    def get_packer_sections(self) -> List[str]:
        '''Returns section names matching known packer signatures.'''
        found = []
        for section in self.pe.sections:
            name = self._section_name(section)
            if name.lower() in PACKER_SECTIONS:
                found.append(name)
        return found

    @staticmethod
    def _section_name(section) -> str:
        try:
            return section.Name.decode(errors='ignore').strip('\x00')
        except Exception:
            return str(section.Name)

    def _get_sections(self) -> List[Dict[str, Any]]:
        sections = []
        for section in self.pe.sections:
            sections.append({
                'name': self._section_name(section),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'permissions': self._get_section_permissions(section)})
        return sections

    def _get_section_permissions(self, section) -> str:
        perms = []
        if section.Characteristics & 0x20000000:
            perms.append('X')
        if section.Characteristics & 0x40000000:
            perms.append('R')
        if section.Characteristics & 0x80000000:
            perms.append('W')
        return ''.join(perms)

    def _get_imports(self) -> Dict[str, List[str]]:
        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else 'unknown'
                func_names = []
                for imp in entry.imports:
                    if imp.name:
                        func_names.append(imp.name.decode('utf-8', 'ignore'))
                    elif hasattr(imp, 'ordinal'):
                        func_names.append(f'ordinal_{imp.ordinal}')
                imports[dll_name] = func_names
        return imports

    def _get_exports(self) -> List[str]:
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', 'ignore'))
        return exports

    def _get_resources(self) -> List[Dict[str, Any]]:
        resources = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for res_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = str(res_type.name) if res_type.name else hex(res_type.struct.Id)
                count = len(res_type.directory.entries) if hasattr(res_type, 'directory') else 0
                resources.append({'type': type_name, 'entries': count})
        return resources

    def _check_anomalies(self) -> List[str]:
        warnings = []
        resource_section = self.get_resource_section()
        for section in self.pe.sections:
            # The resource section holds icons, images and compressed
            # resources: high entropy there is normal and is not counted. It
            # is found through the resource data directory, not by name.
            if section is resource_section:
                # exempt only the resource data entries themselves; the rest
                # of the section is still judged
                slack = self.resource_slack_entropy(section)
                if slack['size'] >= MIN_RESOURCE_SLACK_BYTES and slack['entropy'] > 7:
                    warnings.append(f'Section {self._section_name(section)} has very high entropy '
                                    f'outside its resource data entries')
            elif section.get_entropy() > 7:
                warnings.append(f'Section {self._section_name(section)} has very high entropy (packed/encrypted?)')
            perms = self._get_section_permissions(section)
            if 'W' in perms and 'X' in perms:
                warnings.append(f'Section {self._section_name(section)} is both writable and executable')
        if self.pe.FILE_HEADER.TimeDateStamp == 0 or self.pe.FILE_HEADER.TimeDateStamp > 2147483647:
            warnings.append('Suspicious compilation timestamp')
        if self.pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            warnings.append('Entry point is zero')
        if self.has_tls_callbacks():
            warnings.append('PE uses TLS Callbacks to execute code before main entry point')
        overlay = self.get_overlay_info()
        if overlay.get('present') and overlay.get('size', 0) > 1024 * 1024:
            warnings.append(f"Significant PE overlay data detected ({overlay['size'] // (1024*1024)} MB appended past last section)")
        return warnings
