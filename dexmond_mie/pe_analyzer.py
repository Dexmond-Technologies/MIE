import datetime
import logging
from typing import Dict, Any, List

try:
    import pefile
except ImportError:
    pefile = None

logger = logging.getLogger('DEXMOND_MIE')

# Section names commonly left behind by executable packers
PACKER_SECTIONS = {
    'upx0', 'upx1', 'upx2', '.upx', '.aspack', '.adata', '.themida',
    '.vmp0', '.vmp1', '.vmp2', '.petite', '.nsp0', '.nsp1', '.mpress1',
    '.mpress2', '.enigma1', '.enigma2', '.fsg', '.mew', '.y0da'}

SUSPICIOUS_IMPORTS = {
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'WriteProcessMemory',
    'ReadProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx',
    'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookExA', 'SetWindowsHookExW',
    'LdrLoadDll', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'AdjustTokenPrivileges', 'OpenProcessToken', 'CryptEncrypt', 'CryptDecrypt',
    'InternetOpenA', 'InternetOpenUrlA', 'URLDownloadToFileA', 'URLDownloadToFileW',
    'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'RegSetValueExA', 'RegSetValueExW'}


class PEAnalyzer:
    '''Analyzes Portable Executable (PE) files.'''

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.pe = None
        if pefile is None:
            logger.warning('pefile is not installed; PE analysis disabled')
            return
        try:
            self.pe = pefile.PE(file_path, fast_load=False)
        except pefile.PEFormatError:
            logger.debug(f'Not a valid PE file: {file_path}')
        except Exception as e:
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
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources(),
            'warnings': self._check_anomalies()}
        return results

    def get_suspicious_imports(self) -> List[str]:
        '''Returns imported API names commonly abused by malware.'''
        found = []
        for funcs in self._get_imports().values():
            for func in funcs:
                if func in SUSPICIOUS_IMPORTS:
                    found.append(func)
        return sorted(set(found))

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
        for section in self.pe.sections:
            if section.get_entropy() > 7:
                warnings.append(f'Section {self._section_name(section)} has very high entropy (packed/encrypted?)')
            perms = self._get_section_permissions(section)
            if 'W' in perms and 'X' in perms:
                warnings.append(f'Section {self._section_name(section)} is both writable and executable')
        if self.pe.FILE_HEADER.TimeDateStamp == 0 or self.pe.FILE_HEADER.TimeDateStamp > 2147483647:
            warnings.append('Suspicious compilation timestamp')
        if self.pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
            warnings.append('Entry point is zero')
        return warnings
