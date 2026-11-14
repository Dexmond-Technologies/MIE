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

# APIs that are suspicious ON THEIR OWN. Routine APIs that every loader, UI
# tool or installer imports (LoadLibrary*, GetProcAddress, VirtualAlloc,
# VirtualProtect, IsDebuggerPresent, OpenProcessToken, RegSetValueEx*,
# ShellExecute*) are not listed here; they only count as part of a chain in
# get_api_chains().
SUSPICIOUS_IMPORTS = {
    'VirtualAllocEx', 'WriteProcessMemory',
    'ReadProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx',
    'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookExA', 'SetWindowsHookExW',
    'LdrLoadDll',
    'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
    'AdjustTokenPrivileges', 'CryptEncrypt', 'CryptDecrypt',
    'InternetOpenA', 'InternetOpenUrlA', 'URLDownloadToFileA', 'URLDownloadToFileW',
    'WinExec'}

# Removed from the single-import list in fix X3; still used inside chains.
CHAIN_ONLY_IMPORTS = {
    'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'VirtualProtect', 'VirtualAlloc',
    'IsDebuggerPresent', 'OpenProcessToken', 'RegSetValueExA', 'RegSetValueExW',
    'ShellExecuteA', 'ShellExecuteW'}

class PEAnalyzer:
    '''Analyzes Portable Executable (PE) files.'''

    @classmethod
    def from_pe(cls, pe, file_path: str = ''):
        '''Wraps an already-parsed PE object (used by tests).'''
        obj = cls.__new__(cls)
        obj.file_path = file_path
        obj.pe = pe
        return obj

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
            'imphash': self.get_imphash(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources(),
            'api_chains': self.get_api_chains(),
            'overlay': self.get_overlay_info(),
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

    def has_tls_callbacks(self) -> bool:
        '''Checks if binary uses TLS Callbacks to execute code before main entry point.'''
        if not self.pe:
            return False
        return hasattr(self.pe, 'DIRECTORY_ENTRY_TLS') and bool(getattr(self.pe, 'DIRECTORY_ENTRY_TLS', None))

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
            # .rsrc holds icons, images and compressed resources: high entropy
            # there is normal and is not counted
            if self._section_name(section).lower() != '.rsrc' and section.get_entropy() > 7:
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
