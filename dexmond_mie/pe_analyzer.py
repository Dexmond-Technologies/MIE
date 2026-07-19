# Source Generated with Decompyle++
# File: pe_analyzer.pyc (Python 3.10)

import pefile
import datetime
import logging
from typing import Dict, Any, List
logger = logging.getLogger('DEXMOND_MIE')

class PEAnalyzer:
    '''Analyzes Portable Executable (PE) files.'''
    
    def __init__(self = None, file_path = None):
        self.file_path = file_path
        self.pe = None
    # WARNING: Decompyle incomplete

    
    def is_valid(self):
        return self.pe is not None

    
    def analyze(self = None):
        '''Performs static analysis on the PE file.'''
        if not self.pe:
            return { }
        results = {
            'is_pe': None,
            'machine_type': hex(self.pe.FILE_HEADER.Machine),
            'timestamp': str(datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)),
            'compile_time': self.pe.FILE_HEADER.TimeDateStamp,
            'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'resources': self._get_resources(),
            'warnings': self._check_anomalies() }
        return results

    
    def _get_sections(self = None):
        sections = []
        for section in self.pe.sections:
            
            try:
                name = section.Name.decode().strip('\x00')
            finally:
                pass
            name = str(section.Name)
            sections.append({
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'permissions': self._get_section_permissions(section) })
            continue
            return sections


    
    def _get_section_permissions(self = None, section = None):
        perms = []
        if section.Characteristics & 536870912:
            perms.append('X')
        if section.Characteristics & 1073741824:
            perms.append('R')
        if section.Characteristics & 0x80000000:
            perms.append('W')
        return ''.join(perms)

    
    def _get_imports(self = None):
        imports = { }
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else 'unknown'
                func_names = []
                for imp in entry.imports:
                    if imp.name:
                        func_names.append(imp.name.decode('utf-8', 'ignore'))
                        continue
                    if hasattr(imp, 'ordinal'):
                        func_names.append(f'''ordinal_{imp.ordinal}''')
                imports[dll_name] = func_names
        return imports

    
    def _get_exports(self = None):
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', 'ignore'))
        return exports

    
    def _get_resources(self = None):
        resources = []
        return resources

    
    def _check_anomalies(self = None):
        warnings = []
        for section in self.pe.sections:
            if section.get_entropy() > 7:
                warnings.append(f'''Section {section.Name.decode('ignore', **('errors',)).strip(chr(0))} has very high entropy (packed/encrypted?)''')
        if self.pe.FILE_HEADER.TimeDateStamp == 0 or self.pe.FILE_HEADER.TimeDateStamp > 2147483647:
            warnings.append('Suspicious compilation timestamp')
        return warnings


