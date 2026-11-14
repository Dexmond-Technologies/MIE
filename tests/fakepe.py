'''A minimal stand-in for a pefile.PE object, so PE heuristics can be tested
without pefile and without real binaries. Tests using it are
PASS UNDER MOCK: they check MIE's logic, not pefile's parsing.'''
from types import SimpleNamespace as NS

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class FakeSection:
    def __init__(self, name, entropy=5.0, perms='R', raw_size=0x1000, va=0x1000,
                 raw_ptr=0x400):
        self.Name = name.encode().ljust(8, b'\0')
        self._entropy = entropy
        self.Characteristics = 0
        if 'X' in perms:
            self.Characteristics |= IMAGE_SCN_MEM_EXECUTE
        if 'R' in perms:
            self.Characteristics |= IMAGE_SCN_MEM_READ
        if 'W' in perms:
            self.Characteristics |= IMAGE_SCN_MEM_WRITE
        self.Misc_VirtualSize = raw_size
        self.VirtualAddress = va
        self.SizeOfRawData = raw_size
        self.PointerToRawData = raw_ptr

    def get_entropy(self):
        return self._entropy


class FakePE:
    def __init__(self, imports=None, sections=None, timestamp=0x60000000,
                 entry=0x1000, tls_callbacks=None, overlay_size=0, image_base=0x400000,
                 is_64=False):
        self.FILE_HEADER = NS(Machine=0x8664 if is_64 else 0x14c, TimeDateStamp=timestamp)
        self.OPTIONAL_HEADER = NS(AddressOfEntryPoint=entry, ImageBase=image_base,
                                  DATA_DIRECTORY=[])
        self.PE_TYPE = 0x20b if is_64 else 0x10b
        self.sections = sections if sections is not None else [FakeSection('.text', perms='RX')]
        if imports:
            self.DIRECTORY_ENTRY_IMPORT = [
                NS(dll=dll.encode(), imports=[NS(name=f.encode(), ordinal=None) for f in funcs])
                for dll, funcs in imports.items()]
        # tls_callbacks: None = no TLS directory; [] = TLS directory with an
        # empty callback array; [va, ...] = callback addresses
        self._tls = tls_callbacks
        if tls_callbacks is not None:
            arr_va = image_base + 0x5000 if tls_callbacks else 0
            self.DIRECTORY_ENTRY_TLS = NS(struct=NS(AddressOfCallBacks=arr_va))
        self._overlay_size = overlay_size
        self.__data__ = b'\0' * (0x2000 + overlay_size)

    # pefile-like helpers used by PEAnalyzer
    def get_imphash(self):
        return 'fakeimphash'

    def get_overlay_data_offset(self):
        return 0x2000 if self._overlay_size else None

    def get_dword_at_rva(self, rva):
        return self._callback_at(rva, 4)

    def get_qword_at_rva(self, rva):
        return self._callback_at(rva, 8)

    def _callback_at(self, rva, width):
        base = self.OPTIONAL_HEADER.ImageBase + 0x5000 - self.OPTIONAL_HEADER.ImageBase
        idx = (rva - base) // width
        cbs = self._tls or []
        return cbs[idx] if 0 <= idx < len(cbs) else 0


def analyzer(**kwargs):
    from dexmond_mie.pe_analyzer import PEAnalyzer
    return PEAnalyzer.from_pe(FakePE(**kwargs))
