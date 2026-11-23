// Reader for Windows executables (PE), written to give what pefile 2024.8.26 gives for the
// fields the Python reference uses (dexmond_mie/pe_analyzer.py). Reviewer's conditions M-4b
// (board B-3608): worker process only; every read goes through one bounds-checked view;
// values from the file are widened to 64 bits and range-checked before use; caps on
// sections, imports, resource entries and depth; a file that cannot be read as PE gives
// parsed == false with a reason, never a guess.
//
// The reader only reports what is in the file. Judging it (packer names, W+X, API chains,
// entropy) belongs to the analysis layer. The rules copied from pefile, with line numbers,
// are in PE_READER_SPEC.md; the known differences are listed there too.
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace mie::pe {

// Caps. The first six are pefile's own; the last two are the reference's (pe_analyzer.py).
inline constexpr std::uint32_t kMaxSections = 0x800;
inline constexpr std::uint32_t kMaxImportSymbols = 0x2000;
inline constexpr std::uint32_t kMaxImportNameLength = 0x200;
inline constexpr std::uint32_t kMaxDllLength = 0x200;
inline constexpr std::uint32_t kMaxResourceEntries = 0x8000;
inline constexpr std::uint32_t kMaxResourceDepth = 32;
inline constexpr std::uint32_t kMaxResourceRanges = 10000;
inline constexpr std::uint32_t kMaxResourceWalkDepth = 4;

// A half-open range of file offsets, always inside the buffer that was parsed.
struct Range {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

struct Section {
    std::array<std::uint8_t, 8> raw_name{};
    std::string name;  // as pe_analyzer._section_name: UTF-8 decoded, bad bytes dropped, NULs stripped
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_pointer = 0;
    std::uint32_t characteristics = 0;
    Range data;        // the bytes pefile's section.get_data() returns (entropy is taken over these)
};

struct ImportSymbol {
    std::string name;             // an import by ordinal has no name, except from oleaut32.dll,
                                  // ws2_32.dll and wsock32.dll: pefile names those from its own
                                  // tables ("ord<N>" when the ordinal is not in the table)
    bool by_ordinal = false;
    std::uint32_t ordinal = 0;
    bool has_name_offset = false;
    std::uint64_t name_offset = 0;  // file offset of the name string (pefile's name_offset)
};

struct ImportLibrary {
    std::string dll;              // "*invalid*" when the name is not a valid file name (as pefile)
    std::vector<ImportSymbol> symbols;
};

struct DataDirectory {
    std::uint32_t virtual_address = 0;  // for index 4 (security) this is a file offset
    std::uint32_t size = 0;
};

struct Tls {
    bool present = false;                    // pefile has DIRECTORY_ENTRY_TLS
    std::uint64_t address_of_callbacks = 0;  // a virtual address, as stored
    bool first_readable = false;             // the first callback slot could be read
    std::uint64_t first_callback = 0;        // its value (a virtual address)
    bool has_callbacks = false;              // pe_analyzer.has_tls_callbacks()
};

struct ResourceData {
    std::uint32_t rva = 0;   // IMAGE_RESOURCE_DATA_ENTRY.OffsetToData
    std::uint32_t size = 0;
};

struct Certificates {            // pe_analyzer.parse_certificate_table()
    bool present = false;
    bool valid = false;
    std::uint64_t offset = 0;
    std::uint64_t declared_size = 0;
    std::uint64_t parsed_size = 0;
    std::uint32_t entries = 0;
    std::vector<Range> spans;
    std::vector<std::string> problems;
};

struct Image {
    bool parsed = false;
    std::string error;           // why parsed is false

    std::uint16_t machine = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t magic = 0;     // 0x10b, 0x20b, or something else (then read as PE32, as pefile)
    bool pe32_plus = false;
    std::uint32_t entry_point = 0;
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;

    std::vector<DataDirectory> directories;  // at most 16, as many as pefile reads
    std::vector<Section> sections;           // in pefile's order: sorted by virtual address

    bool has_imports = false;                // pefile has DIRECTORY_ENTRY_IMPORT
    std::vector<ImportLibrary> imports;
    bool has_delay_imports = false;          // pefile has DIRECTORY_ENTRY_DELAY_IMPORT
    std::vector<ImportLibrary> delay_imports;

    Tls tls;

    bool has_resources = false;              // pefile has DIRECTORY_ENTRY_RESOURCE
    bool resource_root_has_entries = false;
    std::vector<ResourceData> resource_data; // pe_analyzer.get_resource_data_ranges(), same order and caps

    Certificates certificates;
};

// Parses `data`. Never throws, never reads outside `data`.
Image parse(std::span<const std::uint8_t> data);

// The reference's view of the import table (pe_analyzer._get_imports at ff313e2): one entry
// per DLL name in order of first appearance; a DLL listed again REPLACES its earlier list;
// an import by ordinal that pefile did not name is called "ordinal_<n>" (one that pefile named
// from its tables keeps that name). Delay imports are not included (the reference at ff313e2
// does not read them).
std::vector<std::pair<std::string, std::vector<std::string>>> reference_imports(const Image& image);

}  // namespace mie::pe
