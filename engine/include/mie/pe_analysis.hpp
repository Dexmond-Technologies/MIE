// Analysis of a Windows executable on top of the reader (mie/pe.hpp): everything the
// Python reference's PEAnalyzer (dexmond_mie/pe_analyzer.py at ff313e2) derives from the
// parsed file and that Engine.scan_file reads (dexmond_mie/core.py 145-260, and 429-442
// for the head window of an oversize file).
//
// This is the PARITY behaviour: the reference is reproduced with its defects. In
// particular the overlay is never seen (difference D-14 of the design): the reference
// asks pefile for the overlay through a method pefile 2024.8.26 does not have and
// swallows the error, so get_overlay_info() says "not present" and get_overlay_entropy()
// says size 0 for every file. The same is reported here, on purpose.
//
// No file reading happens here beyond the byte ranges the reader reported; every range
// and index is checked against the buffer before use.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mie/pe.hpp"

namespace mie::pe {

// pe_analyzer.py:22 and :64
inline constexpr std::size_t kMinResourceSlackBytes = 1024;
inline constexpr std::size_t kTinyImportTable = 5;
// pe_analyzer.py:618 and :621: a section (or the resource slack) is "very high entropy"
// when its entropy is GREATER than this.
inline constexpr double kSectionHighEntropy = 7.0;

// What the import table alone gives (also the head-window analysis of an oversize file:
// core.py:429-442 calls only _get_imports, get_api_chains, get_minor_api_chains and
// get_suspicious_imports on PEAnalyzer.from_data).
struct ImportAnalysis {
    // pe_analyzer._get_imports(): DLL name -> function names, in order of first appearance
    std::vector<std::pair<std::string, std::vector<std::string>>> imports;
    std::size_t total_imports = 0;                 // sum of the list lengths
    std::vector<std::string> api_chains;           // get_api_chains(), exact strings
    std::vector<std::string> minor_api_chains;     // get_minor_api_chains(), exact strings
    std::vector<std::string> suspicious_imports;   // get_suspicious_imports(): sorted, unique
    std::vector<std::string> scored_import_names;  // scored_import_names(): sorted, unique
};

struct ResourceSlack {         // resource_slack_entropy(section)
    std::uint64_t size = 0;
    double entropy = 0.0;
};

struct OverlayInfo {           // get_overlay_info(): parity, never present
    bool present = false;
    std::uint64_t size = 0;
};

struct OverlayEntropy {        // get_overlay_entropy(): parity, always size 0
    std::uint64_t size = 0;
    double entropy = 0.0;
    std::uint64_t certificate_excluded = 0;
};

struct Analysis {
    bool valid = false;        // PEAnalyzer.is_valid(): the reader parsed the file

    // per section, in the reader's (pefile's) order
    std::vector<std::string> section_names;        // _section_name
    std::vector<std::string> section_permissions;  // _get_section_permissions: "X", "R", "W" in this order
    std::vector<double> section_entropy;           // pefile section.get_entropy()

    ImportAnalysis imports;
    std::vector<Range> scored_import_name_spans;   // scored_import_name_spans(): sorted, unique

    std::vector<std::string> packer_sections;      // get_packer_sections()
    std::vector<std::size_t> confirmed_upx_sections;  // confirmed_upx_sections(packer rules): sorted

    // analyze(): the fields that feed scoring
    std::vector<std::string> warnings;             // _check_anomalies(), exact strings, reference order
    std::vector<std::size_t> high_entropy_sections;
    std::vector<std::size_t> wx_sections;
    bool tls_callbacks = false;                    // has_tls_callbacks()
    std::optional<std::size_t> tls_callback_section;
    std::optional<std::size_t> resource_section;   // get_resource_section()
    ResourceSlack resource_slack;                  // only meaningful when resource_section is set

    bool certificate_present = false;              // parse_certificate_table()
    bool certificate_valid = false;
    std::vector<std::string> certificate_problems;

    OverlayInfo overlay;
    OverlayEntropy overlay_entropy;
};

// The reference's section_at_rva(rva): index of the first section with
// VirtualAddress <= rva < VirtualAddress + max(VirtualSize, SizeOfRawData), or nothing.
// `rva` is signed because the reference computes some RVAs by subtraction.
std::optional<std::size_t> section_at_rva(const Image& image, std::int64_t rva);

// Import-table analysis only. For an image that did not parse it is empty.
ImportAnalysis analyze_imports(const Image& image);

// Full analysis. `data` must be the buffer `image` was parsed from. `packer_rules` are the
// names of the packer-category rules that matched the file (for confirmed_upx_sections).
Analysis analyze(const Image& image, std::span<const std::uint8_t> data,
                 const std::vector<std::string>& packer_rules);

}  // namespace mie::pe
