#include "mie/pe_analysis.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <string_view>

#include "mie/entropy.hpp"

namespace mie::pe {

namespace {

using std::string_view;

// ---- the reference's lists, copied exactly (line numbers: dexmond_mie/pe_analyzer.py at ff313e2) ----

// PACKER_SECTIONS, pe_analyzer.py:26-29
constexpr std::array<string_view, 20> kPackerSections{
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".themida",
    ".vmp0", ".vmp1", ".vmp2", ".petite", ".nsp0", ".nsp1", ".mpress1",
    ".mpress2", ".enigma1", ".enigma2", ".fsg", ".mew", ".y0da"};

// SUSPICIOUS_IMPORTS, pe_analyzer.py:34-42
constexpr std::array<string_view, 20> kSuspiciousImports{
    "VirtualAllocEx", "WriteProcessMemory",
    "ReadProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookExA", "SetWindowsHookExW",
    "LdrLoadDll",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "AdjustTokenPrivileges", "CryptEncrypt", "CryptDecrypt",
    "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinExec"};

// CHAIN_ONLY_IMPORTS, pe_analyzer.py:52-55. The reference defines this set and never reads
// it in pe_analyzer.py; it is kept here for the record and used by nothing.
[[maybe_unused]] constexpr std::array<string_view, 11> kChainOnlyImports{
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualProtect", "VirtualAlloc",
    "IsDebuggerPresent", "OpenProcessToken", "RegSetValueExA", "RegSetValueExW",
    "ShellExecuteA", "ShellExecuteW"};

// _LOADLIB, pe_analyzer.py:57
constexpr std::array<string_view, 5> kLoadLib{
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"};

// _EXEC, pe_analyzer.py:58-59
constexpr std::array<string_view, 7> kExec{
    "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "WinExec"};

// _ANTIDEBUG_EXTRA, pe_analyzer.py:61-62
constexpr std::array<string_view, 4> kAntiDebugExtra{
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "ZwQueryInformationProcess", "NtSetInformationThread"};

// CHAIN_APIS, pe_analyzer.py:70-85: the start of a chain's description -> the APIs it is built from.
struct ChainApis {
    string_view prefix;
    std::vector<string_view> apis;
};

const std::vector<ChainApis>& chain_apis() {
    static const std::vector<ChainApis> table = [] {
        std::vector<ChainApis> t;
        t.push_back({"Process Injection Chain",                                   // :71-73
                     {"VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory", "NtWriteVirtualMemory",
                      "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"}});
        t.push_back({"Remote Download & Exec Chain",                              // :74-76
                     {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenUrlA",
                      "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"}});
        t.push_back({"System Hooking / Keylogging Chain",                         // :77-78
                     {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetForegroundWindow"}});
        ChainApis dynamic{"Dynamic API Resolution Chain", {}};                    // :79-80
        dynamic.apis.assign(kLoadLib.begin(), kLoadLib.end());
        dynamic.apis.insert(dynamic.apis.end(), {"GetProcAddress", "VirtualAlloc", "VirtualProtect"});
        t.push_back(std::move(dynamic));
        ChainApis persistence{"Persistence Chain", {"RegSetValueExA", "RegSetValueExW"}};  // :81
        persistence.apis.insert(persistence.apis.end(), kExec.begin(), kExec.end());
        t.push_back(std::move(persistence));
        t.push_back({"Privilege Adjustment Chain",                                // :82-83
                     {"OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
                      "LookupPrivilegeValueW"}});
        ChainApis antidebug{"Anti-Debug Chain", {"IsDebuggerPresent"}};           // :84
        antidebug.apis.insert(antidebug.apis.end(), kAntiDebugExtra.begin(), kAntiDebugExtra.end());
        t.push_back(std::move(antidebug));
        return t;
    }();
    return table;
}

// ---- helpers ----

using NameSet = std::set<std::string, std::less<>>;

bool has(const NameSet& names, string_view name) { return names.find(name) != names.end(); }

template <typename List>
bool has_any(const NameSet& names, const List& candidates) {
    for (const string_view candidate : candidates) {
        if (has(names, candidate)) {
            return true;
        }
    }
    return false;
}

template <typename List>
bool in_list(const List& list, string_view name) {
    return std::find(list.begin(), list.end(), name) != list.end();
}

// _get_section_permissions, pe_analyzer.py:547-555
std::string permissions_of(const Section& section) {
    std::string perms;
    if ((section.characteristics & 0x20000000u) != 0) perms.push_back('X');
    if ((section.characteristics & 0x40000000u) != 0) perms.push_back('R');
    if ((section.characteristics & 0x80000000u) != 0) perms.push_back('W');
    return perms;
}

bool executable(const Section& section) { return (section.characteristics & 0x20000000u) != 0; }
bool writable(const Section& section) { return (section.characteristics & 0x80000000u) != 0; }

// The bytes of a range the reader reported, checked against the buffer. A range that does
// not lie inside the buffer gives no bytes.
std::span<const std::uint8_t> bytes_of(const Range& range, std::span<const std::uint8_t> data) {
    if (range.begin > range.end || range.end > data.size()) {
        return {};
    }
    return data.subspan(static_cast<std::size_t>(range.begin), static_cast<std::size_t>(range.end - range.begin));
}

// The span the reference uses to decide "rva is in this section" (pe_analyzer.py:301, :459).
std::int64_t section_span(const Section& section) {
    return static_cast<std::int64_t>(std::max(section.virtual_size, section.raw_size));
}

std::string ascii_lower(const std::string& text) {
    std::string out = text;
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool starts_with(const std::string& text, string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

// _section_names_clean, pe_analyzer.py:480-492: every raw name is printable ASCII with no NUL
// before its padding, and no name repeats.
bool section_names_clean(const Image& image) {
    std::set<std::string> seen;
    for (const Section& section : image.sections) {
        std::size_t length = section.raw_name.size();
        while (length > 0 && section.raw_name[length - 1] == 0) {
            --length;
        }
        std::string name;
        for (std::size_t i = 0; i < length; ++i) {
            const std::uint8_t byte = section.raw_name[i];
            if (byte < 0x20 || byte > 0x7e) {  // includes an embedded NUL
                return false;
            }
            name.push_back(static_cast<char>(byte));
        }
        if (!seen.insert(name).second) {
            return false;
        }
    }
    return true;
}

// get_resource_section, pe_analyzer.py:291-307.
std::optional<std::size_t> resource_section_of(const Image& image) {
    if (!image.has_resources || !image.resource_root_has_entries || image.directories.size() <= 2 ||
        image.directories[2].virtual_address == 0) {
        return std::nullopt;
    }
    const std::int64_t rva = image.directories[2].virtual_address;
    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        const Section& section = image.sections[i];
        const std::int64_t start = section.virtual_address;
        if (start <= rva && rva < start + section_span(section)) {
            if (executable(section) || writable(section)) {
                return std::nullopt;
            }
            return i;
        }
    }
    return std::nullopt;
}

// resource_slack_entropy, pe_analyzer.py:324-341: the section's bytes that are not inside a
// resource data entry.
ResourceSlack resource_slack_of(const Image& image, const Section& section, std::span<const std::uint8_t> data) {
    const std::span<const std::uint8_t> raw = bytes_of(section.data, data);
    const std::int64_t raw_size = static_cast<std::int64_t>(raw.size());
    std::vector<std::pair<std::int64_t, std::int64_t>> covered;
    for (const ResourceData& entry : image.resource_data) {
        const std::int64_t relative = static_cast<std::int64_t>(entry.rva) - static_cast<std::int64_t>(section.virtual_address);
        const std::int64_t start = std::max<std::int64_t>(relative, 0);
        const std::int64_t end = std::min<std::int64_t>(relative + static_cast<std::int64_t>(entry.size), raw_size);
        if (start < end) {
            covered.emplace_back(start, end);
        }
    }
    std::sort(covered.begin(), covered.end());
    std::vector<std::uint8_t> slack;
    std::int64_t pos = 0;
    for (const auto& [start, end] : covered) {
        if (start > pos) {
            slack.insert(slack.end(), raw.begin() + static_cast<std::ptrdiff_t>(pos),
                         raw.begin() + static_cast<std::ptrdiff_t>(start));
        }
        pos = std::max(pos, end);
    }
    if (pos < raw_size) {
        slack.insert(slack.end(), raw.begin() + static_cast<std::ptrdiff_t>(pos), raw.end());
    }
    ResourceSlack out;
    out.size = slack.size();
    out.entropy = slack.empty() ? 0.0 : shannon_entropy(slack);
    return out;
}

}  // namespace

// section_at_rva, pe_analyzer.py:456-462
std::optional<std::size_t> section_at_rva(const Image& image, std::int64_t rva) {
    for (std::size_t i = 0; i < image.sections.size(); ++i) {
        const Section& section = image.sections[i];
        const std::int64_t start = section.virtual_address;
        if (start <= rva && rva < start + section_span(section)) {
            return i;
        }
    }
    return std::nullopt;
}

ImportAnalysis analyze_imports(const Image& image) {
    ImportAnalysis out;
    if (!image.parsed) {
        return out;
    }
    out.imports = reference_imports(image);  // _get_imports, pe_analyzer.py:557-569

    NameSet all;
    for (const auto& [dll, names] : out.imports) {
        out.total_imports += names.size();
        for (const std::string& name : names) {
            all.insert(name);
        }
    }

    // get_api_chains, pe_analyzer.py:216-239
    if ((has(all, "VirtualAllocEx") || has(all, "VirtualAlloc")) &&
        (has(all, "WriteProcessMemory") || has(all, "NtWriteVirtualMemory")) &&
        (has(all, "CreateRemoteThread") || has(all, "NtCreateThreadEx") || has(all, "QueueUserAPC"))) {
        out.api_chains.emplace_back("Process Injection Chain (VirtualAllocEx + WriteProcessMemory + Thread Creation)");
    }
    static constexpr std::array<string_view, 4> download{"URLDownloadToFileA", "URLDownloadToFileW",
                                                         "InternetOpenA", "InternetOpenUrlA"};
    static constexpr std::array<string_view, 5> execute{"WinExec", "ShellExecuteA", "ShellExecuteW",
                                                        "CreateProcessA", "CreateProcessW"};
    if (has_any(all, download) && has_any(all, execute)) {
        out.api_chains.emplace_back("Remote Download & Exec Chain (Internet API + Execution)");
    }
    static constexpr std::array<string_view, 2> hooks{"SetWindowsHookExA", "SetWindowsHookExW"};
    static constexpr std::array<string_view, 2> capture{"GetAsyncKeyState", "GetForegroundWindow"};
    if (has_any(all, hooks) && has_any(all, capture)) {
        out.api_chains.emplace_back("System Hooking / Keylogging Chain (SetWindowsHookEx + Input Capture)");
    }

    // get_minor_api_chains, pe_analyzer.py:241-268
    static constexpr std::array<string_view, 2> alloc_or_protect{"VirtualAlloc", "VirtualProtect"};
    static constexpr std::array<string_view, 2> reg_set{"RegSetValueExA", "RegSetValueExW"};
    static constexpr std::array<string_view, 2> lookup{"LookupPrivilegeValueA", "LookupPrivilegeValueW"};
    if (has_any(all, kLoadLib) && has(all, "GetProcAddress")) {
        if (has_any(all, alloc_or_protect)) {
            out.minor_api_chains.emplace_back(
                "Dynamic API Resolution Chain (LoadLibrary + GetProcAddress + VirtualAlloc/VirtualProtect)");
        } else if (out.total_imports <= kTinyImportTable) {
            out.minor_api_chains.emplace_back("Dynamic API Resolution Chain (LoadLibrary + GetProcAddress, only " +
                                              std::to_string(out.total_imports) + " imports)");
        }
    }
    if (has_any(all, reg_set) && has_any(all, kExec)) {
        out.minor_api_chains.emplace_back("Persistence Chain (RegSetValueEx + process execution)");
    }
    if (has(all, "OpenProcessToken") && has(all, "AdjustTokenPrivileges")) {
        const std::string extra = has_any(all, lookup) ? " + LookupPrivilegeValue" : "";
        out.minor_api_chains.emplace_back("Privilege Adjustment Chain (OpenProcessToken + AdjustTokenPrivileges" +
                                          extra + ")");
    }
    if (has(all, "IsDebuggerPresent") && has_any(all, kAntiDebugExtra)) {
        out.minor_api_chains.emplace_back("Anti-Debug Chain (IsDebuggerPresent + a second anti-debug API)");
    }

    // get_suspicious_imports, pe_analyzer.py:180-187: sorted(set(...))
    for (const std::string& name : all) {  // a std::set iterates in sorted order
        if (in_list(kSuspiciousImports, name)) {
            out.suspicious_imports.push_back(name);
        }
    }

    // scored_import_names, pe_analyzer.py:189-198: imported names that are in SUSPICIOUS_IMPORTS
    // or belong to a chain that was reported (matched by the start of its description).
    NameSet scored;
    for (const string_view name : kSuspiciousImports) {
        scored.insert(std::string(name));
    }
    std::vector<std::string> reported = out.api_chains;
    reported.insert(reported.end(), out.minor_api_chains.begin(), out.minor_api_chains.end());
    for (const std::string& chain : reported) {
        for (const ChainApis& entry : chain_apis()) {
            if (starts_with(chain, entry.prefix)) {
                for (const string_view api : entry.apis) {
                    scored.insert(std::string(api));
                }
            }
        }
    }
    for (const std::string& name : all) {
        if (has(scored, name)) {
            out.scored_import_names.push_back(name);
        }
    }
    return out;
}

Analysis analyze(const Image& image, std::span<const std::uint8_t> data,
                 const std::vector<std::string>& packer_rules) {
    Analysis out;
    out.valid = image.parsed;
    if (!image.parsed) {
        return out;
    }
    const std::size_t count = image.sections.size();

    for (const Section& section : image.sections) {
        out.section_names.push_back(section.name);
        out.section_permissions.push_back(permissions_of(section));
        const std::span<const std::uint8_t> bytes = bytes_of(section.data, data);
        out.section_entropy.push_back(bytes.empty() ? 0.0 : shannon_entropy(bytes));  // pefile get_entropy
    }

    out.imports = analyze_imports(image);

    // scored_import_name_spans, pe_analyzer.py:200-214: over EVERY import descriptor pefile
    // listed (not the dictionary of _get_imports), the name strings of scored imports.
    {
        const NameSet scored(out.imports.scored_import_names.begin(), out.imports.scored_import_names.end());
        std::set<std::pair<std::uint64_t, std::uint64_t>> spans;
        for (const ImportLibrary& library : image.imports) {
            for (const ImportSymbol& symbol : library.symbols) {
                if (symbol.name.empty() || !symbol.has_name_offset) {
                    continue;
                }
                if (has(scored, symbol.name)) {
                    spans.emplace(symbol.name_offset, symbol.name_offset + symbol.name.size());
                }
            }
        }
        for (const auto& [begin, end] : spans) {
            out.scored_import_name_spans.push_back(Range{begin, end});
        }
    }

    // get_packer_sections, pe_analyzer.py:519-526. Lower-casing is ASCII only here; no
    // non-ASCII character lower-cases to a name of the list within the eight bytes of a
    // section name.
    for (const Section& section : image.sections) {
        if (in_list(kPackerSections, ascii_lower(section.name))) {
            out.packer_sections.push_back(section.name);
        }
    }

    // confirmed_upx_sections, pe_analyzer.py:494-517
    if (std::find(packer_rules.begin(), packer_rules.end(), "Packer_UPX") != packer_rules.end() &&
        section_names_clean(image)) {
        std::optional<std::size_t> i0;
        std::optional<std::size_t> i1;
        for (std::size_t i = 0; i < count; ++i) {  // a later section of the same name wins, as in the dict
            if (image.sections[i].name == "UPX0") i0 = i;
            if (image.sections[i].name == "UPX1") i1 = i;
        }
        if (i0 && i1) {
            const Section& upx0 = image.sections[*i0];
            const Section& upx1 = image.sections[*i1];
            const bool layout = upx0.raw_size == 0 && upx0.virtual_size != 0 && upx1.raw_size != 0 &&
                                executable(upx0) && executable(upx1);
            if (layout && section_at_rva(image, static_cast<std::int64_t>(image.entry_point)) == i1) {
                out.confirmed_upx_sections = {*i0, *i1};
                std::sort(out.confirmed_upx_sections.begin(), out.confirmed_upx_sections.end());
            }
        }
    }

    // has_tls_callbacks and tls_callback_section, pe_analyzer.py:433-478
    out.tls_callbacks = image.tls.has_callbacks;
    if (out.tls_callbacks && image.tls.first_readable && image.tls.first_callback >= image.image_base) {
        // first - ImageBase; a negative difference names no section
        const std::uint64_t rva = image.tls.first_callback - image.image_base;
        if (rva <= 0x7FFFFFFFFFFFFFFFull) {
            out.tls_callback_section = section_at_rva(image, static_cast<std::int64_t>(rva));
        }
    }

    // _check_anomalies, pe_analyzer.py:605-639
    out.resource_section = resource_section_of(image);
    for (std::size_t i = 0; i < count; ++i) {
        const Section& section = image.sections[i];
        if (out.resource_section && *out.resource_section == i) {
            out.resource_slack = resource_slack_of(image, section, data);
            if (out.resource_slack.size >= kMinResourceSlackBytes && out.resource_slack.entropy > kSectionHighEntropy) {
                out.warnings.push_back("Section " + section.name +
                                       " has very high entropy outside its resource data entries");
            }
        } else if (out.section_entropy[i] > kSectionHighEntropy) {
            out.high_entropy_sections.push_back(i);
            out.warnings.push_back("Section " + section.name + " has very high entropy (packed/encrypted?)");
        }
        if (writable(section) && executable(section)) {
            out.wx_sections.push_back(i);
        }
    }
    if (!out.wx_sections.empty()) {
        // ", ".join(names): a separator between every two names, also when a name is empty
        // (a section with an empty name gives ", UPX1", as in the reference).
        std::string names;
        bool first = true;
        for (const std::size_t index : out.wx_sections) {
            if (!first) {
                names += ", ";
            }
            first = false;
            names += image.sections[index].name;
        }
        out.warnings.push_back("Writable and executable section(s): " + names);
    }
    if (image.entry_point == 0) {
        out.warnings.emplace_back("Entry point is zero");
    }
    if (out.tls_callbacks) {
        out.warnings.emplace_back("PE uses TLS Callbacks to execute code before main entry point");
    }
    // The overlay warning of pe_analyzer.py:636-638 can never be produced: see D-14 below.

    // parse_certificate_table, pe_analyzer.py:343-403 (computed by the reader)
    out.certificate_present = image.certificates.present;
    out.certificate_valid = image.certificates.valid;
    out.certificate_problems = image.certificates.problems;

    // D-14 (design, section 7c), PARITY behaviour: get_overlay_info (pe_analyzer.py:270-282) and
    // get_overlay_entropy (:405-431) call pefile's PE.get_overlay_data_offset(), which pefile
    // 2024.8.26 does not have; the AttributeError is swallowed. The reference therefore reports
    // "no overlay" and an overlay entropy of size 0 for EVERY file. Reproduced as is; real
    // overlay detection belongs to the stage 1 profile and is measured on its own.
    out.overlay = OverlayInfo{};
    out.overlay_entropy = OverlayEntropy{};
    return out;
}

}  // namespace mie::pe
