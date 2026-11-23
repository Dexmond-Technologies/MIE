// mie-pe-analysis-probe DIR [--packer-rule NAME ...]: a test tool, not a product program.
// For every regular file directly in DIR (sorted by name) it prints one ASCII-only JSON
// line with everything the analysis layer (mie/pe_analysis.hpp) reports, in a shape that
// engine/tests/pe_analysis_parity.py compares with the reference's PEAnalyzer.
//
// The names given with --packer-rule are passed as the matched packer rules to every file.
// Numbers that must compare exactly are printed with 17 significant digits, as text.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/pe.hpp"
#include "mie/pe_analysis.hpp"

namespace {

using nlohmann::json;

std::string exact(double value) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.17g", value);
    return buffer;
}

json index_or_null(const std::optional<std::size_t>& index) {
    return index ? json(*index) : json(nullptr);
}

json import_list(const std::vector<std::pair<std::string, std::vector<std::string>>>& imports) {
    json out = json::array();
    for (const auto& [dll, names] : imports) {
        out.push_back(json::array({dll, names}));
    }
    return out;
}

// The RVAs at which section_at_rva is compared with the reference: the entry point, and
// for each of the first 64 sections its start, the byte before it, its last byte and the
// byte after it (by the reference's span rule). The test builds the same list.
std::vector<std::int64_t> probe_rvas(const mie::pe::Image& image) {
    std::vector<std::int64_t> rvas{static_cast<std::int64_t>(image.entry_point)};
    const std::size_t count = std::min<std::size_t>(image.sections.size(), 64);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& s = image.sections[i];
        const std::int64_t start = s.virtual_address;
        const std::int64_t span = static_cast<std::int64_t>(std::max(s.virtual_size, s.raw_size));
        rvas.push_back(start);
        rvas.push_back(start - 1);
        rvas.push_back(start + span - 1);
        rvas.push_back(start + span);
    }
    return rvas;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> packer_rules;
    std::string directory;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--packer-rule" && i + 1 < argc) {
            packer_rules.emplace_back(argv[++i]);
        } else if (directory.empty() && !arg.empty() && arg[0] != '-') {
            directory = arg;
        } else {
            directory.clear();
            break;
        }
    }
    if (directory.empty()) {
        std::fputs("usage: mie-pe-analysis-probe DIR [--packer-rule NAME ...]\n", stderr);
        return 2;
    }

    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const std::span<const std::uint8_t> data(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());

        const mie::pe::Image image = mie::pe::parse(data);
        json line = {{"file", path.filename().string()}, {"parsed", image.parsed}};
        if (image.parsed) {
            const mie::pe::Analysis a = mie::pe::analyze(image, data, packer_rules);
            const mie::pe::Analysis without_rule = mie::pe::analyze(image, data, {});
            const mie::pe::ImportAnalysis head = mie::pe::analyze_imports(image);

            json entropies = json::array();
            for (const double e : a.section_entropy) {
                entropies.push_back(exact(e));
            }
            json spans = json::array();
            for (const auto& span : a.scored_import_name_spans) {
                spans.push_back(json::array({span.begin, span.end}));
            }
            json at_rva = json::array();
            for (const std::int64_t rva : probe_rvas(image)) {
                at_rva.push_back(json::array({rva, index_or_null(mie::pe::section_at_rva(image, rva))}));
            }

            line["section_names"] = a.section_names;
            line["section_permissions"] = a.section_permissions;
            line["section_entropy"] = entropies;
            line["imports"] = import_list(a.imports.imports);
            line["total_imports"] = a.imports.total_imports;
            line["api_chains"] = a.imports.api_chains;
            line["minor_api_chains"] = a.imports.minor_api_chains;
            line["suspicious_imports"] = a.imports.suspicious_imports;
            line["scored_import_names"] = a.imports.scored_import_names;
            line["scored_import_name_spans"] = spans;
            line["packer_sections"] = a.packer_sections;
            line["confirmed_upx_sections"] = a.confirmed_upx_sections;
            line["confirmed_upx_sections_without_rule"] = without_rule.confirmed_upx_sections;
            line["warnings"] = a.warnings;
            line["high_entropy_sections"] = a.high_entropy_sections;
            line["wx_sections"] = a.wx_sections;
            line["tls_callbacks"] = a.tls_callbacks;
            line["tls_callback_section"] = index_or_null(a.tls_callback_section);
            line["resource_section"] = index_or_null(a.resource_section);
            line["resource_slack"] = a.resource_section
                                         ? json{{"size", a.resource_slack.size}, {"entropy", exact(a.resource_slack.entropy)}}
                                         : json(nullptr);
            line["certificate"] = json{{"present", a.certificate_present},
                                       {"valid", a.certificate_valid},
                                       {"problems", a.certificate_problems}};
            line["overlay"] = json{{"present", a.overlay.present}, {"size", a.overlay.size}};
            line["overlay_entropy"] = json{{"size", a.overlay_entropy.size},
                                           {"entropy", exact(a.overlay_entropy.entropy)},
                                           {"certificate_excluded", a.overlay_entropy.certificate_excluded}};
            line["section_at_rva"] = at_rva;
            // the head-window analysis of an oversize file: the import table alone
            line["head"] = json{{"imports", import_list(head.imports)},
                                {"api_chains", head.api_chains},
                                {"minor_api_chains", head.minor_api_chains},
                                {"suspicious_imports", head.suspicious_imports}};
        }
        // ASCII only: every other character is written as an escape, so a line can never be
        // cut by a line-separator character inside a damaged name.
        std::printf("%s\n", line.dump(-1, ' ', true, json::error_handler_t::replace).c_str());
    }
    return 0;
}
