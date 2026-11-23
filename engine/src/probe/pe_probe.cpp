// mie-pe-probe DIR: a test tool, not a product program. For every regular file directly in
// DIR (sorted by name) it prints one JSON line with everything the PE reader reports, in a
// shape engine/tests/pe_parity.py compares with pefile field by field.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/pe.hpp"

namespace {

using nlohmann::json;

json libraries(const std::vector<mie::pe::ImportLibrary>& list) {
    json out = json::array();
    for (const auto& library : list) {
        json symbols = json::array();
        for (const auto& s : library.symbols) {
            symbols.push_back(json{{"name", s.name},
                                   {"by_ordinal", s.by_ordinal},
                                   {"ordinal", s.ordinal},
                                   {"name_offset", s.has_name_offset ? json(s.name_offset) : json(nullptr)}});
        }
        out.push_back(json{{"dll", library.dll}, {"symbols", symbols}});
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fputs("usage: mie-pe-probe DIR\n", stderr);
        return 2;
    }
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(argv[1], ec)) {
        if (entry.is_regular_file(ec)) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const mie::pe::Image image = mie::pe::parse(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size()));
        json line = {{"file", path.filename().string()}, {"parsed", image.parsed}, {"error", image.error}};
        if (image.parsed) {
            json directories = json::array();
            for (const auto& d : image.directories) directories.push_back(json::array({d.virtual_address, d.size}));
            json sections = json::array();
            for (const auto& s : image.sections) {
                static const char digits[] = "0123456789abcdef";
                std::string hex;
                for (const std::uint8_t b : s.raw_name) {
                    hex.push_back(digits[b >> 4]);
                    hex.push_back(digits[b & 0x0F]);
                }
                sections.push_back(json{{"raw_name", hex},
                                        {"name", s.name},
                                        {"virtual_size", s.virtual_size},
                                        {"virtual_address", s.virtual_address},
                                        {"raw_size", s.raw_size},
                                        {"raw_pointer", s.raw_pointer},
                                        {"characteristics", s.characteristics},
                                        {"data", json::array({s.data.begin, s.data.end})}});
            }
            json resources = json::array();
            for (const auto& r : image.resource_data) resources.push_back(json::array({r.rva, r.size}));
            json spans = json::array();
            for (const auto& span : image.certificates.spans) spans.push_back(json::array({span.begin, span.end}));
            json reference = json::array();
            for (const auto& [dll, names] : mie::pe::reference_imports(image)) reference.push_back(json::array({dll, names}));
            line.update(json{
                {"machine", image.machine},
                {"timestamp", image.timestamp},
                {"characteristics", image.characteristics},
                {"magic", image.magic},
                {"pe32_plus", image.pe32_plus},
                {"entry_point", image.entry_point},
                {"image_base", image.image_base},
                {"section_alignment", image.section_alignment},
                {"file_alignment", image.file_alignment},
                {"size_of_image", image.size_of_image},
                {"size_of_headers", image.size_of_headers},
                {"directories", directories},
                {"sections", sections},
                {"has_imports", image.has_imports},
                {"imports", libraries(image.imports)},
                {"has_delay_imports", image.has_delay_imports},
                {"delay_imports", libraries(image.delay_imports)},
                {"reference_imports", reference},
                {"tls", json{{"present", image.tls.present},
                             {"address_of_callbacks", image.tls.address_of_callbacks},
                             {"first_readable", image.tls.first_readable},
                             {"first_callback", image.tls.first_callback},
                             {"has_callbacks", image.tls.has_callbacks}}},
                {"has_resources", image.has_resources},
                {"resource_root_has_entries", image.resource_root_has_entries},
                {"resource_data", resources},
                {"certificates", json{{"present", image.certificates.present},
                                      {"valid", image.certificates.valid},
                                      {"offset", image.certificates.offset},
                                      {"declared_size", image.certificates.declared_size},
                                      {"parsed_size", image.certificates.parsed_size},
                                      {"entries", image.certificates.entries},
                                      {"spans", spans},
                                      {"problems", image.certificates.problems}}},
            });
        }
        std::printf("%s\n", line.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
    }
    return 0;
}
