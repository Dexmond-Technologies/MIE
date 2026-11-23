// mie-probe: a test tool, not a product program. It prints, as one JSON object, what
// the week 0 primitives say about one file: is it accepted by the safe open, its size,
// its three hashes, its entropy figures. The CI tests compare this output with the
// Python reference and with the file-type refusal rules.
//
// Numbers are printed with 17 significant digits so that the comparison is exact.
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

#include "mie/entropy.hpp"
#include "mie/hash.hpp"
#include "mie/io.hpp"
#include "mie/strings.hpp"
#ifdef MIE_WITH_RULES
#include "mie/rules.hpp"
#endif

namespace {

std::string exact(double value) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.17g", value);
    return buffer;
}

constexpr std::uint64_t kMaxProbeBytes = 64ull * 1024 * 1024;

}  // namespace

#ifdef MIE_WITH_RULES
// mie-probe rules RULES_DIR [FILE]: loads the rules and, with FILE, prints the matches.
int probe_rules(int argc, char** argv) {
    using nlohmann::json;
    const auto set = mie::rules::RuleSet::load(std::filesystem::path(argv[2]));
    json errors = json::array();
    for (const auto& e : set->errors()) {
        errors.push_back(json{{"file", e.file}, {"error", e.error}});
    }
    json out = {{"yara_library", mie::rules::RuleSet::library_version()},
                {"rule_files", set->file_hashes()},
                {"rules_state", mie::to_string(set->state())},
                {"files_loaded", set->files_loaded()},
                {"rules_sha256", set->sha256()},
                {"errors", errors}};
    if (argc == 4) {
        mie::io::IoError error;
        const auto file = mie::io::open_regular(std::filesystem::path(argv[3]), error);
        if (!file) {
            out["scan"] = "refused";
            out["code"] = mie::io::to_string(error.code);
        } else {
            std::vector<std::uint8_t> data(static_cast<std::size_t>(file->size()));
            std::uint64_t done = 0;
            while (done < data.size()) {
                const std::int64_t n = file->read_at(
                    done, std::span<std::uint8_t>(data.data() + done, data.size() - static_cast<std::size_t>(done)), error);
                if (n <= 0) {
                    break;
                }
                done += static_cast<std::uint64_t>(n);
            }
            data.resize(static_cast<std::size_t>(done));
            std::vector<mie::rules::RuleMatch> matches;
            std::string scan_error;
            if (set->scan(data, matches, scan_error)) {
                json list = json::array();
                for (const auto& m : matches) {
                    list.push_back(json{{"rule", m.rule}, {"namespace", m.name_space}, {"severity", m.severity},
                                        {"category", m.category}, {"description", m.description}});
                }
                out["scan"] = "ok";
                out["matches"] = list;
            } else {
                out["scan"] = "failed";
                out["scan_error"] = scan_error;
            }
        }
    }
    std::printf("%s\n", out.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
    return 0;
}
#endif

// mie-probe strings DIR: for every regular file directly in DIR (sorted by name) prints one
// JSON line with the string indicators. A file "<name>.spans" beside a file, if present, holds
// lines "begin end": ASCII runs at exactly these offsets do not count for suspicious_api.
int probe_strings(const char* directory) {
    using nlohmann::json;
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() != ".spans") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::vector<mie::strings::Span> spans;
        std::ifstream span_file(path.string() + ".spans");
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        while (span_file >> begin >> end) {
            spans.emplace_back(begin, end);
        }
        const mie::strings::Indicators found = mie::strings::scan(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size()), spans);
        const json line = {{"name", path.filename().string()},
                           {"powershell", found.powershell},
                           {"suspicious_api", found.suspicious_api},
                           {"b64_executable", found.b64_executable},
                           {"obfuscated_script", found.obfuscated_script},
                           {"string_count", found.string_count}};
        std::printf("%s\n", line.dump().c_str());
    }
    return 0;
}

int main(int argc, char** argv) {
    using nlohmann::json;
    if (argc == 3 && std::string(argv[1]) == "strings") {
        return probe_strings(argv[2]);
    }
#ifdef MIE_WITH_RULES
    if ((argc == 3 || argc == 4) && std::string(argv[1]) == "rules") {
        return probe_rules(argc, argv);
    }
#endif
    const bool usage_ok = (argc == 3 || (argc == 4 && std::string(argv[3]) == "--allow-cloud-only")) &&
                          std::string(argv[1]) == "file";
    if (!usage_ok) {
        std::fputs("usage: mie-probe file PATH [--allow-cloud-only]\n", stderr);
        return 2;
    }
    mie::io::OpenOptions options;
    options.allow_cloud_only = (argc == 4);
    mie::io::IoError error;
    const auto file = mie::io::open_regular(std::filesystem::path(argv[2]), error, options);
    if (!file) {
        const json refused = {{"state", "refused"},
                              {"code", mie::io::to_string(error.code)},
                              {"detail", error.detail}};
        std::printf("%s\n", refused.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
        return 0;
    }

    mie::Hashes hashes;
    if (!mie::hash_file(*file, hashes, error)) {
        const json failed = {{"state", "error"}, {"code", mie::io::to_string(error.code)}, {"detail", error.detail}};
        std::printf("%s\n", failed.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
        return 1;
    }

    json out = {{"state", "ok"},
                {"size", file->size()},
                {"md5", hashes.md5},
                {"sha1", hashes.sha1},
                {"sha256", hashes.sha256}};

    if (file->size() <= kMaxProbeBytes) {
        std::vector<std::uint8_t> data(static_cast<std::size_t>(file->size()));
        std::uint64_t done = 0;
        while (done < data.size()) {
            const std::int64_t n = file->read_at(
                done, std::span<std::uint8_t>(data.data() + done, data.size() - static_cast<std::size_t>(done)), error);
            if (n <= 0) {
                break;
            }
            done += static_cast<std::uint64_t>(n);
        }
        data.resize(static_cast<std::size_t>(done));
        const mie::SlidingEntropy sliding = mie::sliding_window_entropy(data);
        out["entropy"] = exact(mie::shannon_entropy(data));
        out["sliding"] = json{{"max", exact(sliding.max)},
                              {"min", exact(sliding.min)},
                              {"avg", exact(sliding.avg)},
                              {"high_entropy_windows", sliding.high_entropy_windows},
                              {"total_windows", sliding.total_windows}};
    }
    std::printf("%s\n", out.dump().c_str());
    return 0;
}
