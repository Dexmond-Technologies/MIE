// mie-parity-run: the C++ side of the parity harness. A test tool, not a product program.
//
//   mie-parity-run --corpus DIR --out FILE.jsonl --rules DIR --reputation FILE --scoring FILE
//                  [--no-reputation] [--details FILE.jsonl]
//
// Scans every file below DIR with the engine and writes the result table in exactly the
// format of engine/tools/parity/run_reference.py, so that engine/tools/parity/compare.py
// can compare the two:
//   line 1: {"record":"header", ...}
//   then one line per file, sorted by its path below DIR (forward slashes):
//     {"record":"file","path":...,"sha256":...,"size":...,"score":...,"verdict":...,
//      "categories":[sorted finding categories],"error":...,"error_class":...}
// As the reference runner does, an entry that is not a regular file is listed with the
// error "not a regular file" and is not opened; directories are not listed.
// JSON keys are sorted, one record per line, line feeds only, on every system.
//
// --details writes, per scanned file, every finding with its weight and family.
//
// Until the confined worker exists this tool is for TEST FILES ONLY (generated sets).
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/engine.hpp"
#include "mie/hash.hpp"
#include "mie/result.hpp"
#include "mie/rules.hpp"
#include "mie/scoring.hpp"
#include "mie/version.hpp"

namespace {

using nlohmann::json;

bool read_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

std::string utf8(const std::filesystem::path& path) {
    const std::u8string text = path.generic_u8string();
    return std::string(text.begin(), text.end());
}

// The error class the comparison works on (ERROR_RESULT_MAPPING.md): the reason of a
// "not scanned" result is the code of the refusal.
std::string error_class_of(const std::string& reason) {
    if (reason == "not_found") {
        return "not_found";
    }
    if (reason == "access_denied") {
        return "access_denied";
    }
    if (reason == "link" || reason == "not_regular" || reason == "cloud_only") {
        return "not_regular";
    }
    return "unreadable";
}

const char* reference_rules_status(mie::RulesState state) {
    switch (state) {
        case mie::RulesState::On: return "ON";
        case mie::RulesState::Degraded: return "DEGRADED";
        case mie::RulesState::Off: return "YARA-OFF";  // the reference's spelling
    }
    return "YARA-OFF";
}

std::string line_of(const json& record) {
    // ASCII only and sorted keys (nlohmann keeps object keys sorted).
    return record.dump(-1, ' ', true, json::error_handler_t::replace) + "\n";
}

void usage() {
    std::fputs("usage: mie-parity-run --corpus DIR --out FILE.jsonl --rules DIR --reputation FILE --scoring FILE\n"
               "                      [--no-reputation] [--details FILE.jsonl] [--times FILE.jsonl]\n",
               stderr);
}

}  // namespace

int main(int argc, char** argv) {
    std::string corpus, out_path, rules_dir, reputation_path, scoring_path, details_path, times_path;
    bool use_reputation = true;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&](std::string& target) {
            if (i + 1 >= argc) {
                return false;
            }
            target = argv[++i];
            return true;
        };
        bool ok = true;
        if (arg == "--corpus") {
            ok = value(corpus);
        } else if (arg == "--out") {
            ok = value(out_path);
        } else if (arg == "--rules") {
            ok = value(rules_dir);
        } else if (arg == "--reputation") {
            ok = value(reputation_path);
        } else if (arg == "--scoring") {
            ok = value(scoring_path);
        } else if (arg == "--details") {
            ok = value(details_path);
        } else if (arg == "--times") {
            ok = value(times_path);
        } else if (arg == "--no-reputation") {
            use_reputation = false;
        } else {
            ok = false;
        }
        if (!ok) {
            usage();
            return 2;
        }
    }
    if (corpus.empty() || out_path.empty() || rules_dir.empty() || reputation_path.empty() || scoring_path.empty()) {
        usage();
        return 2;
    }

    std::string scoring_text;
    std::string reputation_text;
    if (!read_file(scoring_path, scoring_text) || !read_file(reputation_path, reputation_text)) {
        std::fputs("mie-parity-run: cannot read the scoring table or the reputation list\n", stderr);
        return 2;
    }
    mie::ScoringTable table;
    std::string error;
    if (!mie::load_scoring_table(scoring_text, table, error)) {
        std::fprintf(stderr, "mie-parity-run: %s\n", error.c_str());
        return 2;
    }
    const auto rules = mie::rules::RuleSet::load(std::filesystem::path(rules_dir));
    mie::EngineOptions options;
    options.use_reputation = use_reputation;
    const mie::UnavailableSignatureVerifier no_signatures;
    const mie::Engine engine(table, *rules, reputation_text, options, &no_signatures);
    if (!engine.usable(error)) {
        std::fprintf(stderr, "mie-parity-run: %s\n", error.c_str());
        return 2;
    }

    // Every entry below the corpus that is not a directory, sorted by its relative path.
    // Directory links are not followed (as os.walk without followlinks); a link to a
    // directory is not listed, any other link is listed and then refused.
    const std::filesystem::path root(corpus);
    std::vector<std::pair<std::string, std::filesystem::path>> entries;
    std::error_code ec;
    for (std::filesystem::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code status_error;
        if (std::filesystem::is_directory(it->path(), status_error)) {
            continue;
        }
        entries.emplace_back(utf8(it->path().lexically_relative(root)), it->path());
    }
    if (ec) {
        std::fprintf(stderr, "mie-parity-run: cannot list %s: %s\n", corpus.c_str(), ec.message().c_str());
        return 2;
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    std::ofstream details;
    if (!details_path.empty()) {
        details.open(details_path, std::ios::binary | std::ios::trunc);
    }
    std::ofstream times;
    if (!times_path.empty()) {
        times.open(times_path, std::ios::binary | std::ios::trunc);
    }
    if (!out || (!details_path.empty() && !details) || (!times_path.empty() && !times)) {
        std::fputs("mie-parity-run: cannot open an output file\n", stderr);
        return 2;
    }

    const json header = {
        {"record", "header"},
        {"producer", "cpp-engine"},
        {"engine_version", mie::kEngineVersion},
        {"profile", table.profile},
        {"commit", nullptr},
        {"python", nullptr},
        {"pefile", nullptr},
        {"yara_python", nullptr},
        {"yara_library", mie::rules::RuleSet::library_version()},
        {"yara_status", reference_rules_status(rules->state())},
        {"rules", rules->file_hashes()},
        {"rules_sha256", rules->sha256()},
        {"options", json{{"use_reputation", use_reputation},
                         {"reputation_sha256",
                          mie::sha256_hex(std::span<const std::uint8_t>(
                              reinterpret_cast<const std::uint8_t*>(reputation_text.data()), reputation_text.size()))}}},
        {"signature_checking", "not built: every signature is unavailable"},
    };
    out << line_of(header);

    for (const auto& [relative, path] : entries) {
        json record = {{"record", "file"}, {"path", relative},   {"sha256", nullptr}, {"size", nullptr},
                       {"score", nullptr}, {"verdict", nullptr}, {"categories", json::array()},
                       {"error", nullptr}, {"error_class", nullptr}};
        std::error_code status_error;
        const std::filesystem::file_status status = std::filesystem::symlink_status(path, status_error);
        if (status_error || !std::filesystem::is_regular_file(status)) {
            record["error"] = "not a regular file";
            record["error_class"] = "not_regular";
            out << line_of(record);
            continue;
        }
        std::error_code size_error;
        const std::uintmax_t size = std::filesystem::file_size(path, size_error);
        if (!size_error) {
            record["size"] = size;
        }
        const std::chrono::steady_clock::time_point scan_start = std::chrono::steady_clock::now();
        const mie::ScanResult result = engine.scan_file(path);
        if (times.is_open()) {
            times << line_of(json{{"path", relative},
                                  {"total_ms", std::chrono::duration<double, std::milli>(
                                                   std::chrono::steady_clock::now() - scan_start)
                                                   .count()}});
        }
        if (!result.hashes.sha256.empty()) {
            record["sha256"] = result.hashes.sha256;
        }
        if (result.state == mie::ScanState::NotScanned) {
            record["error"] = "NOT SCANNED: " + result.reason;
            record["error_class"] = error_class_of(result.reason);
        } else {
            std::vector<std::string> categories;
            for (const mie::Finding& finding : result.findings) {
                categories.push_back(finding.category);
            }
            std::sort(categories.begin(), categories.end());
            record["score"] = result.score;
            record["verdict"] = result.verdict;
            record["categories"] = categories;
            if (details.is_open()) {
                json findings = json::array();
                for (const mie::Finding& finding : result.findings) {
                    findings.push_back(json{{"category", finding.category},
                                            {"weight", finding.weight},
                                            {"family", finding.family},
                                            {"floor", finding.floor},
                                            {"description", finding.description}});
                }
                details << line_of(json{{"path", relative},
                                        {"score", result.score},
                                        {"verdict", result.verdict},
                                        {"state", mie::to_string(result.state)},
                                        {"reason", result.reason},
                                        {"findings", findings}});
            }
        }
        out << line_of(record);
    }
    out.flush();
    if (!out) {
        std::fputs("mie-parity-run: writing the result file failed\n", stderr);
        return 2;
    }
    std::printf("mie-parity-run: %zu files, results in %s\n", entries.size(), out_path.c_str());
    return 0;
}
