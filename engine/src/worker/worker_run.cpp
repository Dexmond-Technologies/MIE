// mie-worker-run: the result table of mie-parity-run, but every scan goes through a
// CONFINED WORKER (one worker process per file). A test tool, not a product program.
//
//   mie-worker-run --worker PROGRAM --corpus DIR --out FILE.jsonl --rules DIR
//                  --reputation FILE --scoring FILE [--no-reputation] [--details FILE.jsonl]
//                  [--log FILE.jsonl] [--wall SECONDS] [--memory BYTES]
//                  [--test-fault RELATIVE/PATH=KIND]... [--unconfined] [--allow-weaker]
//   mie-worker-run --sid
//
// --out and --details have EXACTLY the format of mie-parity-run (src/tools/parity_run.cpp),
// header included, so `compare.py --identical` can show that the confined path gives the
// same table as the unconfined test runner. What is specific to the worker goes to --log:
// per file how the worker ended, what confinement the parent applied, what the worker says
// was applied, its process id, time and peak memory.
//
// --test-fault, --unconfined and --allow-weaker are for the tests only. A fault needs the
// test-hooks build of the worker (the shipped worker refuses such a job); --unconfined
// starts the worker without confinement, which the shipped worker refuses as well.
// --sid prints the AppContainer SID of the worker (Windows; empty elsewhere) so a test can
// grant it read access to the program folder.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/hash.hpp"
#include "mie/result.hpp"
#include "mie/sandbox.hpp"
#include "mie/version.hpp"
#include "mie/worker.hpp"

namespace {

using nlohmann::json;

std::string utf8(const std::filesystem::path& path) {
    const std::u8string text = path.generic_u8string();
    return std::string(text.begin(), text.end());
}

// As mie-parity-run.
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
        case mie::RulesState::Off: return "YARA-OFF";
    }
    return "YARA-OFF";
}

std::string line_of(const json& record) {
    return record.dump(-1, ' ', true, json::error_handler_t::replace) + "\n";
}

void usage() {
    std::fputs("usage: mie-worker-run --worker PROGRAM --corpus DIR --out FILE.jsonl --rules DIR --reputation FILE\n"
               "                      --scoring FILE [--no-reputation] [--details FILE.jsonl] [--log FILE.jsonl]\n"
               "                      [--wall SECONDS] [--memory BYTES] [--test-fault PATH=KIND]... [--unconfined]\n"
               "                      [--allow-weaker]\n"
               "       mie-worker-run --sid\n",
               stderr);
}

}  // namespace

int main(int argc, char** argv) {
    std::string worker, corpus, out_path, rules_dir, reputation_path, scoring_path, details_path, log_path;
    std::string wall_text, memory_text;
    std::map<std::string, std::string> faults;
    bool use_reputation = true;
    mie::sandbox::RunOptions run_options;
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
        std::string fault;
        if (arg == "--sid") {
            std::string error;
            const std::string sid = mie::sandbox::appcontainer_sid_text(error);
            std::fputs(line_of(json{{"sid", sid}, {"error", error}}).c_str(), stdout);
            return 0;
        } else if (arg == "--worker") {
            ok = value(worker);
        } else if (arg == "--corpus") {
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
        } else if (arg == "--log") {
            ok = value(log_path);
        } else if (arg == "--wall") {
            ok = value(wall_text);
        } else if (arg == "--memory") {
            ok = value(memory_text);
        } else if (arg == "--test-fault") {
            ok = value(fault);
            const std::size_t equals = fault.rfind('=');
            if (ok && equals != std::string::npos) {
                faults[fault.substr(0, equals)] = fault.substr(equals + 1);
            } else {
                ok = false;
            }
        } else if (arg == "--no-reputation") {
            use_reputation = false;
        } else if (arg == "--unconfined") {
            run_options.confine = false;
        } else if (arg == "--allow-weaker") {
            run_options.allow_weaker = true;
        } else {
            ok = false;
        }
        if (!ok) {
            usage();
            return 2;
        }
    }
    if (worker.empty() || corpus.empty() || out_path.empty() || rules_dir.empty() || reputation_path.empty() ||
        scoring_path.empty()) {
        usage();
        return 2;
    }

    mie::worker::Config config;
    std::string error;
    if (!mie::worker::load_config(scoring_path, reputation_path, rules_dir, config, error)) {
        std::fprintf(stderr, "mie-worker-run: %s\n", error.c_str());
        return 2;
    }
    config.use_reputation = use_reputation;
    const std::string reputation_sha256 = mie::sha256_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(config.reputation_json.data()), config.reputation_json.size()));

    mie::worker::HostOptions options;
    options.worker_program = std::filesystem::path(worker);
    options.run = run_options;
    if (!wall_text.empty()) {
        options.limits.wall_seconds = std::atoi(wall_text.c_str());
    }
    if (!memory_text.empty()) {
        options.limits.memory_bytes = std::strtoull(memory_text.c_str(), nullptr, 10);
    }
    if (options.limits.wall_seconds <= 0 || options.limits.memory_bytes == 0) {
        usage();
        return 2;
    }
    mie::worker::Host host(std::move(config), options);

    // What the worker runs with: asked of a worker, because this program compiles no rules.
    mie::worker::Description description;
    if (!host.describe(description, error)) {
        std::fprintf(stderr, "mie-worker-run: %s\n", error.c_str());
        return 3;
    }
    if (!description.usable) {
        std::fprintf(stderr, "mie-worker-run: %s\n", mie::worker::printable(description.why_unusable).c_str());
        return 2;
    }

    // Every entry below the corpus that is not a directory, sorted by its relative path
    // (as mie-parity-run).
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
        std::fprintf(stderr, "mie-worker-run: cannot list %s: %s\n", corpus.c_str(), ec.message().c_str());
        return 2;
    }
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    std::ofstream details;
    std::ofstream log;
    if (!details_path.empty()) {
        details.open(details_path, std::ios::binary | std::ios::trunc);
    }
    if (!log_path.empty()) {
        log.open(log_path, std::ios::binary | std::ios::trunc);
    }
    if (!out || (!details_path.empty() && !details) || (!log_path.empty() && !log)) {
        std::fputs("mie-worker-run: cannot open an output file\n", stderr);
        return 2;
    }

    // Field for field the header of mie-parity-run.
    const json header = {
        {"record", "header"},
        {"producer", "cpp-engine"},
        {"engine_version", mie::kEngineVersion},
        {"profile", description.profile},
        {"commit", nullptr},
        {"python", nullptr},
        {"pefile", nullptr},
        {"yara_python", nullptr},
        {"yara_library", description.rules_library},
        {"yara_status", reference_rules_status(description.rules_state)},
        {"rules", description.rule_files},
        {"rules_sha256", description.rules_sha256},
        {"options", json{{"use_reputation", use_reputation}, {"reputation_sha256", reputation_sha256}}},
        {"signature_checking", "not built: every signature is unavailable"},
    };
    out << line_of(header);
    if (log.is_open()) {
        log << line_of(json{{"record", "describe"},
                            {"worker", worker},
                            {"worker_confinement", description.confinement},
                            {"rule_errors", description.rule_errors},
                            {"wall_seconds", options.limits.wall_seconds},
                            {"memory_bytes", options.limits.memory_bytes},
                            {"files_per_worker", mie::worker::kFilesPerWorker},
                            {"sanitizer_build", mie::sandbox::sanitizer_build()}});
    }

    std::size_t answered = 0;
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
        const auto fault = faults.find(relative);
        host.set_test_fault(fault != faults.end() ? fault->second : std::string());
        const mie::worker::JobOutcome outcome = host.scan_file(path);
        const mie::ScanResult& result = outcome.result;
        answered += outcome.answered ? 1 : 0;
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
        if (log.is_open()) {
            log << line_of(json{{"record", "job"},
                                {"path", relative},
                                {"answered", outcome.answered},
                                {"end", mie::sandbox::to_string(outcome.end)},
                                {"exit_code", outcome.exit_code},
                                {"state", mie::to_string(result.state)},
                                {"reason", result.reason},
                                {"detail", outcome.detail},
                                {"confinement", outcome.confinement},
                                {"worker_confinement", outcome.worker_confinement},
                                {"worker_pid", outcome.worker_pid},
                                {"seconds", outcome.seconds},
                                {"peak_memory_bytes", outcome.peak_memory_bytes},
                                {"setup_ms", outcome.setup_ms},
                                {"scan_ms", outcome.scan_ms},
                                {"worker_alive_ms", outcome.worker_alive_ms},
                                {"hash_ms", outcome.hash_ms},
                                {"worker_run_ms", outcome.worker_run_ms},
                                {"start_overhead_ms", outcome.start_overhead_ms},
                                {"total_ms", outcome.total_ms}});
            log.flush();
        }
    }
    out.flush();
    if (!out) {
        std::fputs("mie-worker-run: writing the result file failed\n", stderr);
        return 2;
    }
    std::printf("mie-worker-run: %zu files, %zu answered by a worker, %llu workers started, results in %s\n",
                entries.size(), answered, static_cast<unsigned long long>(host.workers_started()), out_path.c_str());
    return 0;
}
