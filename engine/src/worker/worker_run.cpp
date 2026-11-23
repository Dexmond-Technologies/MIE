// mie-worker-run: the result table of mie-parity-run, but every scan goes through a
// CONFINED WORKER (one worker process per file, in either shape of mie/worker.hpp). A test
// tool, not a product program.
//
//   mie-worker-run --worker PROGRAM --corpus DIR --out FILE.jsonl --rules DIR
//                  --reputation FILE --scoring FILE [--no-reputation] [--details FILE.jsonl]
//                  [--log FILE.jsonl] [--wall SECONDS] [--memory BYTES]
//                  [--pool N|proposed] [--max-age SECONDS] [--idle-before-first SECONDS]
//                  [--reload-after RELATIVE/PATH]
//                  [--test-fault RELATIVE/PATH=KIND]... [--unconfined] [--allow-weaker]
//                  [--test-second-hand-over] [--test-die-waiting N] [--test-die-waiting-from K]
//   mie-worker-run --sid
//
// --pool 0 (the default) is one worker STARTED per file (shape A, today's shipped shape);
// --pool N > 0 keeps up to N PRE-STARTED one-shot workers (shape B, reviewer's ruling M-13);
// "proposed" is 2, at most the number of processor cores. --max-age: a waiting worker older
// than this is replaced (default 300). --idle-before-first: wait until the pool is full, then
// this many seconds, before the first file (the "one file after idle" figure).
// --reload-after: after that file, the configuration is read again and set (every waiting
// worker is ended; reviewer's condition 5).
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
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <span>
#include <string>
#include <system_error>
#include <thread>
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
               "                      [--allow-weaker] [--pool N|proposed] [--max-age SECONDS]\n"
               "                      [--idle-before-first SECONDS] [--reload-after PATH] [--test-second-hand-over]\n"
               "                      [--test-die-waiting N] [--test-die-waiting-from K]\n"
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
    std::string pool_text = "0", max_age_text, idle_text, reload_after, die_waiting_text, die_from_text;
    bool second_hand_over = false;
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
        } else if (arg == "--pool") {
            ok = value(pool_text);
        } else if (arg == "--max-age") {
            ok = value(max_age_text);
        } else if (arg == "--idle-before-first") {
            ok = value(idle_text);
        } else if (arg == "--reload-after") {
            ok = value(reload_after);
        } else if (arg == "--test-die-waiting") {
            ok = value(die_waiting_text);
        } else if (arg == "--test-die-waiting-from") {
            ok = value(die_from_text);
        } else if (arg == "--test-second-hand-over") {
            second_hand_over = true;
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
    options.pool_size = pool_text == "proposed" ? mie::worker::proposed_pool_size() : std::atoi(pool_text.c_str());
    if (!max_age_text.empty()) {
        options.max_waiting_age_seconds = std::atof(max_age_text.c_str());
    }
    options.test_second_hand_over = second_hand_over;
    options.test_die_while_waiting = die_waiting_text.empty() ? 0 : std::atoi(die_waiting_text.c_str());
    options.test_die_while_waiting_from = die_from_text.empty() ? 0 : std::atoi(die_from_text.c_str());
    const double idle_seconds = idle_text.empty() ? 0.0 : std::atof(idle_text.c_str());
    if (options.pool_size < 0 || options.max_waiting_age_seconds <= 0.0 || idle_seconds < 0.0 ||
        (options.pool_size > 0 && !run_options.confine)) {
        std::fputs("mie-worker-run: --pool must be 0 or more, --max-age above 0; pre-started workers cannot run "
                   "unconfined\n",
                   stderr);
        return 2;
    }
    const mie::worker::Config initial_config = config;
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
        // Reviewer's condition 6 of M-13: pool size and age in the result header. (compare.py
        // --identical leaves header lines out; worker_cases compares the headers itself.)
        {"worker_pool",
         json{{"size", options.pool_size},
              {"max_age_seconds", options.max_waiting_age_seconds},
              {"shape", options.pool_size > 0 ? "pre-started one-shot workers (M-13)" : "one worker started per file"},
              {"files_per_worker", mie::worker::kFilesPerWorker}}},
    };
    out << line_of(header);
    const auto write_events = [&] {
        for (const mie::worker::PoolEvent& happened : host.take_events()) {
            if (log.is_open()) {
                log << line_of(json{{"record", "pool"},
                                    {"what", happened.what},
                                    {"detail", happened.detail},
                                    {"generation", happened.generation},
                                    {"age_seconds", happened.age_seconds}});
            }
        }
        if (log.is_open()) {
            log.flush();
        }
    };
    write_events();
    if (idle_seconds > 0.0 && options.pool_size > 0) {
        // Figure (a) of the reviewer's A-8 line: the pool full, nothing else running, then a pause.
        const auto start = std::chrono::steady_clock::now();
        const auto elapsed = [&] {
            return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        };
        while (!host.pool_full() && elapsed() < mie::worker::kReadyTimeoutSeconds) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        const double filled_after = elapsed();
        while (elapsed() < filled_after + idle_seconds) {
            host.maintain();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const bool full = host.pool_full();
        write_events();
        if (log.is_open()) {
            log << line_of(json{{"record", "idle"},
                                {"pool_filled_after_seconds", filled_after},
                                {"idle_seconds", idle_seconds},
                                {"pool_full_before_the_first_file", full}});
            log.flush();
        }
    }
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
        if (log.is_open()) {
            // Written and flushed BEFORE the file is opened or hashed: a test that changes the
            // file during the scan waits for this line.
            log << line_of(json{{"record", "start"}, {"path", relative}});
            log.flush();
        }
        const auto fault = faults.find(relative);
        host.set_test_fault(fault != faults.end() ? fault->second : std::string());
        host.maintain();
        write_events();
        const mie::worker::JobOutcome outcome = host.scan_file(path);
        write_events();
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
                                {"total_ms", outcome.total_ms},
                                {"after_seal_ms", outcome.after_seal_ms},
                                {"wait_ready_ms", outcome.wait_ready_ms},
                                {"refill_ms", outcome.refill_ms},
                                {"attempts", outcome.attempts},
                                {"worker_generation", outcome.worker_generation},
                                {"second_hand_over", outcome.second_hand_over},
                                {"container_folder_note", outcome.container_folder_note}});
            log.flush();
        }
        if (!reload_after.empty() && relative == reload_after) {
            // Reviewer's condition 5 of M-13: the configuration changes; waiting workers end.
            mie::worker::Config again;
            if (!mie::worker::load_config(scoring_path, reputation_path, rules_dir, again, error)) {
                std::fprintf(stderr, "mie-worker-run: %s\n", error.c_str());
                return 2;
            }
            again.use_reputation = initial_config.use_reputation;
            host.set_config(std::move(again));
            write_events();
            if (log.is_open()) {
                log << line_of(json{{"record", "reloaded"}, {"after", relative}, {"generation", host.generation()}});
                log.flush();
            }
        }
    }
    host.shutdown();
    write_events();
    out.flush();
    if (!out) {
        std::fputs("mie-worker-run: writing the result file failed\n", stderr);
        return 2;
    }
    std::printf("mie-worker-run: %zu files, %zu answered by a worker, %llu workers started, results in %s\n",
                entries.size(), answered, static_cast<unsigned long long>(host.workers_started()), out_path.c_str());
    return 0;
}
