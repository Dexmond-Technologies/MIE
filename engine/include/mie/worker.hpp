// The worker: the low-rights process in which EVERY parse of untrusted bytes happens
// (reviewer's conditions M-2 and M-9), and the parent's side of it.
//
// Scheme (WORKER_NOTES.md): ONE WORKER PROCESS PER FILE.
//   - The parent (the service) opens the file once with mie::io and hands that one
//     read-only handle to a freshly started, confined worker (mie::sandbox::run_confined).
//   - Everything else the worker needs arrives as BYTES on its standard input, in one
//     "job": the scoring table, the reputation list and the text of every rule file. The
//     worker opens no path, on any system, for any purpose. Rules are compiled from their
//     source text inside the worker (never from a compiled-rules file).
//   - The worker answers with one channel frame on its standard output and ends.
//   - A worker that is killed at a limit, crashes, cannot be started, cannot be confined or
//     gives an unusable answer is a RESULT for that file: "not fully scanned", never CLEAN,
//     with the reason. The parent carries on with the next file.
//   - "Recycled after 200 files" is met trivially: a worker serves one file.
//
// The worker's answer is UNTRUSTED (it has parsed hostile bytes): the parent decodes it
// with the bounded frame decoder, parses the result strictly, checks its consistency and
// checks that it speaks about the file the parent handed over (hash and size, computed by
// the parent itself).
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "mie/io.hpp"
#include "mie/result.hpp"
#include "mie/rule_sources.hpp"
#include "mie/sandbox.hpp"

namespace mie::worker {

// ---- the job on the worker's standard input ---------------------------------------------
//
//   8 bytes   "MIEWJOB1"
//   4 bytes   length of the header, big-endian
//   header    JSON object (UTF-8), at most kMaxJobHeaderBytes:
//               {"v":1,"op":"scan"|"describe","display_name":"...","use_reputation":true,
//                "test_fault":"", "sections":[{"kind":"scoring"|"reputation"|"rule",
//                "name":"...","namespace":"...","size":N,"sha256":"..."}]}
//   sections  the bytes of each section, in the order of the list, nothing between them
//
// Unknown fields are refused. Exactly one "scoring" and one "reputation" section; any
// number of "rule" sections up to kMaxRuleFiles. Every size and every hash is checked.
inline constexpr char kJobMagic[8] = {'M', 'I', 'E', 'W', 'J', 'O', 'B', '1'};
inline constexpr int kJobVersion = 1;
inline constexpr std::size_t kMaxJobHeaderBytes = 1024 * 1024;
inline constexpr std::size_t kMaxJobBytes = 64u * 1024 * 1024;  // header and all sections
inline constexpr std::size_t kMaxRuleFiles = 4096;
inline constexpr std::size_t kMaxDisplayNameBytes = 4096;

// A worker serves this many files and ends (the design's upper bound is 200).
inline constexpr int kFilesPerWorker = 1;

// The worker's exit codes. 0: an answer frame was written. Any other value: no answer.
// The values keep clear of the codes a C runtime uses by itself (1, 2, 3 = abort on Windows)
// and of sandbox::kOutOfMemoryExitCode (86).
inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 42;          // an argument (the shipped worker takes none)
inline constexpr int kExitNotConfined = 43;    // the confinement is missing or could not be applied
inline constexpr int kExitBadJob = 44;         // the job could not be read
inline constexpr int kExitTestSwitch = 45;     // a test switch reached a build without test hooks
inline constexpr int kExitNoFile = 46;         // a scan job without a handed-over file
inline constexpr int kExitInternal = 47;       // anything else (an exception)

inline constexpr const char* kAnswerOp = "worker.result";

struct Job {
    std::string op = "scan";  // "scan" or "describe"
    std::string display_name;
    bool use_reputation = true;
    // Only honoured by the test-hooks build of the worker ("spin", "crash", "allocate");
    // the shipped worker refuses a job that carries one.
    std::string test_fault;
    std::string scoring_json;
    std::string reputation_json;
    std::vector<rules::RuleSource> rules;  // readable ones carry their text
};

// The bytes of a job. Empty with `error` set if the job breaks a limit.
std::string encode_job(const Job& job, std::string& error);

// Strict. Returns false with `error` set on any problem.
bool decode_job(std::span<const std::uint8_t> bytes, Job& out, std::string& error);

// ---- the parent's side --------------------------------------------------------------------

// What the engine is configured with: read once by the parent, sent with every job.
struct Config {
    std::string scoring_json;
    std::string reputation_json;
    std::vector<rules::RuleSource> rules;
    bool use_reputation = true;
};

// Reads the scoring table, the reputation list and the rule files. Returns false with
// `error` set if the scoring table or the reputation list cannot be read (a rules
// directory with no rule file is not an error: the worker then reports rules OFF).
bool load_config(const std::filesystem::path& scoring, const std::filesystem::path& reputation,
                 const std::filesystem::path& rules_directory, Config& out, std::string& error);

struct HostOptions {
    std::filesystem::path worker_program;
    sandbox::Limits limits;  // 1 GiB, 60 s by default
    // The parent hashes the file itself and refuses an answer that names another file.
    bool verify_identity = true;
    // TESTS ONLY, never set by the product:
    sandbox::RunOptions run;  // run.confine=false also passes --test-allow-unconfined
    std::string test_fault;   // put into the next job(s); needs the test-hooks worker
};

// What a worker says about itself and its rule set (the "describe" job).
struct Description {
    std::string engine_version;
    std::string profile;
    RulesState rules_state = RulesState::Off;
    std::string rules_sha256;
    std::map<std::string, std::string> rule_files;  // file -> SHA-256, the loaded ones
    std::vector<std::string> rule_errors;           // "<file>: <error>"
    std::string rules_library;                      // version of the rule library
    bool usable = false;
    std::string why_unusable;
    std::string confinement;  // what the worker says was applied
};

struct JobOutcome {
    ScanResult result;                 // always consistent(); never CLEAN after an abnormal end
    bool answered = false;             // true: `result` is the worker's own answer
    sandbox::ChildResult::End end = sandbox::ChildResult::End::StartFailed;
    int exit_code = 0;
    std::string detail;                // why, for logs (bounded, printable)
    std::string confinement;           // what the parent applied (ChildResult::confinement)
    std::string worker_confinement;    // what the worker says was applied
    std::uint64_t peak_memory_bytes = 0;
    double seconds = 0.0;
    std::int64_t worker_pid = 0;       // as the worker reports it (0 = unknown)
    double setup_ms = 0.0;             // worker: table, rules compiled, engine built
    double scan_ms = 0.0;              // worker: the scan itself
};

class Host {
public:
    Host(Config config, HostOptions options);

    // Starts a worker with no file and asks what it runs with. The answer is kept and used
    // for the results the parent has to write itself. False with `error` set on failure.
    bool describe(Description& out, std::string& error);

    // Opens `path` once (links, directories, devices, cloud-only files are refused: "not
    // scanned", as the engine does) and scans it in a new confined worker.
    JobOutcome scan_file(const std::filesystem::path& path);

    // Scans a file the caller has opened. `display_name` is text for people only.
    JobOutcome scan_open(io::File& file, const std::string& display_name);

    void set_test_fault(const std::string& fault) { options_.test_fault = fault; }
    std::uint64_t workers_started() const { return workers_started_; }

private:
    ScanResult base_result(const std::string& display_name) const;
    JobOutcome abnormal(const sandbox::ChildResult& child, const std::string& reason, ScanResult base) const;
    sandbox::ChildResult run(const Job& job, const io::File* file, std::string& error);

    Config config_;
    HostOptions options_;
    bool described_ = false;
    Description description_;
    std::uint64_t workers_started_ = 0;
};

// A short, printable form of text that came from a worker (never trusted): control
// characters and non-ASCII bytes replaced, at most `limit` characters.
std::string printable(const std::string& text, std::size_t limit = 300);

}  // namespace mie::worker
