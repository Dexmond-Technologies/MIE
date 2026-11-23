// The worker: the low-rights process in which EVERY parse of untrusted bytes happens
// (reviewer's conditions M-2 and M-9), and the parent's side of it.
//
// Two shapes (WORKER_NOTES.md). Both: one file per worker process, always.
//
//  A. ONE WORKER STARTED PER FILE (pool size 0; today's shipped shape until the reviewer accepts
//     B). The parent opens the file, starts a confined worker with sandbox::run_confined and
//     hands over that handle at the start; the worker reads its job (scoring table, reputation
//     list, rule texts) from standard input, scans, answers, ends.
//
//  B. PRE-STARTED ONE-SHOT WORKERS (reviewer's ruling M-13; pool size N > 0). Up to N workers
//     are started ahead (sandbox::start_waiting, argument --prestarted). Each enters stage 1 of
//     its confinement, reads the PREPARATION from standard input (the same bytes as the job of
//     shape A, with op "prepare": OUR rule texts and tables, never a scanned byte), builds its
//     engine, writes a READY frame, and waits. The parent hands one file to one ready worker
//     (sandbox::hand_over_file, with a small FILE JOB of at most sandbox::kMaxJobBytes); the
//     worker seals (sandbox::receive_file_and_seal: full confinement before the first byte of
//     the file), scans, answers, ends. A second hand-over to the same worker is refused.
//     The configuration a worker prepared with is named by the SHA-256 of its preparation
//     bytes, echoed in its ready frame and in its answer; an answer from another configuration
//     is discarded and the file scanned again once.
//
// In both shapes: the parent hashes the file before the worker gets it, the worker's answer is
// UNTRUSTED (bounded frame, strict result, consistency, same engine version, same bytes), and
// every abnormal end AFTER the file was handed to a worker is "not fully scanned" for that file
// (never CLEAN). In shape B, a file for which NO worker could be had is "not scanned".
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "mie/io.hpp"
#include "mie/result.hpp"
#include "mie/rule_sources.hpp"
#include "mie/sandbox.hpp"

namespace mie::worker {

// ---- the job / preparation on the worker's standard input ----------------------------------
//
//   8 bytes   "MIEWJOB1"
//   4 bytes   length of the header, big-endian
//   header    JSON object (ASCII), at most kMaxJobHeaderBytes:
//               {"v":1,"op":"scan"|"describe"|"prepare","display_name":"...","use_reputation":true,
//                "test_fault":"", "sections":[{"kind":"scoring"|"reputation"|"rule",
//                "name":"...","namespace":"...","size":N,"sha256":"...","readable":true}]}
//   sections  the bytes of each section, in the order of the list, nothing between them
//
// The message delimits itself: a reader knows from the first 12 bytes and the header exactly
// how many bytes follow, so it can read EXACTLY that much from a pipe that stays open (shape B:
// on Windows the file job follows on the same pipe; no buffered stream may be used).
// Unknown fields are refused. Exactly one "scoring" and one "reputation" section; any number of
// "rule" sections up to kMaxRuleFiles. Every size and every hash is checked.
inline constexpr char kJobMagic[8] = {'M', 'I', 'E', 'W', 'J', 'O', 'B', '1'};
inline constexpr int kJobVersion = 1;
inline constexpr std::size_t kJobPrefixBytes = sizeof kJobMagic + 4;
inline constexpr std::size_t kMaxJobHeaderBytes = 1024 * 1024;
// The most bytes of one job or preparation (header and all sections). Not to be confused with
// sandbox::kMaxJobBytes (4096), the most bytes of the FILE JOB carried by the hand-over.
inline constexpr std::size_t kMaxPreparationBytes = 64u * 1024 * 1024;
inline constexpr std::size_t kMaxRuleFiles = 4096;
inline constexpr std::size_t kMaxDisplayNameBytes = 4096;
// In the file job of shape B the display name is cut to this, so the job stays far below
// sandbox::kMaxJobBytes.
inline constexpr std::size_t kMaxFileJobDisplayNameBytes = 1024;

// A worker serves this many files and ends (the design's upper bound is 200).
inline constexpr int kFilesPerWorker = 1;

// Proposed defaults for shape B (the shipped default stays shape A until the reviewer accepts).
inline constexpr int kProposedPoolSize = 2;              // at most the number of processor cores
inline constexpr double kDefaultMaxWaitingAgeSeconds = 300.0;
inline constexpr int kReadyTimeoutSeconds = 120;         // the most a file waits for a ready worker
inline constexpr int kPreparationSendTimeoutSeconds = 60;

// The worker's exit codes. 0: an answer frame was written. Any other value: no answer.
// The values keep clear of the codes a C runtime uses by itself (1, 2, 3 = abort on Windows),
// of sandbox::kOutOfMemoryExitCode (86) and of the sandbox's 87 and 88.
inline constexpr int kExitOk = 0;
inline constexpr int kExitUsage = 42;          // an argument it does not take
inline constexpr int kExitNotConfined = 43;    // the confinement is missing or could not be applied
inline constexpr int kExitBadJob = 44;         // the job / preparation / file job could not be read
inline constexpr int kExitTestSwitch = 45;     // a test switch reached a build without test hooks
inline constexpr int kExitNoFile = 46;         // a scan job without a handed-over file (shape A)
inline constexpr int kExitInternal = 47;       // anything else (an exception)
inline constexpr int kExitTestDied = 48;       // TEST BUILD ONLY: --test-die-while-waiting

inline constexpr const char* kAnswerOp = "worker.result";
inline constexpr const char* kReadyOp = "worker.ready";
inline constexpr const char* kPrestartedArgument = "--prestarted";

struct Job {
    std::string op = "scan";  // "scan" or "describe" (shape A), "prepare" (shape B)
    std::string display_name;
    bool use_reputation = true;
    // Only honoured by the test-hooks build of the worker; the shipped worker refuses a job
    // that carries one. Empty in a preparation (faults travel in the file job).
    std::string test_fault;
    std::string scoring_json;
    std::string reputation_json;
    std::vector<rules::RuleSource> rules;  // readable ones carry their text
};

// The bytes of a job. Empty with `error` set if the job breaks a limit.
std::string encode_job(const Job& job, std::string& error);

// Strict. Returns false with `error` set on any problem.
bool decode_job(std::span<const std::uint8_t> bytes, Job& out, std::string& error);

// From the 12 prefix bytes: the header length. False with `error` if the prefix is not a job's.
bool job_header_length(std::span<const std::uint8_t> prefix, std::size_t& header_length, std::string& error);
// From the header text: how many section bytes follow it. False with `error` on any problem.
bool job_sections_length(std::span<const std::uint8_t> header_text, std::size_t& sections_length, std::string& error);

// The FILE JOB of shape B: what the worker needs to know about its one file, carried by the
// hand-over and given to the worker only after the seal. JSON, ASCII, at most
// sandbox::kMaxJobBytes: {"v":1,"display_name":"...","test_fault":""}.
struct FileJob {
    std::string display_name;
    std::string test_fault;
};
std::string encode_file_job(const FileJob& job, std::string& error);
bool decode_file_job(std::span<const std::uint8_t> bytes, FileJob& out, std::string& error);

// ---- the parent's side --------------------------------------------------------------------

// What the engine is configured with: read once by the parent, sent with every job / preparation.
struct Config {
    std::string scoring_json;
    std::string reputation_json;
    std::vector<rules::RuleSource> rules;
    bool use_reputation = true;
};

// Reads the scoring table, the reputation list and the rule files. Returns false with `error`
// set if the scoring table or the reputation list cannot be read (a rules directory with no
// rule file is not an error: the worker then reports rules OFF).
bool load_config(const std::filesystem::path& scoring, const std::filesystem::path& reputation,
                 const std::filesystem::path& rules_directory, Config& out, std::string& error);

// The pool size proposed for a machine: kProposedPoolSize, at most the number of processor
// cores (1 when the system does not say).
int proposed_pool_size();

struct HostOptions {
    std::filesystem::path worker_program;
    sandbox::Limits limits;  // 1 GiB, 60 s by default; shape B: wall time counts from the hand-over
    // The parent hashes the file itself and refuses an answer that names other bytes.
    bool verify_identity = true;
    // Shape: 0 = one worker started per file (A); N > 0 = up to N pre-started workers (B).
    int pool_size = 0;
    double max_waiting_age_seconds = kDefaultMaxWaitingAgeSeconds;  // shape B: an older waiting worker is replaced
    int ready_timeout_seconds = kReadyTimeoutSeconds;                // shape B
    // TESTS ONLY, never set by the product:
    sandbox::RunOptions run;  // shape A: run.confine=false also passes --test-allow-unconfined
    std::string test_fault;   // put into the next job(s); needs the test-hooks worker
    // Shape B: the first N workers started get --test-die-while-waiting (test-hooks worker):
    // they read their preparation and end before their ready frame.
    int test_die_while_waiting = 0;
    // Shape B: every worker from the K-th started on (1-based) gets that argument too, so that
    // from then on no worker can be had (reviewer's condition 6: such a file is "not scanned").
    int test_die_while_waiting_from = 0;
    // Shape B: try a second hand-over to the same worker, right after the first and after the
    // collect; both must be refused (reviewer's condition 3 of M-13).
    bool test_second_hand_over = false;
};

// What a worker says about itself and its rule set (shape A: the "describe" job; shape B: the
// ready frame of the first worker of the current configuration).
struct Description {
    std::string engine_version;
    std::string profile;
    RulesState rules_state = RulesState::Off;
    std::string rules_sha256;
    std::map<std::string, std::string> rule_files;  // file -> SHA-256, the loaded ones
    std::vector<std::string> rule_errors;           // "<file>: <error>"
    std::string rules_library;                      // version of the rule library
    std::string preparation_sha256;                 // shape B: SHA-256 of the preparation bytes it read
    bool usable = false;
    std::string why_unusable;
    std::string confinement;  // what the worker says was applied (shape B: stage 1)
};

struct JobOutcome {
    ScanResult result;                 // always consistent(); never CLEAN after an abnormal end
    bool answered = false;             // true: `result` is the worker's own answer
    sandbox::ChildResult::End end = sandbox::ChildResult::End::StartFailed;
    int exit_code = 0;
    std::string detail;                // why, for logs (bounded, printable)
    std::string confinement;           // what the parent applied (ChildResult::confinement)
    std::string worker_confinement;    // what the worker says was applied
    std::string container_folder_note; // ChildResult::container_folder_note (Windows; reviewer's SW-1)
    std::uint64_t peak_memory_bytes = 0;
    double seconds = 0.0;
    std::int64_t worker_pid = 0;       // as the worker reports it (0 = unknown)
    int attempts = 0;                  // workers that got this file (shape B: 2 after a configuration mismatch)
    std::uint64_t worker_generation = 0;  // shape B: configuration generation of the worker that answered
    std::string second_hand_over;      // TESTS: what the second hand-over attempts gave
    // Measured by the worker:
    double setup_ms = 0.0;             // table, rules compiled, engine built (shape B: done before the file)
    double scan_ms = 0.0;              // the scan itself
    double worker_alive_ms = 0.0;      // shape A: from the first line of main to its answer
    double after_seal_ms = 0.0;        // shape B: from the seal to its answer
    // Measured by the PARENT (steady clock):
    double hash_ms = 0.0;              // the parent's own hashing of the file (identity check)
    double wait_ready_ms = 0.0;        // shape B: waiting for a ready worker (0 when the pool was full)
    double refill_ms = 0.0;            // shape B: starting replacements after the hand-over (in total_ms)
    double worker_run_ms = 0.0;        // A: start call to the worker's end; B: hand-over to the worker's end
    double start_overhead_ms = 0.0;    // A: worker_run_ms - worker_alive_ms (start, confine, end)
    double total_ms = 0.0;             // everything the parent did for this file
};

// What happened in the pool, for the run's log (shape B). One JSON object per event.
struct PoolEvent {
    std::string what;     // "started", "ready", "start_failed", "died_waiting", "too_old", "retired",
                          // "config_changed", "unusable"
    std::string detail;
    std::uint64_t generation = 0;
    double age_seconds = 0.0;
};

class Host {
public:
    Host(Config config, HostOptions options);
    ~Host();
    Host(const Host&) = delete;
    Host& operator=(const Host&) = delete;

    // Shape A: starts a worker with no file and asks what it runs with. Shape B: fills the
    // pool and waits for the first ready worker. The answer is kept and used for the results
    // the parent has to write itself. False with `error` set on failure.
    bool describe(Description& out, std::string& error);

    // Opens `path` once (links, directories, devices, cloud-only files are refused: "not
    // scanned", as the engine does) and scans it in a confined worker.
    JobOutcome scan_file(const std::filesystem::path& path);

    // Scans a file the caller has opened. `display_name` is text for people only.
    JobOutcome scan_open(io::File& file, const std::string& display_name);

    // Shape B: polls the waiting workers, sends the preparation to those that reached their
    // first stage of confinement, replaces the dead and the too old, starts new ones up to the
    // pool size. Never waits for a worker to start. Call it between files and while idle. With
    // `send_preparations` false (used while a file is being scanned) no preparation is written,
    // so nothing blocks on a worker that is still starting. Does nothing in shape A.
    void maintain(bool send_preparations = true);
    // Shape B: true when every place of the pool holds a ready worker.
    bool pool_full();
    // Shape B: a new configuration (rules, table or reputation list changed). Every waiting
    // worker is ended; only workers prepared with the new configuration are used afterwards.
    void set_config(Config config);
    // Ends every waiting worker (also done by the destructor).
    void shutdown();
    std::vector<PoolEvent> take_events();

    void set_test_fault(const std::string& fault) { options_.test_fault = fault; }
    std::uint64_t workers_started() const { return workers_started_; }
    std::uint64_t generation() const { return generation_; }
    const HostOptions& options() const { return options_; }

    struct Slot;  // a waiting worker (shape B)

private:
    ScanResult base_result(const std::string& display_name) const;
    JobOutcome abnormal(const sandbox::ChildResult& child, const std::string& reason, ScanResult base) const;
    sandbox::ChildResult run(const Job& job, const io::File* file, std::string& error);
    bool describe_one_shot(Description& out, std::string& error);
    JobOutcome scan_one_shot(io::File& file, const std::string& display_name);
    JobOutcome scan_pooled(io::File& file, const std::string& display_name);
    // One attempt of shape B. `config_mismatch` is set when the answer came from another
    // configuration (the caller then tries once more with a fresh worker).
    JobOutcome pooled_attempt(io::File& file, const std::string& display_name, int attempt, bool& config_mismatch);
    // The parent's own hash; false (with `refused` filled) if the file cannot be read.
    bool hash_for_identity(io::File& file, ScanResult& base, double& hash_ms, JobOutcome& refused);
    bool start_slot(std::string& error);
    void advance(Slot& slot, bool send_preparations);
    std::unique_ptr<Slot> take_ready(std::string& error, double& waited_ms);
    void event(const std::string& what, const std::string& detail, double age_seconds = 0.0);
    void retire(Slot& slot, const std::string& what, const std::string& detail);

    Config config_;
    HostOptions options_;
    bool described_ = false;
    Description description_;
    std::uint64_t workers_started_ = 0;
    // Shape B:
    std::uint64_t generation_ = 1;
    std::string preparation_;          // the preparation bytes of the current configuration
    std::string preparation_sha256_;   // their SHA-256
    std::deque<std::unique_ptr<Slot>> pool_;
    std::vector<PoolEvent> events_;
    int start_failures_in_a_row_ = 0;
    std::uint64_t maintain_round_ = 0;  // a worker started in a round gets its preparation in a later one
    std::string last_failure_;         // why the last worker could not be started or made ready
    std::string preparation_error_;    // the preparation could not be encoded (over a limit)
    int test_dying_left_ = 0;
};

// A short, printable form of text that came from a worker (never trusted): control
// characters and non-ASCII bytes replaced, at most `limit` characters.
std::string printable(const std::string& text, std::size_t limit = 300);

}  // namespace mie::worker
