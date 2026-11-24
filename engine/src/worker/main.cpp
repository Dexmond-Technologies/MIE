// mie-worker: the low-rights process that parses untrusted bytes. One file, then it ends.
//
// Two shapes (mie/worker.hpp, WORKER_NOTES.md):
//
//  A. no argument: ONE WORKER STARTED PER FILE.
//     1. one line on standard error ("main reached");
//     2. what needs the disk to start (the hash library) is touched BEFORE the confinement;
//     3. the full confinement (sandbox::enter_confinement); the worker REFUSES to go on if it
//        was not started confined or if it cannot be applied (exit 43, no answer);
//     4. the job (scoring table, reputation list, rule texts) from standard input; rules are
//        compiled from source; nothing is opened by path;
//     5. the file handed over at the start is scanned; 6. one answer frame; end.
//
//  B. --prestarted: a PRE-STARTED ONE-SHOT WORKER (reviewer's ruling M-13).
//     1. "main reached"; the hash library touched;
//     2. stage 1 of the confinement (sandbox::enter_confinement_stage1); refused: exit 43;
//     3. the PREPARATION from standard input, read with exact-length, unbuffered reads (the
//        file job follows on the same pipe on Windows): OUR rule texts and tables, never a byte
//        of a scanned file; rules compiled, engine built;
//     4. one READY frame on standard output, then wait;
//     5. sandbox::receive_file_and_seal: exactly one read-only regular file, the full
//        confinement applied, only then the file and the file job are given here (on any
//        failure the sandbox ends the process: 87 / 88, no answer);
//     6. the file is scanned; one answer frame; end. A second file is never served.
//
// Every read of standard input is the system's read call (read / _read), counted, never a
// buffered stream; every write of an answer is the system's write call in a loop, counted.
//
// The shipped program takes no argument but --prestarted and honours NO test switch: a job or
// file job that carries one is refused (exit 45). The same source is built a second time as
// mie-worker-testhooks with MIE_WORKER_TEST_HOOKS; that program is never installed or
// packaged, and only the tests start it.
//
// The Authenticode check is not wired in: every signature is "unavailable" (no cap).
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <process.h>
#if defined(MIE_WORKER_TEST_HOOKS)
#include <windows.h>  // the test switch "move-position" only
#endif
#else
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>

#include "mie/channel/frame.hpp"
#include "mie/engine.hpp"
#include "mie/hash.hpp"
#include "mie/result.hpp"
#include "mie/rules.hpp"
#include "mie/sandbox.hpp"
#include "mie/scoring.hpp"
#include "mie/version.hpp"
#include "mie/worker.hpp"

namespace {

using nlohmann::json;
using Clock = std::chrono::steady_clock;

double milliseconds_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

// The steady clock in nanoseconds. On Linux (CLOCK_MONOTONIC) and Windows (the performance
// counter) this clock is the same for every process of the machine, so the parent can put the
// worker's moments on its own time line (shape B's breakdown of the time from the hand-over).
std::int64_t steady_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}

std::int64_t own_process_id() {
#if defined(_WIN32)
    return static_cast<std::int64_t>(_getpid());
#else
    return static_cast<std::int64_t>(::getpid());
#endif
}

void say(const std::string& text) {
    std::fputs(("mie-worker: " + text + "\n").c_str(), stderr);
    std::fflush(stderr);
}

// Reads EXACTLY `size` bytes from standard input with the system's read call (no buffered
// stream: in shape B on Windows the file job follows on the same pipe and must stay there).
// False on an error or an early end.
bool read_exact_from_standard_input(std::uint8_t* data, std::size_t size) {
    std::size_t done = 0;
    while (done < size) {
#if defined(_WIN32)
        const std::size_t step = size - done < (1u << 20) ? size - done : (1u << 20);
        const int n = _read(0, data + done, static_cast<unsigned int>(step));
        if (n <= 0) {
            return false;
        }
#else
        const ssize_t n = ::read(0, data + done, size - done);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
#endif
        done += static_cast<std::size_t>(n);
    }
    return true;
}

// One job or preparation from standard input: it delimits itself (prefix, header, sections),
// so exactly its bytes are read and nothing after them.
bool read_job_bytes(std::vector<std::uint8_t>& out, std::string& error) {
    out.assign(mie::worker::kJobPrefixBytes, 0);
    if (!read_exact_from_standard_input(out.data(), out.size())) {
        error = "the job's first bytes could not be read";
        return false;
    }
    std::size_t header_length = 0;
    if (!mie::worker::job_header_length(out, header_length, error)) {
        return false;
    }
    out.resize(mie::worker::kJobPrefixBytes + header_length);
    if (!read_exact_from_standard_input(out.data() + mie::worker::kJobPrefixBytes, header_length)) {
        error = "the job's header could not be read";
        return false;
    }
    std::size_t sections_length = 0;
    if (!mie::worker::job_sections_length(
            std::span<const std::uint8_t>(out.data() + mie::worker::kJobPrefixBytes, header_length), sections_length,
            error)) {
        return false;
    }
    const std::size_t before = out.size();
    out.resize(before + sections_length);
    if (sections_length > 0 && !read_exact_from_standard_input(out.data() + before, sections_length)) {
        error = "the job's sections could not be read";
        return false;
    }
    return true;
}

// Writes bytes to standard output with the system's own write call, in a loop, and counts
// what the system took. No buffered stream is involved, so nothing depends on a flush when
// the process ends. Returns the number of bytes the system accepted.
std::size_t write_all_to_standard_output(const char* data, std::size_t size) {
    std::size_t done = 0;
    while (done < size) {
#if defined(_WIN32)
        const std::size_t step = size - done < (1u << 20) ? size - done : (1u << 20);
        const int n = _write(1, data + done, static_cast<unsigned int>(step));
        if (n <= 0) {
            break;
        }
#else
        const ssize_t n = ::write(1, data + done, size - done);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
#endif
        done += static_cast<std::size_t>(n);
    }
    return done;
}

#if defined(MIE_WORKER_TEST_HOOKS)
// TEST BUILD ONLY: a switch that takes effect late ("answer-none", "answer-half",
// "answer-extra", "answer-wrong-file", "move-position", "pause-before-read",
// "rules-mismatch", "rules-mismatch-once"); empty = none. Set from the job's test_fault.
std::string g_answer_fault;
#endif

bool write_frame(const char* op, const json& body) {
    mie::channel::Message message;
    message.id = 1;
    message.type = mie::channel::MessageType::Response;
    message.op = op;
    message.body = body;
    std::string frame = mie::channel::encode_frame(message);
    if (frame.empty()) {
        return false;
    }
    std::size_t to_write = frame.size();
#if defined(MIE_WORKER_TEST_HOOKS)
    // The worker then ends with exit code 0, as a worker would whose answer was lost on the way.
    if (std::strcmp(op, mie::worker::kAnswerOp) == 0) {
        if (g_answer_fault == "answer-none") {
            to_write = 0;
        } else if (g_answer_fault == "answer-half") {
            to_write = frame.size() / 2;
        } else if (g_answer_fault == "answer-extra") {
            frame += "extra bytes after the frame";
            to_write = frame.size();
        }
    }
#endif
    const std::size_t written = write_all_to_standard_output(frame.data(), to_write);
    // For the parent's log when a frame does not arrive whole: what the system took from this side.
    say(std::string(op) + " frame of " + std::to_string(frame.size()) + " bytes: the system took " +
        std::to_string(written) + " of " + std::to_string(to_write));
    return written == to_write;
}

bool write_answer(const json& body) { return write_frame(mie::worker::kAnswerOp, body); }

#if defined(MIE_WORKER_TEST_HOOKS)
// TEST BUILD ONLY. Makes this worker fail in a chosen way after it is confined and has
// read its job, so the tests can show what the parent does with a worker that hangs,
// dies or runs out of memory.
void test_fault(const std::string& kind) {
    if (kind == "spin") {
        volatile bool keep_going = true;
        volatile unsigned long long counter = 0;
        while (keep_going) {
            counter = counter + 1;
        }
    } else if (kind == "crash") {
#if defined(_WIN32)
        // An access violation: on Windows abort() is an ordinary exit with code 3, not a crash.
        volatile int* nowhere = nullptr;
        *nowhere = 1;
#else
        std::abort();
#endif
    } else if (kind == "allocate") {
        // Until an allocation is refused: exit_on_out_of_memory() then ends the process
        // with the out-of-memory exit code (or the parent's watch on memory kills it).
        std::vector<std::unique_ptr<char[]>> blocks;
        volatile bool keep_going = true;
        while (keep_going) {
            const std::size_t size = 16u * 1024 * 1024;
            std::unique_ptr<char[]> block(new char[size]);
            std::memset(block.get(), 0x5A, size);
            blocks.push_back(std::move(block));
        }
    }
}

bool is_late_fault(const std::string& fault) {
    return fault.rfind("answer-", 0) == 0 || fault == "move-position" || fault == "pause-before-read" ||
           fault == "rules-mismatch" || fault == "rules-mismatch-once";
}
#endif

// Applies a test fault, or refuses it in the shipped build. Returns an exit code to end with,
// or 0 to go on.
int handle_test_fault(const std::string& fault) {
    if (fault.empty()) {
        return 0;
    }
#if defined(MIE_WORKER_TEST_HOOKS)
    if (is_late_fault(fault)) {
        g_answer_fault = fault;  // takes effect later
    } else {
        test_fault(fault);
    }
    return 0;
#else
    say("the job carries a test switch; this build has no test hooks");
    return mie::worker::kExitTestSwitch;
#endif
}

// Everything the scan needs, built once from the job / preparation. The engine refers to the
// table and the rule set, so all of it lives at one fixed place.
struct Prepared {
    mie::ScoringTable table;
    bool table_ok = false;
    std::string table_error;
    std::unique_ptr<mie::rules::RuleSet> rules;
    std::string reputation_json;
    mie::UnavailableSignatureVerifier no_signatures;
    std::unique_ptr<mie::Engine> engine;
    bool usable = false;
    std::string why_unusable;
    double setup_ms = 0.0;
};

std::unique_ptr<Prepared> prepare(mie::worker::Job& job) {
    const Clock::time_point start = Clock::now();
    auto prepared = std::make_unique<Prepared>();
    prepared->table_ok = mie::load_scoring_table(job.scoring_json, prepared->table, prepared->table_error);
    prepared->rules = mie::rules::RuleSet::load_sources(job.rules);
    job.rules.clear();
    job.rules.shrink_to_fit();
    prepared->reputation_json = std::move(job.reputation_json);
    mie::EngineOptions options;
    options.use_reputation = job.use_reputation;
    prepared->engine = std::make_unique<mie::Engine>(prepared->table, *prepared->rules, prepared->reputation_json,
                                                     options, &prepared->no_signatures);
    prepared->usable = prepared->table_ok && prepared->engine->usable(prepared->why_unusable);
    if (!prepared->table_ok) {
        prepared->why_unusable = "scoring table: " + prepared->table_error;
    }
    prepared->setup_ms = milliseconds_since(start);
    return prepared;
}

// What a worker says about itself: the describe answer (A) and the ready frame (B).
void describe_into(json& body, const Prepared& prepared) {
    json rule_errors = json::array();
    for (const mie::rules::RuleFileError& rule_error : prepared.rules->errors()) {
        rule_errors.push_back(mie::worker::printable(rule_error.file + ": " + rule_error.error, 400));
    }
    body["engine_version"] = mie::kEngineVersion;
    body["profile"] = prepared.table_ok ? prepared.table.profile : std::string();
    body["rules_state"] = mie::to_string(prepared.rules->state());
    body["rules_sha256"] = prepared.rules->sha256();
    body["rule_files"] = prepared.rules->file_hashes();
    body["rule_errors"] = rule_errors;
    body["rules_library"] = mie::rules::RuleSet::library_version();
    body["usable"] = prepared.usable;
    body["why_unusable"] = prepared.why_unusable;
    body["setup_ms"] = prepared.setup_ms;
}

#if defined(MIE_WORKER_TEST_HOOKS)
void test_hooks_before_read(const mie::io::File& file) {
    if (g_answer_fault == "pause-before-read") {
        // TEST BUILD ONLY: three seconds before the first read of the file, so a test can change
        // or replace the file in that window. A busy wait on the steady clock (clock_gettime,
        // normally answered without a system call); no sleep call, none is on the allow list.
        const Clock::time_point until = Clock::now() + std::chrono::seconds(3);
        volatile unsigned long long turns = 0;
        while (Clock::now() < until) {
            turns = turns + 1;
        }
        say("test: paused 3 seconds before the first read of the file");
    }
    if (g_answer_fault == "move-position") {
        // TEST BUILD ONLY (reviewer's question SB-2): the handed-over handle shares its read
        // position with the parent's. Move that position with a plain, non-positional read,
        // then answer normally: nothing on either side may depend on the position.
        char scratch[4096];
#if defined(_WIN32)
        const HANDLE handle = reinterpret_cast<HANDLE>(file.native_handle());
        LARGE_INTEGER to;
        to.QuadPart = 7;
        const BOOL moved = ::SetFilePointerEx(handle, to, nullptr, FILE_BEGIN);
        DWORD got = 0;
        const BOOL read_ok = ::ReadFile(handle, scratch, static_cast<DWORD>(sizeof scratch), &got, nullptr);
        say("test: moved the shared read position: SetFilePointerEx " + std::string(moved ? "ok" : "refused") +
            ", plain ReadFile " + (read_ok ? "read " + std::to_string(got) + " bytes" : "refused"));
#else
        errno = 0;
        const ssize_t got = ::read(static_cast<int>(file.native_handle()), scratch, sizeof scratch);
        say("test: moved the shared read position: plain read " +
            (got >= 0 ? "read " + std::to_string(got) + " bytes" : "refused, errno " + std::to_string(errno)));
#endif
    }
}

void test_hooks_on_result(mie::ScanResult& result) {
    if (g_answer_fault == "answer-wrong-file" && result.state != mie::ScanState::NotScanned) {
        // TEST BUILD ONLY: a well-formed, consistent answer that speaks about another file.
        result.hashes.sha256 = std::string(64, '0');
        result.subject.sha256 = result.hashes.sha256;
    }
    if ((g_answer_fault == "rules-mismatch" || g_answer_fault == "rules-mismatch-once") &&
        result.rules_state != mie::RulesState::Off) {
        // TEST BUILD ONLY: an answer that claims other rules than the worker was prepared with.
        result.rules_sha256 = std::string(64, 'f');
    }
}
#endif

// Scans the file and writes the answer. `body` already holds what the shape adds. `sealed_at`
// (shape B): the moment of the seal; the answer then carries the time from it to the answer.
int scan_and_answer(const Prepared& prepared, mie::io::File& file, const std::string& display_name, json body,
                    const Clock::time_point* sealed_at = nullptr) {
#if defined(MIE_WORKER_TEST_HOOKS)
    test_hooks_before_read(file);
#endif
    const Clock::time_point scan_start = Clock::now();
    mie::ScanResult result = prepared.engine->scan_open(file, display_name);
#if defined(MIE_WORKER_TEST_HOOKS)
    test_hooks_on_result(result);
#endif
    body["kind"] = "scan";
    body["scan_ms"] = milliseconds_since(scan_start);
    std::string why_inconsistent;
    if (!mie::consistent(result, why_inconsistent)) {
        say("the engine produced an inconsistent result: " + why_inconsistent);
        return mie::worker::kExitInternal;
    }
    body["result"] = json::parse(mie::to_json(result));
    if (sealed_at != nullptr) {
        body["after_seal_ms"] = milliseconds_since(*sealed_at);
        body["scan_done_ns"] = steady_ns();
    }
    if (write_answer(body)) {
        // After the answer: the moment it was handed to the system, on standard error (it cannot
        // be in the answer itself). The parent reads it for the breakdown.
        say("answer written at " + std::to_string(steady_ns()));
        return mie::worker::kExitOk;
    }
    // The result does not fit one frame (very many or very long findings). The findings
    // are left out and the result says so; it is then not a full result and never CLEAN.
    if (result.state != mie::ScanState::NotScanned) {
        const std::string note = "the result was larger than one message; its findings were left out";
        result.reason = result.reason.empty() ? note : result.reason + "; " + note;
        result.state = mie::ScanState::NotFullyScanned;
        result.verdict = mie::kNotFullyScannedVerdict;
        result.findings.clear();
        body["result"] = json::parse(mie::to_json(result));
        if (write_answer(body)) {
            return mie::worker::kExitOk;
        }
    }
    say("the answer could not be written");
    return mie::worker::kExitInternal;
}

// ---- shape A: one worker started per file ---------------------------------------------------
int run_per_file(bool allow_unconfined) {
    const Clock::time_point main_start = Clock::now();
    std::string confinement;
    if (std::getenv("MIE_SANDBOX") != nullptr) {
        std::string error;
        if (!mie::sandbox::enter_confinement(confinement, error)) {
            say("the confinement could not be applied: " + error);
            return mie::worker::kExitNotConfined;
        }
    } else if (allow_unconfined) {
        confinement = "WEAKER: not confined (test switch --test-allow-unconfined)";
    } else {
        say("refusing to run: this process was not started confined");
        return mie::worker::kExitNotConfined;
    }

    // From here on nothing is opened by path.
    std::vector<std::uint8_t> job_bytes;
    std::string error;
    mie::worker::Job job;
    if (!read_job_bytes(job_bytes, error) || !mie::worker::decode_job(job_bytes, job, error) || job.op == "prepare") {
        say(error.empty() ? "a preparation was sent to a worker started per file" : error);
        return mie::worker::kExitBadJob;
    }
    job_bytes.clear();
    job_bytes.shrink_to_fit();
    if (const int code = handle_test_fault(job.test_fault); code != 0) {
        return code;
    }
    const std::string display_name = job.display_name;
    const std::string op = job.op;
    const std::unique_ptr<Prepared> prepared = prepare(job);

    json body = {{"confinement", confinement}, {"self", mie::sandbox::describe_self()}, {"pid", own_process_id()},
                 {"setup_ms", prepared->setup_ms}};
    if (op == "describe") {
        describe_into(body, *prepared);
        body["kind"] = "describe";
        body["alive_ms"] = milliseconds_since(main_start);
        return write_answer(body) ? mie::worker::kExitOk : mie::worker::kExitInternal;
    }
    if (!prepared->table_ok) {
        // Without a scoring table no result can even be labelled; the parent writes it.
        say(prepared->why_unusable);
        return mie::worker::kExitBadJob;
    }
    std::string file_error;
    const std::unique_ptr<mie::io::File> file = mie::sandbox::inherited_file(file_error);
    if (!file) {
        say("no file was handed over: " + file_error);
        return mie::worker::kExitNoFile;
    }
    // From the first line here to the answer: what the parent's time for this worker exceeds
    // this by is the cost of starting, confining and ending the process.
    body["alive_ms"] = milliseconds_since(main_start);
    return scan_and_answer(*prepared, *file, display_name, body);
}

// ---- shape B: a pre-started one-shot worker ---------------------------------------------------
int run_prestarted(bool die_while_waiting) {
    if (std::getenv("MIE_SANDBOX") == nullptr) {
        say("refusing to run: a pre-started worker must be started confined");
        return mie::worker::kExitNotConfined;
    }
    std::string stage1;
    std::string error;
    if (!mie::sandbox::enter_confinement_stage1(stage1, error)) {
        say("stage 1 of the confinement could not be applied: " + error);
        return mie::worker::kExitNotConfined;
    }

    // The preparation: OUR rule texts and tables, read with exact-length reads.
    std::vector<std::uint8_t> preparation;
    mie::worker::Job job;
    if (!read_job_bytes(preparation, error) || !mie::worker::decode_job(preparation, job, error)) {
        say(error);
        return mie::worker::kExitBadJob;
    }
    if (job.op != "prepare" || !job.test_fault.empty()) {
        say("the preparation is not a preparation (operation, or a test switch in it)");
        return mie::worker::kExitBadJob;
    }
    const std::string preparation_sha256 = mie::sha256_hex(preparation);
    preparation.clear();
    preparation.shrink_to_fit();
    (void)die_while_waiting;
#if defined(MIE_WORKER_TEST_HOOKS)
    if (die_while_waiting) {
        // TEST BUILD ONLY: a worker that dies while it waits, before it could ever be used.
        say("test: ending while waiting, before the ready frame");
        return mie::worker::kExitTestDied;
    }
#endif
    const std::unique_ptr<Prepared> prepared = prepare(job);

    json ready = {{"kind", "ready"},
                  {"confinement", stage1},
                  {"self", mie::sandbox::describe_self()},
                  {"pid", own_process_id()},
                  {"preparation_sha256", preparation_sha256}};
    describe_into(ready, *prepared);
    if (!write_frame(mie::worker::kReadyOp, ready)) {
        say("the ready frame could not be written");
        return mie::worker::kExitInternal;
    }

    // Wait for the one file. This returns only with the full confinement applied; on any
    // failure the sandbox ends this process (87: hand-over not as required or seal failed;
    // 88: the parent ended this worker unused).
    std::vector<std::uint8_t> file_job_bytes;
    std::string sealed;
    const std::unique_ptr<mie::io::File> file = mie::sandbox::receive_file_and_seal(file_job_bytes, sealed);
    const Clock::time_point sealed_at = Clock::now();
    const std::int64_t sealed_ns = steady_ns();
    if (!file) {
        say("no file came with the hand-over");  // not expected: the sandbox ends the process instead
        return mie::worker::kExitNoFile;
    }
    // From here on: the full confinement; the file's bytes are hostile.
    mie::worker::FileJob file_job;
    if (!mie::worker::decode_file_job(file_job_bytes, file_job, error)) {
        say(error);
        return mie::worker::kExitBadJob;
    }
    if (const int code = handle_test_fault(file_job.test_fault); code != 0) {
        return code;
    }
    if (!prepared->table_ok) {
        say(prepared->why_unusable);
        return mie::worker::kExitBadJob;
    }
    json body = {{"confinement", sealed},
                 {"self", mie::sandbox::describe_self()},
                 {"pid", own_process_id()},
                 {"setup_ms", prepared->setup_ms},
                 {"preparation_sha256", preparation_sha256},
                 {"sealed_ns", sealed_ns}};
    return scan_and_answer(*prepared, *file, file_job.display_name, body, &sealed_at);
}

int run(int argc, char** argv) {
    say("main reached");
    bool allow_unconfined = false;
    bool prestarted = false;
    bool die_while_waiting = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], mie::worker::kPrestartedArgument) == 0) {
            prestarted = true;
#if defined(MIE_WORKER_TEST_HOOKS)
        } else if (std::strcmp(argv[i], "--test-allow-unconfined") == 0) {
            allow_unconfined = true;
        } else if (std::strcmp(argv[i], "--test-die-while-waiting") == 0) {
            die_while_waiting = true;
#endif
        } else {
            say("unknown argument");
            return mie::worker::kExitUsage;
        }
    }
    // Before any confinement: the hash library reads what it needs to start. Trusted input
    // only (nothing); no untrusted byte has been read.
    (void)mie::sha256_hex(std::span<const std::uint8_t>{});
    mie::sandbox::exit_on_out_of_memory();
    if (prestarted) {
        if (allow_unconfined) {
            say("a pre-started worker cannot run unconfined");
            return mie::worker::kExitUsage;
        }
        return run_prestarted(die_while_waiting);
    }
    if (die_while_waiting) {
        say("--test-die-while-waiting needs --prestarted");
        return mie::worker::kExitUsage;
    }
    return run_per_file(allow_unconfined);
}

}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        const int code = run(argc, argv);
        // Everything of run() is torn down here (the engine, the compiled rules, the file); what
        // is left is the C runtime's own end. The parent reads this moment for the breakdown.
        say("main ends at " + std::to_string(steady_ns()));
        return code;
    } catch (const std::bad_alloc&) {
        std::fputs("mie-worker: out of memory\n", stderr);
        return mie::sandbox::kOutOfMemoryExitCode;
    } catch (const std::exception& problem) {
        std::fputs("mie-worker: ", stderr);
        std::fputs(mie::worker::printable(problem.what()).c_str(), stderr);
        std::fputs("\n", stderr);
        return mie::worker::kExitInternal;
    } catch (...) {
        std::fputs("mie-worker: an unknown error\n", stderr);
        return mie::worker::kExitInternal;
    }
}
