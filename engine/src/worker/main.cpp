// mie-worker: the low-rights process that parses untrusted bytes. One file, then it ends.
//
// What it does, in this order (WORKER_NOTES.md):
//   1. one line on standard error ("main reached"), so a parent that gets nothing else
//      knows the program started;
//   2. what needs the disk to start (the hash library) is touched BEFORE the confinement;
//      no untrusted byte has been read yet;
//   3. the confinement: the worker REFUSES to go on if it was not started confined or if
//      the confinement cannot be applied (exit code 43, no answer). There is no silent
//      weaker run;
//   4. the job is read from standard input: scoring table, reputation list and the text of
//      every rule file. The worker opens no path. Rules are compiled from source;
//   5. the one file handed over by the parent is scanned through the pipeline;
//   6. the answer is written as one channel frame on standard output, with the system's write
//      call in a loop and the count checked: no buffered stream, nothing left to a flush at exit.
//
// The shipped program takes NO arguments and honours NO test switch: a job that carries a
// test fault is refused (exit code 45). The same source is built a second time as
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

// Standard input to its end, but never more than the job limit plus one byte.
bool read_job_bytes(std::vector<std::uint8_t>& out) {
    out.clear();
    std::vector<std::uint8_t> block(1u << 16);
    for (;;) {
        const std::size_t got = std::fread(block.data(), 1, block.size(), stdin);
        if (got > 0) {
            const std::size_t before = out.size();
            out.resize(before + got);
            std::memcpy(out.data() + before, block.data(), got);
            if (out.size() > mie::worker::kMaxJobBytes) {
                return false;
            }
        }
        if (got < block.size()) {
            return std::ferror(stdin) == 0;
        }
    }
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
// "answer-extra", "answer-wrong-file", "move-position"); empty = none. Set from the job's test_fault.
std::string g_answer_fault;
#endif

bool write_answer(const json& body) {
    mie::channel::Message message;
    message.id = 1;
    message.type = mie::channel::MessageType::Response;
    message.op = mie::worker::kAnswerOp;
    message.body = body;
    std::string frame = mie::channel::encode_frame(message);
    if (frame.empty()) {
        return false;
    }
    std::size_t to_write = frame.size();
#if defined(MIE_WORKER_TEST_HOOKS)
    // The worker then ends with exit code 0, as a worker would whose answer was lost on the way.
    if (g_answer_fault == "answer-none") {
        to_write = 0;
    } else if (g_answer_fault == "answer-half") {
        to_write = frame.size() / 2;
    } else if (g_answer_fault == "answer-extra") {
        frame += "extra bytes after the frame";
        to_write = frame.size();
    }
#endif
    const std::size_t written = write_all_to_standard_output(frame.data(), to_write);
    // For the parent's log when an answer does not arrive whole: what the system took from this side.
    say("answer frame of " + std::to_string(frame.size()) + " bytes: the system took " + std::to_string(written) +
        " of " + std::to_string(to_write));
    return written == to_write;
}

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
#endif

int run(int argc, char** argv) {
    const Clock::time_point main_start = Clock::now();
    say("main reached");

    bool allow_unconfined = false;
#if defined(MIE_WORKER_TEST_HOOKS)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--test-allow-unconfined") == 0) {
            allow_unconfined = true;
        } else {
            say("unknown argument");
            return mie::worker::kExitUsage;
        }
    }
#else
    (void)argv;
    if (argc > 1) {
        say("this program takes no arguments");
        return mie::worker::kExitUsage;
    }
#endif

    // Before the confinement: the hash library reads what it needs to start. Trusted
    // input only (nothing); no untrusted byte has been read.
    (void)mie::sha256_hex(std::span<const std::uint8_t>{});
    mie::sandbox::exit_on_out_of_memory();

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
    const Clock::time_point setup_start = Clock::now();
    std::vector<std::uint8_t> job_bytes;
    if (!read_job_bytes(job_bytes)) {
        say("the job could not be read or is over the limit");
        return mie::worker::kExitBadJob;
    }
    mie::worker::Job job;
    std::string error;
    if (!mie::worker::decode_job(job_bytes, job, error)) {
        say(error);
        return mie::worker::kExitBadJob;
    }
    job_bytes.clear();
    job_bytes.shrink_to_fit();

    if (!job.test_fault.empty()) {
#if defined(MIE_WORKER_TEST_HOOKS)
        if (job.test_fault.rfind("answer-", 0) == 0 || job.test_fault == "move-position") {
            g_answer_fault = job.test_fault;  // takes effect when the answer is written
        } else {
            test_fault(job.test_fault);
        }
#else
        say("the job carries a test switch; this build has no test hooks");
        return mie::worker::kExitTestSwitch;
#endif
    }

    mie::ScoringTable table;
    std::string table_error;
    const bool table_ok = mie::load_scoring_table(job.scoring_json, table, table_error);
    const std::unique_ptr<mie::rules::RuleSet> rules = mie::rules::RuleSet::load_sources(job.rules);
    job.rules.clear();
    job.rules.shrink_to_fit();

    mie::EngineOptions options;
    options.use_reputation = job.use_reputation;
    const mie::UnavailableSignatureVerifier no_signatures;
    const mie::Engine engine(table, *rules, job.reputation_json, options, &no_signatures);
    std::string why_unusable;
    bool usable = table_ok && engine.usable(why_unusable);
    if (!table_ok) {
        why_unusable = "scoring table: " + table_error;
    }
    const double setup_ms = milliseconds_since(setup_start);

    json body = {{"confinement", confinement},
                 {"self", mie::sandbox::describe_self()},
                 {"pid", own_process_id()},
                 {"setup_ms", setup_ms}};

    if (job.op == "describe") {
        json rule_errors = json::array();
        for (const mie::rules::RuleFileError& rule_error : rules->errors()) {
            rule_errors.push_back(mie::worker::printable(rule_error.file + ": " + rule_error.error, 400));
        }
        body["kind"] = "describe";
        body["engine_version"] = mie::kEngineVersion;
        body["profile"] = table_ok ? table.profile : std::string();
        body["rules_state"] = mie::to_string(rules->state());
        body["rules_sha256"] = rules->sha256();
        body["rule_files"] = rules->file_hashes();
        body["rule_errors"] = rule_errors;
        body["rules_library"] = mie::rules::RuleSet::library_version();
        body["usable"] = usable;
        body["why_unusable"] = why_unusable;
        body["alive_ms"] = milliseconds_since(main_start);
        if (!write_answer(body)) {
            say("the answer could not be written");
            return mie::worker::kExitInternal;
        }
        return mie::worker::kExitOk;
    }

    if (!table_ok) {
        // Without a scoring table no result can even be labelled; the parent writes it.
        say(why_unusable);
        return mie::worker::kExitBadJob;
    }

    std::string file_error;
    const std::unique_ptr<mie::io::File> file = mie::sandbox::inherited_file(file_error);
    if (!file) {
        say("no file was handed over: " + file_error);
        return mie::worker::kExitNoFile;
    }

#if defined(MIE_WORKER_TEST_HOOKS)
    if (g_answer_fault == "move-position") {
        // TEST BUILD ONLY (reviewer's question SB-2): the handed-over handle shares its read
        // position with the parent's. Move that position with a plain, non-positional read,
        // then answer normally: nothing on either side may depend on the position.
        char scratch[4096];
#if defined(_WIN32)
        const HANDLE handle = reinterpret_cast<HANDLE>(file->native_handle());
        LARGE_INTEGER to;
        to.QuadPart = 7;
        const BOOL moved = ::SetFilePointerEx(handle, to, nullptr, FILE_BEGIN);
        DWORD got = 0;
        const BOOL read_ok = ::ReadFile(handle, scratch, static_cast<DWORD>(sizeof scratch), &got, nullptr);
        say("test: moved the shared read position: SetFilePointerEx " + std::string(moved ? "ok" : "refused") +
            ", plain ReadFile " + (read_ok ? "read " + std::to_string(got) + " bytes" : "refused"));
#else
        errno = 0;
        const ssize_t got = ::read(static_cast<int>(file->native_handle()), scratch, sizeof scratch);
        say("test: moved the shared read position: plain read " +
            (got >= 0 ? "read " + std::to_string(got) + " bytes" : "refused, errno " + std::to_string(errno)));
#endif
    }
#endif
    const Clock::time_point scan_start = Clock::now();
    mie::ScanResult result = engine.scan_open(*file, job.display_name);
#if defined(MIE_WORKER_TEST_HOOKS)
    if (g_answer_fault == "answer-wrong-file" && result.state != mie::ScanState::NotScanned) {
        // TEST BUILD ONLY: a well-formed, consistent answer that speaks about another file.
        result.hashes.sha256 = std::string(64, '0');
        result.subject.sha256 = result.hashes.sha256;
    }
#endif
    body["kind"] = "scan";
    body["scan_ms"] = milliseconds_since(scan_start);
    std::string why_inconsistent;
    if (!mie::consistent(result, why_inconsistent)) {
        say("the engine produced an inconsistent result: " + why_inconsistent);
        return mie::worker::kExitInternal;
    }
    body["result"] = json::parse(mie::to_json(result));
    // From the first line of main to here: what the parent's time for this worker exceeds this
    // by is the cost of starting, confining and ending the process.
    body["alive_ms"] = milliseconds_since(main_start);
    if (write_answer(body)) {
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

}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        return run(argc, argv);
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
