// Confinement of the worker process: the child that parses untrusted bytes.
//
// Reviewer's conditions M-2 and M-9 and the design's limits:
//   - the worker has NO network: Windows AppContainer with no capabilities; Linux seccomp
//     filter that refuses socket creation and connection (and Landlock where the kernel has it);
//   - the worker opens no path: the parent opens the file and hands over ONE read-only handle;
//   - memory and time limits are enforced from outside the worker (Windows job object;
//     Linux address-space limit plus the parent watching resident memory; the parent kills
//     the child at the time limit);
//   - a killed, crashed or memory-exhausted worker is a RESULT (ChildResult), never an
//     exception and never a hang of the parent.
//
// Nothing here falls back silently to a weaker child: if a required part cannot be
// applied the run ends as StartFailed with the reason. `allow_weaker` exists for tests that
// want to see what is missing, and is never set by the product.
//
// What each mechanism removes and what it does not is written at each system call in
// sandbox_posix.cpp and sandbox_win.cpp, and in SANDBOX_NOTES.md.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "mie/io.hpp"

namespace mie::sandbox {

inline constexpr std::uint64_t kWorkerMemoryLimitBytes = 1024ull * 1024 * 1024;  // 1 GiB
inline constexpr int kWorkerWallLimitSeconds = 60;

// Exit code of a child that ran out of its memory limit and noticed it itself (an allocation
// was refused). The parent reports it as KilledByMemoryLimit. See exit_on_out_of_memory().
inline constexpr int kOutOfMemoryExitCode = 86;

struct Limits {
    std::uint64_t memory_bytes = kWorkerMemoryLimitBytes;
    int wall_seconds = kWorkerWallLimitSeconds;
};

// `allow_weaker`, `test_break_confinement` and `test_without_mitigations` work ONLY in the
// test build of this library (compile definition MIE_SANDBOX_TEST_HOOKS; library target
// mie_sandbox_testhooks). In the shipped build they are ignored: nothing, and no environment
// variable, can make a confined run weaker; it is applied in full or the start fails.
struct RunOptions {
    // false: the child is started with the limits but without the confinement. Only for
    // tests (the control case that shows a refusal comes from the confinement).
    bool confine = true;
    // true: go on with whatever part of the confinement could be applied and say so in
    // ChildResult::confinement ("WEAKER: ..."). Only for tests.
    bool allow_weaker = false;
    // true: behave as if applying the confinement had failed. Only for the test that shows
    // the result is then StartFailed and not a silent unconfined run.
    bool test_break_confinement = false;
    // true (Windows): start in the AppContainer but without the mitigation and child-process
    // policies, to tell whether a policy keeps a child from starting. The result says WEAKER.
    // Only for tests.
    bool test_without_mitigations = false;
};

struct ChildResult {
    enum class End {
        Exited,               // the child ended by itself; exit_code is its code
        KilledByTimeLimit,    // the parent killed it at Limits::wall_seconds
        KilledByMemoryLimit,  // over Limits::memory_bytes: killed, or an allocation was refused
        Crashed,              // ended by a signal / an exception, or broke the output limit
        StartFailed,          // not started, or the confinement could not be applied
    };
    End end = End::StartFailed;
    int exit_code = 0;
    std::string output;       // the child's standard output, at most max_output_bytes
    std::string detail;       // why, in words; also the first part of the child's standard error
    std::string confinement;  // what was actually applied, e.g. "appcontainer+job", "seccomp+landlock"
    // Windows: not empty when the worker container's own folder could NOT be emptied before
    // this worker started (or its place is not known): the sentence to put in the result
    // header of the scan (reviewer's ruling on SW-1). Empty when the folder was emptied, and
    // always on Linux, where the worker has no folder.
    std::string container_folder_note;
    std::uint64_t peak_memory_bytes = 0;  // measured by the system, not by the child (0 = unknown)
    double seconds = 0.0;                 // wall time from start to end
};

const char* to_string(ChildResult::End end);

// Starts `program` with `arguments` as a confined child, writes `input` to its standard
// input, collects its standard output, and waits until it ends or a limit is reached.
// `inherited_file`, if not null, is handed to the child as its one open, read-only file;
// the child gets it with inherited_file(). Never throws; every outcome is a ChildResult.
ChildResult run_confined(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                         const io::File* inherited_file, std::span<const std::uint8_t> input,
                         const Limits& limits, std::size_t max_output_bytes,
                         const RunOptions& options = RunOptions{});

// ---- the child's side ----------------------------------------------------------------------

// To be called by the worker program first thing in main(), before it reads one untrusted
// byte. Linux: applies no-new-privileges, Landlock (where the kernel has it) and the seccomp
// filter to the calling process, and tells the parent, which sends the input only after
// that. Windows: the confinement was applied by the parent when the process was created;
// this checks that it is really there. Returns false with `error` set if the process is not
// confined as required; the worker must then exit without reading its input.
bool enter_confinement(std::string& what_applied, std::string& error);

// The file the parent handed over, or nullptr (with `error` set) if there is none. The file
// is given out ONCE: a second call returns nullptr. On Linux enter_confinement() has already
// taken it over (its size and kind are read before the system-call filter is installed).
std::unique_ptr<io::File> inherited_file(std::string& error);
std::unique_ptr<io::File> inherited_file();

// Makes a refused allocation (operator new) end the process with kOutOfMemoryExitCode, so
// the parent can report "out of memory" instead of a crash.
void exit_on_out_of_memory();

// What the calling process can tell about its own confinement, for logs and tests.
// Linux: "no_new_privs=1 seccomp=2". Windows: "appcontainer=1 integrity=0x1000 in_job=1".
std::string describe_self();

// Windows: the text form of the AppContainer SID the worker runs under, so that an
// installer or a test can give that SID read access to the program folder. Empty elsewhere.
std::string appcontainer_sid_text(std::string& error);

// Windows: the worker container's own folder (%LOCALAPPDATA%\Packages\<container name>), the
// one place the confined worker can write. run_confined empties it before every confined
// start and says so in ChildResult::confinement. Nothing in the product reads it. Empty
// elsewhere: on Linux the worker has no folder at all.
std::string appcontainer_folder_text();

// True in a build with a memory-error sanitizer. Such a build reserves terabytes of
// address space, so the address-space limit cannot be applied to it; only the parent's
// watch on resident memory remains. Never true for a shipped build.
bool sanitizer_build();

// =============================================================================================
// Pre-started one-shot workers (reviewer's ruling M-13)
//
// A worker is started confined, PREPARES (reads its rules from standard input, builds its
// engine), then WAITS for its one file; it scans that file, answers, and ends. The file
// therefore reaches a RUNNING worker. One file per worker, always.
//
// Parent:   start_waiting -> [send_preparation, take_output: the program's own protocol]
//           -> hand_over_file (once) -> collect.   end_waiting for a worker never used.
// Worker:   enter_confinement_stage1() first thing in main(); prepare; then
//           receive_file_and_seal(), which returns the file only when the worker is fully
//           confined. No byte of the file is read before that.
//
// Linux order in the worker (the reviewer's preferred order: the allow list stays as it is):
//   stage 1: no-new-privileges, not dumpable, Landlock (no path, no TCP). NOT yet the
//            system-call filter. The worker then reads OUR rule files from standard input.
//   seal:    wait on the channel for one message carrying exactly one descriptor; check it
//            (regular file, opened read-only); close the channel; install the system-call
//            filter; report on the status pipe; only then is the file given to the caller.
// Windows: the worker is in its AppContainer from its first instruction, as before. The
//   parent duplicates the file's handle into the worker, read-only and not inheritable, and
//   sends the handle's value in the job message on the worker's standard input.
//
// No thread is used by any function below; the caller may poll.

// Exit codes with which a waiting worker ends WITHOUT an answer.
inline constexpr int kHandOverRefusedExitCode = 87;  // the hand-over was not as required, or the seal failed
inline constexpr int kNoJobExitCode = 88;            // the parent closed the channel: never used

// The most job bytes hand_over_file() carries. The job is the caller's own small message
// (for example which answer format is wanted). It is copied, never interpreted, by the
// sandbox, and given to the worker only after the seal.
inline constexpr std::size_t kMaxJobBytes = 4096;

struct WaitingOptions {
    // Memory limit from the start of the worker (Linux: address-space limit and the parent's
    // watch on resident memory, also while it waits; Windows: job object).
    std::uint64_t memory_bytes = kWorkerMemoryLimitBytes;
    // The most standard output kept in all (take_output plus ChildResult::output).
    std::size_t max_output_bytes = 1024 * 1024;
    RunOptions run;  // the same switches as for run_confined
};

enum class WaitingState {
    Starting,    // created; the worker has not yet reported stage 1 (Linux)
    Waiting,     // stage 1 reported (Linux) / created in its container (Windows): may be handed a file
    HandedOver,  // it was given its one file; collect() is the next call
    Ended,       // it ended, or was ended, without being used; failure() says why
};

class WaitingChild {
public:
    ~WaitingChild();  // ends the worker if it still runs
    WaitingChild(const WaitingChild&) = delete;
    WaitingChild& operator=(const WaitingChild&) = delete;

    struct Impl;
    explicit WaitingChild(std::unique_ptr<Impl> impl);
    Impl& impl() const { return *impl_; }

private:
    std::unique_ptr<Impl> impl_;
};

// Starts `program` confined and returns at once. Never null and never throws: if the worker
// could not be started the state is Ended and failure() says why.
std::unique_ptr<WaitingChild> start_waiting(const std::filesystem::path& program,
                                            const std::vector<std::string>& arguments,
                                            const WaitingOptions& options = WaitingOptions{});

// Moves the worker's output along, notices its death, enforces the memory limit, and returns
// the state. Does not block. A worker that dies or is ended while waiting becomes Ended.
WaitingState poll(WaitingChild& child);

// Writes `bytes` to the worker's standard input (the preparation: rules, tables; OUR data),
// waiting at most `timeout_seconds`. Standard input stays open. False with `error` on failure.
bool send_preparation(WaitingChild& child, std::span<const std::uint8_t> bytes, int timeout_seconds,
                      std::string& error);

// The standard output received so far, removed from the worker's record (for the program's
// own "ready" message). What is taken here is not in ChildResult::output later.
std::string take_output(WaitingChild& child);

// Gives the worker its ONE file and the job bytes (at most kMaxJobBytes). Allowed once, in
// state Waiting; a second call is refused. From this moment the wall time of collect() runs,
// and the worker's standard input is closed.
bool hand_over_file(WaitingChild& child, const io::File& file, std::span<const std::uint8_t> job,
                    std::string& error);

// Waits for the worker to end, at most limits.wall_seconds counted FROM THE HAND-OVER, and
// returns the same ChildResult as run_confined (seconds = time since the hand-over). The
// answer of a worker that did not report its full confinement is DISCARDED (output empty,
// end = StartFailed). limits.memory_bytes is not used here: the limit was set at the start.
ChildResult collect(WaitingChild& child, const Limits& limits);

// Ends a worker that was never used (its rules are out of date, it is too old).
void end_waiting(WaitingChild& child);

// What was applied when the worker started: on Linux what the worker itself reported at
// stage 1, on Windows what the parent applied when it created the process.
std::string confinement_at_start(const WaitingChild& child);
// Why the worker is Ended without having been used; empty otherwise.
std::string failure(const WaitingChild& child);
// Age of the worker, for the caller's "replace after a fixed age" rule.
double seconds_since_start(const WaitingChild& child);

// ---- the worker's side ----------------------------------------------------------------------

// First thing in main(). Linux: no-new-privileges, not dumpable, Landlock; reports "stage 1"
// to the parent. Windows: checks that the process runs in its container, as
// enter_confinement() does. False with `error`: the worker must exit at once.
bool enter_confinement_stage1(std::string& what_applied, std::string& error);

// Blocks until the parent hands over the file, then seals (Linux: installs the system-call
// filter and reports; Windows: nothing more to apply) and returns the file, `job` and what
// is applied in all. Call it ONCE, after the preparation. It does not return on failure: if
// the hand-over is not exactly one read-only regular file, or the seal cannot be applied, the
// process ends with kHandOverRefusedExitCode and no answer; if the parent closed the channel
// without a job, with kNoJobExitCode.
// Windows: the preparation must have been read from standard input with exact-length,
// unbuffered reads (ReadFile / _read): the job message follows it on the same pipe.
std::unique_ptr<io::File> receive_file_and_seal(std::vector<std::uint8_t>& job, std::string& what_applied);

// ---- tests only -----------------------------------------------------------------------------
// Sends a hand-over that is NOT as required, to show that the worker refuses it. Defined only
// in the test build of the library (MIE_SANDBOX_TEST_HOOKS); a shipped program that names it
// does not link.
enum class MalformedHandOver {
    NoDescriptor,     // a job message without a file
    TwoDescriptors,   // two descriptors in one message (Linux)
    NotARegularFile,  // a directory (Linux) / an object that is not a disk file (Windows)
    Writable,         // the file opened for reading AND writing
    ShortMessage,     // a message shorter than the fixed size
};
bool hand_over_malformed(WaitingChild& child, MalformedHandOver kind, const std::filesystem::path& file,
                         std::string& error);

}  // namespace mie::sandbox
