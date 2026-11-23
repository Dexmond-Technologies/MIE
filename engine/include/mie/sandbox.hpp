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

// The file the parent handed over, or nullptr (with `error` set) if there is none.
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

// True in a build with a memory-error sanitizer. Such a build reserves terabytes of
// address space, so the address-space limit cannot be applied to it; only the parent's
// watch on resident memory remains. Never true for a shipped build.
bool sanitizer_build();

}  // namespace mie::sandbox
