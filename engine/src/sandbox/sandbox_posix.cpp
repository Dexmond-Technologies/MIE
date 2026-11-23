// Worker confinement on Linux (and the process plumbing for other POSIX systems).
//
// Who does what:
//   the PARENT, between fork and exec: own process group, die-with-parent, no-new-privileges,
//     no core file, address-space limit, standard input/output/error on pipes, the one
//     inherited file on descriptor 3, a status pipe on descriptor 4, every other descriptor
//     closed, a minimal environment;
//   the CHILD, first thing in main() through enter_confinement(): Landlock (where the kernel
//     has it) and the seccomp filter, then one line on the status pipe;
//   the PARENT again: sends the input only after that line, watches time and resident
//     memory, kills at a limit, and turns every way the child can end into a ChildResult.
//
// On a POSIX system other than Linux the plumbing works but enter_confinement() refuses
// (there is no confinement written for it), so a confined run ends as StartFailed.
#include "mie/sandbox.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <climits>
#include <cstring>
#include <initializer_list>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <cstddef>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define MIE_SANITIZER_BUILD 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) || __has_feature(thread_sanitizer)
#define MIE_SANITIZER_BUILD 1
#endif
#endif
#ifndef MIE_SANITIZER_BUILD
#define MIE_SANITIZER_BUILD 0
#endif

namespace mie::sandbox {

namespace {

constexpr int kChildFileFd = 3;    // the one inherited file
constexpr int kChildStatusFd = 4;  // the child tells the parent that it is confined
constexpr int kChildExecFd = 5;    // close-on-exec: carries the reason if exec fails

std::string errno_text(const char* what, int err) {
    return std::string(what) + ": " + std::strerror(err);
}

bool make_pipe(int ends[2]) {
    if (::pipe(ends) != 0) {
        return false;
    }
    ::fcntl(ends[0], F_SETFD, FD_CLOEXEC);
    ::fcntl(ends[1], F_SETFD, FD_CLOEXEC);
    return true;
}

void close_fd(int& fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

void set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL);
    if (flags >= 0) {
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

double seconds_since(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

#if defined(__linux__)
// Resident memory of a process, read from /proc/<pid>/statm (second number, in pages).
// 0 if it cannot be read (for example the process is gone).
std::uint64_t resident_bytes(pid_t pid) {
    char path[64];
    std::snprintf(path, sizeof path, "/proc/%ld/statm", static_cast<long>(pid));
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    char text[128];
    const ssize_t n = ::read(fd, text, sizeof text - 1);
    ::close(fd);
    if (n <= 0) {
        return 0;
    }
    text[n] = '\0';
    unsigned long long total = 0;
    unsigned long long resident = 0;
    if (std::sscanf(text, "%llu %llu", &total, &resident) != 2) {
        return 0;
    }
    const long page = ::sysconf(_SC_PAGESIZE);
    return static_cast<std::uint64_t>(resident) * static_cast<std::uint64_t>(page > 0 ? page : 4096);
}
#else
std::uint64_t resident_bytes(pid_t) { return 0; }
#endif

void kill_child(pid_t pid) {
    // The child is the leader of its own process group; kill the group so that nothing it
    // may have started survives, then the process itself in case the group call failed.
    ::kill(-pid, SIGKILL);
    ::kill(pid, SIGKILL);
}

// The handed-over file is taken over ONCE, and on Linux inside enter_confinement() BEFORE the
// system-call filter is installed: taking it over asks the kernel for the file's size and
// kind, and depending on the C library version that question is the call "fstat" (allowed by
// the filter) or "newfstatat" (takes a path, so not allowed). Only the descriptor's metadata
// is read at that point, none of the file's bytes.
struct InheritedFile {
    bool tried = false;
    std::unique_ptr<io::File> file;
    std::string error;
};
InheritedFile g_inherited;

void adopt_inherited_file() {
    if (g_inherited.tried) {
        if (!g_inherited.file && g_inherited.error.empty()) {
            g_inherited.error = "the handed-over file was already taken";
        }
        return;
    }
    g_inherited.tried = true;
    const char* value = std::getenv("MIE_INHERITED_FILE");
    if (value == nullptr || *value == '\0') {
        g_inherited.error = "no file was handed over";
        return;
    }
    char* end = nullptr;
    const long fd = std::strtol(value, &end, 10);
    if (end == value || *end != '\0' || fd < 0 || fd > 1024) {
        g_inherited.error = "the handed-over file's number is not valid";
        return;
    }
    io::IoError io_error;
    g_inherited.file = io::adopt_native_handle(static_cast<std::intptr_t>(fd), io_error);
    if (!g_inherited.file) {
        g_inherited.error = std::string("the handed-over file cannot be used: ") + io::to_string(io_error.code);
    }
}

// Closes every descriptor from `first` upwards. Used between fork and exec: only system
// calls, no allocation, no library state. close_range() does it in one call and has no upper
// bound; where the kernel does not have it (before 5.9: "no such call") every number up to
// `highest` is closed one by one. `highest` is the HARD limit on open descriptors, read by the
// parent before fork: no descriptor can have a number at or above it.
void close_descriptors_from(int first, long highest) {
#if defined(__linux__)
#ifdef SYS_close_range
    const long close_range_number = SYS_close_range;
#else
    const long close_range_number = 436;  // the same number on every processor
#endif
    if (::syscall(close_range_number, static_cast<unsigned>(first), ~0u, 0u) == 0) {
        return;
    }
#endif
    for (long fd = first; fd < highest; ++fd) {
        ::close(static_cast<int>(fd));
    }
}

// The one message of a hand-over (ruling M-13): fixed size, sent whole. On Linux it travels
// over the channel together with the file's descriptor; `handle_value` is used on Windows only.
constexpr std::uint32_t kFrameMagic = 0x3145494Du;  // the bytes "MIE1"
struct HandOverFrame {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint64_t handle_value;
    std::uint32_t job_length;
    std::uint32_t reserved;
    std::uint8_t job[kMaxJobBytes];
};

const char* stage_text(int stage) {
    switch (stage) {
        case 1: return "moving the descriptors into place";
        case 2: return "no-new-privileges";
        case 3: return "the address-space limit";
        case 4: return "exec";
        default: return "starting the child";
    }
}

}  // namespace

const char* to_string(ChildResult::End end) {
    switch (end) {
        case ChildResult::End::Exited: return "exited";
        case ChildResult::End::KilledByTimeLimit: return "killed_by_time_limit";
        case ChildResult::End::KilledByMemoryLimit: return "killed_by_memory_limit";
        case ChildResult::End::Crashed: return "crashed";
        case ChildResult::End::StartFailed: return "start_failed";
    }
    return "start_failed";
}

bool sanitizer_build() { return MIE_SANITIZER_BUILD != 0; }

std::string appcontainer_folder_text() { return {}; }

std::string appcontainer_sid_text(std::string& error) {
    error = "AppContainer is a Windows mechanism";
    return {};
}

void exit_on_out_of_memory() {
    std::set_new_handler([] { std::_Exit(kOutOfMemoryExitCode); });
}

std::unique_ptr<io::File> inherited_file(std::string& error) {
    error.clear();
    adopt_inherited_file();
    if (!g_inherited.file) {
        error = g_inherited.error;
        return nullptr;
    }
    return std::move(g_inherited.file);
}

std::unique_ptr<io::File> inherited_file() {
    std::string ignored;
    return inherited_file(ignored);
}

// What a waiting start keeps of a child that run_or_start created (ruling M-13).
struct StartedChild {
    pid_t pid = -1;
    int in = -1;       // the parent's end of the child's standard input
    int out = -1;      // ... of its standard output
    int err = -1;      // ... of its standard error
    int status = -1;   // ... of the status pipe (-1 without confinement)
    int channel = -1;  // the parent's end of the channel for the one file
    bool address_space_limited = false;
};

static ChildResult run_or_start(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                                const io::File* inherited, std::span<const std::uint8_t> input,
                                const Limits& limits, std::size_t max_output_bytes, const RunOptions& options,
                                StartedChild* keep);

ChildResult run_confined(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                         const io::File* inherited, std::span<const std::uint8_t> input,
                         const Limits& limits, std::size_t max_output_bytes, const RunOptions& options) {
    return run_or_start(program, arguments, inherited, input, limits, max_output_bytes, options, nullptr);
}

// Starts a child and, for run_confined (keep == nullptr), runs it to its end. With `keep` (a
// waiting start, ruling M-13) it returns as soon as the child is created, handing the child's
// descriptors to *keep; the child then has, in place of a file on descriptor 3, one end of a
// socket pair: the channel on which it will be sent its one file.
static ChildResult run_or_start(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                                const io::File* inherited, std::span<const std::uint8_t> input,
                                const Limits& limits, std::size_t max_output_bytes, const RunOptions& options,
                                StartedChild* keep) {
    ChildResult result;
    const auto started = std::chrono::steady_clock::now();
    const auto fail_start = [&](const std::string& why) {
        result.end = ChildResult::End::StartFailed;
        result.detail = why;
        result.seconds = seconds_since(started);
        return result;
    };

    // ---- everything the child needs is prepared BEFORE fork: after fork, in a process that
    //      may have other threads, only async-signal-safe calls are made.
    std::vector<std::string> argument_store;
    argument_store.push_back(program.string());
    argument_store.insert(argument_store.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    for (std::string& text : argument_store) {
        argv.push_back(text.data());
    }
    argv.push_back(nullptr);

    // A minimal environment: nothing of the parent's is passed on except what is listed here.
    std::vector<std::string> environment_store;
    if (options.confine) {
        environment_store.push_back("MIE_SANDBOX=1");
        environment_store.push_back("MIE_SANDBOX_STATUS_FD=" + std::to_string(kChildStatusFd));
#if defined(MIE_SANDBOX_TEST_HOOKS)
        // Test builds only: the two switches a test child reads. In the shipped build these
        // names are never passed, and the child's code that reads them does not exist.
        if (options.allow_weaker) {
            environment_store.push_back("MIE_SANDBOX_ALLOW_WEAKER=1");
        }
        if (options.test_break_confinement) {
            environment_store.push_back("MIE_SANDBOX_TEST_BREAK=1");
        }
#endif
    }
    if (inherited != nullptr) {
        environment_store.push_back("MIE_INHERITED_FILE=" + std::to_string(kChildFileFd));
    }
    if (keep != nullptr) {
        environment_store.push_back("MIE_SANDBOX_CHANNEL_FD=" + std::to_string(kChildFileFd));
    }
    if (MIE_SANITIZER_BUILD) {
        // A sanitizer build only (never shipped): keep the sanitizer's own options, and turn
        // the leak check off: it stops the process with a tracer thread and reads /proc, both
        // of which the confinement refuses.
        for (const char* name : {"UBSAN_OPTIONS", "LSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS"}) {
            if (const char* value = std::getenv(name)) {
                environment_store.push_back(std::string(name) + "=" + value);
            }
        }
        const char* asan = std::getenv("ASAN_OPTIONS");
        environment_store.push_back(std::string("ASAN_OPTIONS=") + (asan != nullptr ? std::string(asan) + ":" : "") +
                                    "detect_leaks=0");
    }
    std::vector<char*> envp;
    for (std::string& text : environment_store) {
        envp.push_back(text.data());
    }
    envp.push_back(nullptr);

    int in_pipe[2] = {-1, -1};      // parent writes [1] -> child's standard input [0]
    int out_pipe[2] = {-1, -1};     // child's standard output [1] -> parent reads [0]
    int err_pipe[2] = {-1, -1};     // child's standard error
    int status_pipe[2] = {-1, -1};  // child confirms its confinement
    int exec_pipe[2] = {-1, -1};    // carries the reason if the child cannot be started
    int channel[2] = {-1, -1};      // waiting start only: [0] the parent's end, [1] the child's
    const auto close_all = [&] {
        for (int* ends : {in_pipe, out_pipe, err_pipe, status_pipe, exec_pipe, channel}) {
            close_fd(ends[0]);
            close_fd(ends[1]);
        }
    };
    if (!make_pipe(in_pipe) || !make_pipe(out_pipe) || !make_pipe(err_pipe) || !make_pipe(exec_pipe) ||
        (options.confine && !make_pipe(status_pipe))) {
        const int err = errno;
        close_all();
        return fail_start(errno_text("pipe", err));
    }

    // Waiting start: a socket pair that keeps message boundaries (SOCK_SEQPACKET): the one
    // hand-over message arrives whole or not at all, and the worker sees the end of the
    // channel if the parent goes away.
    if (keep != nullptr && ::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) {
        const int err = errno;
        close_all();
        return fail_start(errno_text("socketpair", err));
    }
    // What goes on the child's descriptor 3: the file (one-shot) or the channel (waiting start).
    const int file_fd = keep != nullptr ? channel[1]
                                        : (inherited != nullptr ? static_cast<int>(inherited->native_handle()) : -1);
    // The hard limit on open descriptors, for the kernels without close_range (see
    // close_descriptors_from). No cap: "unlimited" or an unreadable limit means every number.
    // (Linux never reports "unlimited" here: the kernel bounds the limit by fs.nr_open.)
    long highest_fd = INT_MAX;
#if !defined(__linux__)
    if (const long open_max = ::sysconf(_SC_OPEN_MAX); open_max > 0) {
        highest_fd = open_max;  // systems whose hard limit is "unlimited"
    }
#endif
    struct rlimit descriptor_limit {};
    if (::getrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0 && descriptor_limit.rlim_max != RLIM_INFINITY &&
        descriptor_limit.rlim_max < static_cast<rlim_t>(INT_MAX)) {
        highest_fd = static_cast<long>(descriptor_limit.rlim_max);
    }
    [[maybe_unused]] const pid_t parent_pid = ::getpid();
    const bool limit_address_space = limits.memory_bytes > 0 && !MIE_SANITIZER_BUILD;

    const pid_t pid = ::fork();
    if (pid < 0) {
        const int err = errno;
        close_all();
        return fail_start(errno_text("fork", err));
    }

    if (pid == 0) {
        // ================= the child, before exec: async-signal-safe calls only =================
        const auto give_up = [&](int stage) {
            const int report[2] = {stage, errno};
            const ssize_t ignored = ::write(kChildExecFd, report, sizeof report);
            (void)ignored;
            ::_exit(127);
        };
        // Own process group: the parent can kill everything the child may start.
        ::setpgid(0, 0);
#if defined(__linux__)
        // The child is killed if the parent dies: no orphan keeps parsing.
        ::prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (::getppid() != parent_pid) {
            ::_exit(127);
        }
#endif
        // Move the wanted descriptors out of the way (10 and above), then into their fixed
        // places: 0, 1, 2, the file on 3, the status pipe on 4, the exec-error pipe on 5.
        const int in = ::fcntl(in_pipe[0], F_DUPFD, 10);
        const int out = ::fcntl(out_pipe[1], F_DUPFD, 10);
        const int err = ::fcntl(err_pipe[1], F_DUPFD, 10);
        const int exec_error = ::fcntl(exec_pipe[1], F_DUPFD, 10);
        const int status = options.confine ? ::fcntl(status_pipe[1], F_DUPFD, 10) : -1;
        const int file = file_fd >= 0 ? ::fcntl(file_fd, F_DUPFD, 10) : -1;
        if (in < 0 || out < 0 || err < 0 || exec_error < 0 || (options.confine && status < 0) ||
            (file_fd >= 0 && file < 0)) {
            ::_exit(127);
        }
        if (::dup2(exec_error, kChildExecFd) < 0 || ::fcntl(kChildExecFd, F_SETFD, FD_CLOEXEC) != 0) {
            ::_exit(127);
        }
        if (::dup2(in, 0) < 0 || ::dup2(out, 1) < 0 || ::dup2(err, 2) < 0) {
            give_up(1);
        }
        if (file >= 0) {
            if (::dup2(file, kChildFileFd) < 0) {
                give_up(1);
            }
        } else {
            ::close(kChildFileFd);
        }
        if (status >= 0) {
            if (::dup2(status, kChildStatusFd) < 0) {
                give_up(1);
            }
        } else {
            ::close(kChildStatusFd);
        }
        // Every other descriptor of the parent is closed: the child holds its three standard
        // streams, at most one file, and the two short-lived pipes. Nothing else.
        close_descriptors_from(kChildExecFd + 1, highest_fd);
#if defined(__linux__)
        // no-new-privileges: exec can never raise rights (no set-user-id programs, no file
        // capabilities). Required by seccomp and Landlock for an ordinary user. It removes
        // nothing by itself.
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            give_up(2);
        }
#endif
        // No core file: a crash must not write the scanned bytes to disk.
        struct rlimit none {};
        none.rlim_cur = 0;
        none.rlim_max = 0;
        ::setrlimit(RLIMIT_CORE, &none);
        if (limit_address_space) {
            // Address-space limit. The kernel refuses any mapping that would take the process
            // above it, so resident memory can never exceed it. It limits address space, not
            // resident memory: a program that reserves much and touches little is stopped
            // earlier than a resident limit would stop it.
            struct rlimit memory {};
            memory.rlim_cur = static_cast<rlim_t>(limits.memory_bytes);
            memory.rlim_max = static_cast<rlim_t>(limits.memory_bytes);
            if (::setrlimit(RLIMIT_AS, &memory) != 0) {
                give_up(3);
            }
        }
        // Signals as a fresh program expects them.
        sigset_t empty;
        sigemptyset(&empty);
        ::sigprocmask(SIG_SETMASK, &empty, nullptr);
        ::signal(SIGPIPE, SIG_DFL);
        ::execve(argv[0], argv.data(), envp.data());
        give_up(4);
    }

    // ================================= the parent =================================
    ::setpgid(pid, pid);  // also from this side, so a kill of the group cannot miss
    close_fd(in_pipe[0]);
    close_fd(out_pipe[1]);
    close_fd(err_pipe[1]);
    close_fd(status_pipe[1]);
    close_fd(exec_pipe[1]);
    close_fd(channel[1]);  // the child's end is the child's only

    // If exec failed the child wrote why; if it succeeded the pipe just closes.
    int report[2] = {0, 0};
    ssize_t got = 0;
    do {
        got = ::read(exec_pipe[0], report, sizeof report);
    } while (got < 0 && errno == EINTR);
    close_fd(exec_pipe[0]);
    if (got > 0) {
        int ignored = 0;
        ::waitpid(pid, &ignored, 0);
        close_all();
        return fail_start(std::string("the child could not be started (") + stage_text(report[0]) + "): " +
                          std::strerror(report[1]));
    }

    set_nonblocking(in_pipe[1]);
    set_nonblocking(out_pipe[0]);
    set_nonblocking(err_pipe[0]);
    if (status_pipe[0] >= 0) {
        set_nonblocking(status_pipe[0]);
    }

    if (keep != nullptr) {
        // A waiting start ends here: the caller owns the child and its descriptors from now.
        keep->pid = pid;
        keep->in = in_pipe[1];
        keep->out = out_pipe[0];
        keep->err = err_pipe[0];
        keep->status = status_pipe[0];
        keep->channel = channel[0];
        keep->address_space_limited = limit_address_space;
        in_pipe[1] = out_pipe[0] = err_pipe[0] = status_pipe[0] = channel[0] = -1;
        result.end = ChildResult::End::Exited;
        return result;
    }

    // Writing to a child that has died raises SIGPIPE, which would end the PARENT. The signal
    // is blocked for this thread while the child runs and a pending one is taken away at the end.
    sigset_t pipe_set;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    sigset_t pending_before;
    sigemptyset(&pending_before);
    ::sigpending(&pending_before);
    sigset_t old_mask;
    ::pthread_sigmask(SIG_BLOCK, &pipe_set, &old_mask);

    const auto deadline = started + std::chrono::seconds(limits.wall_seconds > 0 ? limits.wall_seconds : 0);
    std::size_t written = 0;
    bool confirmed = !options.confine;  // without confinement there is nothing to wait for
    std::string status_text;
    std::string child_confinement;
    std::string error_text;
    bool start_failed = false;
    std::string start_failure;
    bool killed_time = false;
    bool killed_memory = false;
    bool killed_output = false;
    bool killed = false;
    bool reaped = false;
    int wait_status = 0;
    struct rusage usage {};
    std::uint64_t highest_resident = 0;
    auto reaped_at = started;

    const auto kill_once = [&] {
        if (!killed && !reaped) {
            kill_child(pid);
            killed = true;
        }
    };
    const auto refuse = [&](const std::string& why) {
        if (!start_failed) {
            start_failed = true;
            start_failure = why;
        }
        kill_once();
    };

    for (;;) {
        if (!reaped) {
            const pid_t done = ::wait4(pid, &wait_status, WNOHANG, &usage);
            if (done == pid) {
                reaped = true;
                reaped_at = std::chrono::steady_clock::now();
            }
        }
        const bool streams_open = out_pipe[0] >= 0 || err_pipe[0] >= 0;
        if (reaped && !streams_open) {
            break;
        }
        // After the child has ended its pipes close at once; a short grace covers what is
        // still in them. Nothing else can hold them: the child's group was killed or is gone.
        if (reaped && std::chrono::steady_clock::now() - reaped_at > std::chrono::milliseconds(500)) {
            break;
        }

        if (!reaped) {
            if (std::chrono::steady_clock::now() >= deadline && !killed) {
                killed_time = true;
                kill_once();
            }
            const std::uint64_t resident = resident_bytes(pid);
            if (resident > highest_resident) {
                highest_resident = resident;
            }
            if (limits.memory_bytes > 0 && resident > limits.memory_bytes && !killed) {
                // The parent's own watch on resident memory. In a normal build the
                // address-space limit stops the child earlier; in a sanitizer build this is
                // the only memory limit. It is a watch, not a wall: between two looks the
                // child can go over by what it allocates in about 20 milliseconds.
                killed_memory = true;
                kill_once();
            }
        }

        struct pollfd fds[4];
        int count = 0;
        int out_index = -1;
        int err_index = -1;
        int status_index = -1;
        int in_index = -1;
        if (out_pipe[0] >= 0) {
            out_index = count;
            fds[count++] = {out_pipe[0], POLLIN, 0};
        }
        if (err_pipe[0] >= 0) {
            err_index = count;
            fds[count++] = {err_pipe[0], POLLIN, 0};
        }
        if (status_pipe[0] >= 0) {
            status_index = count;
            fds[count++] = {status_pipe[0], POLLIN, 0};
        }
        if (in_pipe[1] >= 0 && confirmed) {
            if (written >= input.size()) {
                close_fd(in_pipe[1]);  // everything sent: the child sees the end of its input
            } else {
                in_index = count;
                fds[count++] = {in_pipe[1], POLLOUT, 0};
            }
        }
        const int ready = ::poll(fds, static_cast<nfds_t>(count), 20);
        if (ready < 0 && errno != EINTR) {
            refuse(errno_text("poll", errno));
            continue;
        }
        if (ready <= 0) {
            continue;
        }

        char buffer[64 * 1024];
        if (status_index >= 0 && fds[status_index].revents != 0) {
            const ssize_t n = ::read(status_pipe[0], buffer, sizeof buffer);
            if (n > 0) {
                status_text.append(buffer, static_cast<std::size_t>(n));
                if (status_text.size() > 4096) {
                    refuse("the child's confinement report is too long");
                }
            }
            const std::size_t line_end = status_text.find('\n');
            if (line_end != std::string::npos && !confirmed && !start_failed) {
                const std::string line = status_text.substr(0, line_end);
                if (line.rfind("ok ", 0) == 0) {
                    confirmed = true;
                    child_confinement = line.substr(3);
                } else {
                    refuse("the child could not confine itself: " +
                           (line.rfind("fail ", 0) == 0 ? line.substr(5) : line));
                }
            }
            if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
                close_fd(status_pipe[0]);
                if (!confirmed && !start_failed) {
                    refuse("the child ended, or closed its status channel, without confirming its confinement");
                }
            }
        }
        if (out_index >= 0 && fds[out_index].revents != 0) {
            const ssize_t n = ::read(out_pipe[0], buffer, sizeof buffer);
            if (n > 0) {
                const std::size_t room = max_output_bytes - (result.output.size() < max_output_bytes
                                                                 ? result.output.size()
                                                                 : max_output_bytes);
                const std::size_t take = static_cast<std::size_t>(n) < room ? static_cast<std::size_t>(n) : room;
                result.output.append(buffer, take);
                if (take < static_cast<std::size_t>(n) && !killed_output) {
                    killed_output = true;  // more output than allowed: the child is stopped
                    kill_once();
                }
            } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
                close_fd(out_pipe[0]);
            }
        }
        if (err_index >= 0 && fds[err_index].revents != 0) {
            const ssize_t n = ::read(err_pipe[0], buffer, sizeof buffer);
            if (n > 0) {
                if (error_text.size() < 16 * 1024) {
                    error_text.append(buffer, static_cast<std::size_t>(n));  // the rest is read and dropped
                }
            } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
                close_fd(err_pipe[0]);
            }
        }
        if (in_index >= 0 && fds[in_index].revents != 0 && in_pipe[1] >= 0) {
            const ssize_t n = ::write(in_pipe[1], input.data() + written, input.size() - written);
            if (n > 0) {
                written += static_cast<std::size_t>(n);
            } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
                close_fd(in_pipe[1]);  // the child no longer reads (EPIPE): not an error by itself
            }
        }
    }

    close_all();
    if (!reaped) {
        kill_child(pid);
        ::wait4(pid, &wait_status, 0, &usage);
    }
    // Nothing of the child's group may be left behind.
    ::kill(-pid, SIGKILL);

    // Take away a SIGPIPE that this run raised, then give the signal mask back.
    sigset_t pending_now;
    sigemptyset(&pending_now);
    ::sigpending(&pending_now);
    if (sigismember(&pending_now, SIGPIPE) == 1 && sigismember(&pending_before, SIGPIPE) != 1) {
        int taken = 0;
        ::sigwait(&pipe_set, &taken);
    }
    ::pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);

    result.seconds = seconds_since(started);
#if defined(__APPLE__)
    result.peak_memory_bytes = static_cast<std::uint64_t>(usage.ru_maxrss);  // bytes on macOS
#else
    result.peak_memory_bytes = static_cast<std::uint64_t>(usage.ru_maxrss) * 1024;  // kibibytes on Linux
#endif
    if (result.peak_memory_bytes == 0) {
        result.peak_memory_bytes = highest_resident;
    }

    std::string parent_part = "parent: own process group, no-new-privileges, no core file, no other descriptors";
    if (limit_address_space) {
        parent_part += ", address-space limit " + std::to_string(limits.memory_bytes) + " bytes";
    } else if (limits.memory_bytes > 0) {
        parent_part += ", NO address-space limit (sanitizer build), resident memory watched by the parent";
    }
    result.confinement = options.confine
                             ? parent_part + "; child: " + (child_confinement.empty() ? "not confirmed" : child_confinement)
                             : parent_part + "; child: none (confinement not requested)";
    if (!error_text.empty()) {
        result.detail = "standard error: " + error_text;
    }
    const auto with_detail = [&](const std::string& text) {
        result.detail = result.detail.empty() ? text : text + "; " + result.detail;
    };

    if (start_failed) {
        result.end = ChildResult::End::StartFailed;
        with_detail(start_failure);
        return result;
    }
    if (killed_time) {
        result.end = ChildResult::End::KilledByTimeLimit;
        with_detail("killed at the time limit of " + std::to_string(limits.wall_seconds) + " seconds");
        return result;
    }
    if (killed_memory) {
        result.end = ChildResult::End::KilledByMemoryLimit;
        with_detail("killed: resident memory went over " + std::to_string(limits.memory_bytes) + " bytes");
        return result;
    }
    if (killed_output) {
        result.end = ChildResult::End::Crashed;
        with_detail("killed: more output than the allowed " + std::to_string(max_output_bytes) + " bytes");
        return result;
    }
    if (WIFEXITED(wait_status)) {
        result.exit_code = WEXITSTATUS(wait_status);
        if (result.exit_code == kOutOfMemoryExitCode) {
            result.end = ChildResult::End::KilledByMemoryLimit;
            with_detail("the child ran out of its memory limit (an allocation was refused)");
        } else {
            result.end = ChildResult::End::Exited;
        }
        return result;
    }
    result.end = ChildResult::End::Crashed;
    if (WIFSIGNALED(wait_status)) {
        result.exit_code = 128 + WTERMSIG(wait_status);
        with_detail("ended by signal " + std::to_string(WTERMSIG(wait_status)));
    } else {
        with_detail("ended in an unknown way");
    }
    return result;
}

// ================== pre-started one-shot workers (ruling M-13): the parent ==================
//
// The worker is created by the same code as a one-shot child (run_or_start), with one
// difference: instead of a file, descriptor 3 of the child is one end of a socket pair, the
// CHANNEL over which the parent later sends the one file. Everything below is new code; no
// thread is used; every function moves the pipes along itself.

struct WaitingChild::Impl {
    StartedChild child;
    WaitingState state = WaitingState::Ended;
    std::string failure;
    bool confine = true;
    bool finished = false;  // the process is reaped and every descriptor closed
    std::uint64_t memory_bytes = 0;
    std::size_t max_output = 0;
    std::chrono::steady_clock::time_point started{};
    std::chrono::steady_clock::time_point handed_over{};
    std::chrono::steady_clock::time_point reaped_at{};
    std::string status_text;      // what came on the status pipe, not yet a whole line
    bool stage1 = false;          // the worker reported stage 1
    std::string stage1_text;
    bool sealed = false;          // the worker reported its full confinement
    std::string seal_text;
    std::string seal_failure;     // the worker's "fail" line
    std::string output;
    std::size_t output_total = 0;
    std::string error_text;
    bool killed = false;
    bool killed_memory = false;
    bool killed_output = false;
    bool killed_time = false;
    bool reaped = false;
    int wait_status = 0;
    struct rusage usage {};
    std::uint64_t highest_resident = 0;
};

namespace {

// Blocks SIGPIPE for the calling thread while it writes to a worker that may have died, and
// takes away one that the write raised (the same as run_or_start does for its whole run).
class PipeSignalBlocked {
public:
    PipeSignalBlocked() {
        sigemptyset(&set_);
        sigaddset(&set_, SIGPIPE);
        sigset_t pending;
        sigemptyset(&pending);
        ::sigpending(&pending);
        was_pending_ = sigismember(&pending, SIGPIPE) == 1;
        ::pthread_sigmask(SIG_BLOCK, &set_, &old_);
    }
    ~PipeSignalBlocked() {
        sigset_t pending;
        sigemptyset(&pending);
        ::sigpending(&pending);
        if (sigismember(&pending, SIGPIPE) == 1 && !was_pending_) {
            int taken = 0;
            ::sigwait(&set_, &taken);
        }
        ::pthread_sigmask(SIG_SETMASK, &old_, nullptr);
    }
    PipeSignalBlocked(const PipeSignalBlocked&) = delete;
    PipeSignalBlocked& operator=(const PipeSignalBlocked&) = delete;

private:
    sigset_t set_;
    sigset_t old_;
    bool was_pending_ = false;
};

void kill_waiting(WaitingChild::Impl& c) {
    if (!c.killed && !c.reaped && c.child.pid > 0) {
        kill_child(c.child.pid);
        c.killed = true;
    }
}

// The status pipe carries whole lines: "stage1 <what>", then "ok <what>" or "fail <why>".
void take_status_lines(WaitingChild::Impl& c) {
    for (;;) {
        const std::size_t end = c.status_text.find('\n');
        if (end == std::string::npos) {
            if (c.status_text.size() > 8192) {
                c.seal_failure = "the worker's status report is too long";
                kill_waiting(c);
                c.status_text.clear();
            }
            return;
        }
        const std::string line = c.status_text.substr(0, end);
        c.status_text.erase(0, end + 1);
        if (line.rfind("stage1 ", 0) == 0 && !c.stage1) {
            c.stage1 = true;
            c.stage1_text = line.substr(7);
        } else if (line.rfind("ok ", 0) == 0 && c.stage1 && !c.sealed && c.seal_failure.empty()) {
            c.sealed = true;
            c.seal_text = line.substr(3);
        } else if (line.rfind("fail ", 0) == 0) {
            c.seal_failure = line.substr(5);
        } else {
            c.seal_failure = "unexpected status line from the worker: " + line.substr(0, 200);
        }
    }
}

// One round: notice the worker's end, watch its resident memory, read what it wrote, and
// write `input` from *written on if there is any. Waits at most timeout_ms.
void pump(WaitingChild::Impl& c, int timeout_ms, std::span<const std::uint8_t> input, std::size_t* written) {
    if (c.child.pid <= 0 || c.finished) {
        return;
    }
    if (!c.reaped && ::wait4(c.child.pid, &c.wait_status, WNOHANG, &c.usage) == c.child.pid) {
        c.reaped = true;
        c.reaped_at = std::chrono::steady_clock::now();
    }
    if (!c.reaped) {
        const std::uint64_t resident = resident_bytes(c.child.pid);
        if (resident > c.highest_resident) {
            c.highest_resident = resident;
        }
        if (c.memory_bytes > 0 && resident > c.memory_bytes && !c.killed) {
            c.killed_memory = true;  // also while it waits: a waiting worker over the limit is ended
            kill_waiting(c);
        }
    }

    struct pollfd fds[4];
    int count = 0;
    int out_index = -1;
    int err_index = -1;
    int status_index = -1;
    int in_index = -1;
    if (c.child.out >= 0) {
        out_index = count;
        fds[count++] = {c.child.out, POLLIN, 0};
    }
    if (c.child.err >= 0) {
        err_index = count;
        fds[count++] = {c.child.err, POLLIN, 0};
    }
    if (c.child.status >= 0) {
        status_index = count;
        fds[count++] = {c.child.status, POLLIN, 0};
    }
    if (written != nullptr && *written < input.size() && c.child.in >= 0) {
        in_index = count;
        fds[count++] = {c.child.in, POLLOUT, 0};
    }
    if (count == 0) {
        if (timeout_ms > 0) {
            ::poll(nullptr, 0, timeout_ms);
        }
        return;
    }
    if (::poll(fds, static_cast<nfds_t>(count), timeout_ms) <= 0) {
        return;
    }

    char buffer[64 * 1024];
    if (status_index >= 0 && fds[status_index].revents != 0) {
        const ssize_t n = ::read(c.child.status, buffer, sizeof buffer);
        if (n > 0) {
            c.status_text.append(buffer, static_cast<std::size_t>(n));
            take_status_lines(c);
        } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
            close_fd(c.child.status);
        }
    }
    if (out_index >= 0 && fds[out_index].revents != 0) {
        const ssize_t n = ::read(c.child.out, buffer, sizeof buffer);
        if (n > 0) {
            const std::size_t room = c.output_total < c.max_output ? c.max_output - c.output_total : 0;
            const std::size_t take = static_cast<std::size_t>(n) < room ? static_cast<std::size_t>(n) : room;
            c.output.append(buffer, take);
            c.output_total += take;
            if (take < static_cast<std::size_t>(n) && !c.killed_output) {
                c.killed_output = true;  // more output than allowed: the worker is stopped
                kill_waiting(c);
            }
        } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
            close_fd(c.child.out);
        }
    }
    if (err_index >= 0 && fds[err_index].revents != 0) {
        const ssize_t n = ::read(c.child.err, buffer, sizeof buffer);
        if (n > 0) {
            if (c.error_text.size() < 16 * 1024) {
                c.error_text.append(buffer, static_cast<std::size_t>(n));
            }
        } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
            close_fd(c.child.err);
        }
    }
    if (in_index >= 0 && fds[in_index].revents != 0 && c.child.in >= 0) {
        const ssize_t n = ::write(c.child.in, input.data() + *written, input.size() - *written);
        if (n > 0) {
            *written += static_cast<std::size_t>(n);
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
            close_fd(c.child.in);  // the worker no longer reads
        }
    }
}

std::string end_in_words(const WaitingChild::Impl& c) {
    if (WIFEXITED(c.wait_status)) {
        return "exit code " + std::to_string(WEXITSTATUS(c.wait_status));
    }
    if (WIFSIGNALED(c.wait_status)) {
        return "signal " + std::to_string(WTERMSIG(c.wait_status));
    }
    return "an unknown end";
}

// Closes everything and makes sure the process is gone and reaped.
void finish_child(WaitingChild::Impl& c) {
    if (c.finished) {
        return;
    }
    close_fd(c.child.in);
    close_fd(c.child.out);
    close_fd(c.child.err);
    close_fd(c.child.status);
    close_fd(c.child.channel);
    if (c.child.pid > 0) {
        if (!c.reaped) {
            kill_child(c.child.pid);
            ::wait4(c.child.pid, &c.wait_status, 0, &c.usage);
            c.reaped = true;
        }
        ::kill(-c.child.pid, SIGKILL);  // nothing of the worker's group may be left behind
    }
    c.finished = true;
}

void update_state(WaitingChild::Impl& c) {
    if (c.state == WaitingState::Starting && (c.stage1 || !c.confine)) {
        c.state = WaitingState::Waiting;
    }
    if ((c.state == WaitingState::Starting || c.state == WaitingState::Waiting) && (c.reaped || c.killed)) {
        c.failure = c.killed_memory        ? "ended by the parent: over the memory limit while waiting"
                    : c.killed_output      ? "ended by the parent: more output than allowed while waiting"
                    : !c.seal_failure.empty() ? "the worker could not confine itself: " + c.seal_failure
                                              : std::string("the worker ended while waiting");
        finish_child(c);
        c.failure += " (" + end_in_words(c) + ")";
        if (!c.error_text.empty()) {
            c.failure += "; standard error: " + c.error_text;
        }
        c.state = WaitingState::Ended;
    }
}

std::string parent_part_of(const WaitingChild::Impl& c) {
    std::string text = "parent: own process group, no-new-privileges, no core file, no other descriptors";
    if (c.child.address_space_limited) {
        text += ", address-space limit " + std::to_string(c.memory_bytes) + " bytes";
    } else if (c.memory_bytes > 0) {
        text += ", NO address-space limit (sanitizer build), resident memory watched by the parent";
    }
    return text;
}

// Sends one message on the channel, with `fd_count` descriptors attached.
bool send_on_channel(WaitingChild::Impl& c, const void* data, std::size_t size, const int* descriptors,
                     std::size_t fd_count, std::string& error) {
    struct iovec part {};
    part.iov_base = const_cast<void*>(data);
    part.iov_len = size;
    alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int) * 4)];
    std::memset(control, 0, sizeof control);
    struct msghdr message {};
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    if (fd_count > 0) {
        message.msg_control = control;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        std::memcpy(CMSG_DATA(header), descriptors, sizeof(int) * fd_count);
    }
    ssize_t sent = 0;
    do {
        // MSG_NOSIGNAL: a worker that has died gives an error here, not a signal to the parent.
        sent = ::sendmsg(c.child.channel, &message, MSG_NOSIGNAL | MSG_DONTWAIT);
    } while (sent < 0 && errno == EINTR);
    if (sent < 0) {
        error = errno_text("sending the file to the worker", errno);
        return false;
    }
    if (static_cast<std::size_t>(sent) != size) {
        error = "the hand-over message was not sent whole";
        return false;
    }
    return true;
}

// After the one message: the channel is closed on the parent's side (the worker closes its
// own end before it seals), standard input is closed, and the clock of collect() starts.
void after_hand_over(WaitingChild::Impl& c) {
    close_fd(c.child.channel);
    close_fd(c.child.in);
    c.handed_over = std::chrono::steady_clock::now();
    c.state = WaitingState::HandedOver;
}

const char* state_in_words(WaitingState state) {
    switch (state) {
        case WaitingState::Starting: return "the worker has not yet reported stage 1 of its confinement";
        case WaitingState::Waiting: return "the worker waits";
        case WaitingState::HandedOver: return "this worker was already given its one file";
        case WaitingState::Ended: return "the worker has ended";
    }
    return "the worker has ended";
}

}  // namespace

WaitingChild::WaitingChild(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

WaitingChild::~WaitingChild() {
    if (impl_) {
        kill_waiting(*impl_);
        finish_child(*impl_);
    }
}

std::unique_ptr<WaitingChild> start_waiting(const std::filesystem::path& program,
                                            const std::vector<std::string>& arguments,
                                            const WaitingOptions& options) {
    auto impl = std::make_unique<WaitingChild::Impl>();
    impl->started = std::chrono::steady_clock::now();
    impl->confine = options.run.confine;
    impl->memory_bytes = options.memory_bytes;
    impl->max_output = options.max_output_bytes;
    Limits limits;
    limits.memory_bytes = options.memory_bytes;
    const ChildResult created = run_or_start(program, arguments, nullptr, {}, limits, 0, options.run, &impl->child);
    if (impl->child.pid <= 0) {
        impl->state = WaitingState::Ended;
        impl->failure = created.detail.empty() ? "the worker could not be started" : created.detail;
        impl->finished = true;
    } else {
        // Without confinement (tests only) there is no stage-1 report to wait for.
        impl->state = options.run.confine ? WaitingState::Starting : WaitingState::Waiting;
    }
    return std::make_unique<WaitingChild>(std::move(impl));
}

WaitingState poll(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    pump(c, 0, {}, nullptr);
    update_state(c);
    return c.state;
}

bool send_preparation(WaitingChild& child, std::span<const std::uint8_t> bytes, int timeout_seconds,
                      std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    const PipeSignalBlocked no_signal;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    std::size_t written = 0;
    while (written < bytes.size()) {
        pump(c, 20, bytes, &written);
        update_state(c);
        if (c.state == WaitingState::Ended || c.state == WaitingState::HandedOver) {
            error = std::string("the preparation was not sent: ") + state_in_words(c.state) +
                    (c.failure.empty() ? "" : ": " + c.failure);
            return false;
        }
        if (c.child.in < 0) {
            error = "the preparation was not sent: the worker closed its standard input";
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            error = "the preparation was not sent within " + std::to_string(timeout_seconds) + " seconds";
            return false;
        }
    }
    return true;
}

std::string take_output(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    pump(c, 0, {}, nullptr);
    update_state(c);
    std::string taken;
    taken.swap(c.output);
    return taken;
}

bool hand_over_file(WaitingChild& child, const io::File& file, std::span<const std::uint8_t> job,
                    std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    pump(c, 0, {}, nullptr);
    update_state(c);
    if (c.state != WaitingState::Waiting) {
        // Starting: no file before the worker reported stage 1. HandedOver: one file per worker.
        error = std::string("the file was not handed over: ") + state_in_words(c.state) +
                (c.failure.empty() ? "" : ": " + c.failure);
        return false;
    }
    if (job.size() > kMaxJobBytes) {
        error = "the file was not handed over: the job is longer than " + std::to_string(kMaxJobBytes) + " bytes";
        return false;
    }
    HandOverFrame frame{};
    frame.magic = kFrameMagic;
    frame.version = 1;
    frame.job_length = static_cast<std::uint32_t>(job.size());
    if (!job.empty()) {
        std::memcpy(frame.job, job.data(), job.size());
    }
    // The descriptor of the parent's file: opened read-only by mie::io. The worker gets a
    // descriptor of the same open file, so it is read-only there too; the worker checks it.
    const int descriptor = static_cast<int>(file.native_handle());
    if (!send_on_channel(c, &frame, sizeof frame, &descriptor, 1, error)) {
        kill_waiting(c);
        update_state(c);
        return false;
    }
    after_hand_over(c);
    return true;
}

ChildResult collect(WaitingChild& child, const Limits& limits) {
    WaitingChild::Impl& c = child.impl();
    ChildResult result;
    if (c.state != WaitingState::HandedOver) {
        const std::string why = c.state == WaitingState::Ended
                                    ? "the worker had ended before it was given a file: " + c.failure
                                    : std::string("collect() was called on a worker that was given no file");
        end_waiting(child);
        result.end = ChildResult::End::StartFailed;
        result.detail = why;
        result.confinement = parent_part_of(c) + "; child: " + (c.stage1 ? "stage 1 only: " + c.stage1_text : "not confirmed");
        return result;
    }
    const auto deadline = c.handed_over + std::chrono::seconds(limits.wall_seconds > 0 ? limits.wall_seconds : 0);
    while (!c.finished) {
        pump(c, 20, {}, nullptr);
        const bool streams_open = c.child.out >= 0 || c.child.err >= 0 || c.child.status >= 0;
        if (c.reaped && !streams_open) {
            break;
        }
        if (c.reaped && std::chrono::steady_clock::now() - c.reaped_at > std::chrono::milliseconds(500)) {
            break;
        }
        if (!c.reaped && std::chrono::steady_clock::now() >= deadline && !c.killed) {
            c.killed_time = true;
            kill_waiting(c);
        }
    }
    finish_child(c);
    c.state = WaitingState::Ended;

    result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - c.handed_over).count();
#if defined(__APPLE__)
    result.peak_memory_bytes = static_cast<std::uint64_t>(c.usage.ru_maxrss);
#else
    result.peak_memory_bytes = static_cast<std::uint64_t>(c.usage.ru_maxrss) * 1024;
#endif
    if (result.peak_memory_bytes == 0) {
        result.peak_memory_bytes = c.highest_resident;
    }
    result.confinement =
        parent_part_of(c) + "; child: " +
        (!c.confine ? std::string("none (confinement not requested)")
                    : c.sealed ? c.seal_text
                               : c.stage1 ? "stage 1 only, NOT sealed: " + c.stage1_text : std::string("not confirmed"));
    if (!c.error_text.empty()) {
        result.detail = "standard error: " + c.error_text;
    }
    const auto with_detail = [&](const std::string& text) {
        result.detail = result.detail.empty() ? text : text + "; " + result.detail;
    };
    if (WIFEXITED(c.wait_status)) {
        result.exit_code = WEXITSTATUS(c.wait_status);
    } else if (WIFSIGNALED(c.wait_status)) {
        result.exit_code = 128 + WTERMSIG(c.wait_status);
    }

    if (c.confine && !c.sealed) {
        // Reviewer's condition: the answer of a worker that did not report its full
        // confinement is discarded, whatever it wrote and however it ended.
        result.end = c.killed_time ? ChildResult::End::KilledByTimeLimit : ChildResult::End::StartFailed;
        with_detail(!c.seal_failure.empty()
                        ? "the worker refused the hand-over or could not seal: " + c.seal_failure + " (" +
                              end_in_words(c) + "); nothing it wrote is used"
                        : "the worker did not report its full confinement (" + end_in_words(c) +
                              "); its answer is discarded");
        return result;
    }
    result.output = std::move(c.output);
    if (c.killed_time) {
        result.end = ChildResult::End::KilledByTimeLimit;
        with_detail("killed at the time limit of " + std::to_string(limits.wall_seconds) +
                    " seconds after the hand-over");
    } else if (c.killed_memory) {
        result.end = ChildResult::End::KilledByMemoryLimit;
        with_detail("killed: resident memory went over " + std::to_string(c.memory_bytes) + " bytes");
    } else if (c.killed_output) {
        result.end = ChildResult::End::Crashed;
        with_detail("killed: more output than the allowed " + std::to_string(c.max_output) + " bytes");
    } else if (WIFEXITED(c.wait_status)) {
        if (result.exit_code == kOutOfMemoryExitCode) {
            result.end = ChildResult::End::KilledByMemoryLimit;
            with_detail("the child ran out of its memory limit (an allocation was refused)");
        } else {
            result.end = ChildResult::End::Exited;
        }
    } else {
        result.end = ChildResult::End::Crashed;
        with_detail("ended by " + end_in_words(c));
    }
    return result;
}

void end_waiting(WaitingChild& child) {
    WaitingChild::Impl& c = child.impl();
    if (c.finished) {
        c.state = WaitingState::Ended;
        return;
    }
    // Closing the channel is the polite way (the worker ends by itself with kNoJobExitCode);
    // the kill makes sure.
    kill_waiting(c);
    finish_child(c);
    if (c.failure.empty()) {
        c.failure = "ended by the parent without having been used";
    }
    c.state = WaitingState::Ended;
}

std::string confinement_at_start(const WaitingChild& child) {
    const WaitingChild::Impl& c = child.impl();
    return parent_part_of(c) + "; child: " +
           (!c.confine ? std::string("none (confinement not requested)")
                       : c.stage1 ? "stage 1: " + c.stage1_text : std::string("not yet reported"));
}

std::string failure(const WaitingChild& child) { return child.impl().failure; }

double seconds_since_start(const WaitingChild& child) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - child.impl().started).count();
}

#if defined(MIE_SANDBOX_TEST_HOOKS)
// Tests only: a hand-over that is not as required. The worker must refuse it.
bool hand_over_malformed(WaitingChild& child, MalformedHandOver kind, const std::filesystem::path& file,
                         std::string& error) {
    WaitingChild::Impl& c = child.impl();
    error.clear();
    pump(c, 0, {}, nullptr);
    update_state(c);
    if (c.state != WaitingState::Waiting) {
        error = std::string("not sent: ") + state_in_words(c.state);
        return false;
    }
    HandOverFrame frame{};
    frame.magic = kFrameMagic;
    frame.version = 1;
    int descriptors[2] = {-1, -1};
    std::size_t count = 0;
    std::size_t size = sizeof frame;
    switch (kind) {
        case MalformedHandOver::NoDescriptor:
            break;
        case MalformedHandOver::TwoDescriptors:
            descriptors[0] = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
            descriptors[1] = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
            count = 2;
            break;
        case MalformedHandOver::NotARegularFile:
            descriptors[0] = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            count = 1;
            break;
        case MalformedHandOver::Writable:
            descriptors[0] = ::open(file.c_str(), O_RDWR | O_CLOEXEC);
            count = 1;
            break;
        case MalformedHandOver::ShortMessage:
            descriptors[0] = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
            count = 1;
            size = 8;
            break;
    }
    bool sent = false;
    if ((count >= 1 && descriptors[0] < 0) || (count == 2 && descriptors[1] < 0)) {
        error = errno_text("test set-up: opening the file", errno);
    } else {
        sent = send_on_channel(c, &frame, size, descriptors, count, error);
    }
    close_fd(descriptors[0]);
    close_fd(descriptors[1]);
    if (sent) {
        after_hand_over(c);
    }
    return sent;
}
#endif

// =============================== the child's side ===============================

#if defined(__linux__)

namespace {

#if defined(__x86_64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_X86_64;
#define MIE_SECCOMP_ARCH_KNOWN 1
#elif defined(__aarch64__)
constexpr std::uint32_t kAuditArch = AUDIT_ARCH_AARCH64;
#define MIE_SECCOMP_ARCH_KNOWN 1
#else
#define MIE_SECCOMP_ARCH_KNOWN 0
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

// Landlock, by number, so that old kernel headers do not matter (the numbers are the same
// on every processor).
constexpr long kSysLandlockCreateRuleset = 444;
constexpr long kSysLandlockRestrictSelf = 446;

struct LandlockRulesetAttr {
    std::uint64_t handled_access_fs;
    std::uint64_t handled_access_net;
    std::uint64_t scoped;
};

// Landlock with NO rule: every kind of file access the kernel's Landlock version knows is
// refused for every path, for this process and whatever it starts. It does not refuse
// reading or writing through a descriptor that is already open (the standard streams, the
// handed-over file), nor stat() of a path. From version 4 it also refuses binding and
// connecting TCP sockets; from version 6, signals to processes outside and abstract
// Unix-socket connections. Returns a short description, or the reason it is not there.
bool apply_landlock(std::string& what, std::string& why_not) {
    const long abi = ::syscall(kSysLandlockCreateRuleset, nullptr, 0, 1u /* ask for the version */);
    if (abi < 1) {
        why_not = std::string("no Landlock on this kernel (") + std::strerror(errno) + ")";
        return false;
    }
    LandlockRulesetAttr attr{};
    attr.handled_access_fs = (1ull << 13) - 1;      // version 1: execute ... make_sym
    if (abi >= 2) attr.handled_access_fs |= 1ull << 13;  // refer
    if (abi >= 3) attr.handled_access_fs |= 1ull << 14;  // truncate
    if (abi >= 5) attr.handled_access_fs |= 1ull << 15;  // ioctl on devices
    std::size_t size = sizeof(std::uint64_t);
    if (abi >= 4) {
        attr.handled_access_net = 3;  // bind TCP, connect TCP
        size = 2 * sizeof(std::uint64_t);
    }
    if (abi >= 6) {
        attr.scoped = 3;  // abstract Unix sockets, signals
        size = 3 * sizeof(std::uint64_t);
    }
    const long ruleset = ::syscall(kSysLandlockCreateRuleset, &attr, size, 0u);
    if (ruleset < 0) {
        why_not = errno_text("Landlock ruleset", errno);
        return false;
    }
    const long applied = ::syscall(kSysLandlockRestrictSelf, static_cast<int>(ruleset), 0u);
    const int err = errno;
    ::close(static_cast<int>(ruleset));
    if (applied != 0) {
        why_not = errno_text("Landlock restrict", err);
        return false;
    }
    what = "landlock v" + std::to_string(abi) + " (no file access by path" + (abi >= 4 ? ", no TCP" : "") + ")";
    return true;
}

#if MIE_SECCOMP_ARCH_KNOWN

// ---- the seccomp filter: an ALLOW LIST ---------------------------------------------------
//
// Every system call that is not named below is REFUSED. The refusal is the error "operation
// not permitted" (EPERM), not the death of the process, for this reason: the C library and
// other libraries try optional calls and take another way when one fails (a refused call is
// then harmless), and a refused call leaves a worker that can still report what happened.
// The call is not carried out either way. One exception: a call made through another calling
// convention KILLS the process (nothing legitimate does that).
//
// The list is what a TRACE of the real worker shows (reviewer's ruling B-3627), plus a small
// margin in which every call has one written reason. There is NO call that starts a thread or
// a process, opens a path or makes a socket: a library that tries to start a thread gets the
// refusal error from clone / clone3 (pthread_create fails, std::thread throws).
// SANDBOX_NOTES.md has the same list.

sock_filter stmt(unsigned code, std::uint32_t k) {
    sock_filter instruction{};
    instruction.code = static_cast<__u16>(code);
    instruction.k = k;
    return instruction;
}

sock_filter jump(unsigned code, std::uint32_t k, std::size_t if_true, std::size_t if_false) {
    sock_filter instruction{};
    instruction.code = static_cast<__u16>(code);
    instruction.jt = static_cast<__u8>(if_true);
    instruction.jf = static_cast<__u8>(if_false);
    instruction.k = k;
    return instruction;
}

constexpr unsigned kLoad = BPF_LD | BPF_W | BPF_ABS;
constexpr unsigned kIfEqual = BPF_JMP | BPF_JEQ | BPF_K;
constexpr unsigned kIfAtLeast = BPF_JMP | BPF_JGE | BPF_K;
constexpr unsigned kIfAnyBit = BPF_JMP | BPF_JSET | BPF_K;
constexpr unsigned kReturn = BPF_RET | BPF_K;

// The low 32 bits of argument `index` (little-endian: checked in apply_seccomp).
std::uint32_t argument_low(unsigned index) {
    return static_cast<std::uint32_t>(offsetof(struct seccomp_data, args) + 8u * index);
}

// Why a call is on the list. engine/tools/sandbox_trace_check.py reads these tags from this
// file, so every allow line below ends with exactly one of them:
//   TRACED            seen in a trace of the real worker (OpenSSL, YARA) on the test files;
//   MARGIN("why")     never seen in a trace; it stays for the ONE reason written there.
//                     No reason, no call. Nothing that starts a thread or a process, opens a
//                     path or makes a socket may be a MARGIN call;
//   SANITIZER("why")  only in a sanitizer build, which is never shipped.
struct Tag {
    const char* why;
};
constexpr Tag TRACED{nullptr};
constexpr Tag MARGIN(const char* why) { return Tag{why}; }
constexpr Tag SANITIZER(const char* why) { return Tag{why}; }

// Builds the filter. Every "allow" block starts with the call number in the accumulator and,
// when the number is another one, jumps over itself with the number still there; when the
// number matches, the block always returns.
class Filter {
public:
    explicit Filter(std::uint32_t refuse) : refuse_(refuse) {}

    void raw(sock_filter instruction) { code_.push_back(instruction); }

    void allow(long number, Tag) {
        raw(jump(kIfEqual, static_cast<std::uint32_t>(number), 0, 1));
        raw(stmt(kReturn, SECCOMP_RET_ALLOW));
        ++allowed_;
    }

    // Allowed only if the low 32 bits of argument `index` are one of `values`.
    void allow_if_argument_is(long number, unsigned index, std::initializer_list<std::uint32_t> values, Tag) {
        const std::size_t count = values.size();
        raw(jump(kIfEqual, static_cast<std::uint32_t>(number), 0, count + 3));
        raw(stmt(kLoad, argument_low(index)));
        std::size_t i = 0;
        for (const std::uint32_t value : values) {
            raw(jump(kIfEqual, value, count - i, 0));  // equal: over the rest and the refusal
            ++i;
        }
        raw(stmt(kReturn, refuse_));
        raw(stmt(kReturn, SECCOMP_RET_ALLOW));
        ++allowed_;
    }

    // Allowed only if argument `index` has no bit of `mask`.
    void allow_unless_bits(long number, unsigned index, std::uint32_t mask, Tag) {
        raw(jump(kIfEqual, static_cast<std::uint32_t>(number), 0, 4));
        raw(stmt(kLoad, argument_low(index)));
        raw(jump(kIfAnyBit, mask, 0, 1));
        raw(stmt(kReturn, refuse_));
        raw(stmt(kReturn, SECCOMP_RET_ALLOW));
        ++allowed_;
    }

    std::vector<sock_filter>& code() { return code_; }
    std::size_t allowed() const { return allowed_; }

private:
    std::vector<sock_filter> code_;
    std::uint32_t refuse_;
    std::size_t allowed_ = 0;
};

// Installs the filter for the calling thread (the worker has one thread when it calls this,
// and can start no other). It cannot be removed again.
bool apply_seccomp(std::string& what, std::string& why_not) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    why_not = "the seccomp filter is written for little-endian processors only";
    return false;
#else
    const auto errno_return = [](int err) {
        return static_cast<std::uint32_t>(SECCOMP_RET_ERRNO | (static_cast<std::uint32_t>(err) & SECCOMP_RET_DATA));
    };
    const std::uint32_t own_pid = static_cast<std::uint32_t>(::getpid());
    Filter filter(errno_return(EPERM));

    // A call made through another calling convention (32-bit on a 64-bit kernel) has other
    // numbers and would be judged as the wrong call: such a process is killed.
    filter.raw(stmt(kLoad, static_cast<std::uint32_t>(offsetof(struct seccomp_data, arch))));
    filter.raw(jump(kIfEqual, kAuditArch, 1, 0));
    filter.raw(stmt(kReturn, SECCOMP_RET_KILL_PROCESS));
    filter.raw(stmt(kLoad, static_cast<std::uint32_t>(offsetof(struct seccomp_data, nr))));
#if defined(__x86_64__)
    // The x32 calling convention shares the processor type but numbers its calls from 2^30.
    filter.raw(jump(kIfAtLeast, 0x40000000u, 0, 1));
    filter.raw(stmt(kReturn, errno_return(EPERM)));
#endif

    // ---- seen in the trace of the real worker (run on set S; 14 calls) ----------------------
    filter.allow(SYS_read, TRACED);            // standard input: the rules, the tables
    filter.allow(SYS_pread64, TRACED);         // the handed-over file at an offset
    filter.allow(SYS_write, TRACED);           // the answer, the status line; fails by itself on the read-only file
    filter.allow(SYS_close, TRACED);           // its own descriptors
    filter.allow(SYS_fstat, TRACED);           // size and kind of an OPEN descriptor; takes no path
    filter.allow(SYS_brk, TRACED);             // the allocator's heap
    filter.allow(SYS_munmap, TRACED);          // giving memory back
    filter.allow(SYS_futex, TRACED);           // locks inside the C and C++ libraries (once-only initialisation)
    filter.allow(SYS_getpid, TRACED);          // its own number (OpenSSL asks; abort)
    filter.allow(SYS_rt_sigaction, TRACED);    // its own signal handlers
    filter.allow(SYS_rt_sigprocmask, TRACED);  // its own signal mask
    filter.allow(SYS_exit_group, TRACED);      // the process ends
#if MIE_SANITIZER_BUILD
    filter.allow(SYS_mmap, SANITIZER("the runtime maps its shadow memory and may map with any protection"));
    filter.allow(SYS_prctl, SANITIZER("the runtime names its mappings and reads process settings"));
#else
    // New memory, but never EXECUTABLE (PROT_EXEC = 4): no code can be made after the confinement.
    filter.allow_unless_bits(SYS_mmap, 2, 0x4u, TRACED);
    // prctl: only the three questions describe_self() asks (PR_GET_DUMPABLE = 3,
    // PR_GET_SECCOMP = 21, PR_GET_NO_NEW_PRIVS = 39). Nothing can be set.
    filter.allow_if_argument_is(SYS_prctl, 0, {3u, 21u, 39u}, TRACED);
#endif

    // ---- the margin: never seen in a trace; one reason each ---------------------------------
    filter.allow(SYS_rt_sigreturn, MARGIN("the kernel's return path from a signal handler: a process that has a handler (rt_sigaction is traced) cannot avoid it"));
    filter.allow(SYS_restart_syscall, MARGIN("the kernel's own way to resume an interrupted wait (futex is traced) after the process was stopped and continued: the process does not choose to make it"));
    filter.allow(SYS_clock_gettime, MARGIN("reading a clock: normally answered without a system call (vDSO); this is the fallback on machines whose clock source has none, and a refusal would give the worker a wrong time silently"));
    filter.allow(SYS_getrandom, MARGIN("OpenSSL seeds its random generator on first need; refused, it tries to open /dev/urandom, which is refused, and the operation fails; takes no path, gives no descriptor"));
    filter.allow(SYS_mremap, MARGIN("realloc of a large block; refused, the C library copies instead and needs twice the memory for a moment, which changes what fits under the memory limit; expected in the trace of the large files"));
    filter.allow(SYS_writev, MARGIN("the C++ stream library writes a buffer plus new data with one writev, and the C library prints its fatal messages with it; same open descriptors as write; refused, an answer written through a stream is cut"));
    filter.allow(SYS_gettid, MARGIN("abort() and assert() ask for their own thread number before they signal it (see tgkill); answers a number, changes nothing"));
    // tgkill: only to THIS process (first argument = its own number).
    filter.allow_if_argument_is(SYS_tgkill, 0, {own_pid}, MARGIN("abort() and assert(): a signal to its own thread, checked to be this process; refused, abort falls back to a halt instruction and the crash is reported as signal 11 instead of 6"));

#if MIE_SANITIZER_BUILD
    // ---- SANITIZER BUILD ONLY: never in a shipped program ----------------------------------
    // The sanitizer runtime works while the program runs: it protects and releases memory,
    // sets an alternate signal stack, reads /proc and asks about the machine. This WIDER list
    // exists so that the sanitizer job can run the same tests; the text in `what` says so, so
    // no log can pass for the shipped filter. Paths can be opened here: in this build "no file
    // by path" rests on Landlock alone.
    filter.allow(SYS_mprotect, SANITIZER("runtime: guard pages and shadow memory"));
    filter.allow(SYS_madvise, SANITIZER("runtime: its allocator gives pages back"));
    filter.allow(SYS_sigaltstack, SANITIZER("runtime: alternate signal stack"));
    filter.allow(SYS_sched_yield, SANITIZER("runtime: its spin locks"));
    filter.allow(SYS_nanosleep, SANITIZER("runtime: waits in its locks and at a report"));
    filter.allow(SYS_clock_nanosleep, SANITIZER("runtime: the same, newer C library"));
    filter.allow(SYS_openat, SANITIZER("runtime: reads /proc/self/maps and similar"));
    filter.allow(SYS_readlinkat, SANITIZER("runtime: finds its own program for reports"));
    filter.allow(SYS_newfstatat, SANITIZER("runtime: file questions while reading /proc"));
    filter.allow(SYS_getdents64, SANITIZER("runtime: lists /proc/self/task"));
    filter.allow(SYS_lseek, SANITIZER("runtime: reading /proc files"));
    filter.allow(SYS_sysinfo, SANITIZER("runtime: memory of the machine"));
    filter.allow(SYS_uname, SANITIZER("runtime: kernel version"));
    filter.allow(SYS_getrusage, SANITIZER("runtime: its memory statistics"));
    filter.allow(SYS_prlimit64, SANITIZER("runtime: reads the stack and address-space limits"));
    filter.allow(SYS_sched_getaffinity, SANITIZER("runtime: number of processors"));
    filter.allow(SYS_mincore, SANITIZER("runtime: checks whether memory is mapped"));
    filter.allow(SYS_mlock, SANITIZER("runtime"));
    filter.allow(SYS_munlock, SANITIZER("runtime"));
    filter.allow(SYS_exit, SANITIZER("runtime: a thread of the runtime ends"));
    // Established by CI run 45132119984: without it the runtime stops the real worker at its
    // first check of a memory range ("CHECK failed: sanitizer_posix_libcdep.cpp:324
    // ((0)) == ((pipe(fds)))"), before the worker can answer.
    filter.allow(SYS_pipe2, SANITIZER("runtime: tests whether memory is readable by writing it to a pipe of its own"));
    // Second stop, run 45134340352: "CHECK failed: sanitizer_posix_libcdep.cpp:312
    // ((!internal_iserror(res, nullptr))) != (0)": the runtime then sets that pipe non-blocking.
    filter.allow(SYS_fcntl, SANITIZER("runtime: sets its own pipe non-blocking (F_GETFL, F_SETFL)"));
#ifdef SYS_pipe
    filter.allow(SYS_pipe, SANITIZER("runtime: the same, older call"));
#endif
#ifdef SYS_readlink
    filter.allow(SYS_readlink, SANITIZER("runtime: finds its own program for reports"));
#endif
#ifdef SYS_getrlimit
    filter.allow(SYS_getrlimit, SANITIZER("runtime: reads the stack limit"));
#endif
#endif

    // Everything else.
    filter.raw(stmt(kReturn, errno_return(EPERM)));

    struct sock_fprog program {};
    program.len = static_cast<unsigned short>(filter.code().size());
    program.filter = filter.code().data();
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) != 0) {
        why_not = errno_text("seccomp filter", errno);
        return false;
    }
#if MIE_SANITIZER_BUILD
    what = "seccomp SANITIZER-BUILD WIDER allow list, NOT the shipped filter (" +
           std::to_string(filter.allowed()) + " calls allowed, the rest refused with EPERM)";
#else
    what = "seccomp allow list (" + std::to_string(filter.allowed()) +
           " calls allowed, the rest refused with EPERM)";
#endif
    return true;
#endif
}

#else  // processor not known to the filter

bool apply_seccomp(std::string&, std::string& why_not) {
    why_not = "the seccomp filter is not written for this processor";
    return false;
}

#endif

// One line to the parent on the status descriptor: "ok <what>" or "fail <why>".
void tell_parent(bool ok, const std::string& text) {
    const char* value = std::getenv("MIE_SANDBOX_STATUS_FD");
    if (value == nullptr || *value == '\0') {
        return;  // not started through run_confined: nobody is waiting
    }
    const int fd = std::atoi(value);
    if (fd <= 2) {
        return;
    }
    std::string line = (ok ? "ok " : "fail ") + text;
    for (char& c : line) {
        if (c == '\n' || c == '\r') {
            c = ' ';
        }
    }
    line.push_back('\n');
    std::size_t done = 0;
    while (done < line.size()) {
        const ssize_t n = ::write(fd, line.data() + done, line.size() - done);
        if (n <= 0) {
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    ::close(fd);
}

#if defined(MIE_SANDBOX_TEST_HOOKS)
// Test builds only (reviewer's finding SB-1): the shipped library does not read these.
bool flag_set(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr && std::strcmp(value, "1") == 0;
}
#endif

}  // namespace

bool enter_confinement(std::string& what_applied, std::string& error) {
    what_applied.clear();
    error.clear();
    // The two test switches exist only in the test build of this library. In the shipped
    // build nothing in the environment can weaken or skip the confinement.
    bool allow_weaker = false;
    bool test_break = false;
#if defined(MIE_SANDBOX_TEST_HOOKS)
    allow_weaker = flag_set("MIE_SANDBOX_ALLOW_WEAKER");
    test_break = flag_set("MIE_SANDBOX_TEST_BREAK");
#endif
    std::vector<std::string> applied;
    std::vector<std::string> missing;   // required parts that could not be applied
    std::vector<std::string> remarks;   // optional parts that are not there

    if (test_break) {
        missing.push_back("test hook: the confinement was deliberately not applied");
    } else {
        // no-new-privileges (also set by the parent before exec; repeated so that a worker
        // started some other way still has it).
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
            applied.push_back("no-new-privileges");
        } else {
            missing.push_back(errno_text("no-new-privileges", errno));
        }
        // Not dumpable: no core file, and another process of the same user cannot attach a
        // debugger to this one or read its memory through /proc.
        if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0) {
            applied.push_back("not dumpable");
        }
        std::string what;
        std::string why_not;
        // The handed-over file is taken over before the filter (see adopt_inherited_file).
        if (std::getenv("MIE_INHERITED_FILE") != nullptr) {
            adopt_inherited_file();
            if (!g_inherited.file) {
                missing.push_back(g_inherited.error);
            }
        }
        // Landlock first (its own calls must still be allowed), then the filter.
        if (apply_landlock(what, why_not)) {
            applied.push_back(what);
        } else {
            remarks.push_back(why_not);  // optional: "where the kernel offers it"
        }
        if (apply_seccomp(what, why_not)) {
            applied.push_back(what);
        } else {
            missing.push_back(why_not);  // required: without it the worker could open sockets
        }
    }

    const auto joined = [](const std::vector<std::string>& parts) {
        std::string out;
        for (const std::string& part : parts) {
            out += (out.empty() ? "" : ", ") + part;
        }
        return out;
    };
    what_applied = joined(applied);
    if (!remarks.empty()) {
        what_applied += (what_applied.empty() ? "" : "; ") + joined(remarks);
    }
    if (!missing.empty()) {
        error = joined(missing);
        if (!allow_weaker) {
            tell_parent(false, error);
            return false;
        }
        what_applied += (what_applied.empty() ? "" : "; ") + std::string("WEAKER: ") + error;
    }
    tell_parent(true, what_applied.empty() ? "nothing" : what_applied);
    return true;
}

// ================== pre-started one-shot workers (ruling M-13): the worker ==================
//
// The exact order, and why it is in this order:
//
//   BEFORE exec, by the parent (as for every child): own process group, die-with-parent
//     signal, no-new-privileges, no core file, address-space limit, descriptors 0, 1, 2, the
//     channel on 3, the status pipe on 4, everything else closed, minimal environment.
//
//   enter_confinement_stage1(), first thing in main():
//     1. no-new-privileges (again), not dumpable;
//     2. Landlock: no file by path, no TCP (where the kernel has it);
//     3. one line "stage1 <what>" on the status pipe. The parent hands no file to a worker
//        that has not sent this line.
//     The system-call filter is NOT installed yet.
//
//   The worker PREPARES: it reads its rules and tables from standard input and compiles
//     them. Those bytes come from the parent and are the product's own shipped files; nobody
//     who can choose the file to be scanned can choose them. In this window system calls are
//     not filtered; what holds is Landlock (no path, no TCP), no-new-privileges and the
//     limits. The remaining risk in one sentence: a defect in compiling OUR OWN rule files
//     would run without the filter.
//
//   receive_file_and_seal():
//     4. recvmsg on the channel: ONE message of fixed size with exactly ONE descriptor.
//        (recvmsg is not on the filter's list and need not be: the filter is not yet there.)
//        End of channel instead (the parent closed it or died): exit kNoJobExitCode.
//     5. the message and the descriptor are CHECKED, nothing of the file is read: whole
//        message, right size, one descriptor, a regular file (fstat), opened read-only
//        (fcntl F_GETFL; asked here because fcntl is not on the list afterwards). Anything
//        else: every received descriptor is closed, "fail <why>" on the status pipe, exit
//        kHandOverRefusedExitCode, no answer.
//     6. the channel is closed (no second job can arrive);
//     7. the file is taken over as an io::File (asks its size: fstat);
//     8. the system-call filter is installed (the same list as for a one-shot child);
//     9. one line "ok <what>" on the status pipe, which is then closed. The parent discards
//        the answer of a worker from which this line did not come;
//    10. the file and the job bytes are returned to the caller. The job bytes were copied in
//        step 4 and are not looked at by this code beyond their length.
//   From here on the worker reads the file: the first hostile byte, under the full confinement.
//   Open descriptors at that point: 0, 1, 2 and the file.

namespace {

std::string g_stage1_text;  // what stage 1 applied, repeated in the final report

// One line on the status pipe. `close_after`: the pipe is closed (the last line).
void status_line(const char* prefix, const std::string& text, bool close_after) {
    const char* value = std::getenv("MIE_SANDBOX_STATUS_FD");
    const int fd = value != nullptr ? std::atoi(value) : -1;
    if (fd <= 2) {
        return;  // started without confinement: nobody reads a status
    }
    std::string line = std::string(prefix) + " " + text;
    for (char& c : line) {
        if (c == '\n' || c == '\r') {
            c = ' ';
        }
    }
    line.push_back('\n');
    std::size_t done = 0;
    while (done < line.size()) {
        const ssize_t n = ::write(fd, line.data() + done, line.size() - done);
        if (n <= 0) {
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    if (close_after) {
        ::close(fd);
    }
}

[[noreturn]] void refuse_hand_over(const std::string& why) {
    status_line("fail", why, true);
    ::_exit(kHandOverRefusedExitCode);
}

}  // namespace

bool enter_confinement_stage1(std::string& what_applied, std::string& error) {
    what_applied.clear();
    error.clear();
    if (std::getenv("MIE_SANDBOX") == nullptr) {
        // The parent started this worker without confinement (RunOptions::confine = false).
        what_applied = "none (the parent did not ask for confinement)";
        g_stage1_text = what_applied;
        return true;
    }
    bool allow_weaker = false;
    bool test_break = false;
#if defined(MIE_SANDBOX_TEST_HOOKS)
    allow_weaker = flag_set("MIE_SANDBOX_ALLOW_WEAKER");
    test_break = flag_set("MIE_SANDBOX_TEST_BREAK");
#endif
    std::vector<std::string> applied;
    std::vector<std::string> missing;
    if (test_break) {
        missing.push_back("test hook: the confinement was deliberately not applied");
    } else {
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
            applied.push_back("no-new-privileges");
        } else {
            missing.push_back(errno_text("no-new-privileges", errno));
        }
        if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0) {
            applied.push_back("not dumpable");
        }
        std::string what;
        std::string why_not;
        if (apply_landlock(what, why_not)) {
            applied.push_back(what);
        } else {
            applied.push_back(why_not);  // "no Landlock on this kernel": said, not a failure
        }
    }
    for (const std::string& part : applied) {
        what_applied += (what_applied.empty() ? "" : ", ") + part;
    }
    if (!missing.empty()) {
        for (const std::string& part : missing) {
            error += (error.empty() ? "" : ", ") + part;
        }
        if (!allow_weaker) {
            status_line("fail", error, true);
            return false;
        }
        what_applied += (what_applied.empty() ? "" : "; ") + std::string("WEAKER: ") + error;
    }
    g_stage1_text = what_applied;
    status_line("stage1", what_applied.empty() ? "nothing" : what_applied, false);
    return true;
}

std::unique_ptr<io::File> receive_file_and_seal(std::vector<std::uint8_t>& job, std::string& what_applied) {
    job.clear();
    what_applied.clear();
    const bool confine = std::getenv("MIE_SANDBOX") != nullptr;
    const char* channel_text = std::getenv("MIE_SANDBOX_CHANNEL_FD");
    const int channel = channel_text != nullptr ? std::atoi(channel_text) : -1;
    if (channel < 3) {
        refuse_hand_over("this worker has no channel on which a file could arrive");
    }

    // Step 4: one message. Room for four descriptors, so that "more than one" is seen and
    // every one of them can be closed.
    HandOverFrame frame{};
    struct iovec part {};
    part.iov_base = &frame;
    part.iov_len = sizeof frame;
    alignas(struct cmsghdr) char control[CMSG_SPACE(sizeof(int) * 4)];
    std::memset(control, 0, sizeof control);
    struct msghdr message {};
    message.msg_iov = &part;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    ssize_t got = 0;
    do {
        got = ::recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    } while (got < 0 && errno == EINTR);
    if (got == 0) {
        ::close(channel);
        ::_exit(kNoJobExitCode);  // the parent closed the channel or is gone: never used
    }
    if (got < 0) {
        refuse_hand_over(errno_text("receiving the hand-over", errno));
    }

    // Step 5: checks. The descriptors that came are collected first, so that they can all be
    // closed if anything is wrong.
    int received[4] = {-1, -1, -1, -1};
    std::size_t count = 0;
    bool other_control = false;
    if (message.msg_controllen >= sizeof(struct cmsghdr)) {
        const struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        if (header != nullptr && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS) {
            count = (static_cast<std::size_t>(header->cmsg_len) - CMSG_LEN(0)) / sizeof(int);
            if (count > 4) {
                count = 4;
            }
            std::memcpy(received, CMSG_DATA(header), count * sizeof(int));
            other_control = static_cast<std::size_t>(message.msg_controllen) > CMSG_SPACE(count * sizeof(int));
        } else {
            other_control = true;
        }
    }
    std::string why;
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        why = "the hand-over message was cut: it is too long or carries too many descriptors";
    } else if (static_cast<std::size_t>(got) != sizeof frame) {
        why = "the hand-over message has the wrong size";
    } else if (other_control) {
        why = "the hand-over message carries something other than one descriptor";
    } else if (count == 0) {
        why = "the hand-over message carries no file";
    } else if (count != 1) {
        why = "the hand-over message carries more than one descriptor";
    } else if (frame.magic != kFrameMagic || frame.version != 1 || frame.job_length > kMaxJobBytes) {
        why = "the hand-over message is not in the expected form";
    } else {
        struct stat status {};
        const int flags = ::fcntl(received[0], F_GETFL);
        if (::fstat(received[0], &status) != 0) {
            why = errno_text("the handed-over descriptor cannot be asked what it is", errno);
        } else if (!S_ISREG(status.st_mode)) {
            why = "the handed-over descriptor is not a regular file";
        } else if (flags == -1 || (flags & O_ACCMODE) != O_RDONLY) {
            why = "the handed-over file is not opened read-only";
        }
    }
    if (!why.empty()) {
        for (std::size_t i = 0; i < count; ++i) {
            ::close(received[i]);
        }
        ::close(channel);
        refuse_hand_over(why);
    }

    // Step 6: no second job can arrive.
    ::close(channel);

    // Step 7: the file as the rest of the engine knows it (asks its size; reads no content).
    io::IoError io_error;
    std::unique_ptr<io::File> file = io::adopt_native_handle(static_cast<std::intptr_t>(received[0]), io_error);
    if (!file) {
        refuse_hand_over(std::string("the handed-over file cannot be used: ") + io::to_string(io_error.code));
    }

    // Step 8: the system-call filter.
    std::string filter_text = "no system-call filter (the parent did not ask for confinement)";
    if (confine) {
        bool allow_weaker = false;
        bool test_break = false;
#if defined(MIE_SANDBOX_TEST_HOOKS)
        allow_weaker = flag_set("MIE_SANDBOX_ALLOW_WEAKER");
        test_break = flag_set("MIE_SANDBOX_TEST_BREAK");
#endif
        std::string why_not = "test hook: the system-call filter was deliberately not installed";
        if (test_break || !apply_seccomp(filter_text, why_not)) {
            if (!allow_weaker) {
                refuse_hand_over("the worker could not seal itself: " + why_not);
            }
            filter_text = "WEAKER: " + why_not;
        }
    }

    // Step 9: the report. Step 10: the file goes to the caller.
    what_applied = g_stage1_text + (g_stage1_text.empty() ? "" : ", ") + filter_text;
    status_line("ok", what_applied, true);
    job.assign(frame.job, frame.job + frame.job_length);
    return file;
}

std::string describe_self() {
    const int no_new_privs = ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    const int seccomp = ::prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    const int dumpable = ::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    return "no_new_privs=" + std::to_string(no_new_privs) + " seccomp=" + std::to_string(seccomp) +
           " dumpable=" + std::to_string(dumpable);
}

#else  // POSIX, not Linux

bool enter_confinement(std::string& what_applied, std::string& error) {
    what_applied.clear();
    error = "no confinement is written for this system";
    const char* value = std::getenv("MIE_SANDBOX_STATUS_FD");
    if (value != nullptr && std::atoi(value) > 2) {
        const std::string line = "fail " + error + "\n";
        const ssize_t ignored = ::write(std::atoi(value), line.data(), line.size());
        (void)ignored;
        ::close(std::atoi(value));
    }
    return false;
}

bool enter_confinement_stage1(std::string& what_applied, std::string& error) {
    return enter_confinement(what_applied, error);  // refuses: no confinement on this system
}

std::unique_ptr<io::File> receive_file_and_seal(std::vector<std::uint8_t>& job, std::string& what_applied) {
    job.clear();
    what_applied.clear();
    ::_exit(kHandOverRefusedExitCode);  // no confinement is written for this system
}

std::string describe_self() { return "no confinement on this system"; }

#endif

}  // namespace mie::sandbox
