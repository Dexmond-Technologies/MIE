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
#include <cstring>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
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

std::string appcontainer_sid_text(std::string& error) {
    error = "AppContainer is a Windows mechanism";
    return {};
}

void exit_on_out_of_memory() {
    std::set_new_handler([] { std::_Exit(kOutOfMemoryExitCode); });
}

std::unique_ptr<io::File> inherited_file(std::string& error) {
    error.clear();
    const char* value = std::getenv("MIE_INHERITED_FILE");
    if (value == nullptr || *value == '\0') {
        error = "no file was handed over";
        return nullptr;
    }
    char* end = nullptr;
    const long fd = std::strtol(value, &end, 10);
    if (end == value || *end != '\0' || fd < 0 || fd > 1024) {
        error = "the handed-over file's number is not valid";
        return nullptr;
    }
    io::IoError io_error;
    auto file = io::adopt_native_handle(static_cast<std::intptr_t>(fd), io_error);
    if (!file) {
        error = std::string("the handed-over file cannot be used: ") + io::to_string(io_error.code);
    }
    return file;
}

std::unique_ptr<io::File> inherited_file() {
    std::string ignored;
    return inherited_file(ignored);
}

ChildResult run_confined(const std::filesystem::path& program, const std::vector<std::string>& arguments,
                         const io::File* inherited, std::span<const std::uint8_t> input,
                         const Limits& limits, std::size_t max_output_bytes, const RunOptions& options) {
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
        if (options.allow_weaker) {
            environment_store.push_back("MIE_SANDBOX_ALLOW_WEAKER=1");
        }
        if (options.test_break_confinement) {
            environment_store.push_back("MIE_SANDBOX_TEST_BREAK=1");
        }
    }
    if (inherited != nullptr) {
        environment_store.push_back("MIE_INHERITED_FILE=" + std::to_string(kChildFileFd));
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
    const auto close_all = [&] {
        for (int* ends : {in_pipe, out_pipe, err_pipe, status_pipe, exec_pipe}) {
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

    const int file_fd = inherited != nullptr ? static_cast<int>(inherited->native_handle()) : -1;
    long highest_fd = ::sysconf(_SC_OPEN_MAX);
    if (highest_fd < 0 || highest_fd > 65536) {
        highest_fd = 65536;
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
        for (long fd = kChildExecFd + 1; fd < highest_fd; ++fd) {
            ::close(static_cast<int>(fd));
        }
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

// The system calls the filter refuses with "operation not permitted". Everything else is
// allowed: this is a deny list, not an allow list (see SANDBOX_NOTES.md for why, and for
// what that leaves open). The groups:
//   network: no socket can be created, connected, bound, listened on or accepted from;
//   files by path: nothing can be opened, created, removed, renamed or changed by name;
//   processes: no new program, no new process, no signal to another process, no tracing;
//   kernel features that could get around the above or widen the attack surface.
std::vector<long> denied_system_calls() {
    std::vector<long> deny = {
        // ---- network
        SYS_socket, SYS_socketpair, SYS_connect, SYS_bind, SYS_listen, SYS_accept, SYS_accept4,
        SYS_sendto, SYS_sendmsg, SYS_sendmmsg, SYS_recvfrom, SYS_recvmsg, SYS_recvmmsg, SYS_shutdown,
        // ---- files by path
        SYS_openat, SYS_open_by_handle_at, SYS_name_to_handle_at, SYS_unlinkat, SYS_renameat2,
        SYS_mkdirat, SYS_linkat, SYS_symlinkat, SYS_fchmodat, SYS_fchownat, SYS_mknodat, SYS_truncate,
        SYS_mount, SYS_umount2, SYS_chroot, SYS_pivot_root, SYS_swapon, SYS_swapoff, SYS_acct,
        SYS_setxattr, SYS_lsetxattr, SYS_removexattr, SYS_lremovexattr, SYS_quotactl,
        SYS_fanotify_init, SYS_inotify_init1,
        // ---- processes
        SYS_execve, SYS_execveat, SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_kill,
        SYS_tkill, SYS_rt_sigqueueinfo, SYS_rt_tgsigqueueinfo, SYS_kcmp, SYS_setns, SYS_unshare,
        // ---- kernel features
        SYS_bpf, SYS_perf_event_open, SYS_userfaultfd, SYS_init_module, SYS_finit_module,
        SYS_delete_module, SYS_kexec_load, SYS_reboot, SYS_keyctl, SYS_add_key, SYS_request_key,
        SYS_personality, SYS_mq_open, SYS_msgget, SYS_semget, SYS_shmget, SYS_shmat,
        SYS_settimeofday, SYS_clock_settime, SYS_adjtimex, SYS_sethostname, SYS_setdomainname,
        SYS_vhangup, SYS_syslog,
    };
    // Calls that only some processors or only newer kernel headers have.
#ifdef SYS_open
    deny.push_back(SYS_open);
#endif
#ifdef SYS_creat
    deny.push_back(SYS_creat);
#endif
#ifdef SYS_openat2
    deny.push_back(SYS_openat2);
#endif
#ifdef SYS_unlink
    deny.push_back(SYS_unlink);
#endif
#ifdef SYS_rmdir
    deny.push_back(SYS_rmdir);
#endif
#ifdef SYS_rename
    deny.push_back(SYS_rename);
#endif
#ifdef SYS_renameat
    deny.push_back(SYS_renameat);
#endif
#ifdef SYS_mkdir
    deny.push_back(SYS_mkdir);
#endif
#ifdef SYS_link
    deny.push_back(SYS_link);
#endif
#ifdef SYS_symlink
    deny.push_back(SYS_symlink);
#endif
#ifdef SYS_chmod
    deny.push_back(SYS_chmod);
#endif
#ifdef SYS_fchmodat2
    deny.push_back(SYS_fchmodat2);
#endif
#ifdef SYS_chown
    deny.push_back(SYS_chown);
#endif
#ifdef SYS_lchown
    deny.push_back(SYS_lchown);
#endif
#ifdef SYS_mknod
    deny.push_back(SYS_mknod);
#endif
#ifdef SYS_inotify_init
    deny.push_back(SYS_inotify_init);
#endif
#ifdef SYS_fork
    deny.push_back(SYS_fork);
#endif
#ifdef SYS_vfork
    deny.push_back(SYS_vfork);
#endif
#ifdef SYS_pidfd_open
    deny.push_back(SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_send_signal
    deny.push_back(SYS_pidfd_send_signal);
#endif
#ifdef SYS_pidfd_getfd
    deny.push_back(SYS_pidfd_getfd);
#endif
#ifdef SYS_process_madvise
    deny.push_back(SYS_process_madvise);
#endif
#ifdef SYS_io_uring_setup
    // io_uring can do network and file work without the calls this filter looks at.
    deny.push_back(SYS_io_uring_setup);
#endif
#ifdef SYS_io_uring_enter
    deny.push_back(SYS_io_uring_enter);
#endif
#ifdef SYS_io_uring_register
    deny.push_back(SYS_io_uring_register);
#endif
#ifdef SYS_kexec_file_load
    deny.push_back(SYS_kexec_file_load);
#endif
#ifdef SYS_open_tree
    deny.push_back(SYS_open_tree);
#endif
#ifdef SYS_move_mount
    deny.push_back(SYS_move_mount);
#endif
#ifdef SYS_fsopen
    deny.push_back(SYS_fsopen);
#endif
#ifdef SYS_fsmount
    deny.push_back(SYS_fsmount);
#endif
#ifdef SYS_mount_setattr
    deny.push_back(SYS_mount_setattr);
#endif
#ifdef SYS_iopl
    deny.push_back(SYS_iopl);
#endif
#ifdef SYS_ioperm
    deny.push_back(SYS_ioperm);
#endif
    return deny;
}

// Installs the filter for the calling thread (the worker has one thread when it calls this).
// It cannot be removed again and is inherited by anything the process could still start.
bool apply_seccomp(std::string& what, std::string& why_not) {
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    why_not = "the seccomp filter is written for little-endian processors only";
    return false;
#else
    const auto errno_return = [](int err) {
        return static_cast<std::uint32_t>(SECCOMP_RET_ERRNO | (static_cast<std::uint32_t>(err) & SECCOMP_RET_DATA));
    };
    const std::uint32_t nr_offset = static_cast<std::uint32_t>(offsetof(struct seccomp_data, nr));
    const std::uint32_t arch_offset = static_cast<std::uint32_t>(offsetof(struct seccomp_data, arch));
    const std::uint32_t arg0_offset = static_cast<std::uint32_t>(offsetof(struct seccomp_data, args[0]));

    std::vector<sock_filter> filter;
    const auto add = [&](sock_filter instruction) { filter.push_back(instruction); };

    // A call made through another calling convention (32-bit on a 64-bit kernel) has other
    // numbers and would slip past a filter written for this one: such a process is killed.
    add(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arch_offset));
    add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 1, 0));
    add(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    add(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, nr_offset));
#if defined(__x86_64__)
    // The x32 calling convention shares the processor type but numbers its calls from 2^30.
    add(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1));
    add(BPF_STMT(BPF_RET | BPF_K, errno_return(EPERM)));
#endif

    // clone: a new THREAD is allowed, a new PROCESS is not (flags are the first argument).
    add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(SYS_clone), 0, 4));
    add(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arg0_offset));
    add(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x00010000u /* CLONE_THREAD */, 1, 0));
    add(BPF_STMT(BPF_RET | BPF_K, errno_return(EPERM)));
    add(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#ifdef SYS_clone3
    // clone3 hides its flags behind a pointer the filter cannot read: answered "no such
    // call", and the C library falls back to clone, which is judged above.
    add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(SYS_clone3), 0, 1));
    add(BPF_STMT(BPF_RET | BPF_K, errno_return(ENOSYS)));
#endif
    // tgkill: a signal to a thread of THIS process is allowed (abort() uses it), to any
    // other process it is not.
    add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(SYS_tgkill), 0, 4));
    add(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arg0_offset));
    add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(::getpid()), 1, 0));
    add(BPF_STMT(BPF_RET | BPF_K, errno_return(EPERM)));
    add(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    for (const long number : denied_system_calls()) {
        add(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(number), 0, 1));
        add(BPF_STMT(BPF_RET | BPF_K, errno_return(EPERM)));
    }
    add(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog program {};
    program.len = static_cast<unsigned short>(filter.size());
    program.filter = filter.data();
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0, 0) != 0) {
        why_not = errno_text("seccomp filter", errno);
        return false;
    }
    what = "seccomp (no sockets, no files by path, no new process or program)";
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

bool flag_set(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr && std::strcmp(value, "1") == 0;
}

}  // namespace

bool enter_confinement(std::string& what_applied, std::string& error) {
    what_applied.clear();
    error.clear();
    const bool allow_weaker = flag_set("MIE_SANDBOX_ALLOW_WEAKER");
    std::vector<std::string> applied;
    std::vector<std::string> missing;   // required parts that could not be applied
    std::vector<std::string> remarks;   // optional parts that are not there

    if (flag_set("MIE_SANDBOX_TEST_BREAK")) {
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

std::string describe_self() { return "no confinement on this system"; }

#endif

}  // namespace mie::sandbox
