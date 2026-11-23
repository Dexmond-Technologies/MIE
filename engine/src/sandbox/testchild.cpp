// mie-sandbox-testchild: TEST PROGRAM, never shipped.
//
// Does what the worker will do first (enter_confinement), then ONE action named by its first
// argument, and prints one line of JSON saying what happened. The actions are the things a
// confined worker must not be able to do, plus the things it must be able to do.
//
// When the variable MIE_SANDBOX is not set (the parent asked for no confinement: the control
// cases) enter_confinement is not called.
#include "mie/hash.hpp"
#include "mie/io.hpp"
#include "mie/sandbox.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

std::string json_text(const std::string& text) {
    std::string out = "\"";
    for (const char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (u < 0x20 || u >= 0x7f) {
            char escaped[8];
            std::snprintf(escaped, sizeof escaped, "\\u%04x", static_cast<unsigned>(u));
            out += escaped;
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

// Collects "key":value pairs and prints them as one line.
struct Line {
    std::string body;
    void raw(const char* key, const std::string& value) {
        body += (body.empty() ? "" : ",") + json_text(key) + ":" + value;
    }
    void text(const char* key, const std::string& value) { raw(key, json_text(value)); }
    void flag(const char* key, bool value) { raw(key, value ? "true" : "false"); }
    void number(const char* key, long long value) { raw(key, std::to_string(value)); }
    void print() const {
        std::printf("{%s}\n", body.c_str());
        std::fflush(stdout);
    }
};

std::vector<std::uint8_t> read_standard_input() {
    std::vector<std::uint8_t> data;
    std::uint8_t buffer[64 * 1024];
    for (;;) {
        const std::size_t n = std::fread(buffer, 1, sizeof buffer, stdin);
        if (n == 0) {
            break;
        }
        data.insert(data.end(), buffer, buffer + n);
    }
    return data;
}

long long last_socket_error() {
#if defined(_WIN32)
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

// How long a connection attempt may take. A confined Windows child gets no answer at all (its
// packets are dropped, not refused), so a plain connect() would wait far longer than the
// test's time limit. The control run without confinement has the SAME bound, so "timed out"
// in the confined run means something only because the control connected within it.
constexpr int kConnectSeconds = 5;

// socket_only: stop after creating the socket. Otherwise connect to host:port (numbers only),
// without blocking, waiting at most kConnectSeconds for the outcome.
void try_network(Line& line, bool socket_only, const char* host, const char* port) {
#if defined(_WIN32)
    WSADATA startup{};
    const int started = ::WSAStartup(MAKEWORD(2, 2), &startup);
    if (started != 0) {
        line.flag("socket_created", false);
        line.flag("connected", false);
        line.text("failed_at", "WSAStartup");
        line.number("error", started);
        return;
    }
    const SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const bool created = s != INVALID_SOCKET;
#else
    const int s = ::socket(AF_INET, SOCK_STREAM, 0);
    const bool created = s >= 0;
#endif
    line.flag("socket_created", created);
    if (!created) {
        line.flag("connected", false);
        line.text("failed_at", "socket");
        line.number("error", last_socket_error());
        return;
    }
    if (!socket_only) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<unsigned short>(std::atoi(port)));
        ::inet_pton(AF_INET, host, &address.sin_addr);
#if defined(_WIN32)
        u_long non_blocking = 1;
        ::ioctlsocket(s, FIONBIO, &non_blocking);
#else
        ::fcntl(s, F_SETFL, ::fcntl(s, F_GETFL) | O_NONBLOCK);
#endif
        bool connected = ::connect(s, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0;
        long long error = 0;
        std::string how = "connected at once";
        if (!connected) {
            error = last_socket_error();
#if defined(_WIN32)
            const bool pending = error == WSAEWOULDBLOCK;
#else
            const bool pending = error == EINPROGRESS;
#endif
            if (!pending) {
                how = "refused at once";
            } else {
                fd_set writable;
                fd_set failed;
                FD_ZERO(&writable);
                FD_ZERO(&failed);
                FD_SET(s, &writable);
                FD_SET(s, &failed);
                timeval wait{};
                wait.tv_sec = kConnectSeconds;
                const int ready = ::select(static_cast<int>(s) + 1, nullptr, &writable, &failed, &wait);
                if (ready == 0) {
                    how = "timed out after " + std::to_string(kConnectSeconds) + " s (no answer)";
                    error = 0;
                } else if (ready < 0) {
                    how = "waiting for the connection failed";
                    error = last_socket_error();
                } else {
                    int outcome = 0;
#if defined(_WIN32)
                    int length = sizeof outcome;
                    ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&outcome), &length);
#else
                    socklen_t length = sizeof outcome;
                    ::getsockopt(s, SOL_SOCKET, SO_ERROR, &outcome, &length);
#endif
                    connected = outcome == 0 && FD_ISSET(s, &writable) != 0;
                    error = outcome;
                    how = connected ? "connected within the bound" : "connection failed";
                }
            }
        }
        line.flag("connected", connected);
        line.text("how", how);
        line.number("bound_seconds", kConnectSeconds);
        if (!connected) {
            line.text("failed_at", "connect");
            line.number("error", error);
        }
    }
#if defined(_WIN32)
    ::closesocket(s);
#else
    ::close(s);
#endif
}

void try_spawn(Line& line) {
#if defined(_WIN32)
    wchar_t command[] = L"cmd.exe /c exit 0";
    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    PROCESS_INFORMATION process{};
    const BOOL created =
        ::CreateProcessW(nullptr, command, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                         &process);
    line.flag("spawned", created != FALSE);
    if (created) {
        ::CloseHandle(process.hThread);
        ::CloseHandle(process.hProcess);
    } else {
        line.number("error", static_cast<long long>(::GetLastError()));
    }
#else
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::_exit(0);
    }
    line.flag("spawned", pid > 0);
    if (pid > 0) {
        int status = 0;
        ::waitpid(pid, &status, 0);
        return;
    }
    line.number("error", errno);
    // A new process was refused. Also try replacing this program by another one (only here:
    // where it works, it would end this program before it prints its line).
    char program[] = "/bin/true";
    char* const arguments[] = {program, nullptr};
    char* const environment[] = {nullptr};
    ::execve(program, arguments, environment);
    line.flag("exec_refused", true);  // reached only if execve returned
    line.number("exec_error", errno);
#endif
}

// The raw number of the handed-over file (descriptor or handle value), -1 if there is none.
// Used by the actions that try to misuse it; the sandbox library keeps owning it.
long long inherited_number() {
    const char* value = std::getenv("MIE_INHERITED_FILE");
    if (value == nullptr || *value == '\0') {
        return -1;
    }
    return std::strtoll(value, nullptr, 10);
}

// Tries to WRITE through the handed-over file. It was handed over read-only: must fail.
void try_write_handle(Line& line) {
    const long long number = inherited_number();
    line.flag("handle_present", number >= 0);
    if (number < 0) {
        line.flag("wrote", false);
        return;
    }
#if defined(_WIN32)
    const HANDLE handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(number));
    OVERLAPPED position{};  // offset 0; valid for a handle opened either way
    DWORD written = 0;
    const BOOL done = ::WriteFile(handle, "x", 1, &written, &position);
    line.flag("wrote", done != FALSE && written == 1);
    line.number("error", done ? 0 : static_cast<long long>(::GetLastError()));
#else
    // write(), which the filter allows: the refusal must come from the descriptor itself
    // (opened read-only: error 9, "bad file descriptor"), not from the filter.
    errno = 0;
    const ssize_t written = ::write(static_cast<int>(number), "x", 1);
    line.flag("wrote", written == 1);
    line.number("error", written == 1 ? 0 : errno);
#endif
}

#if !defined(_WIN32)
// Tries to change the handed-over file THROUGH its descriptor, or to make a system call that
// is not on the allow list. `changed` must be false when confined.
void try_descriptor_change(Line& line, const std::string& action) {
    const int fd = static_cast<int>(inherited_number());
    errno = 0;
    int outcome = -1;
    if (action == "fchmod-handle") {
        outcome = ::fchmod(fd, 0600);
    } else if (action == "ftruncate-handle") {
        outcome = ::ftruncate(fd, 0);
    } else {  // unlisted-call: lower this process's own priority; harmless, and not on the list
        outcome = ::setpriority(PRIO_PROCESS, 0, 1);
    }
    line.flag("changed", outcome == 0);
    line.number("error", outcome == 0 ? 0 : errno);
}
#endif

#if defined(_WIN32)
// The layout NtQueryInformationProcess(ProcessHandleInformation = 51) writes: a header, then
// one entry per handle of the process. NOT in the public Windows headers; written here from
// the commonly published native-API definitions. UNSURE of it: the sizes are asserted for
// 64-bit, and the test accepts the answer only if the inheritable handles it yields are
// EXACTLY the three standard handles and the file, which a wrong layout would not produce.
struct HandleEntry {
    HANDLE value;
    ULONG_PTR handle_count;
    ULONG_PTR pointer_count;
    ULONG granted_access;
    ULONG object_type_index;
    ULONG attributes;  // OBJ_INHERIT = 0x2
    ULONG reserved;
};
struct HandleSnapshotHeader {
    ULONG_PTR number_of_handles;
    ULONG_PTR reserved;
};
#if defined(_WIN64)
static_assert(sizeof(HandleEntry) == 40, "handle entry layout (64-bit)");
static_assert(sizeof(HandleSnapshotHeader) == 16, "handle snapshot header layout (64-bit)");
#endif
using QueryProcessFunction = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// NtQueryObject: the type (class 2) and the name (class 1) of an object behind a handle. Both
// answers begin with a counted wide string (the native UNICODE_STRING), whose text follows in
// the same buffer.
using QueryObjectFunction = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct NativeString {
    USHORT length;   // bytes
    USHORT maximum;  // bytes
    PWSTR text;
};
#if defined(_WIN64)
static_assert(sizeof(NativeString) == 16, "native string layout (64-bit)");
#endif

// The call itself, guarded: should a handle from the system's list be gone or refuse the
// question with an exception (invalid-handle use ends an AppContainer process), the exception
// is caught and reported as a failure of this one question. No C++ object lives in here.
LONG guarded_query_object(QueryObjectFunction query, HANDLE handle, ULONG what, void* buffer, ULONG size) {
    __try {
        ULONG needed = 0;
        return query(handle, what, buffer, size, &needed);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<LONG>(0xC0000008u);
    }
}

// The answer of NtQueryObject as UTF-8 text; empty with ok = false if the system refused.
std::string object_text(QueryObjectFunction query, HANDLE handle, ULONG what, bool& ok) {
    std::vector<unsigned char> buffer(4096);
    ok = false;
    if (query == nullptr || guarded_query_object(query, handle, what, buffer.data(),
                                                 static_cast<ULONG>(buffer.size())) != 0) {
        return {};
    }
    NativeString text{};
    std::memcpy(&text, buffer.data(), sizeof text);
    ok = true;
    if (text.text == nullptr || text.length == 0) {
        return {};
    }
    const int wide = text.length / static_cast<int>(sizeof(wchar_t));
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, text.text, wide, nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<std::size_t>(size > 0 ? size : 0), '\0');
    if (size > 0) {
        ::WideCharToMultiByte(CP_UTF8, 0, text.text, wide, out.data(), size, nullptr, nullptr);
    }
    return out;
}
#endif

// Lists what this process holds that it got from its parent.
//   Linux: every open descriptor, asked one by one with the system call fstat (on the allow
//     list; made directly so that the C library cannot turn it into a call that takes a path),
//     for every number below 2^20, the kernel's default ceiling for descriptor numbers.
//   Windows: the system's own list of this process's handles, and which of them are marked
//     inheritable. A handle a process inherits keeps that mark; the handles Windows itself
//     opens in every new process, and the ones the program opens, do not have it. So
//     "inheritable" = "came from the parent". No handle value is ever probed: inside an
//     AppContainer the use of an invalid handle ends the process (status 0xC0000008; third CI
//     run), so asking "is this number a handle" one by one cannot be the method.
void list_inherited(Line& line) {
    std::string list;
#if defined(_WIN32)
    const auto standard = [](DWORD which) {
        return std::to_string(reinterpret_cast<std::uintptr_t>(::GetStdHandle(which)));
    };
    line.raw("standard_handles", "[" + standard(STD_INPUT_HANDLE) + "," + standard(STD_OUTPUT_HANDLE) + "," +
                                     standard(STD_ERROR_HANDLE) + "]");
    const long long file = inherited_number();
    line.number("file_handle", file);
    DWORD counted = 0;
    if (::GetProcessHandleCount(::GetCurrentProcess(), &counted)) {
        line.number("process_handle_count", counted);
    }
    // Whether Windows ends this process on the use of an invalid handle (reported, not needed).
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strict{};
    if (::GetProcessMitigationPolicy(::GetCurrentProcess(), ProcessStrictHandleCheckPolicy, &strict, sizeof strict)) {
        line.number("strict_handle_check_flags", strict.Flags);
    }

    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const QueryProcessFunction query =
        ntdll != nullptr ? reinterpret_cast<QueryProcessFunction>(::GetProcAddress(ntdll, "NtQueryInformationProcess"))
                         : nullptr;
    std::vector<unsigned char> buffer(64 * 1024);
    LONG status = -1;
    for (int attempt = 0; attempt < 8 && query != nullptr; ++attempt) {
        ULONG needed = 0;
        status = query(::GetCurrentProcess(), 51 /* ProcessHandleInformation */, buffer.data(),
                       static_cast<ULONG>(buffer.size()), &needed);
        if (status != static_cast<LONG>(0xC0000004u)) {  // not "buffer too small"
            break;
        }
        buffer.resize(needed > buffer.size() ? static_cast<std::size_t>(needed) + 4096 : buffer.size() * 2);
    }
    if (query == nullptr || status != 0) {
        line.text("method", "count only: the system's handle list could not be read");
        line.number("query_status", status);
        return;
    }
    HandleSnapshotHeader header{};
    std::memcpy(&header, buffer.data(), sizeof header);
    if (header.number_of_handles > (buffer.size() - sizeof header) / sizeof(HandleEntry)) {
        line.text("method", "count only: the system's handle list does not have the expected layout");
        return;
    }
    // For every handle of the list: its TYPE, if the system tells it in here. For a File that
    // is a disk file or folder, and for a Key, also its NAME. Names are NOT asked for pipes,
    // consoles, devices and sockets (asking a pipe for its name can wait for ever), nor for
    // other types (events, sections, threads, ... mostly have none).
    const QueryObjectFunction query_object =
        reinterpret_cast<QueryObjectFunction>(::GetProcAddress(ntdll, "NtQueryObject"));
    std::map<std::string, int> types;
    std::string names;
    long long file_access = -1;
    int types_refused = 0;
    int names_skipped = 0;
    for (std::size_t i = 0; i < header.number_of_handles; ++i) {
        HandleEntry entry{};
        std::memcpy(&entry, buffer.data() + sizeof header + i * sizeof(HandleEntry), sizeof entry);
        const auto value = reinterpret_cast<std::uintptr_t>(entry.value);
        const bool inheritable = (entry.attributes & 0x2u) != 0;
        if (inheritable) {
            list += (list.empty() ? "" : ",") + std::to_string(value);
        }
        if (file >= 0 && value == static_cast<std::uintptr_t>(file)) {
            file_access = entry.granted_access;
        }
        bool ok = false;
        const std::string type = object_text(query_object, entry.value, 2 /* type */, ok);
        if (!ok) {
            ++types_refused;
            ++types["(type not given by the system)"];
            continue;
        }
        ++types[type];
        std::string name;
        bool name_asked = false;
        if (type == "Key" || (type == "File" && ::GetFileType(entry.value) == FILE_TYPE_DISK)) {
            name_asked = true;
            name = object_text(query_object, entry.value, 1 /* name */, ok);
            if (!ok) {
                name = "(name not given by the system)";
            }
        } else if (type == "File") {
            ++names_skipped;
            name = "(pipe, console, device or socket: name not asked)";
        }
        if (name_asked || type == "File") {
            char access[32];
            std::snprintf(access, sizeof access, "0x%lx", static_cast<unsigned long>(entry.granted_access));
            names += (names.empty() ? "" : ",") +
                     json_text(type + " " + std::to_string(value) + (inheritable ? " INHERITED" : "") +
                               " access " + access + ": " + name);
        }
    }
    std::string type_table;
    for (const auto& [type, count] : types) {
        type_table += (type_table.empty() ? "" : ",") + json_text(type) + ":" + std::to_string(count);
    }
    line.raw("handle_types", "{" + type_table + "}");
    line.raw("file_and_key_handles", "[" + names + "]");
    line.number("types_refused", types_refused);
    line.number("file_names_not_asked", names_skipped);
    line.text("method", "NtQueryInformationProcess(ProcessHandleInformation)");
    line.number("total_handles", static_cast<long long>(header.number_of_handles));
    line.raw("inheritable_handles", "[" + list + "]");
    line.number("file_granted_access", file_access);
    line.flag("file_handle_can_write",
              file_access >= 0 && (file_access & (FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0);
#else
    const long highest = 1L << 20;
    for (long fd = 0; fd < highest; ++fd) {
        unsigned char answer[512];  // room for the kernel's answer; only success or failure is used
        if (::syscall(SYS_fstat, static_cast<int>(fd), answer) == 0) {
            list += (list.empty() ? "" : ",") + std::to_string(fd);
        }
    }
    line.raw("open_descriptors", "[" + list + "]");
    line.number("scanned", highest);
    line.number("file_descriptor", inherited_number());
#endif
}

int allocate_until_refused(Line& line) {
    // 16 MiB at a time, every page written so that it is really used, up to 4 GiB.
    constexpr std::size_t kChunk = 16u * 1024 * 1024;
    constexpr int kMostChunks = 256;
    std::vector<void*> chunks;
    chunks.reserve(kMostChunks);
    long long allocated = 0;
    bool refused = false;
    for (int i = 0; i < kMostChunks; ++i) {
        void* chunk = std::malloc(kChunk);
        if (chunk == nullptr) {
            refused = true;
            break;
        }
        std::memset(chunk, 0x5a, kChunk);
        chunks.push_back(chunk);
        allocated += static_cast<long long>(kChunk);
    }
    if (!chunks.empty()) {
        std::free(chunks.back());  // room to print the line
        chunks.pop_back();
    }
    line.flag("allocation_refused", refused);
    line.number("allocated_bytes", allocated);
    line.print();
    return refused ? mie::sandbox::kOutOfMemoryExitCode : 0;
}

}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    // The very first thing: one line on standard error, so that a parent that gets nothing
    // else knows whether main() was reached at all.
    std::fputs("mie-sandbox-testchild: main reached\n", stderr);
    std::fflush(stderr);
    const std::string action = argc > 1 ? argv[1] : "";
    Line line;
    line.text("action", action);

    // Whatever needs a file to start (the hash library reading its configuration) happens
    // BEFORE the confinement; no untrusted byte has been read yet. The real worker must do
    // the same with everything it loads from disk (see SANDBOX_NOTES.md).
    (void)mie::sha256_hex(std::span<const std::uint8_t>{});
    mie::sandbox::exit_on_out_of_memory();

    const bool confine = std::getenv("MIE_SANDBOX") != nullptr;
    line.flag("confinement_requested", confine);
    if (confine) {
        std::string what;
        std::string error;
        if (!mie::sandbox::enter_confinement(what, error)) {
            line.flag("confined", false);
            line.text("error", error);
            line.print();
            return 3;
        }
        line.flag("confined", true);
        line.text("what_applied", what);
    }

    if (action == "echo") {
        const std::vector<std::uint8_t> data = read_standard_input();
        line.number("bytes", static_cast<long long>(data.size()));
        line.text("sha256", mie::sha256_hex(data));
    } else if (action == "read-handle") {
        std::string error;
        const auto file = mie::sandbox::inherited_file(error);
        if (!file) {
            line.flag("read", false);
            line.text("error", error);
        } else {
            std::vector<std::uint8_t> data(static_cast<std::size_t>(file->size()));
            mie::io::IoError io_error;
            const std::int64_t n = file->read_at(0, data, io_error);
            line.flag("read", n == static_cast<std::int64_t>(data.size()));
            line.number("bytes", n);
            line.text("sha256", mie::sha256_hex(data));
        }
    } else if (action == "open-path" || action == "write-path") {
        const char* path = argc > 2 ? argv[2] : "";
        errno = 0;
        std::FILE* file = std::fopen(path, action == "open-path" ? "rb" : "wb");
        line.flag("opened", file != nullptr);
        line.number("error", file != nullptr ? 0 : errno);
        if (file != nullptr) {
            char first = 0;
            if (action == "open-path") {
                line.number("bytes_read", static_cast<long long>(std::fread(&first, 1, 1, file)));
            }
            std::fclose(file);
        }
    } else if (action == "connect") {
        try_network(line, false, argc > 2 ? argv[2] : "127.0.0.1", argc > 3 ? argv[3] : "0");
    } else if (action == "socket") {
        try_network(line, true, "", "");
    } else if (action == "allocate") {
        return allocate_until_refused(line);
    } else if (action == "spin") {
        volatile unsigned long long counter = 0;
        for (;;) {
            counter = counter + 1;
        }
    } else if (action == "crash") {
        std::fflush(stdout);
#if defined(_WIN32)
        volatile int* nowhere = nullptr;
        *nowhere = 1;  // access violation
#else
        std::abort();
#endif
    } else if (action == "spawn") {
        try_spawn(line);
    } else if (action == "handles") {
        list_inherited(line);
    } else if (action == "write-handle") {
        try_write_handle(line);
    } else if (action == "fchmod-handle" || action == "ftruncate-handle" || action == "unlisted-call") {
#if defined(_WIN32)
        line.text("error", "this action has no meaning on Windows");
        line.print();
        return 2;
#else
        try_descriptor_change(line, action);
#endif
    } else if (action == "whoami") {
        line.text("self", mie::sandbox::describe_self());
    } else {
        line.text("error", "unknown action");
        line.print();
        return 2;
    }
    line.print();
    return 0;
}
