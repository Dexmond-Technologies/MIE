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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
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

// socket_only: stop after creating the socket. Otherwise connect to host:port (numbers only).
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
        const int connected = ::connect(s, reinterpret_cast<const sockaddr*>(&address), sizeof address);
        line.flag("connected", connected == 0);
        if (connected != 0) {
            line.text("failed_at", "connect");
            line.number("error", last_socket_error());
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
