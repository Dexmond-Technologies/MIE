#include "fake_service.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace mie::ui::test {

namespace {

std::atomic<unsigned long> g_endpoint_counter{1};

long current_pid_num() {
#ifdef _WIN32
    return static_cast<long>(_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

}  // namespace

TestEndpoint::TestEndpoint(const std::string& tag) {
    const unsigned long seq = g_endpoint_counter.fetch_add(1);
#ifdef _WIN32
    endpoint.name = "\\\\.\\pipe\\DexmondMIE.uitest." +
                    std::to_string(current_pid_num()) + "." +
                    std::to_string(seq) + "." + tag;
#else
    // Keep Unix socket path well below sockaddr_un::sun_path (~108 bytes).
    std::string pattern = "/tmp/mie-ui-XXXXXX";
    const char* tmp_env = std::getenv("TMPDIR");
    if (tmp_env != nullptr && tmp_env[0] == '/' && std::strlen(tmp_env) < 48) {
        pattern = std::string(tmp_env) + "/mie-ui-XXXXXX";
    }
    char* made = ::mkdtemp(pattern.data());
    if (made != nullptr) {
        ::chmod(made, 0700);
        directory = made;
        endpoint.name = directory + "/" + tag + "_" + std::to_string(seq) + ".sock";
    }
#endif
}

TestEndpoint::~TestEndpoint() {
#ifndef _WIN32
    if (!directory.empty()) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
#endif
}

FakeService::FakeService(const mie::channel::Endpoint& endpoint) {
    mie::channel::ListenStatus st = mie::channel::ListenStatus::Error;
    server_ = mie::channel::listen(endpoint, st, listen_error_);
    if (server_ != nullptr && st == mie::channel::ListenStatus::Ok) {
        listening_ = true;
        thread_ = std::thread(&FakeService::runLoop, this);
    }
}

FakeService::~FakeService() {
    stop_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
    server_.reset();
}

void FakeService::setStatusConfig(FakeStatusConfig config) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_cfg_ = std::move(config);
}

void FakeService::setScanUnknownOp() {
    std::lock_guard<std::mutex> lock(mutex_);
    scan_mode_ = ScanMode::UnknownOp;
    scan_raw_body_ = nlohmann::json::object();
}

void FakeService::setScanResult(const mie::ScanResult& result) {
    std::lock_guard<std::mutex> lock(mutex_);
    scan_mode_ = ScanMode::RawBody;
    scan_raw_body_ = nlohmann::json::parse(mie::to_json(result));
}

void FakeService::setScanRawBody(nlohmann::json body) {
    std::lock_guard<std::mutex> lock(mutex_);
    scan_mode_ = ScanMode::RawBody;
    scan_raw_body_ = std::move(body);
}

void FakeService::setOnScanCallback(std::function<void(const nlohmann::json&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    on_scan_cb_ = std::move(callback);
}

std::vector<nlohmann::json> FakeService::recordedScanBodies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return scan_bodies_;
}

void FakeService::clearRecordedScans() {
    std::lock_guard<std::mutex> lock(mutex_);
    scan_bodies_.clear();
}

void FakeService::sleepInterruptibly(int total_ms) const {
    int remaining = total_ms;
    while (remaining > 0 && !stop_.load()) {
        const int step = remaining > 50 ? 50 : remaining;
        std::this_thread::sleep_for(std::chrono::milliseconds(step));
        remaining -= step;
    }
}

void FakeService::runLoop() {
    while (!stop_.load()) {
        std::string accept_error;
        auto conn = server_->accept(100, accept_error);
        if (!conn) {
            continue;
        }
        serveClient(*conn);
    }
}

void FakeService::serveClient(mie::channel::Connection& conn) {
    mie::channel::Message request;
    std::string error;
    if (!conn.receive(request, 2000, error)) {
        return;
    }
    if (request.type != mie::channel::MessageType::Request) {
        return;
    }

    FakeStatusConfig cfg;
    ScanMode scan_mode = ScanMode::UnknownOp;
    nlohmann::json scan_body;
    std::function<void(const nlohmann::json&)> scan_cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cfg = status_cfg_;
        scan_mode = scan_mode_;
        scan_body = scan_raw_body_;
        scan_cb = on_scan_cb_;
        if (request.op == "scan") {
            scan_bodies_.push_back(request.body);
        }
    }

    if (request.op == "scan" && scan_cb) {
        scan_cb(request.body);
    }

    if (cfg.response_delay_ms > 0) {
        sleepInterruptibly(cfg.response_delay_ms);
    }
    if (stop_.load()) {
        return;
    }

    mie::channel::Message response;
    response.v = mie::channel::kProtocolVersion;
    response.id = request.id;
    response.type = mie::channel::MessageType::Response;
    response.op = request.op;

    if (request.op == "ping") {
        response.body = nlohmann::json{{"ok", true}, {"pong", true}};
    } else if (request.op == "status") {
        response.body = nlohmann::json{
            {"ok", true},
            {"service", "mie-service"},
            {"version", cfg.version},
            {"protocol", mie::channel::kProtocolVersion},
            {"result_schema", mie::kResultSchemaVersion},
            {"pid", current_pid_num()},
            {"engine", cfg.engine},
            {"monitoring", cfg.monitoring},
            {"rules", cfg.rules},
            {"profile", cfg.profile},
            {"rules_sha256", cfg.rules == "OFF" ? std::string{} : cfg.rules_sha256},
        };
        if (cfg.extra_unknown_field) {
            response.body["unexpected_extra"] = 42;
        }
    } else if (request.op == "scan") {
        if (scan_mode == ScanMode::RawBody) {
            response.body = scan_body;
        } else {
            response.body = nlohmann::json{{"ok", false}, {"error", "unknown_op"}};
        }
    } else {
        response.body = nlohmann::json{{"ok", false}, {"error", "unknown_op"}};
    }

    conn.send(response, error);
    // Wait briefly for client to close so pipe/socket bytes are read cleanly on Windows.
    mie::channel::Message ignored;
    conn.receive(ignored, 500, error);
}

std::string make_raw_frame(std::string_view payload) {
    const auto len = static_cast<std::uint32_t>(payload.size());
    std::string out;
    out.reserve(4u + payload.size());
    out.push_back(static_cast<char>((len >> 24) & 0xFFu));
    out.push_back(static_cast<char>((len >> 16) & 0xFFu));
    out.push_back(static_cast<char>((len >> 8) & 0xFFu));
    out.push_back(static_cast<char>(len & 0xFFu));
    out.append(payload.data(), payload.size());
    return out;
}

RawFrameServer::RawFrameServer(const mie::channel::Endpoint& endpoint, std::string raw_reply) {
#ifdef _WIN32
    thread_ = std::thread(&RawFrameServer::runWin, this, endpoint.name, std::move(raw_reply));
#else
    thread_ = std::thread(&RawFrameServer::runPosix, this, endpoint.name, std::move(raw_reply));
#endif
    for (int i = 0; i < 100 && !ready_.load() && error_.empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

RawFrameServer::~RawFrameServer() {
    stop_.store(true);
    if (thread_.joinable()) {
        thread_.join();
    }
}

#ifdef _WIN32
void RawFrameServer::runWin(std::string pipe_name, std::string raw_reply) {
    (void)pipe_name;
    const int wlen = ::MultiByteToWideChar(CP_UTF8, 0, pipe_name.data(),
                                           static_cast<int>(pipe_name.size()), nullptr, 0);
    if (wlen <= 0) {
        error_ = "widen failed";
        return;
    }
    std::wstring wname(static_cast<std::size_t>(wlen), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, pipe_name.data(),
                          static_cast<int>(pipe_name.size()), wname.data(), wlen);

    // Explicit current-user owner SDDL so mie::channel::connect's owner check passes
    // even when running as an elevated administrator on Windows CI runners.
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error_ = "OpenProcessToken failed";
        return;
    }
    DWORD needed = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> token_buf(needed, 0);
    if (!::GetTokenInformation(token, TokenUser, token_buf.data(), needed, &needed)) {
        ::CloseHandle(token);
        error_ = "GetTokenInformation failed";
        return;
    }
    ::CloseHandle(token);

    LPWSTR sid_w = nullptr;
    const auto* user = reinterpret_cast<const TOKEN_USER*>(token_buf.data());
    if (!::ConvertSidToStringSidW(user->User.Sid, &sid_w)) {
        error_ = "ConvertSidToStringSidW failed";
        return;
    }
    const std::wstring sddl = std::wstring(L"O:") + sid_w + L"D:P(A;;GA;;;" + sid_w + L")";
    ::LocalFree(sid_w);

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                &sd, nullptr)) {
        error_ = "SDDL failed";
        return;
    }
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    HANDLE event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE pipe = ::CreateNamedPipeW(
        wname.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &sa);
    ::LocalFree(sd);

    if (pipe == INVALID_HANDLE_VALUE || event == nullptr) {
        if (pipe != INVALID_HANDLE_VALUE) ::CloseHandle(pipe);
        if (event != nullptr) ::CloseHandle(event);
        error_ = "CreateNamedPipeW failed";
        return;
    }

    OVERLAPPED ov{};
    ov.hEvent = event;
    const BOOL connected_now = ::ConnectNamedPipe(pipe, &ov);
    const DWORD conn_err = connected_now ? ERROR_SUCCESS : ::GetLastError();
    ready_.store(true);

    bool client_ok = connected_now != FALSE || conn_err == ERROR_PIPE_CONNECTED;
    if (!client_ok && conn_err == ERROR_IO_PENDING) {
        while (!stop_.load()) {
            const DWORD w = ::WaitForSingleObject(event, 50);
            if (w == WAIT_OBJECT_0) {
                DWORD dummy = 0;
                client_ok = ::GetOverlappedResult(pipe, &ov, &dummy, FALSE) != FALSE;
                break;
            }
        }
        if (!client_ok) {
            ::CancelIoEx(pipe, &ov);
            DWORD dummy = 0;
            ::GetOverlappedResult(pipe, &ov, &dummy, TRUE);
        }
    }

    if (client_ok) {
        // Read incoming request frame first.
        char req_buf[4096]{};
        OVERLAPPED rov{};
        rov.hEvent = event;
        ::ResetEvent(event);
        DWORD got = 0;
        if (!::ReadFile(pipe, req_buf, sizeof req_buf, &got, &rov)) {
            if (::GetLastError() == ERROR_IO_PENDING) {
                if (::WaitForSingleObject(event, 2000) == WAIT_OBJECT_0) {
                    ::GetOverlappedResult(pipe, &rov, &got, FALSE);
                } else {
                    ::CancelIoEx(pipe, &rov);
                    ::GetOverlappedResult(pipe, &rov, &got, TRUE);
                }
            }
        }

        // Write raw reply bytes.
        OVERLAPPED wov{};
        wov.hEvent = event;
        ::ResetEvent(event);
        DWORD wrote = 0;
        if (!::WriteFile(pipe, raw_reply.data(), static_cast<DWORD>(raw_reply.size()), &wrote, &wov)) {
            if (::GetLastError() == ERROR_IO_PENDING) {
                ::WaitForSingleObject(event, 2000);
                ::GetOverlappedResult(pipe, &wov, &wrote, TRUE);
            }
        }
        ::FlushFileBuffers(pipe);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ::DisconnectNamedPipe(pipe);
    }

    ::CloseHandle(pipe);
    ::CloseHandle(event);
}

void RawFrameServer::runPosix(std::string, std::string) {}
#else
void RawFrameServer::runWin(std::string, std::string) {}

void RawFrameServer::runPosix(std::string path, std::string raw_reply) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof addr.sun_path) {
        error_ = "bad socket path";
        return;
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    ::unlink(path.c_str());

    const int listen_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        error_ = "socket failed";
        return;
    }
    if (::bind(listen_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 ||
        ::chmod(path.c_str(), 0600) != 0 ||
        ::listen(listen_fd, 4) != 0) {
        ::close(listen_fd);
        ::unlink(path.c_str());
        error_ = "bind/listen failed";
        return;
    }

    ready_.store(true);
    while (!stop_.load()) {
        struct pollfd p {};
        p.fd = listen_fd;
        p.events = POLLIN;
        const int r = ::poll(&p, 1, 50);
        if (r <= 0) {
            continue;
        }
        const int client_fd = ::accept(listen_fd, nullptr, nullptr);
        if (client_fd < 0) {
            continue;
        }
        struct pollfd cp {};
        cp.fd = client_fd;
        cp.events = POLLIN;
        if (::poll(&cp, 1, 2000) > 0) {
            char buf[4096];
            (void)::recv(client_fd, buf, sizeof buf, 0);
        }
        std::size_t sent = 0;
        while (sent < raw_reply.size()) {
#ifdef MSG_NOSIGNAL
            const int flags = MSG_NOSIGNAL;
#else
            const int flags = 0;
#endif
            const ssize_t n = ::send(client_fd, raw_reply.data() + sent, raw_reply.size() - sent, flags);
            if (n <= 0) {
                break;
            }
            sent += static_cast<std::size_t>(n);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ::close(client_fd);
        break;
    }

    ::close(listen_fd);
    ::unlink(path.c_str());
}
#endif

}  // namespace mie::ui::test
