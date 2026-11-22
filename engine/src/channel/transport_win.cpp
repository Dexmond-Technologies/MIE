// Named-pipe transport (Windows).
//
// The pipe is created with an access list that names only the current user, with the
// current user as owner, and with PIPE_REJECT_REMOTE_CLIENTS. The first instance is
// created with FILE_FLAG_FIRST_PIPE_INSTANCE, which also gives "single instance".
// A client checks that the pipe it opened is owned by the current user before it
// sends anything, so another account cannot pose as the service.
#include "mie/channel/transport.hpp"

#include <string>
#include <utility>
#include <vector>

#include <windows.h>

#include <aclapi.h>
#include <sddl.h>

#include "stream_connection.hpp"

namespace mie::channel {

namespace {

std::string win_error(const char* what, DWORD code) {
    return std::string(what) + " failed, error " + std::to_string(code);
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                             static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring out(static_cast<std::size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                          out.data(), length);
    return out;
}

std::string narrow(const wchar_t* text) {
    if (text == nullptr || *text == L'\0') {
        return {};
    }
    const int length = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) {
        return {};
    }
    std::string out(static_cast<std::size_t>(length - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), length, nullptr, nullptr);
    return out;
}

// The current user's SID as binary (for comparisons) and as text (for names).
bool current_user_sid(std::vector<BYTE>& token_user, std::string& sid_text, std::string& error) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error = win_error("OpenProcessToken", ::GetLastError());
        return false;
    }
    DWORD needed = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        error = win_error("GetTokenInformation", ::GetLastError());
        ::CloseHandle(token);
        return false;
    }
    token_user.assign(needed, 0);
    if (!::GetTokenInformation(token, TokenUser, token_user.data(), needed, &needed)) {
        error = win_error("GetTokenInformation", ::GetLastError());
        ::CloseHandle(token);
        return false;
    }
    ::CloseHandle(token);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(token_user.data());
    LPWSTR text = nullptr;
    if (!::ConvertSidToStringSidW(user->User.Sid, &text)) {
        error = win_error("ConvertSidToStringSidW", ::GetLastError());
        return false;
    }
    sid_text = narrow(text);
    ::LocalFree(text);
    if (sid_text.empty()) {
        error = "empty user SID";
        return false;
    }
    return true;
}

class WinConnection final : public StreamConnection {
public:
    WinConnection(HANDLE pipe, bool server_side) : pipe_(pipe), server_side_(server_side) {
        event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    ~WinConnection() override {
        if (pipe_ != INVALID_HANDLE_VALUE) {
            if (server_side_) {
                ::DisconnectNamedPipe(pipe_);
            }
            ::CloseHandle(pipe_);
        }
        if (event_ != nullptr) {
            ::CloseHandle(event_);
        }
    }

protected:
    long read_some(std::uint8_t* data, std::size_t size, int timeout_ms, std::string& error) override {
        if (event_ == nullptr) {
            error = "no event object";
            return -1;
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event_;
        ::ResetEvent(event_);
        DWORD got = 0;
        if (::ReadFile(pipe_, data, static_cast<DWORD>(size), &got, &overlapped)) {
            return static_cast<long>(got);
        }
        DWORD code = ::GetLastError();
        if (code == ERROR_IO_PENDING) {
            const DWORD wait = ::WaitForSingleObject(event_, timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms));
            if (wait == WAIT_TIMEOUT) {
                ::CancelIoEx(pipe_, &overlapped);
                // Wait until the cancelled read has really ended; it may have completed.
                if (::GetOverlappedResult(pipe_, &overlapped, &got, TRUE) && got > 0) {
                    return static_cast<long>(got);
                }
                error = "timeout";
                return -1;
            }
            if (::GetOverlappedResult(pipe_, &overlapped, &got, FALSE)) {
                return static_cast<long>(got);
            }
            code = ::GetLastError();
        }
        if (code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED || code == ERROR_NO_DATA ||
            code == ERROR_HANDLE_EOF) {
            return 0;
        }
        error = win_error("ReadFile", code);
        return -1;
    }

    bool write_all(const char* data, std::size_t size, std::string& error) override {
        if (event_ == nullptr) {
            error = "no event object";
            return false;
        }
        std::size_t done = 0;
        while (done < size) {
            OVERLAPPED overlapped{};
            overlapped.hEvent = event_;
            ::ResetEvent(event_);
            DWORD wrote = 0;
            const DWORD want = static_cast<DWORD>(size - done > 65536 ? 65536 : size - done);
            if (!::WriteFile(pipe_, data + done, want, &wrote, &overlapped)) {
                const DWORD code = ::GetLastError();
                if (code != ERROR_IO_PENDING) {
                    error = win_error("WriteFile", code);
                    return false;
                }
                if (!::GetOverlappedResult(pipe_, &overlapped, &wrote, TRUE)) {
                    error = win_error("WriteFile", ::GetLastError());
                    return false;
                }
            }
            if (wrote == 0) {
                error = "pipe accepted no data";
                return false;
            }
            done += wrote;
        }
        return true;
    }

private:
    HANDLE pipe_;
    HANDLE event_ = nullptr;
    bool server_side_;
};

class WinServer final : public Server {
public:
    WinServer(std::wstring name, std::wstring sddl, HANDLE first_instance)
        : name_(std::move(name)), sddl_(std::move(sddl)), next_(first_instance) {
        event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }

    ~WinServer() override {
        if (next_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(next_);
        }
        if (event_ != nullptr) {
            ::CloseHandle(event_);
        }
    }

    static HANDLE create_instance(const std::wstring& name, const std::wstring& sddl, bool first,
                                  DWORD& error_code) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                                                                    &descriptor, nullptr)) {
            error_code = ::GetLastError();
            return INVALID_HANDLE_VALUE;
        }
        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength = sizeof attributes;
        attributes.lpSecurityDescriptor = descriptor;
        attributes.bInheritHandle = FALSE;
        DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if (first) {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        const HANDLE pipe = ::CreateNamedPipeW(
            name.c_str(), open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &attributes);
        error_code = pipe == INVALID_HANDLE_VALUE ? ::GetLastError() : ERROR_SUCCESS;
        ::LocalFree(descriptor);
        return pipe;
    }

    std::unique_ptr<Connection> accept(int timeout_ms, std::string& error) override {
        error.clear();
        if (event_ == nullptr) {
            error = "no event object";
            return nullptr;
        }
        if (next_ == INVALID_HANDLE_VALUE) {
            DWORD code = 0;
            next_ = create_instance(name_, sddl_, false, code);
            if (next_ == INVALID_HANDLE_VALUE) {
                error = win_error("CreateNamedPipeW", code);
                return nullptr;
            }
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event_;
        ::ResetEvent(event_);
        if (!::ConnectNamedPipe(next_, &overlapped)) {
            const DWORD code = ::GetLastError();
            if (code == ERROR_IO_PENDING) {
                const DWORD wait = ::WaitForSingleObject(event_, timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms));
                DWORD ignored = 0;
                if (wait == WAIT_TIMEOUT) {
                    ::CancelIoEx(next_, &overlapped);
                    if (!::GetOverlappedResult(next_, &overlapped, &ignored, TRUE)) {
                        return nullptr;  // really timed out (or cancelled): no client
                    }
                    // a client connected while we were cancelling: fall through
                } else if (!::GetOverlappedResult(next_, &overlapped, &ignored, FALSE)) {
                    error = win_error("ConnectNamedPipe", ::GetLastError());
                    ::CloseHandle(next_);
                    next_ = INVALID_HANDLE_VALUE;
                    return nullptr;
                }
            } else if (code != ERROR_PIPE_CONNECTED) {
                error = win_error("ConnectNamedPipe", code);
                ::CloseHandle(next_);
                next_ = INVALID_HANDLE_VALUE;
                return nullptr;
            }
        }
        const HANDLE connected = next_;
        // Keep one instance listening at all times so the name is never free.
        DWORD code = 0;
        next_ = create_instance(name_, sddl_, false, code);
        return std::make_unique<WinConnection>(connected, true);
    }

private:
    std::wstring name_;
    std::wstring sddl_;
    HANDLE next_;
    HANDLE event_ = nullptr;
};

// True if the object behind `handle` is owned by the current user.
bool owned_by_current_user(HANDLE handle, std::string& error) {
    std::vector<BYTE> token_user;
    std::string sid_text;
    if (!current_user_sid(token_user, sid_text, error)) {
        return false;
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(token_user.data());
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD result = ::GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &owner,
                                           nullptr, nullptr, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        error = win_error("GetSecurityInfo", result);
        return false;
    }
    const bool same = owner != nullptr && ::EqualSid(owner, user->User.Sid) != FALSE;
    ::LocalFree(descriptor);
    if (!same) {
        error = "the pipe is not owned by the current user";
    }
    return same;
}

}  // namespace

Endpoint default_endpoint(std::string& error) {
    error.clear();
    std::vector<BYTE> token_user;
    std::string sid_text;
    if (!current_user_sid(token_user, sid_text, error)) {
        return Endpoint{};
    }
    return Endpoint{"\\\\.\\pipe\\DexmondMIE." + sid_text + ".service"};
}

std::unique_ptr<Server> listen(const Endpoint& endpoint, ListenStatus& status, std::string& error) {
    status = ListenStatus::Error;
    error.clear();
    const std::wstring name = widen(endpoint.name);
    if (name.empty()) {
        error = "empty or invalid pipe name";
        return nullptr;
    }
    std::vector<BYTE> token_user;
    std::string sid_text;
    if (!current_user_sid(token_user, sid_text, error)) {
        return nullptr;
    }
    // Owner: the current user. Access: the current user only, protected from inheritance.
    const std::wstring sddl = widen("O:" + sid_text + "D:P(A;;GA;;;" + sid_text + ")");
    DWORD code = 0;
    const HANDLE first = WinServer::create_instance(name, sddl, true, code);
    if (first == INVALID_HANDLE_VALUE) {
        if (code == ERROR_ACCESS_DENIED || code == ERROR_PIPE_BUSY) {
            status = ListenStatus::AlreadyRunning;
        } else {
            error = win_error("CreateNamedPipeW", code);
        }
        return nullptr;
    }
    status = ListenStatus::Ok;
    return std::make_unique<WinServer>(name, sddl, first);
}

std::unique_ptr<Connection> connect(const Endpoint& endpoint, std::string& error) {
    error.clear();
    const std::wstring name = widen(endpoint.name);
    if (name.empty()) {
        error = "empty or invalid pipe name";
        return nullptr;
    }
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5; ++attempt) {
        // SECURITY_IDENTIFICATION: the server may learn who we are, never act as us.
        pipe = ::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, nullptr,
                             OPEN_EXISTING,
                             FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                             nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        const DWORD code = ::GetLastError();
        if (code != ERROR_PIPE_BUSY) {
            error = win_error("CreateFileW(pipe)", code);
            return nullptr;
        }
        ::WaitNamedPipeW(name.c_str(), 1000);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        error = "pipe busy";
        return nullptr;
    }
    if (!owned_by_current_user(pipe, error)) {
        ::CloseHandle(pipe);
        return nullptr;
    }
    return std::make_unique<WinConnection>(pipe, false);
}

}  // namespace mie::channel
