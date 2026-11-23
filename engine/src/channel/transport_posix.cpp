// Unix-domain socket transport (Linux, macOS).
#include "mie/channel/transport.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "stream_connection.hpp"

namespace mie::channel {

namespace {

std::string errno_text(const char* what) {
    return std::string(what) + ": " + std::strerror(errno);
}

class PosixConnection final : public StreamConnection {
public:
    explicit PosixConnection(int fd) : fd_(fd) {}
    ~PosixConnection() override {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

protected:
    long read_some(std::uint8_t* data, std::size_t size, int timeout_ms, std::string& error) override {
        for (;;) {
            struct pollfd p {};
            p.fd = fd_;
            p.events = POLLIN;
            const int ready = ::poll(&p, 1, timeout_ms);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                error = errno_text("poll");
                return -1;
            }
            if (ready == 0) {
                error = "timeout";
                return -1;
            }
            const ssize_t n = ::recv(fd_, data, size, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == ECONNRESET) {
                    return 0;
                }
                error = errno_text("recv");
                return -1;
            }
            return static_cast<long>(n);
        }
    }

    bool write_all(const char* data, std::size_t size, std::string& error) override {
        std::size_t done = 0;
        while (done < size) {
#ifdef MSG_NOSIGNAL
            const int flags = MSG_NOSIGNAL;
#else
            const int flags = 0;
#endif
            const ssize_t n = ::send(fd_, data + done, size - done, flags);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                error = errno_text("send");
                return false;
            }
            done += static_cast<std::size_t>(n);
        }
        return true;
    }

private:
    int fd_;
};

bool peer_is_current_user(int fd) {
#if defined(__linux__)
    struct ucred cred {};
    socklen_t length = sizeof cred;
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0) {
        return false;
    }
    return cred.uid == ::geteuid();
#else
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(fd, &uid, &gid) != 0) {
        return false;
    }
    return uid == ::geteuid();
#endif
}

class PosixServer final : public Server {
public:
    PosixServer(int listen_fd, int lock_fd, std::string path)
        : listen_fd_(listen_fd), lock_fd_(lock_fd), path_(std::move(path)) {}

    ~PosixServer() override {
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            ::unlink(path_.c_str());
        }
        if (lock_fd_ >= 0) {
            ::close(lock_fd_);  // releases the lock; the lock file itself stays
        }
    }

    std::unique_ptr<Connection> accept(int timeout_ms, std::string& error) override {
        error.clear();
        struct pollfd p {};
        p.fd = listen_fd_;
        p.events = POLLIN;
        const int ready = ::poll(&p, 1, timeout_ms);
        if (ready < 0) {
            if (errno != EINTR) {
                error = errno_text("poll");
            }
            return nullptr;
        }
        if (ready == 0) {
            return nullptr;
        }
        const int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (errno != EINTR && errno != ECONNABORTED) {
                error = errno_text("accept");
            }
            return nullptr;
        }
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (!peer_is_current_user(fd)) {
            ::close(fd);
            return nullptr;  // not our user: dropped without a word
        }
        return std::make_unique<PosixConnection>(fd);
    }

private:
    int listen_fd_;
    int lock_fd_;
    std::string path_;
};

bool fill_address(const std::string& path, sockaddr_un& address, std::string& error) {
    address = sockaddr_un{};
    address.sun_family = AF_UNIX;
    if (path.empty() || path.size() >= sizeof address.sun_path) {
        error = "socket path empty or too long";
        return false;
    }
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    return true;
}

std::string parent_of(const std::string& path) {
    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        return ".";
    }
    if (slash == 0) {
        return "/";
    }
    return path.substr(0, slash);
}

// The directory that holds the socket must be a real directory (not a link), owned by
// the current user and closed to everyone else. The service creates it 0700 if it is
// missing; a client only checks it, so another account cannot pose as the service.
enum class DirectoryState { Private, Missing, OtherAccount, Unusable };

DirectoryState directory_state(const std::string& directory, std::string& error) {
    struct stat st {};
    if (::lstat(directory.c_str(), &st) != 0) {
        const bool missing = (errno == ENOENT || errno == ENOTDIR);
        error = errno_text("lstat");
        return missing ? DirectoryState::Missing : DirectoryState::Unusable;
    }
    if (!S_ISDIR(st.st_mode)) {
        error = "socket directory is not a directory";
        return DirectoryState::Unusable;
    }
    if (st.st_uid != ::geteuid()) {
        error = "socket directory belongs to another account";
        return DirectoryState::OtherAccount;
    }
    if ((st.st_mode & 0077) != 0) {
        error = "socket directory is open to other users";
        return DirectoryState::Unusable;
    }
    return DirectoryState::Private;
}

bool directory_is_private(const std::string& directory, std::string& error) {
    struct stat st {};
    if (::lstat(directory.c_str(), &st) != 0) {
        error = errno_text("lstat");
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        error = "socket directory is not a directory";
        return false;
    }
    if (st.st_uid != ::geteuid()) {
        error = "socket directory belongs to another user";
        return false;
    }
    if ((st.st_mode & 0077) != 0) {
        error = "socket directory is open to other users";
        return false;
    }
    return true;
}

bool prepare_directory(const std::string& directory, std::string& error) {
    // The level above (for example ~/.cache) may not exist yet on a fresh account.
    // If this fails the next mkdir fails too and reports it.
    ::mkdir(parent_of(directory).c_str(), 0700);
    if (::mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        error = errno_text("mkdir");
        return false;
    }
    return directory_is_private(directory, error);
}


}  // namespace

Endpoint default_endpoint(std::string& error) {
    error.clear();
    // Never a predictable name in a shared directory such as /tmp: another account could
    // create it first and keep the service from starting. Only places the user owns.
    std::string directory;
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    const char* cache = std::getenv("XDG_CACHE_HOME");
    const char* home = std::getenv("HOME");
    if (runtime != nullptr && runtime[0] == '/') {
        directory = std::string(runtime) + "/dexmond-mie";
    } else if (cache != nullptr && cache[0] == '/') {
        directory = std::string(cache) + "/dexmond-mie";
    } else if (home != nullptr && home[0] == '/') {
        directory = std::string(home) + "/.cache/dexmond-mie";
    } else {
        error = "no per-user directory: XDG_RUNTIME_DIR, XDG_CACHE_HOME and HOME are all unset";
        return Endpoint{};
    }
    return Endpoint{directory + "/service.sock"};
}

std::unique_ptr<Server> listen(const Endpoint& endpoint, ListenStatus& status, std::string& error) {
    status = ListenStatus::Error;
    error.clear();
    sockaddr_un address{};
    if (!fill_address(endpoint.name, address, error)) {
        return nullptr;
    }
    if (!prepare_directory(parent_of(endpoint.name), error)) {
        std::string ignored;
        if (directory_state(parent_of(endpoint.name), ignored) == DirectoryState::OtherAccount) {
            status = ListenStatus::HeldByOtherAccount;
        }
        return nullptr;
    }

    // Single instance: an exclusive lock on a file beside the socket.
    const std::string lock_path = endpoint.name + ".lock";
    const int lock_fd = ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock_fd < 0) {
        error = errno_text("open lock file");
        return nullptr;
    }
    if (::flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        const bool held = (errno == EWOULDBLOCK);
        if (!held) {
            error = errno_text("flock");
        }
        ::close(lock_fd);
        status = held ? ListenStatus::AlreadyRunning : ListenStatus::Error;
        return nullptr;
    }

    // We hold the lock, so a socket file left behind belongs to a dead service.
    ::unlink(endpoint.name.c_str());

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = errno_text("socket");
        ::close(lock_fd);
        return nullptr;
    }
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address) != 0) {
        error = errno_text("bind");
        ::close(fd);
        ::close(lock_fd);
        return nullptr;
    }
    if (::chmod(endpoint.name.c_str(), 0600) != 0 || ::listen(fd, 8) != 0) {
        error = errno_text("chmod/listen");
        ::close(fd);
        ::unlink(endpoint.name.c_str());
        ::close(lock_fd);
        return nullptr;
    }
    status = ListenStatus::Ok;
    return std::make_unique<PosixServer>(fd, lock_fd, endpoint.name);
}

std::unique_ptr<Connection> connect(const Endpoint& endpoint, std::string& error) {
    ConnectStatus status = ConnectStatus::Error;
    return connect(endpoint, status, error);
}

std::unique_ptr<Connection> connect(const Endpoint& endpoint, ConnectStatus& status, std::string& error) {
    status = ConnectStatus::Error;
    error.clear();
    sockaddr_un address{};
    if (!fill_address(endpoint.name, address, error)) {
        return nullptr;
    }
    switch (directory_state(parent_of(endpoint.name), error)) {
        case DirectoryState::Private:
            break;
        case DirectoryState::Missing:
            status = ConnectStatus::NotRunning;
            return nullptr;
        case DirectoryState::OtherAccount:
            status = ConnectStatus::HeldByOtherAccount;
            return nullptr;
        case DirectoryState::Unusable:
            return nullptr;
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        error = errno_text("socket");
        return nullptr;
    }
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof address) != 0) {
        if (errno == ENOENT || errno == ECONNREFUSED) {
            status = ConnectStatus::NotRunning;
        }
        error = errno_text("connect");
        ::close(fd);
        return nullptr;
    }
    status = ConnectStatus::Ok;
    return std::make_unique<PosixConnection>(fd);
}

}  // namespace mie::channel
