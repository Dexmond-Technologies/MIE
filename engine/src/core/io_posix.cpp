// POSIX implementation of mie::io (Linux, macOS).
#include "mie/io.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace mie::io {

struct File::Impl {
    int fd = -1;
    std::uint64_t size = 0;
    FileIdentity identity;
};

File::File(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

File::~File() {
    if (impl_ && impl_->fd >= 0) {
        ::close(impl_->fd);
    }
}

std::uint64_t File::size() const { return impl_->size; }

const FileIdentity& File::identity() const { return impl_->identity; }

std::int64_t File::read_at(std::uint64_t offset, std::span<std::uint8_t> buffer, IoError& error) {
    std::size_t done = 0;
    while (done < buffer.size()) {
        const ssize_t n = ::pread(impl_->fd, buffer.data() + done, buffer.size() - done,
                                  static_cast<off_t>(offset + done));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            error.code = IoErrorCode::ReadFailed;
            error.detail = std::strerror(errno);
            return -1;
        }
        if (n == 0) {
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    return static_cast<std::int64_t>(done);
}

namespace {

IoErrorCode code_from_errno(int err) {
    switch (err) {
        case ENOENT:
        case ENOTDIR:
            return IoErrorCode::NotFound;
        case ELOOP:
            return IoErrorCode::Link;
        case EACCES:
        case EPERM:
            return IoErrorCode::AccessDenied;
        default:
            return IoErrorCode::Other;
    }
}

}  // namespace

std::unique_ptr<File> open_regular(const std::filesystem::path& path, IoError& error,
                                   const OpenOptions& /*options: cloud-only files are a Windows matter*/) {
    error = IoError{};

    // 1. Look at the name itself, without following a link.
    struct stat before {};
    if (::lstat(path.c_str(), &before) != 0) {
        error.code = code_from_errno(errno);
        error.detail = std::strerror(errno);
        return nullptr;
    }
    if (S_ISLNK(before.st_mode)) {
        error.code = IoErrorCode::Link;
        error.detail = "symbolic link";
        return nullptr;
    }
    if (!S_ISREG(before.st_mode)) {
        error.code = IoErrorCode::NotRegular;
        error.detail = "not a regular file";
        return nullptr;
    }

    // 2. Open without following a link. O_NONBLOCK: if the name was swapped for a
    //    pipe between step 1 and here, the open must not hang.
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        error.code = code_from_errno(errno);
        error.detail = std::strerror(errno);
        return nullptr;
    }

    // 3. The opened object must be the regular file seen in step 1.
    struct stat after {};
    if (::fstat(fd, &after) != 0) {
        error.code = IoErrorCode::Other;
        error.detail = std::strerror(errno);
        ::close(fd);
        return nullptr;
    }
    if (!S_ISREG(after.st_mode)) {
        error.code = IoErrorCode::NotRegular;
        error.detail = "not a regular file";
        ::close(fd);
        return nullptr;
    }
    if (after.st_dev != before.st_dev || after.st_ino != before.st_ino) {
        error.code = IoErrorCode::Changed;
        error.detail = "file replaced between check and open";
        ::close(fd);
        return nullptr;
    }

    auto impl = std::make_unique<File::Impl>();
    impl->fd = fd;
    impl->size = static_cast<std::uint64_t>(after.st_size);
    impl->identity.volume = static_cast<std::uint64_t>(after.st_dev);
    impl->identity.index_high = 0;
    impl->identity.index_low = static_cast<std::uint64_t>(after.st_ino);
    return std::make_unique<File>(std::move(impl));
}

}  // namespace mie::io
