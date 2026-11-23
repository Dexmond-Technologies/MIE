// Windows implementation of mie::io.
#include "mie/io.hpp"

#include <string>
#include <utility>

#include <windows.h>

namespace mie::io {

struct File::Impl {
    HANDLE handle = INVALID_HANDLE_VALUE;
    std::uint64_t size = 0;
    FileIdentity identity;
};

File::File(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

File::~File() {
    if (impl_ && impl_->handle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(impl_->handle);
    }
}

std::uint64_t File::size() const { return impl_->size; }

const FileIdentity& File::identity() const { return impl_->identity; }

std::int64_t File::read_at(std::uint64_t offset, std::span<std::uint8_t> buffer, IoError& error) {
    std::size_t done = 0;
    while (done < buffer.size()) {
        const std::uint64_t position = offset + done;
        OVERLAPPED at{};
        at.Offset = static_cast<DWORD>(position & 0xFFFFFFFFull);
        at.OffsetHigh = static_cast<DWORD>(position >> 32);
        const std::size_t remaining = buffer.size() - done;
        const DWORD want = remaining > 0x40000000u ? 0x40000000u : static_cast<DWORD>(remaining);
        DWORD got = 0;
        if (!::ReadFile(impl_->handle, buffer.data() + done, want, &got, &at)) {
            const DWORD err = ::GetLastError();
            if (err == ERROR_HANDLE_EOF) {
                break;
            }
            error.code = IoErrorCode::ReadFailed;
            error.detail = "ReadFile failed, error " + std::to_string(err);
            return -1;
        }
        if (got == 0) {
            break;
        }
        done += got;
    }
    return static_cast<std::int64_t>(done);
}

namespace {

IoErrorCode code_from_win32(DWORD err) {
    switch (err) {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_NAME:
        case ERROR_BAD_NETPATH:
        case ERROR_BAD_NET_NAME:
            return IoErrorCode::NotFound;
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
            return IoErrorCode::AccessDenied;
        default:
            return IoErrorCode::Other;
    }
}

struct Facts {
    DWORD attributes = 0;
    std::uint64_t size = 0;
    FileIdentity identity;
};

bool read_facts(HANDLE handle, Facts& facts) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!::GetFileInformationByHandle(handle, &info)) {
        return false;
    }
    facts.attributes = info.dwFileAttributes;
    facts.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    facts.identity.volume = info.dwVolumeSerialNumber;
    facts.identity.index_high = info.nFileIndexHigh;
    facts.identity.index_low = info.nFileIndexLow;
    return true;
}

HANDLE open_handle(const std::filesystem::path& path, bool stop_at_reparse_point) {
    // FILE_FLAG_BACKUP_SEMANTICS lets a directory be opened, so it can be reported as
    // "not a regular file" instead of an unclear access error.
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN;
    if (stop_at_reparse_point) {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }
    return ::CreateFileW(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, flags, nullptr);
}

}  // namespace

// Attribute bits of files whose content is not on this disk. Defined here in case the
// SDK headers in use are older than the attributes.
constexpr DWORD kAttributeOffline = 0x00001000;             // FILE_ATTRIBUTE_OFFLINE
constexpr DWORD kAttributeRecallOnOpen = 0x00040000;        // FILE_ATTRIBUTE_RECALL_ON_OPEN
constexpr DWORD kAttributeRecallOnDataAccess = 0x00400000;  // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

std::unique_ptr<File> open_regular(const std::filesystem::path& path, IoError& error,
                                   const OpenOptions& options) {
    error = IoError{};

    // 1. Open the name itself: a link or junction is opened as the link, not its target.
    HANDLE handle = open_handle(path, true);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        error.code = code_from_win32(err);
        error.detail = "CreateFileW failed, error " + std::to_string(err);
        return nullptr;
    }

    // 2. Only disk files: no pipes, no console or other devices (CON, NUL, COM1 ...).
    if (::GetFileType(handle) != FILE_TYPE_DISK) {
        ::CloseHandle(handle);
        error.code = IoErrorCode::NotRegular;
        error.detail = "not a disk file";
        return nullptr;
    }

    Facts facts;
    if (!read_facts(handle, facts)) {
        const DWORD err = ::GetLastError();
        ::CloseHandle(handle);
        error.code = IoErrorCode::Other;
        error.detail = "GetFileInformationByHandle failed, error " + std::to_string(err);
        return nullptr;
    }

    // 2b. Content only in cloud storage: not opened further unless the caller asked for it.
    //     The handle above was opened with FILE_FLAG_OPEN_REPARSE_POINT and nothing has
    //     been read, so nothing has been downloaded up to here.
    const DWORD cloud_bits = kAttributeOffline | kAttributeRecallOnOpen | kAttributeRecallOnDataAccess;
    if ((facts.attributes & cloud_bits) != 0 && !options.allow_cloud_only &&
        (facts.attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        ::CloseHandle(handle);
        error.code = IoErrorCode::CloudOnly;
        error.detail = "only in the cloud";
        return nullptr;
    }

    // 3. Reparse points. Links and junctions (name surrogates) are refused. Other
    //    reparse points (for example cloud-storage placeholders) are data files: they
    //    are re-opened normally and must turn out to be the same regular file.
    if ((facts.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (!::GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof tag)) {
            const DWORD err = ::GetLastError();
            ::CloseHandle(handle);
            error.code = IoErrorCode::Other;
            error.detail = "reparse tag unreadable, error " + std::to_string(err);
            return nullptr;
        }
        if (IsReparseTagNameSurrogate(tag.ReparseTag)) {
            ::CloseHandle(handle);
            error.code = IoErrorCode::Link;
            error.detail = "symbolic link or junction";
            return nullptr;
        }
        const FileIdentity first = facts.identity;
        ::CloseHandle(handle);
        handle = open_handle(path, false);
        if (handle == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            error.code = code_from_win32(err);
            error.detail = "CreateFileW failed, error " + std::to_string(err);
            return nullptr;
        }
        if (::GetFileType(handle) != FILE_TYPE_DISK || !read_facts(handle, facts)) {
            ::CloseHandle(handle);
            error.code = IoErrorCode::NotRegular;
            error.detail = "not a disk file";
            return nullptr;
        }
        if (!(facts.identity == first)) {
            ::CloseHandle(handle);
            error.code = IoErrorCode::Changed;
            error.detail = "file replaced between check and open";
            return nullptr;
        }
    }

    if ((facts.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        ::CloseHandle(handle);
        error.code = IoErrorCode::NotRegular;
        error.detail = "directory";
        return nullptr;
    }

    auto impl = std::make_unique<File::Impl>();
    impl->handle = handle;
    impl->size = facts.size;
    impl->identity = facts.identity;
    return std::make_unique<File>(std::move(impl));
}

}  // namespace mie::io
