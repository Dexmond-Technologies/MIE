// Safe file opening. A file is opened ONCE; every later stage works on that one
// handle. Links, junctions, directories, pipes, sockets and devices are refused
// before anything is read (review finding S-10).
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>

namespace mie::io {

enum class IoErrorCode {
    None,
    NotFound,       // no such file
    Link,           // symbolic link or junction (Windows name-surrogate reparse point)
    NotRegular,     // directory, pipe, socket, device
    AccessDenied,
    Changed,        // the file was replaced between the check and the open
    CloudOnly,      // Windows: the content exists only in cloud storage; reading would download it
    ReadFailed,
    Other,
};

struct IoError {
    IoErrorCode code = IoErrorCode::None;
    std::string detail;
};

const char* to_string(IoErrorCode code);

// What makes two handles "the same file": device and inode on POSIX, volume serial
// number and file index on Windows.
struct FileIdentity {
    std::uint64_t volume = 0;
    std::uint64_t index_high = 0;
    std::uint64_t index_low = 0;
    bool operator==(const FileIdentity&) const = default;
};

class File {
public:
    ~File();
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    std::uint64_t size() const;
    const FileIdentity& identity() const;

    // Reads up to buffer.size() bytes starting at `offset`. Returns the number of
    // bytes read (0 at end of file), or -1 with `error` set.
    std::int64_t read_at(std::uint64_t offset, std::span<std::uint8_t> buffer, IoError& error);

    // The native handle (POSIX file descriptor, Windows HANDLE value). Still owned by the
    // File. Used to hand the one open file to the confined worker process.
    std::intptr_t native_handle() const;

    struct Impl;
    explicit File(std::unique_ptr<Impl> impl);

private:
    std::unique_ptr<Impl> impl_;
};

struct OpenOptions {
    // Windows: a file whose content is only in cloud storage (OneDrive and similar "files on
    // demand": attributes "recall on data access", "recall on open" or "offline") is NOT
    // opened by default, because reading it makes Windows download it; a folder scan or the
    // watcher over a synced Desktop or Documents would otherwise download everything
    // (reviewer's finding MW-1, board B-3575). Such a file is refused with CloudOnly and
    // reported "not scanned: only in the cloud". Scanning it is an explicit user choice.
    bool allow_cloud_only = false;
};

// Opens `path` for reading if, and only if, it is a regular file reached without
// following a link. Returns nullptr with `error` set otherwise.
//
// Known limit: "the same file" is decided by FileIdentity. On Windows that is the 32-bit
// volume serial number plus the 64-bit file index; two volumes can share a serial number,
// and file systems with 128-bit file ids (ReFS) are compared on 64 bits only.
std::unique_ptr<File> open_regular(const std::filesystem::path& path, IoError& error,
                                   const OpenOptions& options = OpenOptions{});

// Takes ownership of an already-open handle (the one a parent handed to a worker). Refuses
// anything that is not a regular file; fills size and identity as open_regular does. On
// refusal the handle is closed and nullptr is returned with `error` set.
std::unique_ptr<File> adopt_native_handle(std::intptr_t handle, IoError& error);

}  // namespace mie::io
