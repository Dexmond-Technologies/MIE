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

    struct Impl;
    explicit File(std::unique_ptr<Impl> impl);

private:
    std::unique_ptr<Impl> impl_;
};

// Opens `path` for reading if, and only if, it is a regular file reached without
// following a link. Returns nullptr with `error` set otherwise.
std::unique_ptr<File> open_regular(const std::filesystem::path& path, IoError& error);

}  // namespace mie::io
