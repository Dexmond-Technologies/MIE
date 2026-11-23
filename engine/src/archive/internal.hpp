// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// Shared by the zip reader, the tar reader and the decompression wrappers. Not installed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mie/archive.hpp"

namespace mie::archive::detail {

using Bytes = std::span<const std::uint8_t>;
using Buffer = std::vector<std::uint8_t>;

// What the reference would have raised: the Python exception's type name and, where the
// reference prints it, its message. Thrown inside the readers and caught at the same places
// the reference catches. "HardCeiling" is ours: a hard limit was reached.
struct PyError {
    std::string type;
    std::string message;
};
bool is_os_error(const PyError& error);  // OSError or one of its subclasses
[[noreturn]] void seek_too_far();    // what seek() raises for a position of 2^63 or more

// The one bounds-checked view of the file. Every read of file bytes goes through it; a
// range that is not inside the file comes back shorter or empty, never out of bounds.
class View {
public:
    View() = default;
    explicit View(Bytes data) : data_(data) {}
    std::uint64_t size() const { return data_.size(); }
    // The bytes [offset, offset + length) that exist (a Python slice, or a short read).
    Bytes slice(std::uint64_t offset, std::uint64_t length) const {
        if (offset >= data_.size()) return {};
        const std::uint64_t available = data_.size() - offset;
        return data_.subspan(static_cast<std::size_t>(offset),
                             static_cast<std::size_t>(length < available ? length : available));
    }

private:
    Bytes data_;
};

// Little-endian fields. `at + width <= b.size()` is checked; a field outside gives 0.
inline std::uint32_t le32(Bytes b, std::size_t at) {
    if (at > b.size() || b.size() - at < 4) return 0;
    return static_cast<std::uint32_t>(b[at]) | (static_cast<std::uint32_t>(b[at + 1]) << 8) |
           (static_cast<std::uint32_t>(b[at + 2]) << 16) | (static_cast<std::uint32_t>(b[at + 3]) << 24);
}
inline std::uint16_t le16(Bytes b, std::size_t at) {
    if (at > b.size() || b.size() - at < 2) return 0;
    return static_cast<std::uint16_t>(b[at] | (b[at + 1] << 8));
}
inline std::uint64_t le64(Bytes b, std::size_t at) {
    return static_cast<std::uint64_t>(le32(b, at)) | (static_cast<std::uint64_t>(le32(b, at + 4)) << 32);
}

// A signed 128-bit whole number. Python's sizes and offsets have no upper limit; the values
// a zip (64-bit fields plus sums) or a tar (88-bit fields, decimal text) can carry fit here.
// Decimal text beyond 2^100 is clamped to 2^100 by the parser, so no sum can wrap.
struct Num {
    std::int64_t hi = 0;
    std::uint64_t lo = 0;
    constexpr Num() = default;
    constexpr Num(std::int64_t v) : hi(v < 0 ? -1 : 0), lo(static_cast<std::uint64_t>(v)) {}  // NOLINT
    static constexpr Num of(std::uint64_t v) {
        Num n;
        n.lo = v;
        return n;
    }
    friend constexpr Num operator+(Num a, Num b) {
        Num r;
        r.lo = a.lo + b.lo;
        r.hi = static_cast<std::int64_t>(static_cast<std::uint64_t>(a.hi) + static_cast<std::uint64_t>(b.hi) +
                                         (r.lo < a.lo ? 1u : 0u));
        return r;
    }
    constexpr Num operator-() const {
        Num r;
        r.lo = ~lo + 1;
        r.hi = static_cast<std::int64_t>(~static_cast<std::uint64_t>(hi) + (r.lo == 0 ? 1u : 0u));
        return r;
    }
    friend constexpr Num operator-(Num a, Num b) { return a + (-b); }
    friend constexpr bool operator==(const Num&, const Num&) = default;
    friend constexpr bool operator<(Num a, Num b) { return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo; }
    friend constexpr bool operator>(Num a, Num b) { return b < a; }
    friend constexpr bool operator<=(Num a, Num b) { return !(b < a); }
    friend constexpr bool operator>=(Num a, Num b) { return !(a < b); }
    constexpr bool negative() const { return hi < 0; }
    constexpr bool fits_offset() const { return hi == 0 && lo <= 0x7fffffffffffffffull; }  // 0 <= v < 2^63
    constexpr Num times256() const {
        Num r;
        r.hi = static_cast<std::int64_t>((static_cast<std::uint64_t>(hi) << 8) | (lo >> 56));
        r.lo = lo << 8;
        return r;
    }
};

std::string to_text(Bytes bytes);
Bytes as_bytes(std::string_view text);

// Counts every block of bytes produced (decompressed, zero-filled or copied into a member)
// against the hard ceiling of the scan.
struct Meter {
    Budget* budget;
    const Options* options;
    void charge(std::uint64_t bytes) const {
        budget->produced += bytes;
        if (budget->produced > options->hard_produced_bytes) {
            throw PyError{"HardCeiling", "more data produced than the hard limit allows"};
        }
    }
};

// --- the reference's temp folder, kept in memory ---------------------------------------
// Copies what writing members to a Linux file system does to the RESULT: which path a name
// lands on, when creating folders or the file fails (and with which Python exception), and
// that a later write to the same path replaces the earlier content.
class FakeDisk {
public:
    explicit FakeDisk(const Options& options) : options_(options) {}
    // os.path.realpath(join(temp, name)) relative to the temp folder ("" = the folder
    // itself); nullopt when it is outside (the reference's "unsafe member path").
    // Throws PyError ValueError for a NUL byte in the name.
    std::optional<std::string> target(std::string_view name) const;
    void makedirs_parent(const std::string& path);                    // os.makedirs(dirname(out), exist_ok=True)
    std::shared_ptr<Buffer> open_for_write(const std::string& path);  // open(out, 'wb'): the file is now empty
    std::shared_ptr<const Buffer> content(const std::string& path) const;

private:
    bool too_long(std::size_t path_length, std::size_t component_length) const;
    const Options& options_;
    std::map<std::string, std::shared_ptr<Buffer>> entries_;  // null = folder
};

// What both readers fill: the members with their paths, and the reasons.
struct Sink {
    const Options& options;
    Budget& budget;
    Meter meter;
    FakeDisk disk;
    std::vector<Member> members;
    std::vector<std::string>& reasons;
    Sink(const Options& o, Budget& b, std::vector<std::string>& r)
        : options(o), budget(b), meter{&b, &o}, disk(o), reasons(r) {}
    bool take(Num size);  // the reference's _take
    void store(const std::string& name, const std::string& path, const std::shared_ptr<Buffer>& file, Buffer&& data);
    void finish();        // gives each member its bytes: the last write to its path, or its own
};

// --- decompression (zlib, bzip2, liblzma) --------------------------------------------------
std::uint32_t crc32_of(Bytes data, std::uint32_t seed = 0);

// A Python file object as tarfile uses it: the plain file, or gzip.GzipFile, bz2.BZ2File,
// lzma.LZMAFile, each read in the same pieces as CPython reads it, so that a damaged or cut
// stream shows the same bytes before the same error.
class PyFile {
public:
    virtual ~PyFile() = default;
    virtual std::uint64_t tell() = 0;
    virtual void seek(Num target) = 0;             // throws PyError as Python's seek would
    virtual Buffer read(std::uint64_t count) = 0;  // short at the end; throws PyError
};
enum class Codec { Plain, Gzip, Bzip2, Xz };
std::unique_ptr<PyFile> open_file(Codec codec, Bytes file, Meter meter);

// One zip member's bytes, read as zipfile.ZipExtFile.read(max_bytes) reads them.
// Throws PyError (BadZipFile, EOFError, error, OSError, LZMAError, ValueError).
Buffer read_zip_member(int method, View file, Num data_start, Num compress_size, std::int64_t file_size,
                       std::uint32_t expected_crc, std::int64_t max_bytes, Meter meter);
bool zip_method_supported(int method);

// --- the two container readers -----------------------------------------------------------------
bool is_zip(View file, const Options& options);
void extract_zip(View file, Sink& sink);

// tarfile.is_tarfile: true when the file opens as a tar under gzip, bzip2, xz or as it is.
// Throws PyError when tarfile.open lets an exception through (the reference then says "not
// an archive" in _is_archive and "archive could not be read" in _extract_safely).
bool is_tar(Bytes file, const Options& options);
void extract_tar(Bytes file, Sink& sink);

}  // namespace mie::archive::detail
