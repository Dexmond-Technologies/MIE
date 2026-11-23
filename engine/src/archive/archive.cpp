// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// detect() and extract(), and the in-memory copy of the reference's temp folder.
// Reference: dexmond_mie/core.py at ff313e2, lines 504-511 (_is_archive) and 608-655
// (_extract_safely). File-system behaviour: Linux, CPython 3.12.16 posixpath.realpath,
// os.makedirs and open(); see ARCHIVE_SPEC.md section 7.
#include <new>

#include "internal.hpp"

namespace mie::archive {
namespace detail {

std::string to_text(Bytes bytes) {
    return std::string(bytes.begin(), bytes.end());
}

Bytes as_bytes(std::string_view text) {
    return Bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

bool is_os_error(const PyError& error) {
    return error.type == "OSError" || error.type == "BadGzipFile" || error.type == "FileExistsError" ||
           error.type == "NotADirectoryError" || error.type == "IsADirectoryError";
}

// --- FakeDisk --------------------------------------------------------------------------------

// posixpath.realpath of join(temp, name), with no symbolic link below the temp folder (the
// reference never creates one): "" and "." parts are dropped, ".." removes the part before
// it. An absolute name, or one that climbs above the temp folder, is outside it. (A name
// that climbs out and comes back in by the folder's random name cannot be told here; it is
// taken as outside: ARCHIVE_SPEC.md quirk Q-17.)
std::optional<std::string> FakeDisk::target(std::string_view name) const {
    if (name.find('\0') != std::string_view::npos) throw PyError{"ValueError", "lstat: embedded null character in path"};
    if (!name.empty() && name.front() == '/') return std::nullopt;
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (start <= name.size()) {
        std::size_t end = name.find('/', start);
        if (end == std::string_view::npos) end = name.size();
        const std::string_view part = name.substr(start, end - start);
        start = end + 1;
        if (part.empty() || part == ".") continue;
        if (part == "..") {
            if (parts.empty()) return std::nullopt;
            parts.pop_back();
            continue;
        }
        parts.push_back(part);
    }
    std::string out;
    for (const std::string_view part : parts) {
        if (!out.empty()) out.push_back('/');
        out.append(part);
    }
    return out;
}

// ENAMETOOLONG on Linux: a whole path over 4095 bytes, or one name over 255 bytes.
bool FakeDisk::too_long(std::size_t path_length, std::size_t component_length) const {
    const std::uint64_t whole = static_cast<std::uint64_t>(options_.temp_dir_length) + 1 + path_length;
    return whole > 4095 || component_length > 255;
}

// os.makedirs(os.path.dirname(out), exist_ok=True), from the top folder down:
// an existing folder is passed; a file where a folder is needed gives FileExistsError when
// it is the last folder asked for and NotADirectoryError when it is above it; a name or
// path that is too long gives OSError. Folders made before the failure stay.
void FakeDisk::makedirs_parent(const std::string& path) {
    const std::size_t slash = path.rfind('/');
    if (slash == std::string::npos) return;  // the parent is the temp folder itself
    const std::string dir = path.substr(0, slash);
    std::size_t start = 0;
    for (;;) {
        const std::size_t found = dir.find('/', start);
        const bool last = found == std::string::npos;
        const std::size_t end = last ? dir.size() : found;
        const std::string prefix = dir.substr(0, end);
        const auto it = entries_.find(prefix);
        if (it == entries_.end()) {
            if (too_long(prefix.size(), end - start)) throw PyError{"OSError", "[Errno 36] File name too long"};
            entries_[prefix] = nullptr;
        } else if (it->second) {
            if (last) throw PyError{"FileExistsError", "[Errno 17] File exists"};
            std::size_t next_end = dir.find('/', end + 1);
            if (next_end == std::string::npos) next_end = dir.size();
            if (too_long(next_end, 0)) throw PyError{"OSError", "[Errno 36] File name too long"};
            throw PyError{"NotADirectoryError", "[Errno 20] Not a directory"};
        }
        if (last) return;
        start = end + 1;
    }
}

// open(out, 'wb'): the temp folder itself or another folder gives IsADirectoryError, a name
// or path that is too long gives OSError; otherwise the file exists and is empty.
std::shared_ptr<Buffer> FakeDisk::open_for_write(const std::string& path) {
    if (path.empty()) throw PyError{"IsADirectoryError", "[Errno 21] Is a directory"};
    if (too_long(path.size(), 0)) throw PyError{"OSError", "[Errno 36] File name too long"};
    const auto it = entries_.find(path);
    if (it != entries_.end() && !it->second) throw PyError{"IsADirectoryError", "[Errno 21] Is a directory"};
    const std::size_t slash = path.rfind('/');
    const std::size_t base = slash == std::string::npos ? path.size() : path.size() - slash - 1;
    if (too_long(0, base)) throw PyError{"OSError", "[Errno 36] File name too long"};
    auto file = std::make_shared<Buffer>();
    entries_[path] = file;
    return file;
}

std::shared_ptr<const Buffer> FakeDisk::content(const std::string& path) const {
    const auto it = entries_.find(path);
    if (it == entries_.end() || !it->second) return std::make_shared<const Buffer>();
    return it->second;
}

// --- Sink ------------------------------------------------------------------------------------

// core.py:630-636. A negative size (a tar can carry one) passes and GROWS the byte budget,
// as in the reference; the budget is kept inside 64 bits.
bool Sink::take(Num size) {
    if (budget.members <= 0 || size > Num(budget.bytes)) return false;
    budget.members -= 1;
    const Num left = Num(budget.bytes) - size;
    budget.bytes = left.fits_offset() ? static_cast<std::int64_t>(left.lo) : 0x7fffffffffffffffll;
    return true;
}

void Sink::store(const std::string& name, const std::string& path, const std::shared_ptr<Buffer>& file,
                 Buffer&& data) {
    *file = std::move(data);
    members.push_back(Member{name, path, options.duplicate_names_last_wins ? nullptr : file});
}

void Sink::finish() {
    for (Member& member : members) {
        if (!member.bytes) member.bytes = disk.content(member.disk_path);
    }
}

}  // namespace detail

using detail::PyError;

Kind detect(std::span<const std::uint8_t> file, const Options& options) {
    // core.py:509-511: any exception from either check means "not an archive".
    try {
        if (detail::is_zip(detail::View(file), options)) return Kind::Zip;
        if (detail::is_tar(file, options)) return Kind::Tar;
    } catch (const PyError&) {
    } catch (const std::bad_alloc&) {
    }
    return Kind::NotArchive;
}

Extraction extract(std::span<const std::uint8_t> file, Budget& budget, const Options& options) {
    Extraction out;
    detail::Sink sink(options, budget, out.reasons);
    const detail::View view(file);
    bool zip = false;
    try {  // core.py:638-642
        zip = detail::is_zip(view, options);
    } catch (const PyError& error) {
        out.reasons.push_back("zip check failed (" + error.type + ")");
    }
    try {  // core.py:643-654
        if (zip) {
            out.kind = Kind::Zip;
            detail::extract_zip(view, sink);
        } else if (detail::is_tar(file, options)) {
            out.kind = Kind::Tar;
            detail::extract_tar(file, sink);
        } else {
            out.reasons.push_back("not a zip or tar archive");
        }
    } catch (const PyError& error) {
        out.reasons.push_back("archive could not be read (" + error.type + ": " + error.message + ")");
    } catch (const std::bad_alloc&) {
        out.reasons.push_back("archive could not be read (MemoryError: )");
    }
    sink.finish();
    out.members = std::move(sink.members);
    out.complete = out.reasons.empty();
    return out;
}

}  // namespace mie::archive
