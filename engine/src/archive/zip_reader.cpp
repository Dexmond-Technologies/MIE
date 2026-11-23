// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// Zip reader: what CPython 3.12.16 zipfile gives (Lib/zipfile/__init__.py) to the reference's
// _extract_zip and _zip_covers_file (dexmond_mie/core.py at ff313e2, lines 565-606, 657-684).
// Line numbers in comments are those of Lib/zipfile/__init__.py unless core.py is named.
#include <algorithm>
#include <numeric>

#include "internal.hpp"

namespace mie::archive::detail {
namespace {

constexpr std::uint64_t kMaxComment = 65535;  // ZIP_MAX_COMMENT
constexpr std::uint64_t kEndSize = 22, kLocatorSize = 20, kEnd64Size = 56, kCentralSize = 46, kLocalSize = 30;

bool starts_with(Bytes data, std::string_view signature) {
    return data.size() >= signature.size() && std::equal(signature.begin(), signature.end(), data.begin(),
                                                           [](char a, std::uint8_t b) { return static_cast<std::uint8_t>(a) == b; });
}

[[noreturn]] void bad_zip(const std::string& message) {
    throw PyError{"BadZipFile", message};
}

struct EndRecord {
    Num size_cd, offset_cd, location;
    std::size_t comment_length = 0;
};

// _EndRecData64 (238-295): the zip64 locator and record in front of the end record.
EndRecord end_record64(View file, std::uint64_t offset, EndRecord record) {
    if (offset < kLocatorSize) return record;
    offset -= kLocatorSize;
    const Bytes locator = file.slice(offset, kLocatorSize);
    if (!starts_with(locator, "PK\x06\x07")) return record;
    const std::uint64_t relative = le64(locator, 8);
    if (le32(locator, 4) != 0 || le32(locator, 16) > 1) bad_zip("zipfiles that span multiple disks are not supported");
    if (offset < kEnd64Size || relative > offset - kEnd64Size) bad_zip("Corrupt zip64 end of central directory locator");
    offset -= kEnd64Size;
    std::uint64_t extra_size = offset - relative;
    Bytes data = file.slice(relative, kEnd64Size);
    if (!starts_with(data, "PK\x06\x06") && relative != offset) {
        extra_size = 0;
        data = file.slice(offset, kEnd64Size);
    }
    if (!starts_with(data, "PK\x06\x06") || data.size() != kEnd64Size) bad_zip("Zip64 end of central directory record not found");
    const Num dir_size = Num::of(le64(data, 40)), dir_offset = Num::of(le64(data, 48));
    if (dir_offset + dir_size != Num::of(relative) || Num::of(le64(data, 4)) + Num(12) != Num(56) + Num::of(extra_size)) {
        bad_zip("Corrupt zip64 end of central directory record");
    }
    record.size_cd = dir_size;
    record.offset_cd = dir_offset;
    record.location = Num::of(offset - extra_size);
    return record;
}

// _EndRecData (298-355): the end record at the very end of the file, or the LAST "PK\5\6"
// in the final 65557 bytes. nullopt = no end record.
std::optional<EndRecord> end_record(View file) {
    const std::uint64_t size = file.size();
    if (size < kEndSize) return std::nullopt;
    EndRecord record;
    const Bytes last = file.slice(size - kEndSize, kEndSize);
    if (starts_with(last, "PK\x05\x06") && last[20] == 0 && last[21] == 0) {
        record.size_cd = Num::of(le32(last, 12));
        record.offset_cd = Num::of(le32(last, 16));
        record.location = Num::of(size - kEndSize);
        return end_record64(file, size - kEndSize, record);
    }
    const std::uint64_t window_start = size > kMaxComment + kEndSize ? size - kMaxComment - kEndSize : 0;
    const Bytes window = file.slice(window_start, kMaxComment + kEndSize);
    for (std::size_t at = window.size() >= 4 ? window.size() - 4 : 0; window.size() >= 4; --at) {
        if (starts_with(window.subspan(at), "PK\x05\x06")) {
            if (window.size() - at < kEndSize) return std::nullopt;
            const Bytes found = window.subspan(at, kEndSize);
            record.size_cd = Num::of(le32(found, 12));
            record.offset_cd = Num::of(le32(found, 16));
            record.comment_length = std::min<std::size_t>(le16(found, 20), window.size() - at - kEndSize);
            record.location = Num::of(window_start + at);
            return end_record64(file, window_start + at, record);
        }
        if (at == 0) break;
    }
    return std::nullopt;
}

// --- names ---------------------------------------------------------------------------------------

// bytes.decode('utf-8'), strict, as CPython decodes (Objects/stringlib/codecs.h): returns ""
// for valid text, else the message of the UnicodeDecodeError.
std::string utf8_error(Bytes s) {
    const std::size_t n = s.size();
    const auto continuation = [&](std::size_t k) { return (s[k] & 0xC0) == 0x80; };
    const auto fail = [&](std::size_t start, std::size_t length, const char* why) {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string message = "'utf-8' codec can't decode ";
        if (length == 1) {
            message += std::string("byte 0x") + kHex[s[start] >> 4] + kHex[s[start] & 15] + " in position " + std::to_string(start);
        } else {
            message += "bytes in position " + std::to_string(start) + "-" + std::to_string(start + length - 1);
        }
        return message + ": " + why;
    };
    constexpr char kStart[] = "invalid start byte", kCont[] = "invalid continuation byte", kEnd[] = "unexpected end of data";
    std::size_t i = 0;
    while (i < n) {
        const std::uint8_t ch = s[i];
        const std::size_t left = n - i;
        if (ch < 0x80) {
            i += 1;
        } else if (ch < 0xC2 || ch >= 0xF5) {
            return fail(i, 1, kStart);
        } else if (ch < 0xE0) {
            if (left < 2) return fail(i, left, kEnd);
            if (!continuation(i + 1)) return fail(i, 1, kCont);
            i += 2;
        } else if (ch < 0xF0) {
            if (left < 2) return fail(i, left, kEnd);
            const std::uint8_t second = s[i + 1];
            if (!continuation(i + 1) || (second < 0xA0 ? ch == 0xE0 : ch == 0xED)) return fail(i, 1, kCont);
            if (left < 3) return fail(i, left, kEnd);
            if (!continuation(i + 2)) return fail(i, 2, kCont);
            i += 3;
        } else {
            if (left < 2) return fail(i, left, kEnd);
            const std::uint8_t second = s[i + 1];
            if (!continuation(i + 1) || (second < 0x90 ? ch == 0xF0 : ch == 0xF4)) return fail(i, 1, kCont);
            if (left < 3) return fail(i, left, kEnd);
            if (!continuation(i + 2)) return fail(i, 2, kCont);
            if (left < 4) return fail(i, left, kEnd);
            if (!continuation(i + 3)) return fail(i, 3, kCont);
            i += 4;
        }
    }
    return {};
}

// The upper half of code page 437 as Unicode code points (Lib/encodings/cp437.py).
constexpr std::uint16_t kCp437[128] = {
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
    0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
    0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0};

// A raw zip name as the text Python holds, in UTF-8: strict UTF-8 when flag bit 11 is set
// (a UnicodeDecodeError otherwise), else code page 437 (1496-1501, 1682-1686).
std::string decode_name(Bytes raw, bool utf8) {
    if (utf8) {
        const std::string error = utf8_error(raw);
        if (!error.empty()) throw PyError{"UnicodeDecodeError", error};
        return to_text(raw);
    }
    std::string out;
    for (const std::uint8_t byte : raw) {
        if (byte < 0x80) {
            out.push_back(static_cast<char>(byte));
            continue;
        }
        const std::uint16_t point = kCp437[byte - 0x80];
        if (point < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (point >> 6)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (point >> 12)));
            out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3F)));
        }
        out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
    }
    return out;
}

std::string cut_at_nul(const std::string& name) {  // _sanitize_filename (357-372), POSIX
    return name.substr(0, name.find('\0'));
}

// --- the central directory -----------------------------------------------------------------------

struct Entry {
    std::string original;  // the name as decoded (ZipInfo.orig_filename)
    std::string name;      // ZipInfo.filename
    std::uint16_t flags = 0, method = 0;
    std::uint32_t crc = 0;
    Num compress_size, file_size, header_offset, end_offset;
    std::size_t extra_length = 0, comment_length = 0;
};

struct Directory {
    std::vector<Entry> entries;
    std::vector<std::size_t> by_offset;  // entry indexes sorted by header offset (stable)
    Num start;
    std::size_t comment_length = 0;
};

// ZipInfo._decodeExtra (516-560): zip64 sizes and the Unicode path field.
void decode_extra(Entry& entry, Bytes extra, std::uint32_t name_crc) {
    while (extra.size() >= 4) {
        const std::uint16_t type = le16(extra, 0);
        const std::size_t length = le16(extra, 2);
        if (length + 4 > extra.size()) {
            static constexpr char kHex[] = "0123456789abcdef";
            std::string id;
            for (int shift = 12; shift >= 0; shift -= 4) id.push_back(kHex[(type >> shift) & 15]);
            bad_zip("Corrupt extra field " + id + " (size=" + std::to_string(length) + ")");
        }
        Bytes data = extra.subspan(4, length);
        if (type == 0x0001) {
            const auto take = [&](Num& field, const char* label) {
                if (data.size() < 8) bad_zip(std::string("Corrupt zip64 extra field. ") + label + " not found.");
                field = Num::of(le64(data, 0));
            };
            if (entry.file_size == Num::of(0xFFFFFFFFFFFFFFFFull) || entry.file_size == Num::of(0xFFFFFFFFu)) {
                take(entry.file_size, "File size");
                data = data.subspan(8);
            }
            if (entry.compress_size == Num::of(0xFFFFFFFFu)) {
                take(entry.compress_size, "Compress size");
                data = data.subspan(8);
            }
            if (entry.header_offset == Num::of(0xFFFFFFFFu)) take(entry.header_offset, "Header offset");
        } else if (type == 0x7075) {
            if (data.size() < 5) bad_zip("Corrupt unicode path extra field (0x7075)");
            if (data[0] == 1 && le32(data, 1) == name_crc) {
                const Bytes path = data.subspan(5);
                if (!utf8_error(path).empty()) bad_zip("Corrupt unicode path extra field (0x7075): invalid utf-8 bytes");
                if (!path.empty()) entry.name = cut_at_nul(to_text(path));
            }
        }
        extra = extra.subspan(length + 4);
    }
}

// ZipFile._RealGetContents (1455-1535). Throws what the ZipFile constructor raises.
Directory read_directory(View file, const Options& options) {
    const std::optional<EndRecord> record = end_record(file);
    if (!record) bad_zip("File is not a zip file");
    Directory dir;
    dir.comment_length = record->comment_length;
    const Num concat = record->location - record->size_cd - record->offset_cd;
    dir.start = record->offset_cd + concat;
    if (dir.start.negative()) bad_zip("Bad offset for central directory");
    if (!dir.start.fits_offset()) seek_too_far();
    // fp.read(size_cd): Python needs that much memory at once. ARCHIVE_SPEC.md ND-3.
    if (!record->size_cd.fits_offset()) throw PyError{"OverflowError", "Python int too large to convert to C ssize_t"};
    if (record->size_cd > Num(std::int64_t{1} << 40)) throw PyError{"MemoryError", ""};
    const Bytes data = file.slice(dir.start.lo, record->size_cd.lo);
    std::size_t at = 0;
    const auto take = [&](std::size_t count) {  // BytesIO.read: short at the end
        const std::size_t got = std::min(count, data.size() - at);
        const Bytes out = data.subspan(at, got);
        at += got;
        return out;
    };
    Num total = 0;
    while (total < record->size_cd) {
        if (dir.entries.size() >= options.hard_entries) throw PyError{"HardCeiling", "too many zip directory entries"};
        const Bytes central = take(kCentralSize);
        if (central.size() != kCentralSize) bad_zip("Truncated central directory");
        if (!starts_with(central, "PK\x01\x02")) bad_zip("Bad magic number for central directory");
        const std::size_t name_length = le16(central, 28), extra_length = le16(central, 30), comment_length = le16(central, 32);
        const Bytes raw_name = take(name_length);
        Entry entry;
        entry.flags = le16(central, 8);
        entry.original = decode_name(raw_name, (entry.flags & 0x800) != 0);
        entry.name = cut_at_nul(entry.original);
        const Bytes extra = take(extra_length);
        entry.extra_length = extra.size();
        entry.comment_length = take(comment_length).size();
        entry.header_offset = Num::of(le32(central, 42));
        entry.method = le16(central, 10);
        entry.crc = le32(central, 16);
        entry.compress_size = Num::of(le32(central, 20));
        entry.file_size = Num::of(le32(central, 24));
        const unsigned version = central[6];
        if (version > 63) {  // MAX_EXTRACT_VERSION
            throw PyError{"NotImplementedError", "zip file version " + std::to_string(version / 10) + "." + std::to_string(version % 10)};
        }
        decode_extra(entry, extra, crc32_of(raw_name));
        entry.header_offset = entry.header_offset + concat;
        dir.entries.push_back(std::move(entry));
        total = total + Num::of(kCentralSize + name_length + extra_length + comment_length);
    }
    // 1531-1535: each entry ends where the next one (by header offset) starts.
    dir.by_offset.resize(dir.entries.size());
    std::iota(dir.by_offset.begin(), dir.by_offset.end(), std::size_t{0});
    std::stable_sort(dir.by_offset.begin(), dir.by_offset.end(), [&](std::size_t a, std::size_t b) {
        return dir.entries[a].header_offset < dir.entries[b].header_offset;
    });
    Num end = dir.start;
    for (auto it = dir.by_offset.rbegin(); it != dir.by_offset.rend(); ++it) {
        dir.entries[*it].end_offset = end;
        end = dir.entries[*it].header_offset;
    }
    return dir;
}

// core.py:565-606 _zip_covers_file: reasons the members do NOT cover the file.
std::vector<std::string> coverage(View file, const Directory& dir, const Options& options) {
    std::vector<std::string> reasons;
    std::int64_t uncovered = static_cast<std::int64_t>(dir.comment_length);
    if (!starts_with(file.slice(0, 4), "PK\x03\x04")) reasons.emplace_back("no local header at offset 0");
    Num pos = 0, slack = 0;
    for (const std::size_t index : dir.by_offset) {
        const Entry& entry = dir.entries[index];
        if (!(pos <= entry.header_offset && entry.header_offset <= pos + slack)) {
            reasons.push_back("gap or overlap before member " + entry.name);
            break;
        }
        if (!entry.header_offset.fits_offset()) seek_too_far();
        const Bytes local = file.slice(entry.header_offset.lo, kLocalSize);
        if (local.size() < kLocalSize || !starts_with(local, "PK\x03\x04")) {
            reasons.push_back("bad local header for " + entry.name);
            break;
        }
        const std::int64_t name_length = le16(local, 26), extra_length = le16(local, 28);
        uncovered += extra_length + static_cast<std::int64_t>(entry.extra_length + entry.comment_length);
        pos = entry.header_offset + Num(30 + name_length + extra_length) + entry.compress_size;
        slack = (entry.flags & 0x08) != 0 ? Num(options.zip_descriptor_slack) : Num(0);
    }
    if (reasons.empty() && !(pos <= dir.start && dir.start <= pos + slack)) {
        reasons.emplace_back("data between the last member and the central directory");
    }
    const std::int64_t end = static_cast<std::int64_t>(file.size()) - 22 - static_cast<std::int64_t>(dir.comment_length);
    if (end < 0 || !starts_with(file.slice(static_cast<std::uint64_t>(end), 4), "PK\x05\x06")) {
        reasons.emplace_back("data after the end-of-central-directory record");
    }
    if (uncovered > options.max_uncovered_zip_bytes) {
        reasons.push_back(std::to_string(uncovered) + " bytes of extra fields/comments not covered by members");
    }
    return reasons;
}

// ZipFile.open (1657-1722) up to the creation of the reader. Returns where the data starts.
Num open_member(View file, const Entry& entry) {
    if (entry.header_offset.negative()) throw PyError{"OSError", "[Errno 22] Invalid argument"};
    if (!entry.header_offset.fits_offset()) seek_too_far();
    const std::uint64_t offset = entry.header_offset.lo;
    const Bytes local = file.slice(offset, kLocalSize);
    if (local.size() != kLocalSize) bad_zip("Truncated file header");
    if (!starts_with(local, "PK\x03\x04")) bad_zip("Bad magic number for file header");
    const Bytes raw_name = file.slice(offset + kLocalSize, le16(local, 26));
    const Num data_start = Num::of(offset + kLocalSize + raw_name.size() + le16(local, 28));
    if (entry.flags & 0x20) throw PyError{"NotImplementedError", "compressed patched data (flag bit 5)"};
    if (entry.flags & 0x40) throw PyError{"NotImplementedError", "strong encryption (flag bit 6)"};
    if (decode_name(raw_name, (le16(local, 6) & 0x800) != 0) != entry.original) {
        bad_zip("File name in directory and header differ.");
    }
    // 1693-1704: a member that runs into the next header is refused, unless the next header
    // is this very one (two entries for one header: only a warning).
    if (data_start + entry.compress_size > entry.end_offset && !(entry.end_offset == entry.header_offset)) {
        bad_zip("Overlapped entries (possible zip bomb)");
    }
    if (entry.flags & 0x01) throw PyError{"RuntimeError", "File is encrypted, password required for extraction"};
    if (!zip_method_supported(entry.method)) {  // _get_decompressor (790-803)
        throw PyError{"NotImplementedError", "compression type " + std::to_string(entry.method)};
    }
    return data_start;
}

}  // namespace

// zipfile.is_zipfile: an end record is found; any OSError or BadZipFile means "no".
bool is_zip(View file, const Options& options) {
    try {
        const std::optional<EndRecord> record = end_record(file);
        if (!record) return false;
        // Shipped-profile option: a zip that sits after other data is not taken for a zip.
        return options.zip_after_other_data || record->location - record->size_cd - record->offset_cd == Num(0);
    } catch (const PyError&) {
        return false;
    }
}

// core.py:657-684 _extract_zip.
void extract_zip(View file, Sink& sink) {
    const Options& options = sink.options;
    const Directory dir = read_directory(file, options);  // zipfile.ZipFile(file_path)
    try {
        const std::vector<std::string> gaps = coverage(file, dir, options);
        sink.reasons.insert(sink.reasons.end(), gaps.begin(), gaps.end());
    } catch (const PyError& error) {
        sink.reasons.push_back("zip coverage check failed (" + error.type + ")");
    }
    const std::size_t limit = static_cast<std::size_t>(options.max_members_per_archive);
    if (dir.entries.size() > limit) sink.reasons.push_back("more than " + std::to_string(limit) + " members");
    for (std::size_t index = 0; index < std::min(limit, dir.entries.size()); ++index) {
        const Entry& entry = dir.entries[index];
        if (!entry.name.empty() && entry.name.back() == '/') continue;  // ZipInfo.is_dir()
        if (entry.file_size > Num(options.max_member_bytes)) {
            sink.reasons.push_back("member over size limit: " + entry.name);
            continue;
        }
        const std::optional<std::string> out = sink.disk.target(entry.name);
        if (!out) {
            sink.reasons.push_back("unsafe member path: " + entry.name);
            continue;
        }
        if (!sink.take(entry.file_size)) {
            sink.reasons.emplace_back("member/byte budget exhausted");
            break;
        }
        try {
            sink.disk.makedirs_parent(*out);
            const Num data_start = open_member(file, entry);                  // zf.open(info)
            const std::shared_ptr<Buffer> written = sink.disk.open_for_write(*out);  // open(out, 'wb')
            Buffer data = read_zip_member(entry.method, file, data_start, entry.compress_size,
                                          static_cast<std::int64_t>(entry.file_size.lo), entry.crc,
                                          options.max_member_bytes, sink.meter);
            sink.store(entry.name, *out, written, std::move(data));
        } catch (const PyError& error) {
            sink.reasons.push_back("member extraction failed: " + entry.name + " (" + error.type + ")");
        }
    }
}

}  // namespace mie::archive::detail
