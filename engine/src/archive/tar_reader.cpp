// Derived work: ported to C++ from CPython 3.12.16 (Lib/zipfile/__init__.py, Lib/tarfile.py,
// Lib/_compression.py, Lib/gzip.py, Lib/bz2.py, Lib/lzma.py, Modules/_bz2module.c,
// Modules/_lzmamodule.c, Modules/zlibmodule.c, Modules/_io/bufferedio.c), Copyright (c) 2001-2023
// Python Software Foundation, licensed under the PSF License Agreement. Changes made: the reading
// rules, limits, error classes and error texts were re-implemented in C++ over in-memory buffers,
// with hard ceilings of our own added (ARCHIVE_SPEC.md sections 9-10). Full notice in THIRD-PARTY-
// NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond Technologies.
//
// Tar reader: what CPython 3.12.16 tarfile gives (Lib/tarfile.py) to the reference's
// _extract_tar (dexmond_mie/core.py at ff313e2, lines 686-748). Member names are kept as the
// raw bytes of the archive (Python holds them as text with surrogateescape, which gives the
// same bytes back). Line numbers in comments are those of Lib/tarfile.py unless core.py is named.
#include <algorithm>
#include <initializer_list>
#include <utility>

#include "internal.hpp"

namespace mie::archive::detail {
namespace {

constexpr std::uint64_t kBlock = 512;
constexpr int kMaxChain = 256;  // headers that announce another header, one inside the other

// tarfile.HeaderError and its kinds (285-301), caught in Tar::next as TarFile.next does.
struct HeaderError {
    enum class Kind { Empty, Truncated, EndOfFile, Invalid, Subsequent } kind;
};
[[noreturn]] void invalid() {
    throw HeaderError{HeaderError::Kind::Invalid};
}

Bytes part(Bytes data, std::size_t at, std::size_t length) {  // a Python slice: clamped
    if (at >= data.size()) return {};
    return data.subspan(at, std::min(length, data.size() - at));
}

std::string nts(Bytes field) {  // tarfile.nts (167-173): up to the first NUL
    const auto end = std::find(field.begin(), field.end(), std::uint8_t{0});
    return std::string(field.begin(), end);
}

void strip_slashes(std::string& name) {
    while (!name.empty() && name.back() == '/') name.pop_back();
}

// int(text, base) of Python for base 8 and 10, ASCII only: white space around, a sign, for
// base 8 an optional "0o", digits with single underscores between them. false = ValueError.
// Values beyond 2^100 are held at 2^100. Digits and white space outside ASCII, which Python
// also accepts, are refused here (ARCHIVE_SPEC.md Q-24).
bool parse_int(std::string_view text, int base, Num& out) {
    const auto space = [](char c) { return c == ' ' || (c >= '\t' && c <= '\r') || (c >= '\x1c' && c <= '\x1f'); };
    while (!text.empty() && space(text.front())) text.remove_prefix(1);
    while (!text.empty() && space(text.back())) text.remove_suffix(1);
    bool negative = false;
    if (!text.empty() && (text.front() == '+' || text.front() == '-')) {
        negative = text.front() == '-';
        text.remove_prefix(1);
    }
    if (base == 8 && text.size() >= 2 && text[0] == '0' && (text[1] == 'o' || text[1] == 'O')) {
        text.remove_prefix(2);
        if (!text.empty() && text.front() == '_') text.remove_prefix(1);
    }
    Num value = 0;
    bool after_underscore = true;  // a number may not begin with an underscore
    std::size_t digits = 0;
    for (const char c : text) {
        if (c == '_') {
            if (after_underscore) return false;
            after_underscore = true;
            continue;
        }
        if (c < '0' || c >= '0' + base) return false;
        after_underscore = false;
        digits += 1;
        if (value.hi < (std::int64_t{1} << 36)) {
            const Num twice = value + value, eight = twice + twice + twice + twice;
            value = (base == 8 ? eight : eight + twice) + Num(c - '0');
        }
    }
    if (after_underscore || (base == 10 && digits > 4300)) return false;  // 4300: sys.int_info.default_max_str_digits
    out = negative ? -value : value;
    return true;
}

// tarfile.nti (175-195): a number field. Base 256 when the first byte is 0o200 or 0o377,
// else octal text up to the first NUL.
Num nti(Bytes field) {
    if (field.empty()) throw PyError{"IndexError", "index out of range"};
    if (field[0] == 0200 || field[0] == 0377) {
        Num value = 0, scale = 1;
        for (std::size_t i = 1; i < field.size(); ++i) {
            value = value.times256() + Num(field[i]);
            scale = scale.times256();
        }
        return field[0] == 0377 ? value - scale : value;
    }
    const std::string text = nts(field);
    if (std::any_of(text.begin(), text.end(), [](char c) { return static_cast<unsigned char>(c) >= 0x80; })) invalid();
    if (std::all_of(text.begin(), text.end(), [](char c) { return c == ' ' || (c >= '\t' && c <= '\r') || (c >= '\x1c' && c <= '\x1f'); })) {
        return Num(0);
    }
    Num value;
    if (!parse_int(text, 8, value)) invalid();
    return value;
}

Num block(Num count) {  // TarInfo._block (1651-1661): up to a whole number of blocks
    if (count.negative()) invalid();
    Num rounded = count + Num(511);
    rounded.lo &= ~std::uint64_t{511};
    return rounded;
}

// fileobj.read(n) for an n taken from the archive: the data of a pax or long-name header.
Buffer read_sized(PyFile& file, Num count, const Options& options) {
    if (!count.fits_offset()) throw PyError{"OverflowError", "Python int too large to convert to C ssize_t"};
    if (count.lo > options.hard_header_data_bytes) throw PyError{"HardCeiling", "extended header data over the hard limit"};
    return file.read(count.lo);
}

// repr() of the text in int()'s "invalid literal" message; text beyond ASCII is copied as it is.
[[noreturn]] void bad_int(std::string_view text, bool is_bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    const char quote = text.find('\'') != std::string_view::npos && text.find('"') == std::string_view::npos ? '"' : '\'';
    std::string shown = is_bytes ? "b" : "";
    shown.push_back(quote);
    for (const char raw : text) {
        const unsigned char c = static_cast<unsigned char>(raw);
        if (raw == quote || raw == '\\') {
            shown += std::string("\\") + raw;
        } else if (raw == '\t' || raw == '\n' || raw == '\r') {
            shown += raw == '\t' ? "\\t" : raw == '\n' ? "\\n" : "\\r";
        } else if (c < 0x20 || c == 0x7f || (is_bytes && c >= 0x80)) {
            shown += std::string("\\x") + kHex[c >> 4] + kHex[c & 15];
        } else {
            shown.push_back(raw);
        }
    }
    shown.push_back(quote);
    throw PyError{"ValueError", "invalid literal for int() with base 10: " + shown};
}

// The pax keywords that change a result, in the order they were first set (a Python dict).
using PaxMap = std::vector<std::pair<std::string, std::string>>;
constexpr std::string_view kPaxKeys[] = {"GNU.sparse.map",  "GNU.sparse.size",     "GNU.sparse.major", "GNU.sparse.minor",
                                         "GNU.sparse.name", "GNU.sparse.realsize", "path",             "size"};
const std::string* pax_get(const PaxMap& map, std::string_view key) {
    for (const auto& [name, value] : map) {
        if (name == key) return &value;
    }
    return nullptr;
}

struct Info {  // the fields of tarfile.TarInfo that change a result
    std::string name;
    std::uint8_t type = 0;
    Num size, offset, offset_data;
    bool has_sparse = false;  // TarInfo.sparse is not None
    std::vector<std::pair<Num, Num>> sparse;
    bool extended = false;    // old GNU sparse header: more map blocks follow
    Num original_size;
    bool is_reg() const { return type == '0' || type == 0 || type == '7' || type == 'S'; }  // REGULAR_TYPES
    bool is_dir() const { return type == '5'; }
    bool supported() const {  // SUPPORTED_TYPES
        return is_reg() || (type >= '1' && type <= '6') || type == 'L' || type == 'K';
    }
};

class Tar {  // tarfile.TarFile, reading
public:
    Tar(PyFile& file, const Options& options) : file_(file), options_(options) {}
    std::optional<Info> next();
    Num offset() const { return offset_; }
    bool zero_block_first() const { return zero_block_first_; }
    const std::optional<Num>& bad_header() const { return bad_header_; }

private:
    Info from_tar(bool dircheck, int depth);
    Info from_buffer(Bytes buf, bool dircheck) const;
    Info chained(int depth);
    Info process(Info info, int depth);
    Info process_pax(const Info& info, int depth);
    void sparse_10(Info& next);
    void apply_pax(Info& info, const PaxMap& headers) const;
    void add_sparse(Info& info, Num start, Num count) const {
        if (info.sparse.size() >= options_.hard_entries) throw PyError{"HardCeiling", "too many sparse map entries"};
        info.sparse.emplace_back(start, count);
    }
    Num here() { return Num::of(file_.tell()); }

    PyFile& file_;
    const Options& options_;
    Num offset_ = 0;  // TarFile.offset: where the next header is
    PaxMap global_;   // TarFile.pax_headers
    std::uint64_t headers_ = 0;
    bool zero_block_first_ = false;
    std::optional<Num> bad_header_;
};

// TarFile.next (2765-2819). nullopt = no further member.
std::optional<Info> Tar::next() {
    if (offset_ != here()) {
        if (offset_ == Num(0)) return std::nullopt;
        file_.seek(offset_ - Num(1));
        if (file_.read(1).empty()) throw PyError{"ReadError", "unexpected end of data"};
    }
    try {
        return from_tar(true, 0);
    } catch (const HeaderError& error) {
        const bool at_start = offset_ == Num(0);
        switch (error.kind) {
            case HeaderError::Kind::EndOfFile:
                zero_block_first_ = at_start;
                break;
            case HeaderError::Kind::Empty:
                if (at_start) throw PyError{"ReadError", "empty file"};
                break;
            case HeaderError::Kind::Invalid:
            case HeaderError::Kind::Truncated:
                if (at_start) throw PyError{"ReadError", "invalid or truncated header"};
                bad_header_ = offset_;  // the archive ends here without an error (quirk Q-12)
                break;
            case HeaderError::Kind::Subsequent:
                throw PyError{"ReadError", "subsequent header"};
        }
    } catch (const PyError& error) {
        if (error.type == "error") throw PyError{"ReadError", "zlib error: " + error.message};
        throw;
    }
    return std::nullopt;
}

// TarInfo._fromtarfile (1347-1354).
Info Tar::from_tar(bool dircheck, int depth) {
    if (depth > kMaxChain) throw PyError{"RecursionError", "maximum recursion depth exceeded"};
    if (++headers_ > options_.hard_entries) throw PyError{"HardCeiling", "too many tar headers"};
    const Buffer buf = file_.read(kBlock);
    Info info = from_buffer(buf, dircheck);
    info.offset = here() - Num(512);
    return process(std::move(info), depth);
}

// A header after a long-name or pax header: any header error becomes SubsequentHeaderError.
Info Tar::chained(int depth) {
    try {
        return from_tar(false, depth + 1);
    } catch (const HeaderError&) {
        throw HeaderError{HeaderError::Kind::Subsequent};
    }
}

// TarInfo._frombuf (1272-1337).
Info Tar::from_buffer(Bytes buf, bool dircheck) const {
    if (buf.empty()) throw HeaderError{HeaderError::Kind::Empty};
    if (buf.size() != kBlock) throw HeaderError{HeaderError::Kind::Truncated};
    std::int64_t plain = 256, with_sign = 256;  // calc_chksums (225-236)
    bool all_zero = true;
    for (std::size_t i = 0; i < kBlock; ++i) {
        all_zero = all_zero && buf[i] == 0;
        if (i >= 148 && i < 156) continue;
        plain += buf[i];
        with_sign += static_cast<std::int8_t>(buf[i]);
    }
    if (all_zero) throw HeaderError{HeaderError::Kind::EndOfFile};
    const Num checksum = nti(part(buf, 148, 8));
    if (checksum != Num(plain) && checksum != Num(with_sign)) invalid();
    Info info;
    info.name = nts(part(buf, 0, 100));
    for (const std::size_t at : {std::size_t{100}, std::size_t{108}, std::size_t{116}}) nti(part(buf, at, 8));  // mode, uid, gid
    info.size = nti(part(buf, 124, 12));
    nti(part(buf, 136, 12));  // mtime
    info.type = buf[156];
    nti(part(buf, 329, 8));   // devmajor
    nti(part(buf, 337, 8));   // devminor
    const std::string prefix = nts(part(buf, 345, 155));
    if (dircheck && info.type == 0 && !info.name.empty() && info.name.back() == '/') info.type = '5';
    if (info.type == 'S') {  // old GNU sparse: four map entries in the header itself
        for (std::size_t at = 386; at < 386 + 4 * 24; at += 24) {
            const Num start = nti(part(buf, at, 12));
            info.sparse.emplace_back(start, nti(part(buf, at + 12, 12)));
        }
        info.extended = buf[482] != 0;
        info.original_size = nti(part(buf, 483, 12));
    }
    if (info.is_dir()) strip_slashes(info.name);
    if (!prefix.empty() && info.type != 'L' && info.type != 'K' && info.type != 'S') info.name = prefix + "/" + info.name;
    return info;
}

// TarInfo._apply_pax_info (1620-1641), for the keywords kept.
void Tar::apply_pax(Info& info, const PaxMap& headers) const {
    for (const auto& [key, value] : headers) {
        if (key == "GNU.sparse.name") {
            info.name = value;
        } else if (key == "GNU.sparse.size" || key == "GNU.sparse.realsize") {
            if (!parse_int(value, 10, info.size)) bad_int(value, false);
        } else if (key == "path") {
            info.name = value;
            strip_slashes(info.name);
        } else if (key == "size") {
            if (!parse_int(value, 10, info.size)) info.size = Num(0);
        }
    }
}

// TarInfo._proc_member (1367-1378) with _proc_builtin, _proc_gnulong and _proc_sparse.
Info Tar::process(Info info, int depth) {
    if (info.type == 'L' || info.type == 'K') {  // 1402-1427
        const Buffer buf = read_sized(file_, block(info.size), options_);
        Info next = chained(depth);
        next.offset = info.offset;
        if (info.type == 'L') next.name = nts(buf);
        if (next.is_dir() && !next.name.empty() && next.name.back() == '/') next.name.pop_back();
        return next;
    }
    if (info.type == 'x' || info.type == 'g' || info.type == 'X') return process_pax(info, depth);
    if (info.type == 'S') {  // 1429-1455
        std::vector<std::pair<Num, Num>> first;
        first.swap(info.sparse);
        for (const auto& [start, count] : first) add_sparse(info, start, count);
        bool extended = info.extended;
        while (extended) {
            const Buffer buf = file_.read(kBlock);
            for (std::size_t at = 0; at < 21 * 24; at += 24) {
                const Num start = nti(part(buf, at, 12));
                const Num count = nti(part(buf, at + 12, 12));
                if (start != Num(0) && count != Num(0)) add_sparse(info, start, count);
            }
            if (buf.size() <= 504) throw PyError{"IndexError", "index out of range"};
            extended = buf[504] != 0;
        }
        info.has_sparse = true;
        info.offset_data = here();
        offset_ = info.offset_data + block(info.size);
        info.size = info.original_size;
        return info;
    }
    info.offset_data = here();  // 1380-1400
    offset_ = info.is_reg() || !info.supported() ? info.offset_data + block(info.size) : info.offset_data;
    apply_pax(info, global_);
    if (info.is_dir()) strip_slashes(info.name);
    return info;
}

// TarInfo._proc_pax (1457-1576) and the three GNU sparse forms (1578-1618).
Info Tar::process_pax(const Info& info, int depth) {
    const Buffer buf = read_sized(file_, block(info.size), options_);
    PaxMap local = info.type == 'g' ? PaxMap{} : global_;
    PaxMap& headers = info.type == 'g' ? global_ : local;
    PaxMap records;                                 // the records of THIS header, kept ones only
    std::vector<std::string> map_starts, map_counts;  // GNU.sparse.offset / GNU.sparse.numbytes
    std::size_t at = 0;
    while (at < buf.size() && buf[at] != 0) {
        std::size_t digits = 0;  // _header_length_prefix_re: ([0-9]{1,20}) and a space
        std::uint64_t length = 0;
        while (digits < 20 && at + digits < buf.size() && buf[at + digits] >= '0' && buf[at + digits] <= '9') {
            length = length > buf.size() ? length : length * 10 + static_cast<std::uint64_t>(buf[at + digits] - '0');
            digits += 1;
        }
        if (digits == 0 || at + digits >= buf.size() || buf[at + digits] != ' ') invalid();
        if (length < 5 || length > buf.size() - at) invalid();
        const std::size_t last = at + static_cast<std::size_t>(length) - 1;  // the record's last byte
        const std::size_t text_start = at + digits + 1;
        const Bytes text = text_start < last ? part(buf, text_start, last - text_start) : Bytes{};
        const auto equals = std::find(text.begin(), text.end(), std::uint8_t{'='});
        if (equals == text.begin() || equals == text.end() || buf[last] != '\n') invalid();
        const std::string key(text.begin(), equals), value(equals + 1, text.end());
        if (key == "GNU.sparse.offset") map_starts.push_back(value);
        if (key == "GNU.sparse.numbytes") map_counts.push_back(value);
        if (std::find(std::begin(kPaxKeys), std::end(kPaxKeys), key) != std::end(kPaxKeys)) records.emplace_back(key, value);
        at += static_cast<std::size_t>(length);
    }
    for (const auto& [key, value] : records) {  // pax_headers[keyword] = value
        const auto found = std::find_if(headers.begin(), headers.end(), [&](const auto& item) { return item.first == key; });
        if (found == headers.end()) {
            headers.emplace_back(key, value);
        } else {
            found->second = value;
        }
    }
    Info next = chained(depth);
    if (const std::string* map = pax_get(headers, "GNU.sparse.map")) {  // format 0.1 (1598-1602)
        std::vector<Num> numbers;
        std::size_t start = 0;
        for (;;) {
            const std::size_t comma = map->find(',', start);
            const std::string item = map->substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            Num number;
            if (!parse_int(item, 10, number)) bad_int(item, false);
            numbers.push_back(number);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
        next.sparse.clear();
        for (std::size_t i = 0; i + 1 < numbers.size(); i += 2) add_sparse(next, numbers[i], numbers[i + 1]);
        next.has_sparse = true;
    } else if (pax_get(headers, "GNU.sparse.size") != nullptr) {  // format 0.0 (1578-1596)
        next.sparse.clear();
        for (std::size_t i = 0; i < map_starts.size() || i < map_counts.size(); ++i) {
            Num start, count;
            if (i < map_starts.size() && !parse_int(map_starts[i], 10, start)) invalid();
            if (i < map_counts.size() && !parse_int(map_counts[i], 10, count)) invalid();
            if (i < map_starts.size() && i < map_counts.size()) add_sparse(next, start, count);
        }
        next.has_sparse = true;
    } else {
        const std::string* major = pax_get(headers, "GNU.sparse.major");
        const std::string* minor = pax_get(headers, "GNU.sparse.minor");
        if (major != nullptr && minor != nullptr && *major == "1" && *minor == "0") sparse_10(next);
    }
    if (info.type != 'g') {  // 1562-1574
        apply_pax(next, headers);
        next.offset = info.offset;
        if (pax_get(headers, "size") != nullptr) {
            offset_ = next.is_reg() || !next.supported() ? next.offset_data + block(next.size) : next.offset_data;
        }
    }
    return next;
}

// TarInfo._proc_gnusparse_10 (1604-1618): the map is decimal text in front of the data.
void Tar::sparse_10(Info& next) {
    Buffer buf = file_.read(kBlock);
    const auto line = [&](bool read_more) {
        auto end = std::find(buf.begin(), buf.end(), std::uint8_t{'\n'});
        if (end == buf.end() && read_more) {
            const Buffer more = file_.read(kBlock);
            const std::size_t old = buf.size();
            append(buf, more);
            end = std::find(buf.begin() + static_cast<std::ptrdiff_t>(old), buf.end(), std::uint8_t{'\n'});
        }
        if (end == buf.end()) throw PyError{"ValueError", "not enough values to unpack (expected 2, got 1)"};
        const std::string text(buf.begin(), end);
        buf.erase(buf.begin(), end + 1);
        Num number;
        if (!parse_int(text, 10, number)) bad_int(text, true);
        return number;
    };
    const Num fields = line(false);
    std::vector<Num> numbers;
    while (Num::of(numbers.size()) < fields + fields) {
        if (numbers.size() >= 2 * options_.hard_entries) throw PyError{"HardCeiling", "too many sparse map entries"};
        numbers.push_back(line(true));
    }
    next.offset_data = here();
    next.sparse.clear();
    for (std::size_t i = 0; i + 1 < numbers.size(); i += 2) add_sparse(next, numbers[i], numbers[i + 1]);
    next.has_sparse = true;
}

// ExFileObject.read(max) = one _FileInFile.read (608-710): the member's bytes, the holes
// of a sparse member as zero bytes.
Buffer read_member(PyFile& file, const Info& member, const Options& options, Meter meter) {
    struct Piece {
        bool data;
        Num start, stop, real;
    };
    std::vector<Piece> map;
    Num last = 0, real = member.offset_data;
    const std::vector<std::pair<Num, Num>> whole = {{Num(0), member.size}};
    for (const auto& [start, count] : member.has_sparse ? member.sparse : whole) {
        if (start > last) map.push_back({false, last, start, Num(0)});
        map.push_back({true, start, start + count, real});
        real = real + count;
        last = start + count;
    }
    if (last < member.size) map.push_back({false, last, member.size, Num(0)});
    Buffer out;
    Num position = 0;
    Num size = std::min(Num(options.max_member_bytes), member.size);
    std::size_t index = 0;
    while (size > Num(0)) {
        for (std::size_t tried = 0; !(map[index].start <= position && position < map[index].stop); ++tried) {
            // Python searches the map for ever when no piece holds the position (quirk Q-22).
            if (tried > map.size()) throw PyError{"HardCeiling", "sparse map does not cover the member"};
            index = index + 1 == map.size() ? 0 : index + 1;
        }
        const Piece& piece = map[index];
        const Num length = std::min(size, piece.stop - position);
        const std::size_t count = static_cast<std::size_t>(length.lo);
        if (piece.data) {
            file.seek(piece.real + (position - piece.start));
            Buffer got = file.read(count);
            if (got.size() != count) throw PyError{"ReadError", "unexpected end of data"};
            if (out.empty()) {
                out = std::move(got);
            } else {
                append(out, got);
            }
        } else {
            out.insert(out.end(), count, std::uint8_t{0});
        }
        meter.charge(count);
        size = size - length;
        position = position + length;
    }
    return out;
}

struct Opened {
    std::unique_ptr<PyFile> file;
    std::unique_ptr<Tar> tar;
    std::optional<Info> first;  // TarFile.firstmember
};

// TarFile.open(path) (1843-1900): gzip, bzip2, xz, then the file as it is. gzopen turns an
// OSError into ReadError, bz2open an OSError or EOFError, xzopen an LZMAError or EOFError
// (1947-2034); a ReadError means "try the next"; anything else gets out.
std::optional<Opened> open_tar(Bytes file, const Options& options, Meter meter) {
    for (const Codec codec : {Codec::Gzip, Codec::Bzip2, Codec::Xz, Codec::Plain}) {
        Opened opened;
        opened.file = open_file(codec, file, meter);
        opened.tar = std::make_unique<Tar>(*opened.file, options);
        try {
            opened.first = opened.tar->next();
        } catch (const PyError& error) {
            const bool ended = error.type == "EOFError";
            if (error.type == "ReadError" || (codec == Codec::Gzip && is_os_error(error)) ||
                (codec == Codec::Bzip2 && (is_os_error(error) || ended)) ||
                (codec == Codec::Xz && (error.type == "LZMAError" || ended))) {
                continue;
            }
            throw;
        }
        // Shipped-profile option: a leading block of zero bytes does not make a tar.
        if (!options.tar_leading_zero_block_is_tar && opened.tar->zero_block_first()) continue;
        return opened;
    }
    return std::nullopt;
}

bool all_zero(const Buffer& data) {
    return std::all_of(data.begin(), data.end(), [](std::uint8_t b) { return b == 0; });
}

}  // namespace

bool is_tar(Bytes file, const Options& options) {
    Budget budget;
    return open_tar(file, options, Meter{&budget, &options}).has_value();
}

// core.py:686-748 _extract_tar.
void extract_tar(Bytes file, Sink& sink) {
    const Options& options = sink.options;
    std::optional<Opened> opened = open_tar(file, options, sink.meter);
    if (!opened) throw PyError{"ReadError", "file could not be opened successfully"};
    Tar& tar = *opened->tar;
    PyFile& stream = *opened->file;
    std::int64_t overhead = 0;
    bool stopped = false;
    for (bool first = true;; first = false) {
        std::optional<Info> member;
        try {
            member = first ? std::move(opened->first) : tar.next();
        } catch (const PyError& error) {
            sink.reasons.push_back("tar header unreadable (" + error.type + ")");
            stopped = true;
            break;
        }
        if (!member) break;
        const Num extra = member->offset_data - member->offset - Num(512);  // pax / GNU headers before the member
        if (extra > Num(0)) overhead += static_cast<std::int64_t>(extra.lo);
        if (member->is_dir()) continue;
        if (!member->is_reg()) {
            sink.reasons.push_back("non-regular member: " + member->name);
            continue;
        }
        if (member->size > Num(options.max_member_bytes)) {
            sink.reasons.push_back("member over size limit: " + member->name);
            continue;
        }
        const std::optional<std::string> out = sink.disk.target(member->name);  // a NUL in the name ends everything
        if (!out) {
            sink.reasons.push_back("unsafe member path: " + member->name);
            continue;
        }
        if (!sink.take(member->size)) {
            sink.reasons.emplace_back("member/byte budget exhausted");
            stopped = true;
            break;
        }
        try {
            sink.disk.makedirs_parent(*out);
            const std::shared_ptr<Buffer> written = sink.disk.open_for_write(*out);
            Buffer data = read_member(stream, *member, options, sink.meter);
            sink.store(member->name, *out, written, std::move(data));
            const std::uint64_t pad = (512 - (member->size.lo & 511)) & 511;  // (-size) % 512
            if (pad != 0) {
                stream.seek(member->offset_data + member->size);
                const Buffer padding = stream.read(pad);
                if (padding.size() != pad || !all_zero(padding)) {
                    sink.reasons.push_back("non-zero padding after member " + member->name);
                }
            }
        } catch (const PyError& error) {
            sink.reasons.push_back("member extraction failed: " + member->name + " (" + error.type + ")");
        }
    }
    if (!options.tar_bad_header_ends_silently && tar.bad_header()) {
        const Num where = *tar.bad_header();
        sink.reasons.push_back("invalid tar header at offset " + (where.fits_offset() ? std::to_string(where.lo) : "beyond the file"));
    }
    if (overhead > options.max_uncovered_tar_header_bytes) {
        sink.reasons.push_back(std::to_string(overhead) + " bytes of extended (pax/GNU) headers not covered");
    }
    if (!stopped) {  // only zero bytes may follow the last member
        try {
            stream.seek(tar.offset());
            const Buffer rest = stream.read(static_cast<std::uint64_t>(options.max_tar_padding) + 1);
            if (rest.size() > static_cast<std::uint64_t>(options.max_tar_padding) || !all_zero(rest)) {
                sink.reasons.emplace_back("data after the last tar member");
            }
        } catch (const PyError& error) {
            sink.reasons.push_back("tar end not readable (" + error.type + ")");
        }
    }
}

}  // namespace mie::archive::detail
