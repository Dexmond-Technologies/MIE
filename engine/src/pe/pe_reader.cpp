// See include/mie/pe.hpp and PE_READER_SPEC.md. Line numbers in comments ("pefile:NNNN")
// refer to pefile.py of pefile 2024.8.26; "ref:NNN" to dexmond_mie/pe_analyzer.py at ff313e2.
#include "mie/pe.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>

namespace mie::pe {

namespace {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i64 = std::int64_t;

constexpr u64 kNoEnd = ~0ull;

u64 sat_add(u64 a, u64 b) { return a > ~0ull - b ? ~0ull : a + b; }

struct Sec {
    Section out;
    bool has_next = false;  // pefile: next_section_virtual_address is not None
    u32 next_va = 0;
    bool cached = false;    // pefile caches section_min_addr / section_max_addr
    i64 lo = 0;
    i64 hi = 0;
};

struct Thunk {
    u64 address = 0;
};

// pefile's AddressSet: a set that also tracks its smallest and largest member.
struct AddressSet {
    std::set<u64> members;
    u64 diff() const { return members.empty() ? 0 : *members.rbegin() - *members.begin(); }
};

// pefile's ordinal-name tables for three DLLs, copied as data (reviewer's ruling, board
// B-3620: reporting the bare ordinal instead was not accepted as a difference).
struct OrdinalName {
    u16 ordinal;
    const char* name;
};
#include "pe_ordinal_names.inc"

// pefile:5772-5778 and 5942-5948 with ordlookup.ordLookup: an import by ordinal (name None) of
// oleaut32.dll, ws2_32.dll or wsock32.dll (the DLL name lower-cased, ASCII) gets the table's
// name, or "ord<N>" when the ordinal is not in the table. Other DLLs keep no name.
void name_ordinal_imports(ImportLibrary& library) {
    std::string dll = library.dll;
    for (char& ch : dll) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    std::span<const OrdinalName> table;
    if (dll == "oleaut32.dll") {
        table = kOrdinalNamesOleaut32;
    } else if (dll == "ws2_32.dll") {
        table = kOrdinalNamesWs2_32;
    } else if (dll == "wsock32.dll") {
        table = kOrdinalNamesWsock32;
    } else {
        return;
    }
    for (ImportSymbol& symbol : library.symbols) {
        if (!symbol.name.empty()) continue;
        const auto found = std::lower_bound(table.begin(), table.end(), symbol.ordinal,
                                            [](const OrdinalName& entry, u32 ordinal) { return entry.ordinal < ordinal; });
        symbol.name = (found != table.end() && found->ordinal == symbol.ordinal)
                          ? std::string(found->name)
                          : "ord" + std::to_string(symbol.ordinal);
    }
}

struct ResNode {
    bool is_dir = false;
    u32 rva = 0;
    u32 size = 0;
    std::vector<int> children;
};

std::string hex4(u32 value) {
    char buffer[16];
    std::snprintf(buffer, sizeof buffer, "%04x", static_cast<unsigned>(value & 0xFFFFu));
    return buffer;
}

// bytes.decode('utf-8', errors='ignore'): well-formed sequences are kept; an ill-formed
// sequence is dropped up to (not including) the byte where it stops being a valid prefix.
std::string utf8_ignore(const u8* bytes, std::size_t size) {
    std::string out;
    std::size_t i = 0;
    while (i < size) {
        const u8 c = bytes[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        std::size_t need = 0;
        u8 lo = 0x80;
        u8 hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) {
            need = 1;
        } else if (c >= 0xE0 && c <= 0xEF) {
            need = 2;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            need = 3;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
        } else {
            ++i;  // not a lead byte: dropped
            continue;
        }
        std::size_t good = 1;
        while (good <= need && i + good < size) {
            const u8 next = bytes[i + good];
            const u8 low = good == 1 ? lo : 0x80;
            const u8 high = good == 1 ? hi : 0xBF;
            if (next < low || next > high) {
                break;
            }
            ++good;
        }
        if (good == need + 1) {
            out.append(reinterpret_cast<const char*>(bytes + i), need + 1);
        }
        i += good;  // complete: consumed; incomplete: the valid prefix is dropped
    }
    return out;
}

// pefile:2316 is_valid_function_name (not relaxed).
bool valid_function_name(const std::string& s) {
    for (const char ch : s) {
        const bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
        if (!alnum && std::string_view("._?@$()<>").find(ch) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

// pefile:2296 is_valid_dos_filename.
bool valid_dos_filename(const std::string& s) {
    for (const char ch : s) {
        const bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
        if (!alnum && std::string_view("!#$%&'()-@^_`{}~+,.;=[]:\\/").find(ch) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

class Reader {
public:
    explicit Reader(std::span<const u8> data) : d_(data), len_(data.size()) {}

    Image run() {
        Image image;
        std::string error;
        if (!headers(image, error)) {
            image = Image{};
            image.error = error;
            return image;
        }
        image.parsed = true;
        directories(image);
        for (const Sec& s : secs_) {
            image.sections.push_back(s.out);
        }
        certificates(image);
        return image;
    }

private:
    // ---- the one bounds-checked view of the buffer -------------------------------------
    bool in(u64 offset, u64 size) const { return offset <= len_ && size <= len_ - offset; }
    bool rd8(u64 offset, u8& out) const {
        if (!in(offset, 1)) return false;
        out = d_[static_cast<std::size_t>(offset)];
        return true;
    }
    bool rd16(u64 offset, u16& out) const {
        if (!in(offset, 2)) return false;
        out = static_cast<u16>(byte(offset) | (byte(offset + 1) << 8));
        return true;
    }
    bool rd32(u64 offset, u32& out) const {
        if (!in(offset, 4)) return false;
        out = byte(offset) | (byte(offset + 1) << 8) | (byte(offset + 2) << 16) | (byte(offset + 3) << 24);
        return true;
    }
    bool rd64(u64 offset, u64& out) const {
        u32 low = 0;
        u32 high = 0;
        if (!rd32(offset, low) || !rd32(offset + 4, high)) return false;
        out = (static_cast<u64>(high) << 32) | low;
        return true;
    }
    u32 byte(u64 offset) const { return d_[static_cast<std::size_t>(offset)]; }  // callers checked `in`
    // Like rd32 on a buffer padded with zeros (pefile pads short headers with zeros).
    u32 rd32_padded(u64 offset) const {
        u32 value = 0;
        for (u64 i = 0; i < 4; ++i) {
            u8 b = 0;
            if (offset <= ~0ull - i && rd8(offset + i, b)) value |= static_cast<u32>(b) << (8 * i);
        }
        return value;
    }
    u16 rd16_padded(u64 offset) const { return static_cast<u16>(rd32_padded(offset) & 0xFFFFu); }
    // Python's data[a:b] for non-negative a: clipped to the buffer, empty when b <= a.
    Range slice(u64 a, u64 b) const {
        const u64 lo = std::min(a, len_);
        const u64 hi = std::max(lo, std::min(b, len_));
        return Range{lo, hi};
    }
    static u64 width(const Range& r) { return r.end - r.begin; }

    // ---- pefile's address arithmetic ----------------------------------------------------
    static u64 adjust_pointer(u32 value) { return value & ~0x1FFu; }  // pefile:7974
    u64 adjust_va(u32 value) const {                                   // pefile:68, 7995
        u32 alignment = section_alignment_;
        if (alignment < 0x1000) alignment = file_alignment_;
        if (alignment != 0 && value % alignment != 0) return static_cast<u64>(alignment) * (value / alignment);
        return value;
    }
    u64 pointer_adj(const Sec& s) const {  // pefile:1157
        u64 p = adjust_pointer(s.out.raw_pointer);
        if (section_alignment_ < 0x1000 && s.out.raw_pointer == s.out.virtual_address) p = s.out.virtual_address;
        return p;
    }
    bool contains(Sec& s, u64 rva) const {  // pefile:1257 contains_rva
        if (!s.cached) {
            const i64 va = static_cast<i64>(adjust_va(s.out.virtual_address));
            i64 size = 0;
            if (static_cast<i64>(len_) - static_cast<i64>(pointer_adj(s)) < static_cast<i64>(s.out.raw_size)) {
                size = s.out.virtual_size;
            } else {
                size = std::max(s.out.raw_size, s.out.virtual_size);
            }
            if (s.has_next && s.next_va > s.out.virtual_address && va + size > static_cast<i64>(s.next_va)) {
                size = static_cast<i64>(s.next_va) - va;
            }
            s.lo = va;
            s.hi = va + size;
            s.cached = true;
        }
        if (rva > static_cast<u64>(INT64_MAX)) return false;
        const i64 r = static_cast<i64>(rva);
        return s.lo <= r && r < s.hi;
    }
    int section_by_rva(u64 rva) {  // pefile:6528, with its "last used" shortcut
        if (last_used_ >= 0 && contains(secs_[static_cast<std::size_t>(last_used_)], rva)) return last_used_;
        for (std::size_t i = 0; i < secs_.size(); ++i) {
            if (contains(secs_[i], rva)) {
                last_used_ = static_cast<int>(i);
                return last_used_;
            }
        }
        return -1;
    }
    // pefile:1180 SectionStructure.get_data(start, length); start/length optional.
    Range section_data(const Sec& s, bool has_start, u64 start, bool has_length, u64 length) const {
        i64 offset = static_cast<i64>(pointer_adj(s));
        if (has_start) offset += static_cast<i64>(start) - static_cast<i64>(adjust_va(s.out.virtual_address));
        i64 end = offset + static_cast<i64>(has_length ? std::min<u64>(length, 1ull << 40) : s.out.raw_size);
        const i64 limit = static_cast<i64>(s.out.raw_pointer) + static_cast<i64>(s.out.raw_size);
        if (end > limit) end = limit;
        if (offset < 0) offset = 0;  // cannot happen for an address inside the section; kept safe
        if (end < 0) end = 0;
        return slice(static_cast<u64>(offset), static_cast<u64>(end));
    }
    // pefile:6363 PE.get_data(rva, length). nullopt = pefile raises PEFormatError.
    std::optional<Range> get_data(u64 rva, bool has_length, u64 length) {
        const int s = section_by_rva(rva);
        if (s >= 0) return section_data(secs_[static_cast<std::size_t>(s)], true, rva, has_length, length);
        const u64 end = has_length ? sat_add(rva, length) : kNoEnd;
        if (rva < header_len_) return slice(rva, std::min(end, header_len_));
        if (rva < len_) return slice(rva, end);
        return std::nullopt;
    }
    std::optional<u64> offset_from_rva(u64 rva) {  // pefile:6428
        const int s = section_by_rva(rva);
        if (s < 0) return rva < len_ ? std::optional<u64>(rva) : std::nullopt;
        const Sec& sec = secs_[static_cast<std::size_t>(s)];
        const i64 offset = static_cast<i64>(rva) - static_cast<i64>(adjust_va(sec.out.virtual_address)) +
                           static_cast<i64>(pointer_adj(sec));
        return offset < 0 ? 0 : static_cast<u64>(offset);
    }
    std::string string_at(u64 rva, u64 max_length) {  // pefile:6448 get_string_at_rva
        const int s = section_by_rva(rva);
        const Range r = s < 0 ? slice(rva, sat_add(rva, max_length))
                              : section_data(secs_[static_cast<std::size_t>(s)], true, rva, true, max_length);
        std::string out;
        for (u64 i = r.begin; i < r.end; ++i) {
            const char ch = static_cast<char>(byte(i));
            if (ch == '\0') break;
            out.push_back(ch);
        }
        return out;
    }

    // ---- headers and section table (pefile:3013 __parse__, 3547 parse_sections) ---------
    bool headers(Image& image, std::string& error) {
        if (len_ == 0) return fail(error, "The file is empty");
        if (len_ < 64) return fail(error, "Unable to read the DOS Header, possibly a truncated file.");
        u16 e_magic = 0;
        u32 e_lfanew = 0;
        rd16(0, e_magic);
        rd32(0x3C, e_lfanew);
        if (e_magic == 0x4D5A) return fail(error, "Probably a ZM Executable (not a PE file).");
        if (e_magic != 0x5A4D) return fail(error, "DOS Header magic not found.");
        if (e_lfanew > len_) return fail(error, "Invalid e_lfanew value, probably not a PE file");
        const u64 nt = e_lfanew;
        u32 signature = 0;
        if (!rd32(nt, signature) || signature == 0) return fail(error, "NT Headers not found.");
        const u32 low = signature & 0xFFFFu;
        if (low == 0x454E) return fail(error, "Invalid NT Headers signature. Probably a NE file");
        if (low == 0x454C) return fail(error, "Invalid NT Headers signature. Probably a LE file");
        if (low == 0x584C) return fail(error, "Invalid NT Headers signature. Probably a LX file");
        if (low == 0x5A56) return fail(error, "Invalid NT Headers signature. Probably a TE file");
        if (signature != 0x00004550) return fail(error, "Invalid NT Headers signature.");
        if (!in(nt + 4, 20)) return fail(error, "File Header missing");
        u16 number_of_sections = 0;
        u16 size_of_optional = 0;
        rd16(nt + 4, image.machine);
        rd16(nt + 6, number_of_sections);
        rd32(nt + 8, image.timestamp);
        rd16(nt + 20, size_of_optional);
        rd16(nt + 22, image.characteristics);
        machine_ = image.machine;

        const u64 opt = nt + 24;
        const u64 sections_offset = opt + size_of_optional;
        const u64 available = opt >= len_ ? 0 : std::min<u64>(len_ - opt, 0x200);
        // pefile reads the optional header, and if it is cut short but at least 69 bytes
        // (73 for PE32+) are there, reads it again padded with zeros (pefile:3148-3215).
        if (available < 69) return fail(error, "No Optional Header found, invalid PE32 or PE32+ file.");
        image.magic = rd16_padded(opt);
        image.pe32_plus = image.magic == 0x20B;
        if (image.pe32_plus && available < 73) {
            return fail(error, "No Optional Header found, invalid PE32 or PE32+ file.");
        }
        plus_ = image.pe32_plus;
        const u64 opt_size = plus_ ? 112 : 96;
        image.entry_point = rd32_padded(opt + 16);
        if (plus_) {
            image.image_base = (static_cast<u64>(rd32_padded(opt + 28)) << 32) | rd32_padded(opt + 24);
        } else {
            image.image_base = rd32_padded(opt + 28);
        }
        image.section_alignment = rd32_padded(opt + 32);
        image.file_alignment = rd32_padded(opt + 36);
        image.size_of_image = rd32_padded(opt + 56);
        image.size_of_headers = rd32_padded(opt + 60);
        const u32 number_of_rva = rd32_padded(opt + (plus_ ? 108 : 92)) & 0x7FFFFFFFu;
        section_alignment_ = image.section_alignment;
        file_alignment_ = image.file_alignment;
        image_base_ = image.image_base;
        size_of_image_ = image.size_of_image;

        // Data directories (pefile:3269-3311): at most 16; a short tail is padded with zeros.
        u64 offset = opt + opt_size;
        for (u32 i = 0; i < number_of_rva; ++i) {
            if (offset == len_) break;
            if (i >= 16) break;
            DataDirectory entry;
            entry.virtual_address = rd32_padded(offset);
            entry.size = rd32_padded(offset + 4);
            offset += 8;
            image.directories.push_back(entry);
            if (offset >= opt + opt_size + 8 * 16) break;
        }

        // Section table.
        for (u32 i = 0; i < number_of_sections; ++i) {
            if (i >= kMaxSections) break;
            const u64 at = sections_offset + 40ull * i;
            if (at >= len_) break;  // no data at all: pefile stops
            if (!in(at, 40)) return fail(error, "Data length less than expected header length.");
            bool all_zero = true;
            for (u64 k = 0; k < 40; ++k) all_zero = all_zero && byte(at + k) == 0;
            if (all_zero) break;
            Sec s;
            for (std::size_t k = 0; k < 8; ++k) s.out.raw_name[k] = static_cast<u8>(byte(at + k));
            rd32(at + 8, s.out.virtual_size);
            rd32(at + 12, s.out.virtual_address);
            rd32(at + 16, s.out.raw_size);
            rd32(at + 20, s.out.raw_pointer);
            rd32(at + 36, s.out.characteristics);
            int errors = 0;
            if (static_cast<u64>(s.out.raw_size) + s.out.raw_pointer > len_) ++errors;
            if (adjust_pointer(s.out.raw_pointer) > len_) ++errors;
            if (s.out.virtual_size > 0x10000000u) ++errors;
            if (adjust_va(s.out.virtual_address) > 0x10000000u) ++errors;
            if (file_alignment_ != 0 && s.out.raw_pointer % file_alignment_ != 0) ++errors;
            if (errors >= 3) break;
            std::size_t n = 8;  // name: decoded, then NULs stripped at both ends (ref:529)
            std::string name = utf8_ignore(s.out.raw_name.data(), n);
            const std::size_t first = name.find_first_not_of('\0');
            const std::size_t last = name.find_last_not_of('\0');
            s.out.name = first == std::string::npos ? std::string() : name.substr(first, last - first + 1);
            secs_.push_back(std::move(s));
        }
        std::stable_sort(secs_.begin(), secs_.end(), [](const Sec& a, const Sec& b) {
            return a.out.virtual_address < b.out.virtual_address;
        });
        for (std::size_t i = 0; i + 1 < secs_.size(); ++i) {
            secs_[i].has_next = true;
            secs_[i].next_va = secs_[i + 1].out.virtual_address;
        }
        for (Sec& s : secs_) {
            s.out.data = section_data(s, false, 0, false, 0);
        }

        // pefile's "header": the bytes before the first section's data (pefile:3313-3335).
        const u64 after = (number_of_sections > 0 && !secs_.empty()) ? sections_offset + 40ull * number_of_sections
                                                                     : sections_offset;
        u64 lowest = 0;
        for (const Sec& s : secs_) {
            if (s.out.raw_pointer > 0) {
                const u64 p = adjust_pointer(s.out.raw_pointer);
                lowest = (lowest == 0 || p < lowest) ? p : lowest;
            }
        }
        // (a lowest pointer that adjusts to 0 counts as "none", as pefile's "not lowest")
        bool any_zero = false;
        for (const Sec& s : secs_) any_zero = any_zero || (s.out.raw_pointer > 0 && adjust_pointer(s.out.raw_pointer) == 0);
        if (any_zero) lowest = 0;
        header_len_ = std::min((lowest == 0 || lowest < after) ? after : lowest, len_);

        section_by_rva(image.entry_point);  // pefile looks the entry point up here (pefile:3340)
        return true;
    }
    static bool fail(std::string& error, const char* why) {
        error = why;
        return false;
    }

    // ---- data directories, in pefile's order (pefile:3719-3774) --------------------------
    void directories(Image& image) {
        static constexpr int order[] = {1, 0, 2, 6, 5, 9, 10, 13, 11, 3};
        for (const int index : order) {
            if (static_cast<std::size_t>(index) >= image.directories.size()) break;  // IndexError: pefile stops
            const DataDirectory& entry = image.directories[static_cast<std::size_t>(index)];
            if (entry.virtual_address == 0) continue;
            if (index == 1) {
                image.imports = import_directory(entry.virtual_address);
                image.has_imports = !image.imports.empty();
            } else if (index == 2) {
                resources(image, entry.virtual_address);
            } else if (index == 9) {
                tls(image, entry.virtual_address);
            } else if (index == 13) {
                image.delay_imports = delay_import_directory(entry.virtual_address);
                image.has_delay_imports = !image.delay_imports.empty();
            }
        }
    }

    // ---- imports (pefile:5872, 5978, 6136; delay imports 5675) ----------------------------
    u64 normalize_va(u64 va) const {  // pefile:5664
        const u64 end = sat_add(image_base_, size_of_image_);
        return (image_base_ <= va && va < end) ? va - image_base_ : va;
    }
    std::vector<Thunk> import_table(u64 rva, i64 max_length, bool contains_addresses) {
        std::vector<Thunk> table;
        const u64 entry_size = plus_ ? 8 : 4;
        const u64 ordinal_flag = plus_ ? (1ull << 63) : 0x80000000ull;
        AddressSet set32;
        AddressSet set64;
        u32 repeated = 0;
        const u64 start = rva;
        while (rva != 0) {
            if (max_length <= 0 || rva - start >= static_cast<u64>(max_length)) break;
            if (total_import_symbols_ > kMaxImportSymbols) break;
            ++total_import_symbols_;
            if (repeated >= 15) return {};
            if (set32.diff() > 128ull * 1024 * 1024 || set64.diff() > 128ull * 1024 * 1024) return {};
            const std::optional<Range> r = get_data(rva, true, entry_size);
            if (!r || width(*r) != entry_size) return {};
            u64 value = 0;
            if (plus_) {
                rd64(r->begin, value);
            } else {
                u32 v32 = 0;
                rd32(r->begin, v32);
                value = v32;
            }
            const bool raw_zero = value == 0;
            offset_from_rva(rva);  // pefile computes the file offset here (same lookup, pefile:6205)
            if (contains_addresses) value = normalize_va(value);
            if (value >= start && value <= rva) break;
            if (value != 0) {
                if ((value & ordinal_flag) != 0) {
                    if ((value & 0x7FFFFFFFull) > 0xFFFF) return {};
                } else {
                    AddressSet& set = value >= (1ull << 32) ? set64 : set32;
                    if (set.members.count(value) != 0) ++repeated;
                    set.members.insert(value);
                }
            }
            if (raw_zero) break;
            rva += entry_size;
            table.push_back(Thunk{value});
        }
        return table;
    }
    // Returns false where pefile raises PEFormatError (the caller then has no symbols).
    bool parse_imports(u64 original_first_thunk, u64 first_thunk, i64 max_length, bool contains_addresses,
                       std::vector<ImportSymbol>& out) {
        const std::vector<Thunk> ilt = import_table(original_first_thunk, max_length, contains_addresses);
        const std::vector<Thunk> iat = import_table(first_thunk, max_length, contains_addresses);
        if (ilt.empty() && iat.empty()) return true;
        const std::vector<Thunk>& table = !ilt.empty() ? ilt : iat;
        const u64 ordinal_flag = plus_ ? (1ull << 63) : 0x80000000ull;
        const u64 address_mask = plus_ ? 0x7FFFFFFFFFFFFFFFull : 0x7FFFFFFFull;
        u64 invalid = 0;
        for (std::size_t idx = 0; idx < table.size(); ++idx) {
            const u64 address = table[idx].address;
            ImportSymbol symbol;
            bool has_ordinal = false;
            bool has_name = false;
            if (address != 0) {
                if ((address & ordinal_flag) != 0) {
                    symbol.by_ordinal = true;
                    has_ordinal = true;
                    symbol.ordinal = static_cast<u32>(address & 0xFFFF);
                } else if (get_data(address & address_mask, true, 2)) {
                    symbol.name = string_at(sat_add(address, 2), kMaxImportNameLength);
                    has_name = true;
                    if (!valid_function_name(symbol.name)) symbol.name = "*invalid*";
                    if (const std::optional<u64> offset = offset_from_rva(sat_add(address, 2))) {
                        symbol.has_name_offset = true;
                        symbol.name_offset = *offset;
                    }
                }
            }
            if (!has_ordinal && !has_name) return false;  // "Invalid entries, aborting parsing."
            if (has_name && symbol.name == "*invalid*") {
                if (invalid > 1000 && invalid == idx) return false;
                ++invalid;
                continue;
            }
            if ((has_ordinal && symbol.ordinal != 0) || (has_name && !symbol.name.empty())) {
                out.push_back(std::move(symbol));
            }
        }
        return true;
    }
    std::vector<ImportLibrary> import_directory(u64 rva) {
        std::vector<ImportLibrary> libraries;
        int error_count = 0;
        for (u32 guard = 0; guard < 0x10000; ++guard) {
            const std::optional<Range> r = get_data(rva, true, 20);
            if (!r) break;
            const std::optional<u64> file_offset = offset_from_rva(rva);
            if (!file_offset) return {};  // pefile raises here: the whole directory is dropped
            if (width(*r) < 20) break;
            u32 oft = 0, name_rva = 0, ft = 0;
            bool all_zero = true;
            for (u64 k = 0; k < 20; ++k) all_zero = all_zero && byte(r->begin + k) == 0;
            if (all_zero) break;
            rd32(r->begin, oft);
            rd32(r->begin + 12, name_rva);
            rd32(r->begin + 16, ft);
            rva += 20;
            i64 max_length = static_cast<i64>(len_) - static_cast<i64>(*file_offset);
            if (rva > oft || rva > ft) {
                max_length = std::max(static_cast<i64>(rva) - static_cast<i64>(oft),
                                      static_cast<i64>(rva) - static_cast<i64>(ft));
            }
            ImportLibrary library;
            if (!parse_imports(oft, ft, max_length, false, library.symbols)) library.symbols.clear();
            if (error_count > 5) break;
            if (library.symbols.empty()) {
                ++error_count;
                continue;
            }
            library.dll = string_at(name_rva, kMaxDllLength);
            if (!valid_dos_filename(library.dll)) library.dll = "*invalid*";
            if (!library.dll.empty()) {
                name_ordinal_imports(library);
                libraries.push_back(std::move(library));
            }
        }
        return libraries;
    }
    std::vector<ImportLibrary> delay_import_directory(u64 rva) {
        std::vector<ImportLibrary> libraries;
        int error_count = 0;
        for (u32 guard = 0; guard < 0x10000; ++guard) {
            const std::optional<Range> r = get_data(rva, true, 32);
            if (!r) break;
            const std::optional<u64> file_offset = offset_from_rva(rva);
            if (!file_offset) return {};
            if (width(*r) < 32) break;
            bool all_zero = true;
            for (u64 k = 0; k < 32; ++k) all_zero = all_zero && byte(r->begin + k) == 0;
            if (all_zero) break;
            u32 attributes = 0, name32 = 0, iat32 = 0, int32 = 0;
            rd32(r->begin, attributes);
            rd32(r->begin + 4, name32);
            rd32(r->begin + 12, iat32);
            rd32(r->begin + 16, int32);
            u64 name_rva = name32, iat = iat32, names = int32;
            bool contains_addresses = false;
            if (attributes == 0 && machine_ == 0x14C) {  // old format: virtual addresses, not RVAs
                name_rva = normalize_va(name_rva);
                iat = normalize_va(iat);
                names = normalize_va(names);
                contains_addresses = true;
            }
            rva += 32;
            i64 max_length = static_cast<i64>(len_) - static_cast<i64>(*file_offset);
            if (rva > names || rva > iat) {
                max_length = std::max(static_cast<i64>(rva) - static_cast<i64>(names),
                                      static_cast<i64>(rva) - static_cast<i64>(iat));
            }
            ImportLibrary library;
            if (!parse_imports(names, iat, max_length, contains_addresses, library.symbols)) library.symbols.clear();
            if (error_count > 5) break;
            if (library.symbols.empty()) {
                ++error_count;
                continue;
            }
            if (total_import_symbols_ > kMaxImportSymbols) break;
            library.dll = string_at(name_rva, kMaxDllLength);
            if (!valid_dos_filename(library.dll)) library.dll = "*invalid*";
            if (!library.dll.empty()) {
                name_ordinal_imports(library);
                libraries.push_back(std::move(library));
            }
        }
        return libraries;
    }

    // ---- TLS (pefile:3992; ref:433 has_tls_callbacks) --------------------------------------
    void tls(Image& image, u64 rva) {
        const u64 size = plus_ ? 40 : 24;
        const std::optional<Range> r = get_data(rva, true, size);
        if (!r || !offset_from_rva(rva) || width(*r) < size) return;
        image.tls.present = true;
        if (plus_) {
            rd64(r->begin + 24, image.tls.address_of_callbacks);
        } else {
            u32 v = 0;
            rd32(r->begin + 12, v);
            image.tls.address_of_callbacks = v;
        }
    }
    // The reference reads the first slot of the callback array at (address - image base),
    // through pefile's get_dword_at_rva / get_qword_at_rva. Called after all directories,
    // as the reference does (analyze() runs after pefile has finished).
    void tls_first_callback(Image& image) {
        Tls& t = image.tls;
        if (!t.present || t.address_of_callbacks == 0) return;
        const u64 want = plus_ ? 8 : 4;
        Range r{0, 0};
        if (t.address_of_callbacks >= image_base_) {
            const u64 rva = t.address_of_callbacks - image_base_;
            const std::optional<Range> got = get_data(rva, !plus_, 4);
            if (!got) return;
            r = *got;
        } else {
            // A negative RVA: Python indexes pefile's header bytes from their end.
            const u64 back = image_base_ - t.address_of_callbacks;
            const u64 begin = back >= header_len_ ? 0 : header_len_ - back;
            u64 end = header_len_;
            if (!plus_) {
                if (back <= 4) {
                    end = back == 4 ? 0 : std::min<u64>(4 - back, header_len_);
                } else {
                    end = back - 4 >= header_len_ ? 0 : header_len_ - (back - 4);
                }
            }
            r = Range{begin, std::max(begin, end)};
        }
        if (width(r) < want) return;
        t.first_readable = true;
        if (plus_) {
            rd64(r.begin, t.first_callback);
        } else {
            u32 v = 0;
            rd32(r.begin, v);
            t.first_callback = v;
        }
        t.has_callbacks = t.first_callback != 0;
    }

    // ---- resources (pefile:4609; ref:309 get_resource_data_ranges) --------------------------
    int resource_directory(u64 rva, u64 base, u32 level, const std::vector<u64>& path) {
        if (level > kMaxResourceDepth) return -1;
        const std::optional<Range> r = get_data(rva, true, 16);
        if (!r) return -1;
        offset_from_rva(rva);
        if (width(*r) < 16) return -1;
        u16 named = 0, ids = 0;
        rd16(r->begin + 12, named);
        rd16(r->begin + 14, ids);
        const u32 count = static_cast<u32>(named) + ids;
        if (count > 4096) return -1;
        total_resource_entries_ += count;
        if (total_resource_entries_ > kMaxResourceEntries) return -1;
        const int self = static_cast<int>(nodes_.size());
        nodes_.push_back(ResNode{});
        nodes_[static_cast<std::size_t>(self)].is_dir = true;
        rva += 16;
        // pefile:4741-4775: a named entry's string (a 16-bit length, then UTF-16 text) is looked
        // at as well. When the previous name starts before this one and its end (start + its
        // length word) reaches this one's start, pefile takes the directory for corrupt, drops
        // the previous name and stops the directory before this entry.
        std::vector<std::pair<u64, u64>> names;   // (start, length word) of the names kept
        bool have_last = false;
        u64 last_begin = 0, last_end = 0;
        bool overlap = false;
        for (u32 i = 0; i < count; ++i) {
            const std::optional<Range> e = get_data(rva, true, 8);
            if (!e) break;
            offset_from_rva(rva);
            if (width(*e) < 8) break;
            u32 name_field = 0, offset_to_data = 0;
            rd32(e->begin, name_field);
            rd32(e->begin + 4, offset_to_data);
            if ((name_field & 0x80000000u) != 0) {
                const u64 at = base + (name_field & 0x7FFFFFFFu);
                u16 length = 0;                    // pefile:783-795: unreadable counts as 0
                if (const std::optional<Range> w = get_data(at, true, 2); w && width(*w) >= 2) rd16(w->begin, length);
                if (have_last && last_begin < at && last_end >= at) {
                    if (!names.empty()) names.pop_back();
                    overlap = true;
                    break;
                }
                have_last = true;
                last_begin = at;
                last_end = at + length;
                names.emplace_back(at, length);
            }
            const u64 target = base + (offset_to_data & 0x7FFFFFFFu);
            int child = -1;
            if ((offset_to_data & 0x80000000u) != 0) {
                if (std::find(path.begin(), path.end(), target) != path.end()) break;  // a loop
                std::vector<u64> deeper(path);
                deeper.push_back(target);
                child = resource_directory(target, base, level + 1, deeper);
                if (child < 0) break;
            } else {
                const std::optional<Range> data = get_data(target, true, 16);
                if (!data) break;
                offset_from_rva(target);
                if (width(*data) < 16) break;
                child = static_cast<int>(nodes_.size());
                ResNode leaf;
                rd32(data->begin, leaf.rva);
                rd32(data->begin + 4, leaf.size);
                nodes_.push_back(leaf);
            }
            nodes_[static_cast<std::size_t>(self)].children.push_back(child);
            rva += 8;
        }
        // pefile:4902-4906 then reads every kept name (render_pascal_16 -> get_string_u_at_rva,
        // pefile:6476-6490). Only the look-ups are repeated here, in pefile's order, because they
        // move its "last used section" state; the text itself is not used by the reference.
        (void)overlap;
        for (const auto& [at, length] : names) {
            if (length == 0) continue;
            if (!get_data(sat_add(at, 2), true, 2)) continue;
            get_data(sat_add(at, 2), true, std::min<u64>(static_cast<u64>(length) * 2, 256));
        }
        return self;
    }
    void resources(Image& image, u64 rva) {
        const int root = resource_directory(rva, rva, 0, std::vector<u64>{rva});
        if (root < 0) return;
        image.has_resources = true;
        const ResNode& top = nodes_[static_cast<std::size_t>(root)];
        image.resource_root_has_entries = !top.children.empty();
        // The reference's walk: a stack, last in first out, depth counted from the root's entries.
        std::vector<std::pair<int, u32>> stack;
        for (const int child : top.children) stack.emplace_back(child, 0u);
        while (!stack.empty() && image.resource_data.size() < kMaxResourceRanges) {
            const auto [index, depth] = stack.back();
            stack.pop_back();
            const ResNode& node = nodes_[static_cast<std::size_t>(index)];
            if (!node.is_dir) {
                image.resource_data.push_back(ResourceData{node.rva, node.size});
            } else if (depth < kMaxResourceWalkDepth) {
                for (const int child : node.children) stack.emplace_back(child, depth + 1);
            }
        }
    }

    // ---- certificate table, as the reference reads it (ref:343) -----------------------------
    void certificates(Image& image) {
        tls_first_callback(image);
        Certificates& c = image.certificates;
        if (image.directories.size() <= 4 || image.directories[4].size == 0) return;
        const u64 off = image.directories[4].virtual_address;
        const u64 size = image.directories[4].size;
        c.present = true;
        c.offset = off;
        c.declared_size = size;
        if (off == 0 || off >= len_) {
            c.problems.push_back("certificate table offset outside the file");
            return;
        }
        if (off + size > len_) c.problems.push_back("certificate table runs past the end of the file");
        const u64 end = std::min(off + size, len_);
        u64 pos = off;
        std::vector<Range> spans;
        while (pos + 8 <= end) {
            u32 length = 0;
            u16 revision = 0, type = 0;
            rd32(pos, length);
            rd16(pos + 4, revision);
            rd16(pos + 6, type);
            if (length < 12 || pos + length > end) {
                c.problems.push_back("bad dwLength " + std::to_string(length) + " at offset " + std::to_string(pos));
                break;
            }
            if (revision != 0x0200) {
                c.problems.push_back("wRevision 0x" + hex4(revision) + " is not 0x0200");
                break;
            }
            if (type != 0x0002) {
                c.problems.push_back("wCertificateType 0x" + hex4(type) + " is not PKCS#7 (0x0002)");
                break;
            }
            // length >= 12 and pos + length <= end, so the four bytes at pos + 8 are inside the file
            if (byte(pos + 8) != 0x30 || byte(pos + 9) != 0x82) {
                c.problems.push_back("certificate body is not a PKCS#7 DER SEQUENCE (30 82 LL LL)");
                break;
            }
            const u64 der_span = 4 + ((byte(pos + 10) << 8) | byte(pos + 11));
            const i64 inner_pad = static_cast<i64>(length) - 8 - static_cast<i64>(der_span);
            if (inner_pad < 0 || inner_pad > 7) {
                c.problems.push_back("DER length " + std::to_string(der_span) + " does not match dwLength " +
                                     std::to_string(length));
                break;
            }
            const u64 aligned = (static_cast<u64>(length) + 7) & ~7ull;
            bool pad_zero = true;
            for (u64 k = pos + 8 + der_span; k < std::min(pos + aligned, end); ++k) pad_zero = pad_zero && byte(k) == 0;
            if (!pad_zero) {
                c.problems.push_back("non-zero bytes after the DER certificate");
                break;
            }
            ++c.entries;
            spans.push_back(Range{pos, pos + 8 + der_span});
            pos += aligned;
        }
        if (c.problems.empty() && end > pos) {
            c.problems.push_back("declared size is " + std::to_string(end - pos) +
                                 " bytes larger than the certificates in it");
        }
        if (c.entries != 0 && c.problems.empty()) {
            c.valid = true;
            c.spans = spans;
            for (const Range& span : spans) c.parsed_size += span.end - span.begin;
        } else if (c.entries == 0 && c.problems.empty()) {
            c.problems.push_back("no certificate entries");
        }
    }

    std::span<const u8> d_;
    u64 len_;
    u16 machine_ = 0;
    bool plus_ = false;
    u32 section_alignment_ = 0;
    u32 file_alignment_ = 0;
    u64 image_base_ = 0;
    u32 size_of_image_ = 0;
    u64 header_len_ = 0;
    std::vector<Sec> secs_;
    int last_used_ = -1;
    u32 total_import_symbols_ = 0;
    u32 total_resource_entries_ = 0;
    std::vector<ResNode> nodes_;
};

}  // namespace

Image parse(std::span<const std::uint8_t> data) { return Reader(data).run(); }

std::vector<std::pair<std::string, std::vector<std::string>>> reference_imports(const Image& image) {
    std::vector<std::pair<std::string, std::vector<std::string>>> out;
    std::map<std::string, std::size_t> position;
    for (const ImportLibrary& library : image.imports) {
        std::vector<std::string> names;
        for (const ImportSymbol& symbol : library.symbols) {
            names.push_back(!symbol.name.empty() ? symbol.name : "ordinal_" + std::to_string(symbol.ordinal));
        }
        const std::string dll = library.dll.empty() ? "unknown" : library.dll;
        // A map from name to position: with many import descriptors a search of the list so
        // far would cost a quadratic number of comparisons (reviewer's finding, board B-3621).
        const auto [existing, inserted] = position.try_emplace(dll, out.size());
        if (!inserted) {
            out[existing->second].second = std::move(names);  // a DLL listed again replaces its earlier list
        } else {
            out.emplace_back(dll, std::move(names));
        }
    }
    return out;
}

}  // namespace mie::pe
