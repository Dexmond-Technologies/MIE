// libFuzzer target: the tar reader (plain and under gzip, bzip2, xz) must never crash, hang,
// read out of bounds or produce more than its limits allow on any bytes.
// A tar header is only read when its checksum fits, which random changes almost never
// keep. The first input byte therefore chooses: bit 0 set = every 512-byte block of the rest
// gets a fitting checksum written into it before the readers see it (this also changes data
// blocks, which does not matter here); bit 1 set = the shipped profile's switches.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

#include "mie/archive.hpp"

// Says where the target stopped (the line), so a stop in CI can be read from the log alone.
[[noreturn]] inline void mie_fuzz_stop(int line) {
    std::fprintf(stderr, "fuzz_tar: the rule at line %d of fuzz_tar.cpp does not hold\n", line);
    std::abort();
}
#define MIE_FUZZ_STOP() mie_fuzz_stop(__LINE__)

#define REQUIRE(condition) require_at((condition), __LINE__)


namespace {

void require_at(bool condition, int line) {
    if (!condition) mie_fuzz_stop(line);
}

void fit_checksums(std::vector<std::uint8_t>& data) {
    for (std::size_t start = 0; start + 512 <= data.size(); start += 512) {
        unsigned sum = 256;  // the checksum field counts as eight spaces
        for (std::size_t i = 0; i < 512; ++i) {
            if (i < 148 || i >= 156) sum += data[start + i];
        }
        char text[9];
        std::snprintf(text, sizeof(text), "%06o", sum & 0777777u);
        for (std::size_t i = 0; i < 6; ++i) data[start + 148 + i] = static_cast<std::uint8_t>(text[i]);
        data[start + 154] = 0;
        data[start + 155] = ' ';
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace mie::archive;
    if (size == 0) return 0;
    const std::uint8_t mode = data[0];
    std::vector<std::uint8_t> bytes(data + 1, data + size);
    if (mode & 1) fit_checksums(bytes);

    Options options;
    if (mode & 2) {
        options.duplicate_names_last_wins = false;
        options.zip_after_other_data = false;
        options.tar_bad_header_ends_silently = false;
        options.tar_leading_zero_block_is_tar = false;
    }
    // Small limits, so that one input cannot spend the run decompressing.
    options.max_member_bytes = 1 << 20;
    options.hard_produced_bytes = 16u << 20;
    options.hard_entries = 4096;
    options.hard_header_data_bytes = 1u << 20;
    options.lzma_memory_limit = 16u << 20;

    const std::span<const std::uint8_t> file(bytes.data(), bytes.size());
    const Kind kind = detect(file, options);
    Budget budget;
    budget.members = 64;
    budget.bytes = 8 << 20;
    const Extraction extraction = extract(file, budget, options);

    REQUIRE(extraction.complete == extraction.reasons.empty());
    REQUIRE(extraction.members.size() <= 64);
    REQUIRE(budget.members >= 0 && budget.members <= 64);
    REQUIRE(budget.produced <= options.hard_produced_bytes + (64u << 20));
    for (const Member& member : extraction.members) {
        REQUIRE(member.bytes != nullptr);
        REQUIRE(member.bytes->size() <= static_cast<std::uint64_t>(options.max_member_bytes));
        REQUIRE(!member.disk_path.empty());
        REQUIRE(member.disk_path.find('\0') == std::string::npos);
        REQUIRE(member.disk_path.front() != '/');
    }
    if (extraction.kind == Kind::NotArchive) REQUIRE(extraction.members.empty());
    if (kind == Kind::Tar) REQUIRE(extraction.kind == Kind::Tar);
    if (kind == Kind::Zip) REQUIRE(extraction.kind == Kind::Zip);
    return 0;
}
