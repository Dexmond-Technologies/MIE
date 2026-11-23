// libFuzzer target: the zip reader must never crash, hang, read out of bounds or produce
// more than its limits allow on any bytes, in the parity profile and with the shipped
// profile's switches. The tar reader is reached too when the bytes are not a zip.
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "mie/archive.hpp"

// Says where the target stopped (the line), so a stop in CI can be read from the log alone.
[[noreturn]] inline void mie_fuzz_stop(int line) {
    std::fprintf(stderr, "fuzz_zip: the rule at line %d of fuzz_zip.cpp does not hold\n", line);
    std::abort();
}
#define MIE_FUZZ_STOP() mie_fuzz_stop(__LINE__)

#define REQUIRE(condition) require_at((condition), __LINE__)


namespace {

void require_at(bool condition, int line) {
    if (!condition) mie_fuzz_stop(line);
}

void check(std::span<const std::uint8_t> file, mie::archive::Options options) {
    using namespace mie::archive;
    // Small limits, so that one input cannot spend the run decompressing.
    options.max_member_bytes = 1 << 20;
    options.hard_produced_bytes = 16u << 20;
    options.hard_entries = 4096;
    options.hard_header_data_bytes = 1u << 20;
    options.lzma_memory_limit = 16u << 20;

    const Kind kind = detect(file, options);
    Budget budget;
    budget.members = 64;
    budget.bytes = 8 << 20;
    const Extraction extraction = extract(file, budget, options);

    REQUIRE(extraction.complete == extraction.reasons.empty());
    REQUIRE(extraction.members.size() <= 64);
    REQUIRE(budget.members >= 0 && budget.members <= 64);
    // What was produced stays under the hard ceiling plus one block of output.
    REQUIRE(budget.produced <= options.hard_produced_bytes + (64u << 20));
    std::uint64_t total = 0;
    for (const Member& member : extraction.members) {
        REQUIRE(member.bytes != nullptr);
        REQUIRE(member.bytes->size() <= static_cast<std::uint64_t>(options.max_member_bytes));
        REQUIRE(!member.disk_path.empty());
        total += member.bytes->size();
    }
    REQUIRE(total <= 64ull * static_cast<std::uint64_t>(options.max_member_bytes));
    // A file detect() does not take for an archive has no members, and extract() says why.
    if (kind == Kind::NotArchive) {
        REQUIRE(extraction.members.empty() || extraction.kind == Kind::Tar);
        REQUIRE(!extraction.complete);
    }
    if (extraction.kind == Kind::NotArchive) REQUIRE(extraction.members.empty());
    if (kind == Kind::Zip) REQUIRE(extraction.kind == Kind::Zip);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span<const std::uint8_t> file(data, size);
    mie::archive::Options parity;
    check(file, parity);
    mie::archive::Options shipped;
    shipped.duplicate_names_last_wins = false;
    shipped.zip_after_other_data = false;
    shipped.tar_bad_header_ends_silently = false;
    shipped.tar_leading_zero_block_is_tar = false;
    check(file, shipped);
    return 0;
}
