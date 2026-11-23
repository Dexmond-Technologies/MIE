// libFuzzer target: the zip reader must never crash, hang, read out of bounds or produce
// more than its limits allow on any bytes, in the parity profile and with the shipped
// profile's switches. The tar reader is reached too when the bytes are not a zip.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "mie/archive.hpp"

namespace {

void require(bool condition) {
    if (!condition) std::abort();
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

    require(extraction.complete == extraction.reasons.empty());
    require(extraction.members.size() <= 64);
    require(budget.members >= 0 && budget.members <= 64);
    // What was produced stays under the hard ceiling plus one block of output.
    require(budget.produced <= options.hard_produced_bytes + (64u << 20));
    std::uint64_t total = 0;
    for (const Member& member : extraction.members) {
        require(member.bytes != nullptr);
        require(member.bytes->size() <= static_cast<std::uint64_t>(options.max_member_bytes));
        require(!member.disk_path.empty());
        total += member.bytes->size();
    }
    require(total <= 64ull * static_cast<std::uint64_t>(options.max_member_bytes));
    // A file detect() does not take for an archive has no members, and extract() says why.
    if (kind == Kind::NotArchive) {
        require(extraction.members.empty() || extraction.kind == Kind::Tar);
        require(!extraction.complete);
    }
    if (extraction.kind == Kind::NotArchive) require(extraction.members.empty());
    if (kind == Kind::Zip) require(extraction.kind == Kind::Zip);
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
