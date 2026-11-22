#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "mie/hash.hpp"

namespace {

mie::Hashes hash_text(const std::string& text) {
    mie::TripleHasher hasher;
    REQUIRE(hasher.ok());
    hasher.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    return hasher.finish();
}

}  // namespace

// Published test vectors (RFC 1321 for MD5, FIPS 180 examples for SHA-1 and SHA-256).
TEST_CASE("digests of the empty input", "[hash]") {
    const mie::Hashes h = hash_text("");
    REQUIRE(h.md5 == "d41d8cd98f00b204e9800998ecf8427e");
    REQUIRE(h.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    REQUIRE(h.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("digests of abc", "[hash]") {
    const mie::Hashes h = hash_text("abc");
    REQUIRE(h.md5 == "900150983cd24fb0d6963f7d28e17f72");
    REQUIRE(h.sha1 == "a9993e364706816aba3e25717850c26c9cd0d89d");
    REQUIRE(h.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("feeding the input in pieces gives the same digests", "[hash]") {
    const std::string text(100000, 'x');
    const mie::Hashes whole = hash_text(text);

    mie::TripleHasher hasher;
    REQUIRE(hasher.ok());
    std::size_t offset = 0;
    std::size_t step = 1;
    while (offset < text.size()) {
        const std::size_t n = (step < text.size() - offset) ? step : text.size() - offset;
        hasher.update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(text.data()) + offset, n));
        offset += n;
        step = step * 3 + 1;
    }
    const mie::Hashes pieces = hasher.finish();
    REQUIRE(pieces == whole);
    REQUIRE(whole.md5.size() == 32);
    REQUIRE(whole.sha1.size() == 40);
    REQUIRE(whole.sha256.size() == 64);
}
