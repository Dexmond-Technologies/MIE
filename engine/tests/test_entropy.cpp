#include <cstdint>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "mie/entropy.hpp"

using mie::shannon_entropy;
using mie::sliding_window_entropy;

TEST_CASE("entropy of empty data is zero", "[entropy]") {
    const std::vector<std::uint8_t> empty;
    REQUIRE(shannon_entropy(empty) == 0.0);
}

TEST_CASE("entropy of one repeated byte is zero", "[entropy]") {
    const std::vector<std::uint8_t> data(1000, 0x41);
    REQUIRE(shannon_entropy(data) == 0.0);
}

TEST_CASE("two equally frequent bytes give one bit", "[entropy]") {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 512; ++i) {
        data.push_back(0x00);
        data.push_back(0xFF);
    }
    const double e = shannon_entropy(data);
    REQUIRE(e > 0.999999999999);
    REQUIRE(e < 1.000000000001);
}

TEST_CASE("all 256 byte values equally frequent give eight bits", "[entropy]") {
    std::vector<std::uint8_t> data;
    for (int round = 0; round < 16; ++round) {
        for (int value = 0; value < 256; ++value) {
            data.push_back(static_cast<std::uint8_t>(value));
        }
    }
    const double e = shannon_entropy(data);
    REQUIRE(e > 7.999999);
    REQUIRE(e < 8.000001);
}

TEST_CASE("data shorter than one window counts as a single window", "[entropy]") {
    const std::vector<std::uint8_t> data(100, 0x41);
    const mie::SlidingEntropy s = sliding_window_entropy(data);
    REQUIRE(s.total_windows == 1);
    REQUIRE(s.high_entropy_windows == 0);
    REQUIRE(s.max == 0.0);
    REQUIRE(s.min == 0.0);
    REQUIRE(s.avg == 0.0);
}

TEST_CASE("empty data counts as a single window of zero entropy", "[entropy]") {
    const std::vector<std::uint8_t> empty;
    const mie::SlidingEntropy s = sliding_window_entropy(empty);
    REQUIRE(s.total_windows == 1);
    REQUIRE(s.max == 0.0);
}

TEST_CASE("window count follows the reference loop", "[entropy]") {
    // range(0, len - 4096 + 1, 2048): 4096 bytes -> 1 window, 6144 -> 2, 8192 -> 3, 8191 -> 2
    REQUIRE(sliding_window_entropy(std::vector<std::uint8_t>(4096, 1)).total_windows == 1);
    REQUIRE(sliding_window_entropy(std::vector<std::uint8_t>(6144, 1)).total_windows == 2);
    REQUIRE(sliding_window_entropy(std::vector<std::uint8_t>(8192, 1)).total_windows == 3);
    REQUIRE(sliding_window_entropy(std::vector<std::uint8_t>(8191, 1)).total_windows == 2);
}

TEST_CASE("a window of all byte values is counted as high entropy", "[entropy]") {
    std::vector<std::uint8_t> data(8192, 0x00);
    for (std::size_t i = 4096; i < 8192; ++i) {
        data[i] = static_cast<std::uint8_t>(i % 256);
    }
    const mie::SlidingEntropy s = sliding_window_entropy(data);
    REQUIRE(s.total_windows == 3);
    REQUIRE(s.high_entropy_windows == 1);  // only the last window is above 7.2 bits
    REQUIRE(s.min == 0.0);
    REQUIRE(s.max == 8.0);
}

TEST_CASE("round4 rounds to four decimal places", "[entropy]") {
    REQUIRE(mie::round4(0.0) == 0.0);
    REQUIRE(mie::round4(7.25) == 7.25);
    REQUIRE(mie::round4(1.23456) == 1.2346);
    REQUIRE(mie::round4(1.23454) == 1.2345);
}
