// Entropy of byte data, written to give the same numbers as the Python reference
// (dexmond_mie/utils.py: calculate_entropy, calculate_sliding_window_entropy).
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace mie {

// Shannon entropy in bits per byte; 0 for empty data.
// Same arithmetic as the reference: byte values are visited in the order of their
// first appearance, each adds -p * (ln(p) / ln(2)).
double shannon_entropy(std::span<const std::uint8_t> data);

struct SlidingEntropy {
    double max = 0.0;   // rounded to 4 decimal places, as the reference
    double min = 0.0;
    double avg = 0.0;
    std::size_t high_entropy_windows = 0;
    std::size_t total_windows = 0;
    bool operator==(const SlidingEntropy&) const = default;
};

inline constexpr std::size_t kEntropyWindowBytes = 4096;
inline constexpr std::size_t kEntropyStepBytes = 2048;
inline constexpr double kHighEntropyBits = 7.2;

// Entropy of every window of `window` bytes, moved by `step`. Data shorter than one
// window counts as a single window, as in the reference.
SlidingEntropy sliding_window_entropy(std::span<const std::uint8_t> data,
                                      std::size_t window = kEntropyWindowBytes,
                                      std::size_t step = kEntropyStepBytes);

// Rounds to 4 decimal places the way Python's round(x, 4) does (correctly rounded
// decimal, ties to even on the exact binary value).
double round4(double value);

}  // namespace mie
