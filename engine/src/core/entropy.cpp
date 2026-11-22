#include "mie/entropy.hpp"

#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace mie {

double shannon_entropy(std::span<const std::uint8_t> data) {
    if (data.empty()) {
        return 0.0;
    }
    // The reference sums over collections.Counter(data).values(), which keeps the
    // order of first appearance. Floating-point addition is not associative, so the
    // same order is kept here.
    std::array<std::size_t, 256> counts{};
    std::array<std::uint8_t, 256> order{};
    std::size_t distinct = 0;
    for (const std::uint8_t byte : data) {
        if (counts[byte] == 0) {
            order[distinct++] = byte;
        }
        ++counts[byte];
    }
    const double length = static_cast<double>(data.size());
    const double ln2 = std::log(2.0);
    double entropy = 0.0;
    for (std::size_t i = 0; i < distinct; ++i) {
        const double p = static_cast<double>(counts[order[i]]) / length;
        // Python: math.log(p_x, 2) is computed as log(p_x) / log(2).
        entropy += -p * (std::log(p) / ln2);
    }
    return entropy;
}

double round4(double value) {
    if (!std::isfinite(value)) {
        return value;
    }
    // printf with a fixed precision rounds the exact binary value correctly, which is
    // what Python's round(x, 4) does; strtod reads the shortest decimal back.
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.4f", value);
    return std::strtod(buffer, nullptr);
}

namespace {

// Python 3.12 adds floats in sum() with Neumaier compensation. The reference runs
// on 3.12, so the average is computed the same way here.
double compensated_sum(const std::vector<double>& values) {
    double total = 0.0;
    double compensation = 0.0;
    for (const double x : values) {
        const double t = total + x;
        if (std::fabs(total) >= std::fabs(x)) {
            compensation += (total - t) + x;
        } else {
            compensation += (x - t) + total;
        }
        total = t;
    }
    if (compensation != 0.0 && std::isfinite(compensation)) {
        total += compensation;
    }
    return total;
}

SlidingEntropy single_window(std::span<const std::uint8_t> data) {
    const double e = shannon_entropy(data);
    SlidingEntropy out;
    out.max = round4(e);
    out.min = round4(e);
    out.avg = round4(e);
    out.high_entropy_windows = e > kHighEntropyBits ? 1 : 0;
    out.total_windows = 1;
    return out;
}

}  // namespace

SlidingEntropy sliding_window_entropy(std::span<const std::uint8_t> data, std::size_t window,
                                      std::size_t step) {
    if (data.empty() || data.size() < window || window == 0 || step == 0) {
        return single_window(data);
    }
    std::vector<double> entropies;
    entropies.reserve((data.size() - window) / step + 1);
    std::size_t high = 0;
    for (std::size_t i = 0; i + window <= data.size(); i += step) {
        const double e = shannon_entropy(data.subspan(i, window));
        entropies.push_back(e);
        if (e > kHighEntropyBits) {
            ++high;
        }
    }
    if (entropies.empty()) {
        return single_window(data);
    }
    double max = entropies.front();
    double min = entropies.front();
    for (const double e : entropies) {
        if (e > max) max = e;
        if (e < min) min = e;
    }
    SlidingEntropy out;
    out.max = round4(max);
    out.min = round4(min);
    out.avg = round4(compensated_sum(entropies) / static_cast<double>(entropies.size()));
    out.high_entropy_windows = high;
    out.total_windows = entropies.size();
    return out;
}

}  // namespace mie
