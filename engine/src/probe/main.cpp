// mie-probe: a test tool, not a product program. It prints, as one JSON object, what
// the week 0 primitives say about one file: is it accepted by the safe open, its size,
// its three hashes, its entropy figures. The CI tests compare this output with the
// Python reference and with the file-type refusal rules.
//
// Numbers are printed with 17 significant digits so that the comparison is exact.
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/entropy.hpp"
#include "mie/hash.hpp"
#include "mie/io.hpp"

namespace {

std::string exact(double value) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.17g", value);
    return buffer;
}

constexpr std::uint64_t kMaxProbeBytes = 64ull * 1024 * 1024;

}  // namespace

int main(int argc, char** argv) {
    using nlohmann::json;
    const bool usage_ok = (argc == 3 || (argc == 4 && std::string(argv[3]) == "--allow-cloud-only")) &&
                          std::string(argv[1]) == "file";
    if (!usage_ok) {
        std::fputs("usage: mie-probe file PATH [--allow-cloud-only]\n", stderr);
        return 2;
    }
    mie::io::OpenOptions options;
    options.allow_cloud_only = (argc == 4);
    mie::io::IoError error;
    const auto file = mie::io::open_regular(std::filesystem::path(argv[2]), error, options);
    if (!file) {
        const json refused = {{"state", "refused"},
                              {"code", mie::io::to_string(error.code)},
                              {"detail", error.detail}};
        std::printf("%s\n", refused.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
        return 0;
    }

    mie::Hashes hashes;
    if (!mie::hash_file(*file, hashes, error)) {
        const json failed = {{"state", "error"}, {"code", mie::io::to_string(error.code)}, {"detail", error.detail}};
        std::printf("%s\n", failed.dump(-1, ' ', false, json::error_handler_t::replace).c_str());
        return 1;
    }

    json out = {{"state", "ok"},
                {"size", file->size()},
                {"md5", hashes.md5},
                {"sha1", hashes.sha1},
                {"sha256", hashes.sha256}};

    if (file->size() <= kMaxProbeBytes) {
        std::vector<std::uint8_t> data(static_cast<std::size_t>(file->size()));
        std::uint64_t done = 0;
        while (done < data.size()) {
            const std::int64_t n = file->read_at(
                done, std::span<std::uint8_t>(data.data() + done, data.size() - static_cast<std::size_t>(done)), error);
            if (n <= 0) {
                break;
            }
            done += static_cast<std::uint64_t>(n);
        }
        data.resize(static_cast<std::size_t>(done));
        const mie::SlidingEntropy sliding = mie::sliding_window_entropy(data);
        out["entropy"] = exact(mie::shannon_entropy(data));
        out["sliding"] = json{{"max", exact(sliding.max)},
                              {"min", exact(sliding.min)},
                              {"avg", exact(sliding.avg)},
                              {"high_entropy_windows", sliding.high_entropy_windows},
                              {"total_windows", sliding.total_windows}};
    }
    std::printf("%s\n", out.dump().c_str());
    return 0;
}
