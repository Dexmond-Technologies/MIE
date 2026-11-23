// mie-archive-probe DIR [--temp-dir-length N]
// For every regular file in DIR, sorted by name, prints one ASCII-only JSON line with what
// the archive readers give in the parity profile:
//   file        the file's name
//   is_archive  detect() != NotArchive (the reference's Engine._is_archive)
//   kind        "zip", "tar" or "none" as extract() saw it
//   members     [{name_hex, path_hex, size, sha256}] in order: the member's name and the path
//               below the temp folder the reference would have written, both as hex of their
//               bytes, and the SHA-256 of the bytes that get scanned
//   reasons_hex the coverage reasons in order, each as hex of its bytes
//   complete    no reasons
// Names and reasons are hex because a tar name is raw bytes, not text. A fresh budget is used
// for each file. --temp-dir-length gives the length in bytes of the temp folder path the
// reference extracts to (it counts toward the path length limit); the default is 25.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/archive.hpp"
#include "mie/hash.hpp"

namespace {

using nlohmann::json;

std::string hex(std::string_view bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const char c : bytes) {
        const auto b = static_cast<unsigned char>(c);
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    mie::archive::Options options;  // the parity profile
    if (argc == 4 && std::strcmp(argv[2], "--temp-dir-length") == 0) {
        options.temp_dir_length = std::strtoll(argv[3], nullptr, 10);
    } else if (argc != 2) {
        std::fputs("usage: mie-archive-probe DIR [--temp-dir-length N]\n", stderr);
        return 2;
    }
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(argv[1], ec)) {
        if (entry.is_regular_file(ec)) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());

        const mie::archive::Kind detected = mie::archive::detect(bytes, options);
        mie::archive::Budget budget;
        const mie::archive::Extraction extraction = mie::archive::extract(bytes, budget, options);

        json members = json::array();
        for (const auto& member : extraction.members) {
            const std::span<const std::uint8_t> content(member.bytes->data(), member.bytes->size());
            members.push_back(json{{"name_hex", hex(member.name)},
                                   {"path_hex", hex(member.disk_path)},
                                   {"size", member.bytes->size()},
                                   {"sha256", mie::sha256_hex(content)}});
        }
        json reasons = json::array();
        for (const auto& reason : extraction.reasons) reasons.push_back(hex(reason));
        const char* kind = extraction.kind == mie::archive::Kind::Zip   ? "zip"
                           : extraction.kind == mie::archive::Kind::Tar ? "tar"
                                                                        : "none";
        const json line = {{"file", path.filename().string()},
                           {"is_archive", detected != mie::archive::Kind::NotArchive},
                           {"kind", kind},
                           {"members", members},
                           {"reasons_hex", reasons},
                           {"complete", extraction.complete}};
        std::fputs(line.dump(-1, ' ', true, json::error_handler_t::replace).c_str(), stdout);
        std::fputc('\n', stdout);
    }
    return 0;
}
