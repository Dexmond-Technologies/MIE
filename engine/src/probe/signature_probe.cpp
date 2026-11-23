// mie-signature-probe ROOTS.pem PINNED_SHA256 POLICY.json DIR: a test tool, not a product
// program. For every regular file directly in DIR (sorted by name) it prints one ASCII JSON
// line with what the Authenticode check reports, in the shape engine/tests/
// signature_parity.py compares with the Python reference's verify_portable.
// PINNED_SHA256 "-" means "store not provisioned"; POLICY.json "-" means the default policy.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/signature.hpp"

namespace {

using nlohmann::json;

std::string read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5 && argc != 6) {
        std::fputs("usage: mie-signature-probe ROOTS.pem PINNED_SHA256 POLICY.json DIR [parity|shipped]\n", stderr);
        return 2;
    }
    mie::signature::Options options;
    // "parity" (the default): the reference's leniency on five unread fields (D-17) is on and
    // there is no second check. "shipped": strict fields, and the second check must agree.
    const bool shipped = argc == 6 && std::string(argv[5]) == "shipped";
    options.accept_unread_fields = !shipped;
    options.signer_by_second_lookup = !shipped;
    options.accept_long_lengths = !shipped;
    options.require_second_check = shipped;
    mie::signature::load_roots_file(argv[1], options);
    const std::string pinned = argv[2];
    options.pinned_sha256 = pinned == "-" ? std::string() : pinned;
    const std::string policy_path = argv[3];
    if (policy_path != "-") options.policy = mie::signature::load_policy(read_text(policy_path));

    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(argv[4], ec)) {
        if (entry.is_regular_file(ec)) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        const std::vector<char> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const std::span<const std::uint8_t> data(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
        const mie::signature::Precheck checked = mie::signature::precheck(data);
        const mie::signature::Result result = mie::signature::verify(data, options);
        const bool valid = result.status == "valid";
        mie::signature::SecondCheck second;
        if (shipped && valid) second = mie::signature::second_check(data, result, options);
        json line = {
            {"file", path.filename().string()},
            {"precheck_status", checked.status},
            {"precheck_detail", checked.detail},
            {"precheck_entries", checked.entries},
            {"status", result.status},
            {"publisher", result.has_publisher ? json(result.publisher) : json(nullptr)},
            {"publisher_allowed", valid ? json(result.publisher_allowed) : json(nullptr)},
            {"detail", result.detail},
            {"issuer", valid ? json(result.issuer) : json(nullptr)},
            {"issuer_spki_sha256", valid ? json(result.issuer_spki_sha256) : json(nullptr)},
            {"timestamp", valid && !result.timestamp.empty() ? json(result.timestamp) : json(nullptr)},
            {"error_class", result.error_class},
            {"certificate_table_verified", result.certificate_table_verified},
            {"second_check", shipped && valid ? json(second.agree) : json(nullptr)},
            {"second_check_reason", second.reason},
        };
        // ASCII only, invalid UTF-8 replaced: the test splits the output on b'\n' alone.
        const std::string text = line.dump(-1, ' ', true, json::error_handler_t::replace);
        std::fputs(text.c_str(), stdout);
        std::fputc('\n', stdout);
    }
    return 0;
}
