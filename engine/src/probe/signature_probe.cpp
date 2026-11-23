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
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/io.hpp"
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
        std::fputs("usage: mie-signature-probe ROOTS.pem PINNED_SHA256 POLICY.json DIR [parity|shipped|strict-d13|strict-d17|strict-d19|strict-d20]\n", stderr);
        return 2;
    }
    mie::signature::Options options;
    // "parity" (the default): the reference's leniency on five unread fields (D-17) is on and
    // there is no second check. "shipped": strict fields, and the second check must agree.
    // "strict-d13", "strict-d17", "strict-d19", "strict-d20": parity with that ONE numbered
    // difference switched to its shipped value, so a test can say which one changed an answer.
    const std::string mode = argc == 6 ? argv[5] : "parity";
    const bool shipped = mode == "shipped";
    options.verify_every_entry = shipped || mode == "strict-d13";
    options.accept_unread_fields = !(shipped || mode == "strict-d17");
    options.signer_by_second_lookup = !(shipped || mode == "strict-d19");
    options.accept_long_lengths = !(shipped || mode == "strict-d20");
    options.require_second_check = shipped;
    mie::signature::load_roots_file(argv[1], options);
    const std::string pinned = argv[2];
    options.pinned_sha256 = pinned == "-" ? std::string() : pinned;
    const std::string policy_path = argv[3];
    if (policy_path != "-") options.policy = mie::signature::load_policy(read_text(policy_path));

    // The settings this run REALLY uses, read back from the Options object (not from the mode
    // name), as the first line of the output.
    {
        const json settings = {
            {"record", "settings"},
            {"mode", mode},
            {"D-13 verify_every_entry", options.verify_every_entry},
            {"D-17 accept_unread_fields", options.accept_unread_fields},
            {"D-19 signer_by_second_lookup", options.signer_by_second_lookup},
            {"D-20 accept_long_lengths", options.accept_long_lengths},
            {"require_second_check", options.require_second_check},
            {"second_check_called_by_probe_when_walker_valid", options.require_second_check},
            {"file_handle_passed_to_second_check", true},
            {"roots_loaded", options.roots_loaded},
            {"pinned_sha256_given", !options.pinned_sha256.empty()},
            {"now_unix", options.now_unix},
            {"policy_publishers", options.policy.publishers.size()},
            {"policy_issuing_intermediates", options.policy.issuing_intermediates.size()},
        };
        std::fputs(settings.dump(-1, ' ', true, json::error_handler_t::replace).c_str(), stdout);
        std::fputc('\n', stdout);
    }

    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(argv[4], ec)) {
        if (entry.is_regular_file(ec)) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        // The file is opened ONCE through mie::io, as the engine does; the bytes are read from
        // that handle and the same handle goes to the second check (WinVerifyTrust on Windows).
        mie::io::IoError io_error;
        const std::unique_ptr<mie::io::File> file = mie::io::open_regular(path, io_error);
        std::vector<std::uint8_t> bytes;
        std::intptr_t handle = -1;
        if (file && file->size() <= mie::signature::kMaxVerifyBytes) {
            bytes.resize(static_cast<std::size_t>(file->size()));
            std::size_t done = 0;
            while (done < bytes.size()) {
                const std::int64_t got =
                    file->read_at(done, std::span<std::uint8_t>(bytes.data() + done, bytes.size() - done), io_error);
                if (got <= 0) break;
                done += static_cast<std::size_t>(got);
            }
            bytes.resize(done);
            handle = file->native_handle();
        }
        const std::span<const std::uint8_t> data(bytes.data(), bytes.size());
        const mie::signature::Precheck checked = mie::signature::precheck(data);
        const mie::signature::Result result = mie::signature::verify(data, options);
        const bool valid = result.status == "valid";
        mie::signature::SecondCheck second;
        if (shipped && valid) second = mie::signature::second_check(data, result, options, handle);
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
            {"opened", file != nullptr},
        };
        // ASCII only, invalid UTF-8 replaced: the test splits the output on b'\n' alone.
        const std::string text = line.dump(-1, ' ', true, json::error_handler_t::replace);
        std::fputs(text.c_str(), stdout);
        std::fputc('\n', stdout);
    }
    return 0;
}
