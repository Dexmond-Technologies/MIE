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
#include <iostream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/io.hpp"
#include "mie/signature.hpp"
#include "../signature/internal.hpp"  // detail::primary_view: the walker's own file-digest verdict (SG-7)

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

using nlohmann::json;

#if defined(_WIN32)
// The cap path's own handle (reviewer's ruling on the Windows second check): the file is
// opened a SECOND time WITHOUT write sharing (reading and deleting stay shared), hashed
// through that handle, and WinVerifyTrust runs on it. Any failure costs only the cap.
// Here for the test tool only; mie::io is not changed and the general scan keeps its sharing.
struct CapHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;
    bool opened = false;
    bool bytes_equal = false;  // what is read through it equals what the walker was given
    bool identity_known = false;
    BY_HANDLE_FILE_INFORMATION identity{};
};

CapHandle open_cap_handle(const std::filesystem::path& path, std::span<const std::uint8_t> expected) {
    CapHandle cap;
    cap.handle = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (cap.handle == INVALID_HANDLE_VALUE) return cap;
    cap.opened = true;
    cap.identity_known = ::GetFileInformationByHandle(cap.handle, &cap.identity) != FALSE;
    std::vector<std::uint8_t> read(expected.size() + 1);
    std::size_t done = 0;
    while (done < read.size()) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(std::min<std::size_t>(read.size() - done, 1u << 20));
        if (::ReadFile(cap.handle, read.data() + done, want, &got, nullptr) == FALSE || got == 0) break;
        done += got;
    }
    cap.bytes_equal = done == expected.size() && std::equal(expected.begin(), expected.end(), read.begin());
    return cap;
}

// Is the file now behind `path` still the one the cap handle holds (volume serial number and
// file index)? "same", "different", "path gone" or "not known".
const char* path_identity(const std::filesystem::path& path, const CapHandle& cap) {
    if (!cap.identity_known) return "not known";
    const HANDLE now = ::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                     OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (now == INVALID_HANDLE_VALUE) return "path gone";
    BY_HANDLE_FILE_INFORMATION other{};
    const bool read = ::GetFileInformationByHandle(now, &other) != FALSE;
    ::CloseHandle(now);
    if (!read) return "not known";
    return other.dwVolumeSerialNumber == cap.identity.dwVolumeSerialNumber &&
                   other.nFileIndexHigh == cap.identity.nFileIndexHigh && other.nFileIndexLow == cap.identity.nFileIndexLow
               ? "same"
               : "different";
}
#endif

std::string read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5 && argc != 6) {
        std::fputs("usage: mie-signature-probe ROOTS.pem PINNED_SHA256 POLICY.json DIR [parity|shipped|shipped-pause|strict-d13|strict-d17|strict-d19|strict-d20|strict-d21|strict-d22]\n", stderr);
        return 2;
    }
    mie::signature::Options options;
    // "parity" (the default): the reference's leniency on five unread fields (D-17) is on and
    // there is no second check. "shipped": strict fields, and the second check must agree.
    // "strict-d13", "strict-d17", "strict-d19", "strict-d20": parity with that ONE numbered
    // difference switched to its shipped value, so a test can say which one changed an answer.
    const std::string mode = argc == 6 ? argv[5] : "parity";
    // "shipped-pause" (test only): the shipped setting; after a file is opened and read, the
    // probe prints an "opened" record, waits for one line on standard input, and only then
    // checks; the second check is called whatever the walker says. A test changes the file
    // behind the path during the wait, to see whether the answer follows the open handle.
    const bool pause = mode == "shipped-pause";
    const bool shipped = mode == "shipped" || pause;
    options.verify_every_entry = shipped || mode == "strict-d13";
    options.accept_unread_fields = !(shipped || mode == "strict-d17");
    options.signer_by_second_lookup = !(shipped || mode == "strict-d19");
    options.accept_long_lengths = !(shipped || mode == "strict-d20");
    options.accept_md5 = !(shipped || mode == "strict-d21");
    options.accept_malformed_page_hashes = !(shipped || mode == "strict-d22");
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
            {"D-21 accept_md5", options.accept_md5},
            {"D-22 accept_malformed_page_hashes", options.accept_malformed_page_hashes},
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
        json cap_opened = nullptr;
        json cap_bytes_equal = nullptr;
        std::string identity_after = "not checked";
#if defined(_WIN32)
        CapHandle cap;
        if (pause) {
            // the cap path: a second open without write sharing; its bytes must be the walker's
            cap = open_cap_handle(path, data);
            cap_opened = cap.opened;
            cap_bytes_equal = cap.bytes_equal;
            handle = cap.opened && cap.bytes_equal ? reinterpret_cast<std::intptr_t>(cap.handle) : -1;
        }
#endif
        if (pause) {
            const json opened = {{"record", "opened"}, {"file", path.filename().string()}, {"bytes", bytes.size()}};
            std::fputs(opened.dump(-1, ' ', true, json::error_handler_t::replace).c_str(), stdout);
            std::fputc('\n', stdout);
            std::fflush(stdout);
            std::string ignored;
            std::getline(std::cin, ignored);
        }
        const mie::signature::Precheck checked = mie::signature::precheck(data);
        // SG-7: the walker's reading of the first entry (strict) and the file digest it computes
        mie::signature::detail::PrimaryView view;
        const bool walker_view = mie::signature::detail::primary_view(data, view);
        const mie::signature::Result result = mie::signature::verify(data, options);
        const bool valid = result.status == "valid";
        mie::signature::SecondCheck second;
        const bool second_asked = (shipped && valid) || pause;
        if (second_asked) second = mie::signature::second_check(data, result, options, handle);
#if defined(_WIN32)
        if (pause && cap.opened) {
            identity_after = path_identity(path, cap);  // after the check: did the path still name this file?
            ::CloseHandle(cap.handle);
        }
#endif
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
            {"second_check", second_asked ? json(second.agree) : json(nullptr)},
            {"second_check_reason", second.reason},
            {"file_digest", result.file_digest},
            {"signer_digest", result.signer_digest},
            {"countersigner_digest", result.countersigner_digest},
            {"walker_digest_name", walker_view ? json(view.digest_name) : json(nullptr)},
            {"walker_digest_equal", walker_view ? json(view.signed_digest == view.image_digest) : json(nullptr)},
            {"signer_chain", result.signer_chain},
            {"timestamp_chain", result.timestamp_chain},
            {"opened", file != nullptr},
            {"cap_handle_opened", cap_opened},
            {"cap_handle_bytes_equal", cap_bytes_equal},
            {"path_identity_after_check", identity_after},
        };
        // ASCII only, invalid UTF-8 replaced: the test splits the output on b'\n' alone.
        const std::string text = line.dump(-1, ' ', true, json::error_handler_t::replace);
        std::fputs(text.c_str(), stdout);
        std::fputc('\n', stdout);
    }
    return 0;
}
