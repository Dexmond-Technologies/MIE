// libFuzzer target: the Authenticode check on an attacker-controlled certificate table.
// The input is the certificate table's bytes. They are put behind a small, fixed PE32+
// header whose certificate-table directory entry points at them, so the structural
// precheck, the SignedData parser, the digest and page-hash code and OpenSSL's X.509
// parser, signature verification and chain building all see hostile bytes.
// The root store is empty (its pinned hash is the SHA-256 of nothing), so no chain can
// succeed: a result of "valid" is a bug and aborts.
//
// The first input byte chooses switches: bit 0 turns D-13 (verify every entry) on; bit 1
// turns D-17 (five unread fields accepted) on; bit 2 also runs the second check
// (second_check.cpp: on Linux OpenSSL's own PKCS#7 parser and verification) on the same
// bytes, whatever the walker said. With an empty store it can never agree: "agree" aborts.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>
#include <vector>

#include "mie/signature.hpp"

namespace {

constexpr std::size_t kHeaderSize = 0x200;

void put32(std::vector<std::uint8_t>& out, std::size_t at, std::uint32_t value) {
    out[at] = static_cast<std::uint8_t>(value & 0xff);
    out[at + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    out[at + 2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    out[at + 3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

void put16(std::vector<std::uint8_t>& out, std::size_t at, std::uint16_t value) {
    out[at] = static_cast<std::uint8_t>(value & 0xff);
    out[at + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1 || size > mie::signature::kMaxSignatureBytes) return 0;
    const std::uint8_t switches = data[0];
    const std::span<const std::uint8_t> table(data + 1, size - 1);

    std::vector<std::uint8_t> file(kHeaderSize, 0);
    file[0] = 'M';
    file[1] = 'Z';
    put32(file, 0x3C, 0x80);            // e_lfanew
    file[0x80] = 'P';
    file[0x81] = 'E';
    put16(file, 0x84, 0x8664);          // machine
    put16(file, 0x94, 240);             // SizeOfOptionalHeader
    const std::size_t optional = 0x98;
    put16(file, optional, 0x20B);       // PE32+
    put32(file, optional + 108, 16);    // NumberOfRvaAndSizes
    put32(file, optional + 144, static_cast<std::uint32_t>(kHeaderSize));   // certificate table offset
    put32(file, optional + 148, static_cast<std::uint32_t>(table.size()));  // certificate table size
    file.insert(file.end(), table.begin(), table.end());

    mie::signature::Options options;
    options.roots_loaded = true;
    options.roots_pem.clear();
    options.pinned_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    options.now_unix = 1795000000;  // fixed, so that a finding reproduces
    options.verify_every_entry = (switches & 1) != 0;
    options.accept_unread_fields = (switches & 2) != 0;

    const mie::signature::Precheck checked = mie::signature::precheck(file);
    const mie::signature::Result result = mie::signature::verify(file, options);

    const bool known_status = result.status == "valid" || result.status == "invalid" || result.status == "unsigned" ||
                              result.status == "unavailable";
    if (!known_status) std::abort();
    if (result.status == "valid" || result.publisher_allowed || result.certificate_table_verified) std::abort();
    if (checked.status != "ok" && result.status != checked.status) std::abort();
    if (checked.status == "ok" && (checked.entries == 0 || checked.primary_der.empty())) std::abort();
    if ((switches & 4) != 0) {
        const mie::signature::SecondCheck second = mie::signature::second_check(file, result, options);
        if (second.agree || second.reason.empty()) std::abort();
    }
    return 0;
}
