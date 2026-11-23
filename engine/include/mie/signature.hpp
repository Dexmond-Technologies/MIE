// Authenticode signature check (parity with dexmond_mie/signature.py at ff313e2, the
// portable path: precheck_data + signify 0.9.3 + certvalidator 0.11.1 with the pinned
// root store). A VALID signature from an allowlisted publisher lets the scorer cap the
// heuristic score, so everything here fails closed: whatever cannot be decided is
// "unavailable" or "invalid", never "valid".
//
// The verifier never opens the scanned file: it works on the bytes that were scanned.
// The root store is a PEM file given by path and loaded once (load_roots_file); its
// SHA-256 must equal the pinned value or every check answers "unavailable".
//
// This code parses attacker-controlled bytes (the certificate table) and hands parts of
// them to OpenSSL (X.509 parsing, chain building, signature verification). It belongs in
// the confined worker process.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace mie::signature {

inline constexpr std::size_t kMaxSignatureBytes = 1024 * 1024;       // signature.py MAX_SIGNATURE_BYTES
inline constexpr std::size_t kMaxVerifyBytes = 32u * 1024u * 1024u;  // signature.py MAX_VERIFY_BYTES
inline constexpr const char* kRevocationNote = "revocation not checked (offline)";

// config/trusted_publishers.json (signature.py load_policy).
struct Intermediate {
    std::string cn;
    std::string spki_sha256;  // lower-case hex; empty = "not pinned yet" (never usable)
};
struct Policy {
    std::vector<std::string> publishers{"Microsoft Corporation"};
    std::vector<Intermediate> issuing_intermediates;
    std::vector<std::string> rejected_issuers;
    std::vector<std::string> rejected_leaf_cns;
};
// Text that is not a JSON object gives the default policy (Microsoft Corporation, no
// usable intermediate, so no cap), as the reference does for a missing or unreadable file.
Policy load_policy(std::string_view json_text);

// signature.py precheck_data: the structural check on the exact bytes that were scanned.
struct Precheck {
    std::string status;  // "ok", "unsigned" or "invalid"
    std::string detail;  // the reference's text (empty for "ok")
    std::uint64_t cert_offset = 0;
    std::uint64_t cert_size = 0;
    std::size_t entries = 0;
    std::span<const std::uint8_t> primary_der;  // first entry, without its zero padding
};
Precheck precheck(std::span<const std::uint8_t> data);

struct Options {
    // The pinned root store. `roots_loaded` false: "pinned root store missing: <roots_error>".
    bool roots_loaded = false;
    std::string roots_pem;
    std::string roots_error;
    // Required SHA-256 (hex) of the root store file. Empty = store not provisioned.
    std::string pinned_sha256;
    Policy policy;
    // Seconds since 1970 used as "now"; negative = the system clock.
    std::int64_t now_unix = -1;

    // ---- stage 1 differences, OFF in the parity profile ---------------------------------
    // D-13: the reference verifies only the FIRST certificate-table entry (the others are
    // parsed, not verified). ON: every entry must verify like the first, else "invalid".
    bool verify_every_entry = false;

    // ---- parity-only leniency, OFF by default (= the shipped profile) -------------------
    // D-17: the reference never looks at five fields of a signature (SignedData.version,
    // SignerInfo.version, SignerInfo.signatureAlgorithm, TSTInfo.policy,
    // TSTInfo.serialNumber) and accepts anything there. ON: the same. OFF: each must be
    // what the format says, or the signature is refused.
    bool accept_unread_fields = false;

    // ---- shipped profile only, OFF in the parity profile ---------------------------------
    // The walker alone never grants the cap: a second, independent check (second_check)
    // must agree. Applied by the caller (mie/signature_adapter.hpp), not by verify().
    bool require_second_check = false;
};

struct Result {
    std::string status = "unavailable";  // "valid", "invalid", "unsigned", "unavailable"
    bool has_publisher = false;
    std::string publisher;
    bool publisher_allowed = false;  // meaningful for "valid" only
    std::string detail;
    std::string issuer;              // "valid" only: CN of the CA that issued the leaf
    std::string issuer_spki_sha256;  // "valid" only
    std::string timestamp;           // "valid" only: trusted countersignature time, ISO 8601, or empty
    // The reference's exception class behind an "invalid" ("signify: X: ...") or an
    // "unavailable" ("verification error: X: ..."); empty otherwise. For tests.
    std::string error_class;
    // D-12 support: true only when status is "valid", i.e. the certificate table's bytes
    // were verified. The overlay-entropy step may leave the table's bytes out only then.
    bool certificate_table_verified = false;
    std::uint64_t cert_offset = 0;
    std::uint64_t cert_size = 0;
    // "valid" only: the moment (seconds since 1970) at which the chain was checked: the
    // trusted countersignature time, or now.
    std::int64_t checked_at_unix = 0;
};

// signature.py verify_portable with data given and no file to re-stat. No timeout here:
// the worker's wall-time limit bounds it.
Result verify(std::span<const std::uint8_t> data, const Options& options);

// Reads the root store file into `options` (roots_loaded, roots_pem or roots_error).
// Returns roots_loaded. The file's content is never logged.
bool load_roots_file(const std::string& path, Options& options);

std::string sha256_hex(std::span<const std::uint8_t> data);

// The second, independent check of a signature the walker called "valid" (second_check.cpp;
// reviewer's condition 8). Linux and macOS: OpenSSL's own PKCS#7 verification of the first
// certificate-table entry against the pinned roots. Windows: WinVerifyTrust on the open
// file handle (`native_handle`, the HANDLE value; without one the answer is "disagree").
// `agree` is true only if the walker's result is "valid" AND this check reaches the same
// signer, issuer and file digest. On disagreement there is no cap.
struct SecondCheck {
    bool agree = false;
    std::string reason;
};
SecondCheck second_check(std::span<const std::uint8_t> data, const Result& walker, const Options& options,
                         std::intptr_t native_handle = -1);

}  // namespace mie::signature
