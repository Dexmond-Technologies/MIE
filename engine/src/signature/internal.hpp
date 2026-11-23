// Shared between authenticode.cpp (the walker) and second_check.cpp. Not a public header.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mie::signature {
// ASCII lower case (policy.cpp).
std::string lower(std::string text);
}  // namespace mie::signature

namespace mie::signature::detail {

// What the walker read from the FIRST certificate-table entry, parsed strictly (D-17 off),
// plus the image digest it computes itself. All spans point into the scanned bytes.
struct PrimaryView {
    std::span<const std::uint8_t> entry_der;       // the PKCS#7 blob, without its zero padding
    std::span<const std::uint8_t> content_whole;   // SpcIndirectDataContent, the whole element
    std::span<const std::uint8_t> content_inside;  // the same without its SEQUENCE header (what is signed)
    std::string digest_name;                       // "md5", "sha1", "sha256", "sha384", "sha512"
    std::vector<std::uint8_t> signed_digest;       // the digest stated inside SpcIndirectDataContent
    std::vector<std::uint8_t> image_digest;        // the Authenticode digest of the file, recomputed
};

// False when the file has no well-formed first entry.
bool primary_view(std::span<const std::uint8_t> data, PrimaryView& out);

}  // namespace mie::signature::detail
