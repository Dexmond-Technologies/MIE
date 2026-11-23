// Derived work: follows the Python library signify 0.9.3 (https://github.com/ralphje/signify),
// Copyright (c) 2018 Ralph Broenink, MIT License (parts based on Google's verify-sigs, Copyright
// 2011 Google Inc., Apache License 2.0), and the rules of certvalidator 0.11.1 and asn1crypto
// 1.5.1, Copyright (c) Will Bond, MIT License. Changes made: re-implemented in C++ on OpenSSL.
// Full notices in THIRD-PARTY-NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond
// Technologies.
//
// Shared between authenticode.cpp (the walker) and second_check.cpp. Not a public header.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

struct x509_st;  // OpenSSL's X509, declared here so that this header needs no OpenSSL header

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

// measure.cpp (SG-5): "type:bits/digest,...,type:bits" of a chain, first certificate first.
std::string describe_chain(const std::vector<x509_st*>& chain);

}  // namespace mie::signature::detail
