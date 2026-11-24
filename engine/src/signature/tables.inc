// Derived work: follows the Python library signify 0.9.3 (https://github.com/ralphje/signify),
// Copyright (c) 2018 Ralph Broenink, MIT License (parts based on Google's verify-sigs, Copyright
// 2011 Google Inc., Apache License 2.0), and the rules of certvalidator 0.11.1 and asn1crypto
// 1.5.1, Copyright (c) Will Bond, MIT License. Changes made: re-implemented in C++ on OpenSSL.
// Full notices in THIRD-PARTY-NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond
// Technologies Ltd.
//
// Constants of the Authenticode check: limits and object identifiers. No code.
// Included by authenticode.cpp INSIDE its anonymous namespace (it is not a header of its own).
// Moved out of authenticode.cpp unchanged (reviewer's ruling: the line limit is on the code
// that parses hostile bytes).

// ---- limits of our own (the Python libraries have none) --------------------------------
constexpr std::size_t kMaxCertificates = 64;    // certificates in one SignedData
constexpr std::size_t kMaxSignerInfos = 8;
constexpr std::size_t kMaxAttributes = 64;      // attributes in one set, values in one attribute
constexpr int kMaxNestedDepth = 4;              // nested signatures inside nested signatures
constexpr std::size_t kMaxNestedTotal = 16;
constexpr std::size_t kMaxPageHashEntries = 1u << 16;
constexpr int kMaxChainDepth = 10;
// Page hashes: the total number of bytes hashed for ONE signature's page hashes (file bytes
// plus zero padding) may not pass kPageHashBudgetFactor times the file size plus
// kPageHashBudgetSlack. A well-formed table covers the file once per table; a signature
// carries at most two (SHA-1 and SHA-256), so the honest total is about two file sizes.
// Four leaves a factor of two; the slack covers the padding of small files, where one
// page of padding per entry outweighs the file itself. signify has no such limit: it
// accepts any number of tables and repeated or overlapping ranges
// (indirect_data.py:157-170 and 194-217); the reference only has its 2-second timeout.
constexpr std::uint64_t kPageHashBudgetFactor = 4;
constexpr std::uint64_t kPageHashBudgetSlack = 1024 * 1024;
// D-13 on (every entry verified): at most this many certificate-table entries. Each
// verified entry costs one image digest and one page-hash budget.
constexpr std::size_t kMaxEntriesWhenAllVerified = 4;

constexpr std::array<std::uint8_t, 9> kOidSignedData{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
constexpr std::array<std::uint8_t, 9> kOidContentType{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03};
constexpr std::array<std::uint8_t, 9> kOidMessageDigest{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04};
constexpr std::array<std::uint8_t, 9> kOidSigningTime{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05};
constexpr std::array<std::uint8_t, 9> kOidCounterSignature{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x06};
constexpr std::array<std::uint8_t, 11> kOidTstInfo{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04};
constexpr std::array<std::uint8_t, 10> kOidSpcIndirectData{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04};
constexpr std::array<std::uint8_t, 10> kOidSpcPeImageData{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F};
constexpr std::array<std::uint8_t, 10> kOidSpcStatementType{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0B};
constexpr std::array<std::uint8_t, 10> kOidSpcOpusInfo{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0C};
constexpr std::array<std::uint8_t, 10> kOidNestedSignature{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01};
constexpr std::array<std::uint8_t, 10> kOidMsTimeStampToken{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x03, 0x01};
constexpr std::array<std::uint8_t, 10> kOidPageHashesV1{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x01};
constexpr std::array<std::uint8_t, 10> kOidPageHashesV2{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x02};
constexpr std::array<std::uint8_t, 8> kOidMd5{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05};
constexpr std::array<std::uint8_t, 5> kOidSha1{0x2B, 0x0E, 0x03, 0x02, 0x1A};
constexpr std::array<std::uint8_t, 9> kOidSha256{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
constexpr std::array<std::uint8_t, 9> kOidSha384{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
constexpr std::array<std::uint8_t, 9> kOidSha512{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
// SpcSerializedObject class id a6b586d5-b4a1-2466-ae05-a217da8e60d6 (page hashes)
constexpr std::array<std::uint8_t, 16> kPageHashClassId{0xA6, 0xB5, 0x86, 0xD5, 0xB4, 0xA1, 0x24, 0x66,
                                                        0xAE, 0x05, 0xA2, 0x17, 0xDA, 0x8E, 0x60, 0xD6};
constexpr const char* kEkuCodeSigning = "1.3.6.1.5.5.7.3.3";
constexpr const char* kEkuTimeStamping = "1.3.6.1.5.5.7.3.8";
constexpr const char* kEkuLifetimeSigning = "1.3.6.1.4.1.311.10.3.13";
