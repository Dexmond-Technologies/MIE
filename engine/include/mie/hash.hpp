// MD5, SHA-1 and SHA-256 of the same bytes in one pass (the Python reference reports
// all three: dexmond_mie/utils.py calculate_hashes). Hashing is done by OpenSSL.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "mie/io.hpp"
#include "mie/result.hpp"

namespace mie {

class TripleHasher {
public:
    TripleHasher();
    ~TripleHasher();
    TripleHasher(const TripleHasher&) = delete;
    TripleHasher& operator=(const TripleHasher&) = delete;

    // False if the hash library could not be set up; update and finish then do nothing.
    bool ok() const;
    void update(std::span<const std::uint8_t> data);
    // Lower-case hex digests. Call once.
    Hashes finish();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// SHA-256 of a buffer, lower-case hex; empty if the hash library failed.
std::string sha256_hex(std::span<const std::uint8_t> data);

inline constexpr std::size_t kHashChunkBytes = 1024 * 1024;

// Hashes the whole file through its one open handle, in chunks, with constant memory.
bool hash_file(io::File& file, Hashes& out, io::IoError& error);

}  // namespace mie
