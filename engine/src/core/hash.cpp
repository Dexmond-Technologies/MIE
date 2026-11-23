#include "mie/hash.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace mie {

struct TripleHasher::Impl {
    std::array<EVP_MD_CTX*, 3> ctx{nullptr, nullptr, nullptr};
    bool ok = false;
};

TripleHasher::TripleHasher() : impl_(std::make_unique<Impl>()) {
    const std::array<const EVP_MD*, 3> algorithms{EVP_md5(), EVP_sha1(), EVP_sha256()};
    bool ok = true;
    for (std::size_t i = 0; i < impl_->ctx.size(); ++i) {
        impl_->ctx[i] = EVP_MD_CTX_new();
        if (impl_->ctx[i] == nullptr || EVP_DigestInit_ex(impl_->ctx[i], algorithms[i], nullptr) != 1) {
            ok = false;
        }
    }
    impl_->ok = ok;
}

TripleHasher::~TripleHasher() {
    for (EVP_MD_CTX* ctx : impl_->ctx) {
        if (ctx != nullptr) {
            EVP_MD_CTX_free(ctx);
        }
    }
}

bool TripleHasher::ok() const { return impl_->ok; }

void TripleHasher::update(std::span<const std::uint8_t> data) {
    if (!impl_->ok || data.empty()) {
        return;
    }
    for (EVP_MD_CTX* ctx : impl_->ctx) {
        if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
            impl_->ok = false;
        }
    }
}

namespace {

std::string to_hex(const unsigned char* bytes, unsigned int length) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(length) * 2);
    for (unsigned int i = 0; i < length; ++i) {
        out.push_back(digits[bytes[i] >> 4]);
        out.push_back(digits[bytes[i] & 0x0F]);
    }
    return out;
}

}  // namespace

Hashes TripleHasher::finish() {
    Hashes out;
    if (!impl_->ok) {
        return out;
    }
    std::array<std::string*, 3> targets{&out.md5, &out.sha1, &out.sha256};
    for (std::size_t i = 0; i < impl_->ctx.size(); ++i) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(impl_->ctx[i], digest, &length) != 1) {
            impl_->ok = false;
            return Hashes{};
        }
        *targets[i] = to_hex(digest, length);
    }
    return out;
}

std::string sha256_hex(std::span<const std::uint8_t> data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    static const unsigned char nothing = 0;
    const unsigned char* bytes = data.empty() ? &nothing : data.data();
    if (EVP_Digest(bytes, data.size(), digest, &length, EVP_sha256(), nullptr) != 1) {
        return {};
    }
    return to_hex(digest, length);
}

bool hash_file(io::File& file, Hashes& out, io::IoError& error) {
    TripleHasher hasher;
    if (!hasher.ok()) {
        error.code = io::IoErrorCode::Other;
        error.detail = "hash library unavailable";
        return false;
    }
    std::vector<std::uint8_t> buffer(kHashChunkBytes);
    std::uint64_t offset = 0;
    for (;;) {
        const std::int64_t n = file.read_at(offset, buffer, error);
        if (n < 0) {
            return false;
        }
        if (n == 0) {
            break;
        }
        hasher.update(std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(n)));
        offset += static_cast<std::uint64_t>(n);
    }
    if (!hasher.ok()) {
        error.code = io::IoErrorCode::Other;
        error.detail = "hashing failed";
        return false;
    }
    out = hasher.finish();
    return true;
}

}  // namespace mie
