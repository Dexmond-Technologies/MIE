// Joins the Authenticode check (mie/signature.hpp) to the scan pipeline's interface
// (mie::SignatureVerifier in mie/engine.hpp). Header-only so that the signature library
// does not depend on the pipeline.
#pragma once

#include <cstdint>
#include <span>
#include <utility>

#include "mie/engine.hpp"
#include "mie/signature.hpp"

namespace mie {

class AuthenticodeSignatureVerifier final : public SignatureVerifier {
public:
    explicit AuthenticodeSignatureVerifier(signature::Options options) : options_(std::move(options)) {}

    SignatureResult verify(std::span<const std::uint8_t> data) const override {
        const signature::Result checked = signature::verify(data, options_);
        SignatureResult out;
        out.status = checked.status;
        out.publisher = checked.publisher;  // empty when the reference has None
        out.publisher_allowed = checked.status == "valid" && checked.publisher_allowed;
        return out;
    }

private:
    signature::Options options_;
};

}  // namespace mie
