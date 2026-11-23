// Keys and signature digests along a certificate chain, for counting on the corpus (reviewer's
// SG-5; no refusal is based on it). It calls OpenSSL accessors on certificates that are ALREADY
// parsed and verified; it parses nothing itself (not counted in the hostile-parsing line limit).
#include <cstddef>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "internal.hpp"

namespace mie::signature::detail {

namespace {

std::string key_of(X509* certificate) {
    EVP_PKEY* key = X509_get0_pubkey(certificate);
    if (key == nullptr) return "unreadable";
    const char* type = "other";
    switch (EVP_PKEY_get_base_id(key)) {
        case EVP_PKEY_RSA: type = "rsa"; break;
        case EVP_PKEY_RSA_PSS: type = "rsa-pss"; break;
        case EVP_PKEY_DSA: type = "dsa"; break;
        case EVP_PKEY_EC: type = "ec"; break;
        case EVP_PKEY_ED25519: type = "ed25519"; break;
        case EVP_PKEY_ED448: type = "ed448"; break;
        default: break;
    }
    return std::string(type) + ":" + std::to_string(EVP_PKEY_get_bits(key));
}

// The digest of the certificate's own signature: "none" for algorithms without a separate
// digest (EdDSA), "unreadable" if OpenSSL cannot say.
std::string signature_digest_of(X509* certificate) {
    int digest_nid = NID_undef;
    if (X509_get_signature_info(certificate, &digest_nid, nullptr, nullptr, nullptr) != 1) return "unreadable";
    if (digest_nid == NID_undef) return "none";
    const char* name = OBJ_nid2sn(digest_nid);
    return name != nullptr ? std::string(name) : std::string("unknown");
}

}  // namespace

// "type:bits/digest,type:bits/digest,...,type:bits": from the first certificate (the signer or
// the time-stamper) to the root; the root's own signature digest is left out, as in
// path_uses_weak_hash.
std::string describe_chain(const std::vector<x509_st*>& chain) {
    std::string out;
    for (std::size_t i = 0; i < chain.size(); ++i) {
        if (!out.empty()) out += ",";
        out += key_of(chain[i]);
        if (i + 1 < chain.size()) out += "/" + signature_digest_of(chain[i]);
    }
    return out;
}

}  // namespace mie::signature::detail
