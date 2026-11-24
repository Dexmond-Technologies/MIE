// Derived work: follows the Python library signify 0.9.3 (https://github.com/ralphje/signify),
// Copyright (c) 2018 Ralph Broenink, MIT License (parts based on Google's verify-sigs, Copyright
// 2011 Google Inc., Apache License 2.0), and the rules of certvalidator 0.11.1 and asn1crypto
// 1.5.1, Copyright (c) Will Bond, MIT License. Changes made: re-implemented in C++ on OpenSSL.
// Full notices in THIRD-PARTY-NOTICES. This file: Apache License 2.0, Copyright 2026 Dexmond
// Technologies Ltd.
//
// The second, independent check of an Authenticode signature (reviewer's condition 8,
// board B-3630). SHIPPED PROFILE ONLY; off in the parity profile.
//
// The walker (authenticode.cpp) is our own reading of the signature. In the shipped profile
// its "valid" is not enough for the score cap: a second, maintained implementation must
// reach the same answer. This file contains NO parsing of its own: it calls
//   - Linux / macOS: OpenSSL's PKCS#7 parser and PKCS7_verify, and X509_verify_cert;
//   - Windows: WinVerifyTrust and the certificate functions of crypt32;
// and compares what they return with what the walker returned. The only bytes it looks at
// itself are compared for equality, never interpreted.
//
// It is meant to be called only after the walker said "valid" for an allowlisted
// publisher, so OpenSSL's PKCS#7 parser normally sees only blobs the walker has already
// verified. (The fuzz target calls it on anything.)
//
// Every API detail I could not confirm by compiling or running is marked UNSURE.
#include "mie/signature.hpp"

#include <cstdint>
#include <ctime>
#include <initializer_list>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "internal.hpp"

namespace mie::signature {

namespace {

SecondCheck disagree(std::string reason) {
    SecondCheck out;
    out.agree = false;
    out.reason = std::move(reason);
    return out;
}

SecondCheck conclude(const Result& walker) {
    if (walker.status != "valid") return disagree("the walker's result is not valid");
    SecondCheck out;
    out.agree = true;
    out.reason = "second check agrees";
    return out;
}

}  // namespace

}  // namespace mie::signature

#if defined(_WIN32)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

namespace mie::signature {

// Windows: WinVerifyTrust on the one open handle of the scanned file, with no user
// interface, no revocation check and no network retrieval; then the signer and the CA
// that issued it are compared with the walker's (publisher name, issuer key hash).
//
// UNSURE (none of this has been compiled or run):
//  - WINTRUST_FILE_INFO with hFile set and an EMPTY pcwszFilePath: the documentation says the
//    path must not be NULL; whether an empty string is enough for the file-type lookup when
//    a handle is given is not confirmed. If it is not, the caller must also pass the path
//    (used for the type lookup only; the bytes come from the handle).
//  - whether WinVerifyTrust works inside the worker's AppContainer at all (it needs the
//    system's trust providers and certificate stores). If not, this check has to run in the
//    service process on the handle, not in the worker.
//  - WinVerifyTrust trusts the SYSTEM root store, not our pinned store. The pinned policy is
//    applied through the comparison with the walker (whose chain ended in the pinned store).
//  - WinVerifyTrust accepts bytes appended behind the certificate table unless the system
//    setting EnableCertPaddingCheck is on; the walker's precheck has already refused those.
//  - CERT_NAME_ATTR_TYPE with szOID_COMMON_NAME returns the FIRST common name; the walker
//    takes the first too, and falls back to the organization; the fallback is copied.
SecondCheck second_check(std::span<const std::uint8_t> data, const Result& walker, const Options& options,
                         std::intptr_t native_handle) {
    (void)options;
    detail::PrimaryView view;
    if (!detail::primary_view(data, view)) return disagree("the first entry is not well formed under the strict rules");
    if (view.signed_digest != view.image_digest) return disagree("the signed digest is not the file's digest");
    if (native_handle == -1 || native_handle == 0) return disagree("no open file handle for WinVerifyTrust");

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.hFile = reinterpret_cast<HANDLE>(native_handle);
    // The path string is taken FROM THE HANDLE (never from the caller): WinVerifyTrust's
    // documentation wants a path besides the handle, and uses it to find the file type. If the
    // system will not give one (UNSURE inside an AppContainer), an empty string is passed.
    wchar_t path_of_handle[1024] = L"";
    const DWORD path_length =
        ::GetFinalPathNameByHandleW(file_info.hFile, path_of_handle, 1024, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (path_length == 0 || path_length >= 1024) path_of_handle[0] = L'\0';
    file_info.pcwszFilePath = path_of_handle;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file_info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

    const LONG status = ::WinVerifyTrust(nullptr, &action, &trust);
    SecondCheck out = disagree("WinVerifyTrust did not accept the file");
    if (status == ERROR_SUCCESS) {
        out = disagree("WinVerifyTrust gave no signer chain");
        CRYPT_PROVIDER_DATA* provider = ::WTHelperProvDataFromStateData(trust.hWVTStateData);
        CRYPT_PROVIDER_SGNR* signer = provider != nullptr ? ::WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer != nullptr && signer->csCertChain >= 2 && signer->pasCertChain != nullptr) {
            PCCERT_CONTEXT leaf = signer->pasCertChain[0].pCert;
            PCCERT_CONTEXT issuer = signer->pasCertChain[1].pCert;
            // the leaf's name, as UTF-8
            std::string publisher;
            for (const char* oid : {szOID_COMMON_NAME, szOID_ORGANIZATION_NAME}) {
                wchar_t wide[512];
                const DWORD count = ::CertGetNameStringW(leaf, CERT_NAME_ATTR_TYPE, 0,
                                                         const_cast<void*>(static_cast<const void*>(oid)), wide, 512);
                if (count > 1) {
                    char narrow[2048];
                    const int written = ::WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(count - 1), narrow,
                                                              static_cast<int>(sizeof narrow), nullptr, nullptr);
                    if (written > 0) publisher.assign(narrow, static_cast<std::size_t>(written));
                    break;
                }
            }
            // the issuing CA's public key info, encoded, hashed as the walker hashes it
            std::string issuer_key;
            DWORD encoded_size = 0;
            if (issuer != nullptr && issuer->pCertInfo != nullptr &&
                ::CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &issuer->pCertInfo->SubjectPublicKeyInfo, 0,
                                      nullptr, nullptr, &encoded_size) != FALSE &&
                encoded_size > 0 && encoded_size < (1u << 20)) {
                std::vector<std::uint8_t> encoded(encoded_size);
                if (::CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &issuer->pCertInfo->SubjectPublicKeyInfo,
                                          0, nullptr, encoded.data(), &encoded_size) != FALSE) {
                    encoded.resize(encoded_size);
                    issuer_key = sha256_hex(encoded);
                }
            }
            if (publisher.empty() || !walker.has_publisher || publisher != walker.publisher) {
                out = disagree("WinVerifyTrust's signer is not the walker's publisher");
            } else if (issuer_key.empty() || issuer_key != walker.issuer_spki_sha256) {
                out = disagree("WinVerifyTrust's issuing CA is not the walker's");
            } else {
                out = conclude(walker);
            }
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &trust);
    return out;
}

}  // namespace mie::signature

#else  // not Windows

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace mie::signature {

namespace {

struct Pkcs7Free { void operator()(PKCS7* p) const { PKCS7_free(p); } };
struct StoreFree { void operator()(X509_STORE* p) const { X509_STORE_free(p); } };
struct StoreCtxFree { void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); } };
struct BioFree { void operator()(BIO* p) const { BIO_free(p); } };
struct X509Free { void operator()(X509* p) const { X509_free(p); } };
struct StackFree { void operator()(STACK_OF(X509)* p) const { sk_X509_free(p); } };  // not the certificates

bool same(const unsigned char* a, std::size_t a_size, std::span<const std::uint8_t> b) {
    if (a_size != b.size()) return false;
    for (std::size_t i = 0; i < a_size; ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

std::string name_text(X509_NAME* name, int nid) {
    char buffer[512];
    const int length = X509_NAME_get_text_by_NID(name, nid, buffer, static_cast<int>(sizeof buffer));
    return length > 0 ? std::string(buffer, static_cast<std::size_t>(length)) : std::string();
}

}  // namespace

// Linux / macOS: OpenSSL parses the first certificate-table entry itself (d2i_PKCS7) and
// verifies it (PKCS7_verify) against the pinned roots.
//
// How the Authenticode quirk is handled: the signed content's type is
// SpcIndirectDataContent (1.3.6.1.4.1.311.2.1.4), not "data", so OpenSSL keeps it as an
// untyped element (`d.other`, an ASN1_TYPE holding a SEQUENCE) and cannot find the content
// to hash by itself. As Authenticode defines it, what is signed is the INSIDE of that
// SEQUENCE (without its tag and length). The inside is handed to PKCS7_verify as the
// content (`indata`). Before that, the bytes OpenSSL holds for the element are compared
// with the bytes the walker read: they must be identical, so that the digest the walker
// took out of the element is the digest inside the content OpenSSL verified. The walker
// has recomputed the file's Authenticode digest; it must equal that digest.
//
// Flags: PKCS7_BINARY only. NOT set: PKCS7_NOVERIFY (the chain IS verified), PKCS7_NOSIGS,
// PKCS7_NOINTERN, PKCS7_NOCHAIN (signer and intermediates come from the signature itself).
// Trust: only the pinned roots (the store holds nothing else; no default paths loaded).
// Purpose: PKCS7_verify would check the S/MIME purpose, which a code-signing certificate
// fails; the store's purpose is set to X509_PURPOSE_ANY and the code-signing extended key
// usage is checked here on the signer (X509_get_extended_key_usage, XKU_CODE_SIGN).
// Time: the chain is checked at the moment the walker used (Result::checked_at_unix: its
// trusted countersignature time, or now). The countersignature itself is NOT verified a
// second time here: OpenSSL has no Authenticode timestamp verification. That part of a
// "valid" answer rests on the walker alone.
//
// UNSURE (not compiled, not run):
//  - that a purpose set on the STORE's parameters survives PKCS7_verify's own
//    X509_STORE_CTX_set_default(ctx, "smime_sign") (read: values already set are kept when
//    parameters are inherited; not confirmed for 3.6.5). If it does not survive, every
//    code-signing certificate fails here and the check always disagrees (no cap: safe, useless).
//  - the trust setting PKCS7_verify ends up with (S/MIME trust on a plain self-signed root:
//    believed accepted by the compatibility rule; not confirmed).
//  - that `d.other->value.sequence` holds the WHOLE element (tag, length, content). If it
//    held only the content, the equality test below fails and the check always disagrees.
//  - PKCS7_verify re-encodes the signed attributes before checking the signature; a
//    signature whose attributes are not in sorted order verifies in the walker (which uses
//    the bytes as they are, like the reference) and fails here: disagree, no cap.
//  - OpenSSL checks the validity dates of the root too; the walker does not (as the
//    reference): a chain to an expired pinned root disagrees here.
//  - X509_PURPOSE_ANY: whether intermediates are still required to be CAs under it
//    (believed yes: the CA check is separate from the purpose).
SecondCheck second_check(std::span<const std::uint8_t> data, const Result& walker, const Options& options,
                         std::intptr_t native_handle) {
    (void)native_handle;
    detail::PrimaryView view;
    if (!detail::primary_view(data, view)) return disagree("the first entry is not well formed under the strict rules");
    if (view.entry_der.empty() || view.entry_der.size() > kMaxSignatureBytes) return disagree("no first entry");

    // OpenSSL's own reading of the same bytes
    const unsigned char* cursor = view.entry_der.data();
    std::unique_ptr<PKCS7, Pkcs7Free> p7(d2i_PKCS7(nullptr, &cursor, static_cast<long>(view.entry_der.size())));
    ERR_clear_error();
    if (!p7 || cursor != view.entry_der.data() + view.entry_der.size()) return disagree("OpenSSL cannot read the PKCS#7 blob");
    if (!PKCS7_type_is_signed(p7.get()) || p7->d.sign == nullptr || p7->d.sign->contents == nullptr) {
        return disagree("OpenSSL: not signed data");
    }
    const PKCS7* contents = p7->d.sign->contents;
    char type_text[64];
    const int type_length = OBJ_obj2txt(type_text, sizeof type_text, contents->type, 1);
    if (type_length <= 0 || std::string(type_text) != "1.3.6.1.4.1.311.2.1.4") return disagree("OpenSSL: content is not SpcIndirectDataContent");
    const ASN1_TYPE* other = contents->d.other;
    if (other == nullptr || other->type != V_ASN1_SEQUENCE || other->value.sequence == nullptr) {
        return disagree("OpenSSL: the content is not a SEQUENCE");
    }
    const ASN1_STRING* element = other->value.sequence;
    if (!same(ASN1_STRING_get0_data(element), static_cast<std::size_t>(ASN1_STRING_length(element)), view.content_whole)) {
        return disagree("OpenSSL and the walker read different signed content");
    }

    // the pinned roots, and nothing else
    if (!options.roots_loaded || options.pinned_sha256.empty()) return disagree("no pinned root store");
    const std::span<const std::uint8_t> pem(reinterpret_cast<const std::uint8_t*>(options.roots_pem.data()),
                                            options.roots_pem.size());
    std::string pinned = options.pinned_sha256;
    for (char& c : pinned) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
    if (sha256_hex(pem) != pinned) return disagree("the root store is not the pinned one");
    std::unique_ptr<X509_STORE, StoreFree> store(X509_STORE_new());
    std::unique_ptr<BIO, BioFree> pem_bio(BIO_new_mem_buf(options.roots_pem.data(), static_cast<int>(options.roots_pem.size())));
    if (!store || !pem_bio) return disagree("out of memory");
    for (int count = 0; count < 64; ++count) {
        std::unique_ptr<X509, X509Free> root(PEM_read_bio_X509(pem_bio.get(), nullptr, nullptr, nullptr));
        if (!root) break;
        if (X509_STORE_add_cert(store.get(), root.get()) != 1) return disagree("a root cannot be added to the store");
    }
    ERR_clear_error();
    X509_VERIFY_PARAM* param = X509_STORE_get0_param(store.get());
    X509_VERIFY_PARAM_set_time(param, static_cast<time_t>(walker.checked_at_unix));
    X509_VERIFY_PARAM_set_depth(param, 10);
    if (X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY) != 1) return disagree("the purpose cannot be set");

    // OpenSSL verifies: the content's digest against the signed attributes, the signature
    // over the attributes, and the signer's chain to the pinned roots
    std::unique_ptr<BIO, BioFree> content(
        BIO_new_mem_buf(view.content_inside.data(), static_cast<int>(view.content_inside.size())));
    if (!content) return disagree("out of memory");
    const int verified = PKCS7_verify(p7.get(), nullptr, store.get(), content.get(), nullptr, PKCS7_BINARY);
    ERR_clear_error();
    if (verified != 1) return disagree("OpenSSL's PKCS7_verify does not accept the signature");

    // the file is the one that was signed
    if (view.signed_digest.empty() || view.signed_digest != view.image_digest) {
        return disagree("the signed digest is not the file's digest");
    }

    // the signer OpenSSL found is the walker's, with the code-signing usage
    std::unique_ptr<STACK_OF(X509), StackFree> signers(PKCS7_get0_signers(p7.get(), nullptr, 0));
    if (!signers || sk_X509_num(signers.get()) != 1) return disagree("OpenSSL: not exactly one signer");
    X509* signer = sk_X509_value(signers.get(), 0);
    const std::uint32_t usage = X509_get_extended_key_usage(signer);
    if (usage == UINT32_MAX || (usage & XKU_CODE_SIGN) == 0) return disagree("the signer has no code-signing usage");
    std::string publisher = name_text(X509_get_subject_name(signer), NID_commonName);
    if (publisher.empty()) publisher = name_text(X509_get_subject_name(signer), NID_organizationName);
    if (publisher.empty() || !walker.has_publisher || publisher != walker.publisher) {
        return disagree("OpenSSL's signer is not the walker's publisher");
    }

    // the CA that issued the signer, from a chain OpenSSL builds to the pinned roots
    std::unique_ptr<X509_STORE_CTX, StoreCtxFree> ctx(X509_STORE_CTX_new());
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), signer, p7->d.sign->cert) != 1) {
        return disagree("the chain cannot be set up");
    }
    const int chain_ok = X509_verify_cert(ctx.get());
    ERR_clear_error();
    STACK_OF(X509)* chain = chain_ok == 1 ? X509_STORE_CTX_get0_chain(ctx.get()) : nullptr;
    if (chain == nullptr || sk_X509_num(chain) < 2) return disagree("OpenSSL finds no chain to the pinned roots");
    unsigned char* key_der = nullptr;
    const int key_length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(sk_X509_value(chain, 1)), &key_der);
    if (key_length <= 0 || key_der == nullptr) return disagree("the issuing CA's key cannot be encoded");
    const std::string issuer_key = sha256_hex(std::span<const std::uint8_t>(key_der, static_cast<std::size_t>(key_length)));
    OPENSSL_free(key_der);
    if (issuer_key != walker.issuer_spki_sha256) return disagree("OpenSSL's issuing CA is not the walker's");

    return conclude(walker);
}

}  // namespace mie::signature

#endif
