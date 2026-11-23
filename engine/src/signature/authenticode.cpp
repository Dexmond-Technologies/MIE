// Authenticode signature check. See mie/signature.hpp.
//
// What is copied, and from where (Python reference at ff313e2):
//   precheck()            dexmond_mie/signature.py precheck_data (texts included)
//   the three stages      signature.py _verify_portable_inner / _signify_verify:
//     PARSE   signify 0.9.3 parsing all certificate-table entries; an error here leaves
//             the reference through its outer handler: "unavailable"
//     VERIFY  signify's AuthenticodeFile.verify(first entry only); an error: "invalid",
//             detail "signify: <class>: <text>"
//     AFTER   the reference's own checks (leaf, trusted timestamp, leaf EKU and validity,
//             issuing CA, publisher decision); an error: "unavailable"
// signify and certvalidator are Python libraries; their checks are re-made here with
// OpenSSL. The exception TEXTS after the class name are not reproduced exactly; statuses
// and the cap decision are what must agree. Every place that could not be determined
// fails closed. The list is in work/mie-cpp/SIGNATURE_INTEGRATION.md.
#include "mie/signature.hpp"

#include "internal.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace mie::signature {

namespace {

using Bytes = std::span<const std::uint8_t>;

// A failure, named by the Python exception class the reference would see.
struct Fail {
    std::string cls;
    std::string text;
};

#include "tables.inc"  // limits and object identifiers (constants only)

// The page-hash budget ran out. Not a Fail: it must pass through the handlers that turn a
// verification failure into "invalid" and end as "unavailable", which is what the
// reference answers when its timeout fires (signature.py:539-543).
struct OverBudget {};

#include "support.inc"  // OpenSSL owners and date arithmetic (no parsing)

// ---- little-endian reads ---------------------------------------------------------------
bool rd16(Bytes d, std::uint64_t off, std::uint32_t& v) {
    if (off > d.size() || d.size() - off < 2) return false;
    const std::size_t o = static_cast<std::size_t>(off);
    v = static_cast<std::uint32_t>(d[o]) | (static_cast<std::uint32_t>(d[o + 1]) << 8);
    return true;
}
bool rd32(Bytes d, std::uint64_t off, std::uint32_t& v) {
    if (off > d.size() || d.size() - off < 4) return false;
    const std::size_t o = static_cast<std::size_t>(off);
    v = static_cast<std::uint32_t>(d[o]) | (static_cast<std::uint32_t>(d[o + 1]) << 8) |
        (static_cast<std::uint32_t>(d[o + 2]) << 16) | (static_cast<std::uint32_t>(d[o + 3]) << 24);
    return true;
}
bool all_zero(Bytes d) {
    return std::all_of(d.begin(), d.end(), [](std::uint8_t b) { return b == 0; });
}

// ---- DER (definite lengths, one-byte tags only; anything else is refused) --------------
struct Tlv {
    std::uint8_t tag = 0;
    Bytes content;
    Bytes whole;
};

// D-20 (proposed): asn1crypto accepts a length written longer than needed (81 05 for 05,
// 82 00 85 for 81 85). ON (parity) the same is accepted; OFF (the default, the shipped
// profile) only the shortest form is: strict DER. Set for one verify() call, like D-17.
thread_local bool g_accept_long_lengths = false;

bool read_tlv(Bytes& in, Tlv& out) {
    if (in.size() < 2) return false;
    const std::uint8_t tag = in[0];
    if ((tag & 0x1f) == 0x1f) return false;
    std::size_t pos = 1;
    std::size_t length = in[pos++];
    if ((length & 0x80) != 0) {
        const std::size_t count = length & 0x7f;
        if (count == 0 || count > 4 || in.size() - pos < count) return false;
        length = 0;
        for (std::size_t i = 0; i < count; ++i) length = (length << 8) | in[pos++];
        const std::size_t least = count == 1 ? 0x80 : std::size_t{1} << (8 * (count - 1));
        if (!g_accept_long_lengths && length < least) return false;
    }
    if (in.size() - pos < length) return false;
    out.tag = tag;
    out.content = in.subspan(pos, length);
    out.whole = in.first(pos + length);
    in = in.subspan(pos + length);
    return true;
}

// A REQUIRED field that signify never reads. asn1crypto 1.5.1 splits a SEQUENCE into its
// children without looking at the tag of a required field (core.py:3893-3928: only an
// optional or defaulted field is compared, by class and tag number, line 3899); the tag is
// checked when the field is first used (core.py:3471-3479 _lazy_child -> _build,
// core.py:5458-5580). A field nobody uses is therefore accepted with ANY tag and ANY
// content, as long as it is one well-formed element. Used for exactly these fields, which
// signify 0.9.3 never touches while verifying: SignedData.version, SignerInfo.version,
// SignerInfo.signatureAlgorithm (only the unused property pkcs7/signer_info.py:204 reads
// it; the verify function is chosen from the certificate's key, x509/certificates.py
// verify_signature), TSTInfo.policy and TSTInfo.serialNumber (properties only,
// authenticode/tsp.py:57 and :75). None of them is covered by a signature, and none is
// used by this code either, so accepting them unread changes no decision.
//
// This is numbered difference D-17 and a DATA switch (Options::accept_unread_fields): ON
// in the parity profile only. OFF (the default, the shipped profile) each of the five must
// carry its proper tag, or the signature is refused. The switch is held for the length of
// one verify() call in a thread-local, set and cleared by UnreadFieldsScope.
thread_local bool g_accept_unread_fields = false;
struct UnreadFieldsScope {
    UnreadFieldsScope(bool fields, bool long_lengths) {
        g_accept_unread_fields = fields;
        g_accept_long_lengths = long_lengths;
    }
    ~UnreadFieldsScope() { g_accept_unread_fields = g_accept_long_lengths = false; }
    UnreadFieldsScope(const UnreadFieldsScope&) = delete;
    UnreadFieldsScope& operator=(const UnreadFieldsScope&) = delete;
};
Tlv skip_unread(Bytes& in, std::uint8_t strict_tag, const char* what) {
    Tlv out;
    if (!read_tlv(in, out) || (!g_accept_unread_fields && out.tag != strict_tag)) {
        throw Fail{"ValueError", std::string("ASN.1: ") + what};
    }
    return out;
}

Tlv expect(Bytes& in, std::uint8_t tag, const char* what) {
    Tlv out;
    if (!read_tlv(in, out) || out.tag != tag) throw Fail{"ValueError", std::string("ASN.1: ") + what};
    return out;
}

std::vector<std::uint8_t> der_header(std::uint8_t tag, std::size_t length) {
    std::vector<std::uint8_t> out{tag};
    if (length < 0x80) {
        out.push_back(static_cast<std::uint8_t>(length));
    } else {
        std::array<std::uint8_t, 4> digits{};
        std::size_t count = 0;
        for (std::size_t rest = length; rest != 0; rest >>= 8) digits[count++] = static_cast<std::uint8_t>(rest & 0xff);
        out.push_back(static_cast<std::uint8_t>(0x80 | count));
        for (std::size_t i = count; i > 0; --i) out.push_back(digits[i - 1]);
    }
    return out;
}

// ---- object identifiers (DER content bytes) --------------------------------------------
template <std::size_t N>
bool is_oid(Bytes content, const std::array<std::uint8_t, N>& oid) {
    return content.size() == N && std::equal(content.begin(), content.end(), oid.begin());
}

// ---- digests ---------------------------------------------------------------------------
struct DigestAlg {
    const EVP_MD* md = nullptr;
    std::string name;
};

// signify.asn1.hashing._get_digest_algorithm on an AlgorithmIdentifier SEQUENCE.
DigestAlg digest_algorithm(const Tlv& algorithm, const std::string& location) {
    Bytes in = algorithm.content;
    const Tlv oid = expect(in, 0x06, "digest algorithm identifier");
    DigestAlg out;
    if (is_oid(oid.content, kOidMd5)) {
        out = {EVP_md5(), "md5"};
    } else if (is_oid(oid.content, kOidSha1)) {
        out = {EVP_sha1(), "sha1"};
    } else if (is_oid(oid.content, kOidSha256)) {
        out = {EVP_sha256(), "sha256"};
    } else if (is_oid(oid.content, kOidSha384)) {
        out = {EVP_sha384(), "sha384"};
    } else if (is_oid(oid.content, kOidSha512)) {
        out = {EVP_sha512(), "sha512"};
    } else {
        throw Fail{"ParseError", location + " must be one of ['md5', 'sha1', 'sha256', 'sha384', 'sha512']"};
    }
    if (!in.empty()) {
        Tlv parameters;
        if (!read_tlv(in, parameters)) throw Fail{"ValueError", "ASN.1: digest algorithm parameters"};
        const bool is_null = parameters.tag == 0x05 && parameters.content.empty();
        if (!is_null) throw Fail{"ParseError", location + " has parameters set, which is unexpected"};
    }
    return out;
}

class Hasher {
public:
    explicit Hasher(const EVP_MD* md) : ctx_(EVP_MD_CTX_new()) {
        if (!ctx_ || EVP_DigestInit_ex(ctx_.get(), md, nullptr) != 1) throw Fail{"ValueError", "digest not available"};
    }
    void update(Bytes data) {
        if (!data.empty() && EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) != 1) {
            throw Fail{"ValueError", "digest update failed"};
        }
    }
    std::vector<std::uint8_t> finish() {
        std::vector<std::uint8_t> out(EVP_MAX_MD_SIZE);
        unsigned int length = 0;
        if (EVP_DigestFinal_ex(ctx_.get(), out.data(), &length) != 1) throw Fail{"ValueError", "digest failed"};
        out.resize(length);
        return out;
    }

private:
    std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx_;
};

std::vector<std::uint8_t> digest_of(const EVP_MD* md, Bytes data) {
    Hasher hasher(md);
    hasher.update(data);
    return hasher.finish();
}

bool same_bytes(Bytes a, Bytes b) { return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin()); }

std::string hex(Bytes data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::uint8_t b : data) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

// ---- time ------------------------------------------------------------------------------
bool asn1_time_epoch(const ASN1_TIME* value, std::int64_t& out) {
    struct tm parts {};
    if (value == nullptr || ASN1_TIME_to_tm(value, &parts) != 1) return false;
    out = days_from_civil(static_cast<std::int64_t>(parts.tm_year) + 1900, parts.tm_mon + 1, parts.tm_mday) * 86400 +
          parts.tm_hour * 3600 + parts.tm_min * 60 + parts.tm_sec;
    return true;
}

// A UTCTime (0x17) or GeneralizedTime (0x18) element.
bool der_time_epoch(const Tlv& value, std::int64_t& out) {
    if (value.tag != 0x17 && value.tag != 0x18) return false;
    const int type = value.tag == 0x17 ? V_ASN1_UTCTIME : V_ASN1_GENERALIZEDTIME;
    std::unique_ptr<ASN1_TIME, TimeFree> stamp(ASN1_STRING_type_new(type));
    if (!stamp) return false;
    if (ASN1_STRING_set(stamp.get(), value.content.data(), static_cast<int>(value.content.size())) != 1) return false;
    return asn1_time_epoch(stamp.get(), out);
}

// ---- Python repr() of an optional string (the reference's texts use !r) -----------------
std::string py_repr(const std::optional<std::string>& value) {
    if (!value) return "None";
    const bool has_single = value->find('\'') != std::string::npos;
    const bool has_double = value->find('"') != std::string::npos;
    const char quote = (has_single && !has_double) ? '"' : '\'';
    std::string out(1, quote);
    for (char c : *value) {
        if (c == '\\' || c == quote) {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else {
            out.push_back(c);  // other control and non-ASCII characters: not escaped as Python does
        }
    }
    out.push_back(quote);
    return out;
}

// ---- CMS structures --------------------------------------------------------------------
struct Attr {
    Bytes oid;
    std::vector<Tlv> values;
};

std::vector<Attr> parse_attributes(Bytes content) {
    std::vector<Attr> out;
    while (!content.empty()) {
        if (out.size() >= kMaxAttributes) throw Fail{"ValueError", "too many attributes"};
        const Tlv attribute = expect(content, 0x30, "attribute");
        Bytes inner = attribute.content;
        Attr parsed;
        parsed.oid = expect(inner, 0x06, "attribute type").content;
        Bytes values = expect(inner, 0x31, "attribute values").content;
        while (!values.empty()) {
            if (parsed.values.size() >= kMaxAttributes) throw Fail{"ValueError", "too many attribute values"};
            Tlv value;
            if (!read_tlv(values, value)) throw Fail{"ValueError", "ASN.1: attribute value"};
            parsed.values.push_back(value);
        }
        out.push_back(std::move(parsed));
    }
    return out;
}

// signify builds a dict from the attributes: of two with the same type, the LAST counts.
template <std::size_t N>
const Attr* find_attr(const std::vector<Attr>& attrs, const std::array<std::uint8_t, N>& oid) {
    const Attr* found = nullptr;
    for (const Attr& attr : attrs) {
        if (is_oid(attr.oid, oid)) found = &attr;
    }
    return found;
}

enum class SignerKind { Authenticode, Counter, Tst };

struct Signer {
    Bytes issuer;        // the issuer Name, whole element
    Bytes serial;        // the serial INTEGER, whole element
    Tlv digest_alg;      // AlgorithmIdentifier
    Bytes signed_attrs;  // content of the [0] element
    std::vector<Attr> auth;
    std::vector<Attr> unauth;
    Bytes signature;
};

template <std::size_t N>
void require_single(const std::vector<Attr>& attrs, const std::array<std::uint8_t, N>& oid, const char* name,
                    const char* where) {
    const Attr* attr = find_attr(attrs, oid);
    if (attr != nullptr && attr->values.size() != 1) {
        throw Fail{"SignerInfoParseError", std::string("Only one ") + name + " expected in SignerInfo." + where +
                                               ", found " + std::to_string(attr->values.size())};
    }
}

// signify.pkcs7.SignerInfo.__init__ / _validate_asn1 and its subclasses.
Signer parse_signer(Bytes content, SignerKind kind) {
    Signer out;
    skip_unread(content, 0x02, "SignerInfo.version");
    Tlv sid;
    if (!read_tlv(content, sid)) throw Fail{"ValueError", "ASN.1: SignerInfo.sid"};
    if (sid.tag == 0x80 || sid.tag == 0xA0) {
        throw Fail{"SignerInfoParseError", "Cannot handle SignerInfo.sid with a subject_key_identifier"};
    }
    if (sid.tag != 0x30) throw Fail{"ValueError", "ASN.1: SignerInfo.sid"};
    {
        Bytes inner = sid.content;
        out.issuer = expect(inner, 0x30, "SignerInfo issuer").whole;
        out.serial = expect(inner, 0x02, "SignerInfo serial number").whole;
    }
    out.digest_alg = expect(content, 0x30, "SignerInfo.digestAlgorithm");
    Tlv next;
    if (!read_tlv(content, next)) throw Fail{"ValueError", "ASN.1: SignerInfo"};
    bool has_signed_attrs = false;
    if (next.tag == 0xA0) {
        has_signed_attrs = true;
        out.signed_attrs = next.content;
        out.auth = parse_attributes(next.content);
        if (!read_tlv(content, next)) throw Fail{"ValueError", "ASN.1: SignerInfo"};
    }
    // `next` is SignerInfo.signatureAlgorithm: never read by the reference; with D-17 on any element is
    // accepted (see skip_unread). An element with tag [0] cannot arrive here: it was taken as the signed attributes.
    if (!g_accept_unread_fields && next.tag != 0x30) throw Fail{"ValueError", "ASN.1: SignerInfo.signatureAlgorithm"};
    out.signature = expect(content, 0x04, "SignerInfo.signature").content;
    if (!content.empty()) {
        const Tlv unsigned_attrs = expect(content, 0xA1, "SignerInfo.unsignedAttrs");
        out.unauth = parse_attributes(unsigned_attrs.content);
    }

    const bool has_content_type = find_attr(out.auth, kOidContentType) != nullptr;
    const bool has_message_digest = find_attr(out.auth, kOidMessageDigest) != nullptr;
    const bool has_signing_time = find_attr(out.auth, kOidSigningTime) != nullptr;
    if (!has_signed_attrs || !has_content_type || !has_message_digest ||
        (kind == SignerKind::Counter && !has_signing_time)) {
        throw Fail{"SignerInfoParseError", "Not all required attributes found."};
    }
    require_single(out.auth, kOidMessageDigest, "message_digest", "authenticatedAttributes");
    require_single(out.auth, kOidContentType, "content_type", "authenticatedAttributes");
    require_single(out.auth, kOidSigningTime, "signing_time", "authenticatedAttributes");
    if (kind == SignerKind::Authenticode) {
        require_single(out.auth, kOidSpcStatementType, "microsoft_spc_statement_type", "authenticatedAttributes");
        require_single(out.auth, kOidSpcOpusInfo, "microsoft_spc_sp_opus_info", "authenticatedAttributes");
    }
    require_single(out.unauth, kOidCounterSignature, "counter_signature", "unauthenticatedAttributes");
    if (kind == SignerKind::Authenticode) {
        require_single(out.unauth, kOidMsTimeStampToken, "microsoft_time_stamp_token", "unauthenticatedAttributes");
    }
    if (kind != SignerKind::Counter) {
        const Tlv& type = find_attr(out.auth, kOidContentType)->values[0];
        const bool matches = type.tag == 0x06 && (kind == SignerKind::Authenticode ? is_oid(type.content, kOidSpcIndirectData)
                                                                                  : is_oid(type.content, kOidTstInfo));
        if (!matches) throw Fail{"SignerInfoParseError", "Unexpected content type for SignerInfo"};
    }
    if (kind == SignerKind::Authenticode) {
        const Attr* token = find_attr(out.unauth, kOidMsTimeStampToken);
        if (token != nullptr && find_attr(out.unauth, kOidCounterSignature) != nullptr) {
            throw Fail{"AuthenticodeParseError",
                       "Countersignature and RFC-3161 timestamp present in SignerInfo.unauthenticatedAttributes"};
        }
        if (token != nullptr) {
            Bytes inner = token->values[0].content;
            Tlv type;
            if (token->values[0].tag != 0x30 || !read_tlv(inner, type) || type.tag != 0x06 ||
                !is_oid(type.content, kOidSignedData)) {
                throw Fail{"AuthenticodeParseError", "RFC-3161 Timestamp does not contain SignedData structure"};
            }
        }
    }
    return out;
}

enum class DataKind { Authenticode, Tst };

struct SignedData {
    std::vector<Tlv> digest_algs;
    bool has_content = false;
    Tlv content;                 // the element inside encapContentInfo's [0]
    std::vector<Bytes> certs;    // each certificate, whole element
    Signer signer;
};

// signify.pkcs7.SignedData.__init__ (+ AuthenticodeSignature / RFC3161SignedData checks) on
// the content of the SignedData SEQUENCE.
SignedData parse_signed_data(Bytes content, DataKind kind) {
    SignedData out;
    skip_unread(content, 0x02, "SignedData.version");
    Bytes algorithms = expect(content, 0x31, "SignedData.digestAlgorithms").content;
    while (!algorithms.empty()) {
        if (out.digest_algs.size() >= kMaxAttributes) throw Fail{"ValueError", "too many digest algorithms"};
        out.digest_algs.push_back(expect(algorithms, 0x30, "digest algorithm"));
    }
    Bytes encap = expect(content, 0x30, "SignedData.encapContentInfo").content;
    const Tlv content_type = expect(encap, 0x06, "content type");
    if (!encap.empty()) {
        Bytes wrapped = expect(encap, 0xA0, "encapsulated content").content;
        if (!read_tlv(wrapped, out.content)) throw Fail{"ValueError", "ASN.1: encapsulated content"};
        out.has_content = true;
    }
    Tlv next;
    if (!read_tlv(content, next)) throw Fail{"ValueError", "ASN.1: SignedData"};
    if (next.tag == 0xA0) {
        Bytes certificates = next.content;
        while (!certificates.empty()) {
            Tlv certificate;
            if (!read_tlv(certificates, certificate)) throw Fail{"ValueError", "ASN.1: certificate set"};
            if (certificate.tag == 0x30) {  // other choices (attribute certificates) are skipped, as in signify
                if (out.certs.size() >= kMaxCertificates) throw Fail{"ValueError", "too many certificates in the signature"};
                out.certs.push_back(certificate.whole);
            }
        }
        if (!read_tlv(content, next)) throw Fail{"ValueError", "ASN.1: SignedData"};
    }
    bool has_crls = false;
    if (next.tag == 0xA1) {
        has_crls = !next.content.empty();
        if (!read_tlv(content, next)) throw Fail{"ValueError", "ASN.1: SignedData"};
    }
    if (next.tag != 0x31) throw Fail{"ValueError", "ASN.1: SignedData.signerInfos"};

    if (out.digest_algs.size() > 1) {
        throw Fail{"ParseError", "SignedData.digestAlgorithms must contain exactly 1 algorithm, not " +
                                     std::to_string(out.digest_algs.size())};
    }
    const bool type_ok = kind == DataKind::Authenticode ? is_oid(content_type.content, kOidSpcIndirectData)
                                                        : is_oid(content_type.content, kOidTstInfo);
    if (!type_ok) throw Fail{"ParseError", "SignedData.contentInfo contains an unexpected content type"};

    Bytes signers = next.content;
    std::vector<Signer> parsed;
    while (!signers.empty()) {
        if (parsed.size() >= kMaxSignerInfos) throw Fail{"ValueError", "too many signer infos"};
        const Tlv signer = expect(signers, 0x30, "SignerInfo");
        parsed.push_back(
            parse_signer(signer.content, kind == DataKind::Authenticode ? SignerKind::Authenticode : SignerKind::Tst));
    }
    if (parsed.size() != 1) {
        throw Fail{"AuthenticodeParseError",
                   std::string(kind == DataKind::Tst ? "RFC3161 " : "") +
                       "SignedData.signerInfos must contain exactly 1 signer, not " + std::to_string(parsed.size())};
    }
    if (kind == DataKind::Authenticode && has_crls) {
        throw Fail{"AuthenticodeParseError", "SignedData.crls is present, but that is unexpected."};
    }
    out.signer = std::move(parsed[0]);
    return out;
}

// signify.pkcs7.SignedData.from_envelope: a ContentInfo that holds SignedData. Bytes behind
// the element (the entry's zero padding) are ignored, as asn1crypto does.
SignedData parse_content_info(Bytes der, DataKind kind, const char* not_signed_class, const char* not_signed_text) {
    const Tlv info = expect(der, 0x30, "ContentInfo");
    Bytes inner = info.content;
    const Tlv type = expect(inner, 0x06, "ContentInfo.contentType");
    if (!is_oid(type.content, kOidSignedData)) throw Fail{not_signed_class, not_signed_text};
    Bytes wrapped = expect(inner, 0xA0, "ContentInfo.content").content;
    const Tlv body = expect(wrapped, 0x30, "SignedData");
    return parse_signed_data(body.content, kind);
}

// ---- certificates ----------------------------------------------------------------------
// ORDER- AND COUNT-STABLE, and it must stay so: exactly one certificate per element of
// `ders`, in the same order, or an exception. The position of "the certificate that
// verified" (VerifiedBy, finding SG-1) is carried from one call of this function to a
// later call on the same list; the callers check the count again where they use it.
std::vector<X509Ptr> load_certificates(const std::vector<Bytes>& ders) {
    std::vector<X509Ptr> out;
    for (Bytes der : ders) {
        const unsigned char* cursor = der.data();
        X509Ptr certificate(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
        if (!certificate) throw Fail{"ValueError", "a certificate in the signature cannot be parsed"};
        out.push_back(std::move(certificate));
    }
    return out;
}

std::vector<X509*> raw(const std::vector<X509Ptr>& certificates) {
    std::vector<X509*> out;
    for (const X509Ptr& certificate : certificates) out.push_back(certificate.get());
    return out;
}

// Certificates of `pool` whose issuer and serial number are the signer's.
std::vector<X509*> find_certificates(const std::vector<X509*>& pool, const Signer& signer) {
    const unsigned char* cursor = signer.issuer.data();
    std::unique_ptr<X509_NAME, NameFree> issuer(d2i_X509_NAME(nullptr, &cursor, static_cast<long>(signer.issuer.size())));
    cursor = signer.serial.data();
    std::unique_ptr<ASN1_INTEGER, IntFree> serial(
        d2i_ASN1_INTEGER(nullptr, &cursor, static_cast<long>(signer.serial.size())));
    if (!issuer || !serial) throw Fail{"ValueError", "the signer's issuer or serial number cannot be parsed"};
    std::vector<X509*> out;
    for (X509* certificate : pool) {
        if (ASN1_INTEGER_cmp(X509_get0_serialNumber(certificate), serial.get()) == 0 &&
            X509_NAME_cmp(X509_get_issuer_name(certificate), issuer.get()) == 0) {
            out.push_back(certificate);
        }
    }
    return out;
}

std::optional<std::string> name_field(const X509_NAME* name, int nid) {
    const int index = X509_NAME_get_index_by_NID(name, nid, -1);
    if (index < 0) return std::nullopt;
    const ASN1_STRING* value = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, index));
    unsigned char* utf8 = nullptr;
    const int length = ASN1_STRING_to_UTF8(&utf8, value);
    if (length < 0 || utf8 == nullptr) return std::nullopt;
    std::string out(reinterpret_cast<const char*>(utf8), static_cast<std::size_t>(length));
    OPENSSL_free(utf8);
    if (out.empty()) return std::nullopt;  // the reference: `value or None`
    return out;
}

std::string spki_sha256(X509* certificate) {
    unsigned char* der = nullptr;
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    if (length <= 0 || der == nullptr) throw Fail{"ValueError", "the public key cannot be encoded"};
    const std::string out = sha256_hex(Bytes(der, static_cast<std::size_t>(length)));
    OPENSSL_free(der);
    return out;
}

// The extended key usages of a certificate as dotted numbers. `present` is false when
// the extension is absent or empty (certvalidator: `not cert.extended_key_usage_value`).
std::vector<std::string> extended_key_usages(X509* certificate, bool& present) {
    std::vector<std::string> out;
    present = false;
    std::unique_ptr<EXTENDED_KEY_USAGE, EkuFree> usage(
        static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(certificate, NID_ext_key_usage, nullptr, nullptr)));
    if (!usage) return out;
    for (int i = 0; i < sk_ASN1_OBJECT_num(usage.get()); ++i) {
        char buffer[128];
        const int length = OBJ_obj2txt(buffer, sizeof buffer, sk_ASN1_OBJECT_value(usage.get(), i), 1);
        if (length > 0 && static_cast<std::size_t>(length) < sizeof buffer) out.emplace_back(buffer);
    }
    present = !out.empty();
    return out;
}

bool has_usage(const std::vector<std::string>& usages, const char* oid) {
    return std::find(usages.begin(), usages.end(), oid) != usages.end();
}

struct Roots {
    std::vector<X509Ptr> certs;
    StorePtr store;
};

// signify Certificate.from_pems / asn1crypto pem.unarmor(multiple=True) on the root store.
Roots load_roots(const std::string& pem) {
    Roots out;
    out.store.reset(X509_STORE_new());
    if (!out.store) throw Fail{"MemoryError", ""};
    std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio) throw Fail{"MemoryError", ""};
    while (true) {
        X509Ptr certificate(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
        if (!certificate) break;
        if (out.certs.size() >= kMaxCertificates) throw Fail{"ValueError", "too many certificates in the root store"};
        if (X509_STORE_add_cert(out.store.get(), certificate.get()) != 1) {
            throw Fail{"ValueError", "a root certificate cannot be added to the store"};
        }
        out.certs.push_back(std::move(certificate));
    }
    ERR_clear_error();  // the end of the PEM text leaves an error behind
    return out;
}

// certvalidator does not check the trust anchor's own validity period (the anchor is not
// part of the path). OpenSSL does; this callback takes that one check back.
int tolerate_anchor_dates(int ok, X509_STORE_CTX* ctx) {
    if (ok == 0) {
        const int error = X509_STORE_CTX_get_error(ctx);
        if ((error == X509_V_ERR_CERT_HAS_EXPIRED || error == X509_V_ERR_CERT_NOT_YET_VALID) &&
            X509_STORE_CTX_get_error_depth(ctx) >= X509_STORE_CTX_get_num_untrusted(ctx)) {
            return 1;
        }
    }
    return ok;
}

// Builds and checks a path from `leaf` to a pinned root at the moment `when`, with
// intermediates only from `untrusted`. `chain`: leaf first, root last.
bool build_chain(X509* leaf, const std::vector<X509*>& untrusted, const Roots& roots, std::int64_t when,
                 std::vector<X509Ptr>& chain, std::string& error) {
    std::unique_ptr<STACK_OF(X509), StackFree> stack(sk_X509_new_null());
    std::unique_ptr<X509_STORE_CTX, StoreCtxFree> ctx(X509_STORE_CTX_new());
    if (!stack || !ctx) {
        error = "out of memory";
        return false;
    }
    for (X509* certificate : untrusted) {
        if (sk_X509_push(stack.get(), certificate) == 0) {
            error = "out of memory";
            return false;
        }
    }
    if (X509_STORE_CTX_init(ctx.get(), roots.store.get(), leaf, stack.get()) != 1) {
        error = "the verification context cannot be set up";
        return false;
    }
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx.get());
    X509_VERIFY_PARAM_set_time(param, static_cast<time_t>(when));
    X509_VERIFY_PARAM_set_depth(param, kMaxChainDepth);
    X509_VERIFY_PARAM_set_auth_level(param, 0);  // signify: allow_legacy (old hash algorithms accepted here)
    X509_STORE_CTX_set_verify_cb(ctx.get(), tolerate_anchor_dates);
    const int ok = X509_verify_cert(ctx.get());
    if (ok != 1) {
        error = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()));
        ERR_clear_error();
        return false;
    }
    STACK_OF(X509)* built = X509_STORE_CTX_get1_chain(ctx.get());
    if (built == nullptr) {
        error = "no chain returned";
        return false;
    }
    chain.clear();
    for (int i = 0; i < sk_X509_num(built); ++i) chain.emplace_back(sk_X509_value(built, i));  // takes the references
    sk_X509_free(built);
    return true;
}

// certvalidator ValidationContext(weak_hash_algos={'md2', 'md5'}): no certificate of the
// path except the trust anchor may be signed with MD2 or MD5.
bool path_uses_weak_hash(const std::vector<X509Ptr>& chain) {
    for (std::size_t i = 0; i + 1 < chain.size(); ++i) {
        int digest_nid = NID_undef;
        if (X509_get_signature_info(chain[i].get(), &digest_nid, nullptr, nullptr, nullptr) != 1) return true;
        if (digest_nid == NID_md5 || digest_nid == NID_md2) return true;
    }
    return false;
}

// signify VerificationContext.verify as AuthenticodeSignature.verify configures it:
// key usage digital_signature if the certificate has a key usage extension, the given
// extended key usage REQUIRED (optional_eku False), old hash algorithms allowed.
void signify_chain(X509* certificate, const std::vector<X509*>& untrusted, const Roots& roots, std::int64_t when,
                   const char* eku_oid, const char* eku_name) {
    std::vector<X509Ptr> chain;
    std::string error;
    if (!build_chain(certificate, untrusted, roots, when, chain, error)) {
        throw Fail{"CertificateVerificationError", "Chain verification failed: " + error};
    }
    const std::uint32_t key_usage = X509_get_key_usage(certificate);
    const bool lacks_digital_signature = key_usage != UINT32_MAX && (key_usage & X509v3_KU_DIGITAL_SIGNATURE) == 0;
    bool eku_present = false;
    const std::vector<std::string> usages = extended_key_usages(certificate, eku_present);
    if (lacks_digital_signature || !has_usage(usages, eku_oid)) {
        throw Fail{"CertificateVerificationError",
                   std::string("Chain verification failed: The X.509 certificate provided is not valid for the purpose of ") +
                       (lacks_digital_signature ? "digital signature" : eku_name)};
    }
}

// signify Certificate.verify_signature on the signed attributes. The re-encoding is the
// SET OF tag in front of the attributes' own bytes, as signify does. signify's second,
// "legacy" attempt for RSA (the bare digest signed without its DigestInfo) is NOT made:
// such a signature is "invalid" here (fails closed).
void verify_attribute_signature(X509* certificate, const Signer& signer, const DigestAlg& algorithm) {
    EVP_PKEY* key = X509_get0_pubkey(certificate);
    if (key == nullptr) throw Fail{"SignerInfoVerificationError", "the signer's public key cannot be read"};
    const int type = EVP_PKEY_get_base_id(key);
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_DSA && type != EVP_PKEY_EC) {
        throw Fail{"SignerInfoVerificationError", "Signature algorithm is unsupported"};
    }
    // (Built by size and copy, not by insert: GCC 15 reports a false out-of-bounds copy there.)
    const std::vector<std::uint8_t> set_header = der_header(0x31, signer.signed_attrs.size());
    std::vector<std::uint8_t> signed_bytes(set_header.size() + signer.signed_attrs.size());
    std::memcpy(signed_bytes.data(), set_header.data(), set_header.size());
    if (!signer.signed_attrs.empty()) {
        std::memcpy(signed_bytes.data() + set_header.size(), signer.signed_attrs.data(), signer.signed_attrs.size());
    }
    std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx(EVP_MD_CTX_new());
    const bool ok = ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, algorithm.md, nullptr, key) == 1 &&
                    EVP_DigestVerify(ctx.get(), signer.signature.data(), signer.signature.size(), signed_bytes.data(),
                                     signed_bytes.size()) == 1;
    ERR_clear_error();
    if (!ok) throw Fail{"SignerInfoVerificationError", "Could not verify the signer of the authenticated attributes"};
}

// signify SignerInfo._build_chain: every certificate with the signer's issuer and serial
// number, from the pinned store and from `pool`; one success is enough; with none, the
// first error. `chain_time` may depend on the candidate (lifetime signing).
// Returns the FIRST certificate that verified the signature and chained (finding SG-1).
template <typename TimeFor>
X509* verify_signer(const Signer& signer, const std::vector<X509*>& pool, const Roots& roots, TimeFor time_for,
                   const char* eku_oid, const char* eku_name, const char* signer_class) {
    // The file's own certificates first, the pinned store's after (r-01, B-3632 follow-up): of
    // a certificate present in both, the file's copy is "the one that verified", as the
    // reference judges the file's copy (signature.py:297-310, 320-333). signify walks the
    // store first (x509/context.py:369); the order changes no answer, only which copy is named.
    std::vector<X509*> all = pool;
    for (const X509Ptr& root : roots.certs) all.push_back(root.get());
    const DigestAlg algorithm = digest_algorithm(signer.digest_alg, "SignerInfo.digestAlgorithm");
    std::optional<Fail> first_error;
    X509* verified = nullptr;
    for (X509* candidate : find_certificates(all, signer)) {
        try {
            verify_attribute_signature(candidate, signer, algorithm);
            signify_chain(candidate, pool, roots, time_for(candidate), eku_oid, eku_name);
            if (verified == nullptr) verified = candidate;
        } catch (const Fail& failure) {
            if (!first_error) first_error = failure;
        }
    }
    if (verified != nullptr) return verified;
    if (first_error) throw *first_error;
    throw Fail{"SignerInfoVerificationError",
               std::string("No valid certificate chain found to a trust anchor from ") + signer_class};
}

// Which entry of `pool` the certificate is, or -1 (it came from the pinned store).
std::ptrdiff_t index_in(const std::vector<X509*>& pool, const X509* certificate) {
    const auto found = std::find(pool.begin(), pool.end(), certificate);
    return found == pool.end() ? -1 : found - pool.begin();
}

const Tlv& single_value(const std::vector<Attr>& attrs, const std::array<std::uint8_t, 9>& oid, const char* what) {
    const Attr* attr = find_attr(attrs, oid);
    if (attr == nullptr || attr->values.size() != 1) throw Fail{"ValueError", std::string("missing attribute: ") + what};
    return attr->values[0];
}

Bytes message_digest_of(const Signer& signer) {
    const Tlv& value = single_value(signer.auth, kOidMessageDigest, "message_digest");
    if (value.tag != 0x04) throw Fail{"ValueError", "message_digest is not an OCTET STRING"};
    return value.content;
}

// ---- the countersignature (timestamp) --------------------------------------------------
struct Countersignature {
    bool present = false;
    bool rfc3161 = false;
    Signer signer;               // the countersigner's SignerInfo (Authenticode) or the token's signer
    SignedData token;            // RFC 3161 only
    DigestAlg imprint_alg;       // RFC 3161 only: TSTInfo.messageImprint.hashAlgorithm
    Bytes imprint;               // RFC 3161 only
    std::int64_t time = 0;
};

// The primary signer's countersigner as signify sees it (RFC3161SignerInfoMixin.countersigner,
// TSTInfo). Parse failures carry signify's class names.
Countersignature read_countersignature(const Signer& primary) {
    Countersignature out;
    if (const Attr* token = find_attr(primary.unauth, kOidMsTimeStampToken)) {
        out.present = true;
        out.rfc3161 = true;
        if (token->values.empty()) throw Fail{"ValueError", "empty timestamp token attribute"};
        out.token = parse_content_info(token->values[0].whole, DataKind::Tst, "AuthenticodeParseError",
                                       "RFC-3161 Timestamp does not contain SignedData structure");
        out.signer = out.token.signer;
        if (!out.token.has_content || out.token.content.tag != 0x04) {
            throw Fail{"ValueError", "the timestamp token has no TSTInfo"};
        }
        Bytes wrapped = out.token.content.content;
        Bytes info = expect(wrapped, 0x30, "TSTInfo").content;
        const Tlv version = expect(info, 0x02, "TSTInfo.version");
        if (version.content.size() != 1 || version.content[0] != 1) {
            throw Fail{"AuthenticodeParseError", "TSTInfo.version must be v1"};
        }
        skip_unread(info, 0x06, "TSTInfo.policy");
        Bytes imprint = expect(info, 0x30, "TSTInfo.messageImprint").content;
        const Tlv algorithm = expect(imprint, 0x30, "TSTInfo.messageImprint.hashAlgorithm");
        out.imprint_alg = digest_algorithm(algorithm, "TSTInfo.messageImprint.hashAlgorithm");
        out.imprint = expect(imprint, 0x04, "TSTInfo.messageImprint.hashedMessage").content;
        skip_unread(info, 0x02, "TSTInfo.serialNumber");
        const Tlv stamp = expect(info, 0x18, "TSTInfo.genTime");
        if (!der_time_epoch(stamp, out.time)) throw Fail{"ValueError", "TSTInfo.genTime cannot be read"};
        return out;
    }
    if (const Attr* counter = find_attr(primary.unauth, kOidCounterSignature)) {
        out.present = true;
        if (counter->values.empty() || counter->values[0].tag != 0x30) {
            throw Fail{"ValueError", "the countersignature is not a SignerInfo"};
        }
        out.signer = parse_signer(counter->values[0].content, SignerKind::Counter);
        const Tlv& stamp = single_value(out.signer.auth, kOidSigningTime, "signing_time");
        if (!der_time_epoch(stamp, out.time)) throw Fail{"ValueError", "countersignature present but its time is unreadable"};
    }
    return out;
}

// signify SignerInfo._verify_countersigner in "strict" mode: returns the countersignature
// time; any failure is AuthenticodeCounterSignerError. `verified_index`: which certificate
// verified the countersignature and chained, as an index into the set it was searched in
// (the token's certificates for RFC 3161, the signature's own otherwise), or -1.
std::int64_t signify_countersignature(const Countersignature& counter, const Signer& primary,
                                      const std::vector<X509*>& primary_certs, const Roots& roots,
                                      std::vector<X509Ptr>& token_certs, std::ptrdiff_t& verified_index) {
    try {
        if (counter.rfc3161) {
            if (!same_bytes(digest_of(counter.imprint_alg.md, primary.signature), counter.imprint)) {
                throw Fail{"CounterSignerError",
                           "The expected hash of the encryptedDigest does not match countersigner's SignerInfo"};
            }
            if (counter.token.digest_algs.size() != 1) {
                throw Fail{"InvalidDigestError", "SignedData.digestAlgorithms does not contain any algorithms"};
            }
            const DigestAlg algorithm = digest_algorithm(counter.token.digest_algs[0], "SignedData.digestAlgorithm");
            if (!same_bytes(digest_of(algorithm.md, counter.token.content.content), message_digest_of(counter.signer))) {
                throw Fail{"InvalidDigestError", "The expected hash of the content does not match SignerInfo"};
            }
            token_certs = load_certificates(counter.token.certs);
            const std::int64_t when = counter.time;
            const std::vector<X509*> token_pool = raw(token_certs);
            verified_index = index_in(token_pool, verify_signer(counter.signer, token_pool, roots,
                                                                 [when](X509*) { return when; }, kEkuTimeStamping,
                                                                 "time stamping", "RFC3161SignerInfo"));
        } else {
            const DigestAlg algorithm = digest_algorithm(counter.signer.digest_alg, "SignerInfo.digestAlgorithm");
            if (!same_bytes(digest_of(algorithm.md, primary.signature), message_digest_of(counter.signer))) {
                throw Fail{"CounterSignerError",
                           "The expected hash of the encryptedDigest does not match countersigner's SignerInfo"};
            }
            const std::int64_t when = counter.time;
            verified_index = index_in(primary_certs, verify_signer(counter.signer, primary_certs, roots,
                                                                    [when](X509*) { return when; }, kEkuTimeStamping,
                                                                    "time stamping", "AuthenticodeCounterSignerInfo"));
        }
    } catch (const Fail& failure) {
        throw Fail{"AuthenticodeCounterSignerError",
                   "An error occurred while validating the countersignature: " + failure.text};
    }
    return counter.time;
}

// ---- the file's own digests (signify SignedPEFile / Fingerprinter) ----------------------
struct Range {
    std::uint64_t start = 0;
    std::uint64_t end = 0;
};

struct Layout {
    std::uint64_t pe_offset = 0;
    Range checksum;
    Range directory_entry;
    Range table;
    std::uint64_t page_size = 0x1000;
};

// signify SignedPEFile._parse_pe_header_locations, for a file that has a certificate
// table. Whatever keeps signify from finding the table ends in the same error:
// "The PE file does not contain a certificate table."
Layout signify_layout(Bytes data) {
    const Fail no_table{"SignedPEParseError", "The PE file does not contain a certificate table."};
    const std::uint64_t size = data.size();
    std::uint32_t pe_offset = 0;
    if (size < 2 || data[0] != 'M' || data[1] != 'Z' || !rd32(data, 0x3C, pe_offset)) throw no_table;
    if (pe_offset >= size) throw no_table;
    if (size - pe_offset < 4 || data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' || data[pe_offset + 2] != 0 ||
        data[pe_offset + 3] != 0) {
        throw no_table;
    }
    Layout out;
    out.pe_offset = pe_offset;
    std::uint32_t machine = 0;
    std::uint32_t optional_size = 0;
    if (!rd16(data, std::uint64_t{pe_offset} + 4, machine) || !rd16(data, std::uint64_t{pe_offset} + 20, optional_size)) {
        throw no_table;
    }
    out.page_size = machine == 0x200 ? 0x2000 : 0x1000;
    const std::uint64_t optional_offset = std::uint64_t{pe_offset} + 24;
    if (optional_offset + optional_size > size || optional_size < 68) throw no_table;
    std::uint32_t magic = 0;
    if (!rd16(data, optional_offset, magic)) throw no_table;
    std::uint64_t count_at = 0;
    std::uint64_t entry_at = 0;
    if (magic == 0x10B) {
        count_at = optional_offset + 92;
        entry_at = optional_offset + 128;
    } else if (magic == 0x20B) {
        count_at = optional_offset + 108;
        entry_at = optional_offset + 144;
    } else {
        throw no_table;
    }
    out.checksum = {optional_offset + 64, optional_offset + 68};
    std::uint32_t count = 0;
    if (optional_offset + optional_size < count_at + 4 || !rd32(data, count_at, count) || count < 5) throw no_table;
    if (optional_offset + optional_size < entry_at + 8) throw no_table;
    out.directory_entry = {entry_at, entry_at + 8};
    std::uint32_t address = 0;
    std::uint32_t length = 0;
    if (!rd32(data, entry_at, address) || !rd32(data, entry_at + 4, length) || length == 0) throw no_table;
    if (address < optional_offset + optional_size || std::uint64_t{address} + length > size) throw no_table;
    out.table = {address, std::uint64_t{address} + length};
    return out;
}

// Fingerprinter with one finger: the bytes of the file outside the checksum, the
// certificate-table directory entry and the certificate table, restricted to
// [start, end), then padded with zeros to a multiple of `block` (0 = no padding).
// `budget` (may be null): bytes this call may still hash; what it hashes is taken off, and
// OverBudget is thrown BEFORE hashing anything the budget does not cover.
std::vector<std::uint8_t> fingerprint(Bytes data, const Layout& layout, const EVP_MD* md, std::uint64_t start,
                                      std::uint64_t end, std::uint64_t block, std::uint64_t* budget = nullptr) {
    const std::uint64_t size = data.size();
    const std::array<Range, 4> ranges{Range{0, layout.checksum.start}, Range{layout.checksum.end, layout.directory_entry.start},
                                      Range{layout.directory_entry.end, layout.table.start}, Range{layout.table.end, size}};
    std::vector<Range> adjusted;
    for (const Range& range : ranges) {
        if (range.end < start || range.start > end) continue;
        adjusted.push_back({std::max(start, range.start), std::min(end, range.end)});
    }
    if (adjusted.empty()) throw Fail{"IndexError", "list index out of range"};
    for (const Range& range : adjusted) {
        if (range.start > range.end || range.end > size) throw Fail{"RuntimeError", "Short read on file."};
    }
    const std::uint64_t covered_span = adjusted.back().end - adjusted.front().start;
    if (budget != nullptr) {
        std::uint64_t cost = (block != 0 && covered_span % block != 0) ? block - covered_span % block : 0;
        for (const Range& range : adjusted) cost += range.end - range.start;
        if (cost > *budget) throw OverBudget{};
        *budget -= cost;
    }
    Hasher hasher(md);
    for (const Range& range : adjusted) {
        hasher.update(data.subspan(static_cast<std::size_t>(range.start), static_cast<std::size_t>(range.end - range.start)));
    }
    if (block != 0) {
        if (covered_span % block != 0) {
            const std::vector<std::uint8_t> zeros(static_cast<std::size_t>(block - covered_span % block), 0);
            hasher.update(zeros);
        }
    }
    return hasher.finish();
}

struct IndirectData {
    bool is_pe_image = false;
    bool has_value = false;
    Tlv value;            // SpcPeImageData when is_pe_image
    Tlv digest_alg;
    Bytes digest;
};

IndirectData parse_indirect_data(const SignedData& signed_data) {
    if (!signed_data.has_content || signed_data.content.tag != 0x30) {
        throw Fail{"ValueError", "the signature has no SpcIndirectDataContent"};
    }
    IndirectData out;
    Bytes content = signed_data.content.content;
    Bytes data = expect(content, 0x30, "SpcIndirectDataContent.data").content;
    const Tlv type = expect(data, 0x06, "SpcAttributeTypeAndOptionalValue.type");
    out.is_pe_image = is_oid(type.content, kOidSpcPeImageData);
    if (!data.empty()) {
        if (!read_tlv(data, out.value)) throw Fail{"ValueError", "ASN.1: SpcAttributeTypeAndOptionalValue.value"};
        out.has_value = true;
    }
    Bytes digest_info = expect(content, 0x30, "SpcIndirectDataContent.messageDigest").content;
    out.digest_alg = expect(digest_info, 0x30, "DigestInfo.digestAlgorithm");
    out.digest = expect(digest_info, 0x04, "DigestInfo.digest").content;
    return out;
}

// signify SignedPEFile.verify_additional_hashes: the page hashes inside SpcPeImageData.
// D-22: what a well-formed page-hash table is (shipped profile): a whole number of entries of
// 4 + digest bytes, at least two; offsets strictly increasing, the first 0; the last entry
// closes the table: an all-zero digest and an offset not behind the certificate table.
void require_well_formed_page_hashes(Bytes table, std::size_t digest_size, const Layout& layout) {
    const std::size_t entry = 4 + digest_size;
    const Fail bad{"MalformedPageHashes", "the page-hash table is not well formed"};
    if (table.size() < 2 * entry || table.size() % entry != 0) throw bad;
    std::uint32_t previous = 0;
    for (std::size_t at = 0; at < table.size(); at += entry) {
        std::uint32_t offset = 0;
        rd32(table, at, offset);
        if (at == 0 ? offset != 0 : offset <= previous) throw bad;
        previous = offset;
    }
    if (previous > layout.table.start || !all_zero(table.last(digest_size))) throw bad;
}

void verify_page_hashes(const IndirectData& indirect, Bytes data, const Layout& layout, bool well_formed_only) {
    if (!indirect.is_pe_image || !indirect.has_value) return;
    std::uint64_t budget = kPageHashBudgetFactor * data.size() + kPageHashBudgetSlack;
    if (indirect.value.tag != 0x30) throw Fail{"ValueError", "SpcPeImageData is not a SEQUENCE"};
    Bytes image = indirect.value.content;
    Tlv element;
    Bytes link;
    bool has_link = false;
    while (!image.empty()) {
        if (!read_tlv(image, element)) throw Fail{"ValueError", "ASN.1: SpcPeImageData"};
        if (element.tag == 0xA0) {
            link = element.content;
            has_link = true;
        }
    }
    if (!has_link) throw Fail{"AttributeError", "SpcPeImageData has no file link"};
    Tlv choice;
    if (!read_tlv(link, choice)) throw Fail{"ValueError", "ASN.1: SpcLink"};
    if (choice.tag != 0xA1) return;  // url or file: no serialized data, so no page hashes
    Bytes moniker = choice.content;
    const Tlv class_id = expect(moniker, 0x04, "SpcSerializedObject.classId");
    const Tlv serialized = expect(moniker, 0x04, "SpcSerializedObject.serializedData");
    if (class_id.content.size() != 16) throw Fail{"ValueError", "SpcUuid is not 16 bytes"};
    if (!std::equal(class_id.content.begin(), class_id.content.end(), kPageHashClassId.begin())) return;

    Bytes set = serialized.content;
    Bytes pairs = expect(set, 0x31, "page hash attributes").content;
    std::size_t entries = 0;
    bool seen_sha1 = false;
    bool seen_sha256 = false;
    while (!pairs.empty()) {
        Bytes pair = expect(pairs, 0x30, "page hash attribute").content;
        const Tlv type = expect(pair, 0x06, "page hash attribute type");
        const EVP_MD* md = nullptr;
        if (is_oid(type.content, kOidPageHashesV1)) {
            md = EVP_sha1();
        } else if (is_oid(type.content, kOidPageHashesV2)) {
            md = EVP_sha256();
        } else {
            throw Fail{"AuthenticodeParseError", "Unknown content type for page hashes"};
        }
        const std::size_t digest_size = static_cast<std::size_t>(EVP_MD_get_size(md));
        const Fail several{"MalformedPageHashes", "more than one page-hash table for one digest"};
        bool& seen = is_oid(type.content, kOidPageHashesV1) ? seen_sha1 : seen_sha256;
        if (well_formed_only && seen) throw several;
        seen = true;
        std::size_t tables = 0;
        Bytes values = expect(pair, 0x31, "page hash attribute values").content;
        while (!values.empty()) {
            const Bytes table = expect(values, 0x04, "page hash table").content;
            if (well_formed_only && ++tables > 1) throw several;
            if (well_formed_only) require_well_formed_page_hashes(table, digest_size, layout);
            std::size_t position = 0;
            bool have_previous = false;
            std::uint32_t previous_offset = 0;
            Bytes previous_digest;
            while (position < table.size()) {
                std::uint32_t offset = 0;
                if (!rd32(table, position, offset)) throw Fail{"error", "unpack requires a buffer of 4 bytes"};
                if (have_previous) {
                    if (++entries > kMaxPageHashEntries) throw Fail{"ValueError", "too many page hashes"};
                    const std::vector<std::uint8_t> expected =
                        fingerprint(data, layout, md, previous_offset, offset, layout.page_size, &budget);
                    if (!same_bytes(expected, previous_digest)) {
                        throw Fail{"AuthenticodeInvalidPageHashError",
                                   "The page hash for page " + std::to_string(previous_offset) + "-" +
                                       std::to_string(offset) + " is invalid."};
                    }
                }
                const std::size_t digest_start = std::min(position + 4, table.size());
                const std::size_t digest_end = std::min(position + 4 + digest_size, table.size());
                previous_digest = table.subspan(digest_start, digest_end - digest_start);
                previous_offset = offset;
                have_previous = true;
                position += 4 + digest_size;
            }
        }
    }
}

// Nested signatures (signify iter_recursive_nested): they are PARSED during verification
// (a malformed one makes the file "invalid") and never verified.
void parse_nested(const Signer& signer, int depth, std::size_t& total) {
    const Attr* nested = find_attr(signer.unauth, kOidNestedSignature);
    if (nested == nullptr) return;
    for (const Tlv& value : nested->values) {
        if (depth >= kMaxNestedDepth || ++total > kMaxNestedTotal) throw Fail{"ValueError", "too many nested signatures"};
        const SignedData inner = parse_content_info(value.whole, DataKind::Authenticode, "AuthenticodeParseError",
                                                    "Nested signature is not a SignedData structure");
        parse_nested(inner.signer, depth + 1, total);
    }
}

// signify AuthenticodeFile.verify(multi_verify_mode='first', countersignature_mode='strict')
// on one signature. Throws the failure. Returns which certificates did the verifying
// (finding SG-1): `signer` is an index into signed_data.certs; `countersigner` an index into
// the timestamp token's certificates (RFC 3161) or into signed_data.certs (Authenticode
// countersignature); -1 where the certificate came from the store or there is none.
struct VerifiedBy {
    std::ptrdiff_t signer = -1;
    std::ptrdiff_t countersigner = -1;
    std::string file_digest, signer_digest, countersigner_digest;  // algorithm names (D-21, counting)
};

// The weakest digest a time-stamp relies on: its signer's and, for RFC 3161, also the token's
// own and the message imprint's. "md5" if any of them is MD5.
std::string countersigner_digest(const Countersignature& counter) {
    std::string name = digest_algorithm(counter.signer.digest_alg, "SignerInfo.digestAlgorithm").name;
    if (counter.rfc3161) {
        if (counter.imprint_alg.name == "md5") name = "md5";
        for (const Tlv& algorithm : counter.token.digest_algs) {
            if (digest_algorithm(algorithm, "SignedData.digestAlgorithm").name == "md5") name = "md5";
        }
    }
    return name;
}

VerifiedBy signify_verify(const SignedData& signed_data, Bytes data, const Layout& layout, const Roots& roots,
                          std::int64_t now, bool well_formed_page_hashes) {
    std::size_t nested_total = 0;
    parse_nested(signed_data.signer, 0, nested_total);

    const IndirectData indirect = parse_indirect_data(signed_data);
    const DigestAlg indirect_alg = digest_algorithm(indirect.digest_alg, "SpcIndirectDataContent.digestAlgorithm");
    const std::vector<std::uint8_t> expected = fingerprint(data, layout, indirect_alg.md, 0, data.size(), 0);

    if (signed_data.digest_algs.size() != 1) {
        throw Fail{"InvalidDigestError",
                   "SignedData.digestAlgorithms does not contain any algorithms and is probably not signed."};
    }
    const DigestAlg data_alg = digest_algorithm(signed_data.digest_algs[0], "SignedData.digestAlgorithm");
    if (data_alg.name != indirect_alg.name) {
        throw Fail{"AuthenticodeInconsistentDigestAlgorithmError",
                   "SignedData.digestAlgorithm must equal SpcInfo.digestAlgorithm"};
    }
    const DigestAlg signer_alg = digest_algorithm(signed_data.signer.digest_alg, "SignerInfo.digestAlgorithm");
    if (data_alg.name != signer_alg.name) {
        throw Fail{"AuthenticodeInconsistentDigestAlgorithmError",
                   "SignedData.digestAlgorithm must equal SignerInfo.digestAlgorithm"};
    }
    if (!same_bytes(expected, indirect.digest)) {
        throw Fail{"AuthenticodeInvalidDigestError", "The expected hash does not match the digest in the indirect data."};
    }
    verify_page_hashes(indirect, data, layout, well_formed_page_hashes);

    // the content's digest: the bytes INSIDE the SpcIndirectDataContent SEQUENCE
    if (!same_bytes(digest_of(data_alg.md, signed_data.content.content), message_digest_of(signed_data.signer))) {
        throw Fail{"AuthenticodeInvalidDigestError", "The expected hash of the content does not match SignerInfo"};
    }

    const std::vector<X509Ptr> certificates = load_certificates(signed_data.certs);
    const std::vector<X509*> pool = raw(certificates);

    const Countersignature counter = read_countersignature(signed_data.signer);
    std::optional<std::int64_t> signing_time;
    std::vector<X509Ptr> token_certificates;
    VerifiedBy verified_by;
    if (counter.present) {
        signing_time = signify_countersignature(counter, signed_data.signer, pool, roots, token_certificates,
                                                verified_by.countersigner);
        verified_by.countersigner_digest = countersigner_digest(counter);
    }
    verified_by.file_digest = indirect_alg.name;
    verified_by.signer_digest = signer_alg.name;

    // AuthenticodeSignerInfo._verify_issuer: a signer certificate with the "lifetime signing"
    // extended key usage is checked at the present time even when there is a timestamp.
    const auto time_for = [&](X509* candidate) {
        bool present = false;
        const std::vector<std::string> usages = extended_key_usages(candidate, present);
        if (!signing_time || has_usage(usages, kEkuLifetimeSigning)) return now;
        return *signing_time;
    };
    verified_by.signer = index_in(pool, verify_signer(signed_data.signer, pool, roots, time_for, kEkuCodeSigning,
                                                      "code signing", "AuthenticodeSignerInfo"));
    return verified_by;
}

// ---- the reference's own checks after signify (signature.py) ----------------------------

// _signing_time / _countersigner_trusted: the countersignature time, used only if the
// countersigner chains to the pinned store with the time-stamping usage at that time and
// without MD2/MD5 in the path.
// WHICH certificate is "the countersigner" here: the reference looks it up again by issuer
// name and serial number and takes the first match (signature.py:333, _find_cert 297-301),
// which need not be the one whose key verified the countersignature. D-19: by default
// (shipped) the certificate that verified it (`verified_index`, from signify_verify) is
// the one whose chain and usage are checked; the reference's lookup only with the parity
// switch `second_lookup`. The timestamp decides whether an expired signer still counts.
std::optional<std::int64_t> trusted_signing_time(const SignedData& primary, const std::vector<X509*>& primary_certs,
                                                 const Roots& roots, bool second_lookup,
                                                 std::ptrdiff_t verified_index, std::string& chain_text) {
    const Countersignature counter = read_countersignature(primary.signer);
    if (!counter.present) return std::nullopt;
    std::vector<X509Ptr> token_certificates;
    std::vector<X509*> pool;
    if (counter.rfc3161) {
        token_certificates = load_certificates(counter.token.certs);
        pool = raw(token_certificates);
    }
    // `verified_index` counts in the set the countersigner was searched in; that set is the
    // front of `pool` in both cases (the token's certificates, or the signature's own).
    const std::size_t searched = counter.rfc3161 ? token_certificates.size() : primary_certs.size();
    if (counter.rfc3161 && token_certificates.size() != counter.token.certs.size()) return std::nullopt;
    pool.insert(pool.end(), primary_certs.begin(), primary_certs.end());
    X509* certificate = nullptr;
    if (second_lookup) {
        const std::vector<X509*> found = find_certificates(pool, counter.signer);
        if (!found.empty()) certificate = found.front();
    } else if (verified_index >= 0 && static_cast<std::size_t>(verified_index) < searched) {
        certificate = pool[static_cast<std::size_t>(verified_index)];
    }
    if (certificate == nullptr) return std::nullopt;
    std::vector<X509*> others;
    for (X509* other : pool) {
        if (other != certificate) others.push_back(other);
    }
    std::vector<X509Ptr> chain;
    std::string error;
    if (!build_chain(certificate, others, roots, counter.time, chain, error) || path_uses_weak_hash(chain)) {
        return std::nullopt;
    }
    chain_text = detail::describe_chain(raw(chain));
    bool present = false;
    if (!has_usage(extended_key_usages(certificate, present), kEkuTimeStamping)) return std::nullopt;
    return counter.time;
}

struct Decision {
    bool allowed = false;
    std::string reason;
};

// signature.py publisher_decision. Kept as it is in the reference, including this: of two
// allowlisted intermediates with the same CN, only the FIRST is ever compared.
Decision publisher_decision(X509* leaf, X509* issuer, const Policy& policy) {
    const std::optional<std::string> cn = name_field(X509_get_subject_name(leaf), NID_commonName);
    const std::optional<std::string> org = name_field(X509_get_subject_name(leaf), NID_organizationName);
    const std::optional<std::string> issuer_cn = name_field(X509_get_subject_name(issuer), NID_commonName);
    const auto in = [](const std::vector<std::string>& list, const std::optional<std::string>& value) {
        return value && std::find(list.begin(), list.end(), *value) != list.end();
    };
    if (in(policy.rejected_leaf_cns, cn) || in(policy.rejected_issuers, issuer_cn)) {
        return {false, "rejected chain (leaf " + py_repr(cn) + ", issuer " + py_repr(issuer_cn) + ")"};
    }
    if (!in(policy.publishers, cn) || !in(policy.publishers, org)) {
        return {false, "publisher not allowlisted (CN " + py_repr(cn) + ", O " + py_repr(org) + ")"};
    }
    const std::string spki = spki_sha256(issuer);
    for (const Intermediate& entry : policy.issuing_intermediates) {
        if (issuer_cn && entry.cn == *issuer_cn) {
            if (entry.spki_sha256.empty()) return {false, "issuing CA " + py_repr(issuer_cn) + " SPKI not pinned yet"};
            if (entry.spki_sha256 == spki) return {true, "issuer " + *issuer_cn + " (SPKI " + spki.substr(0, 16) + "...)"};
            return {false, "issuing CA " + py_repr(issuer_cn) + " SPKI mismatch (" + spki.substr(0, 16) + "...)"};
        }
    }
    return {false, "issuing CA " + py_repr(issuer_cn) + " not an allowlisted intermediate"};
}

Result make_result(const std::string& status, const std::string& detail) {
    Result out;
    out.status = status;
    out.detail = detail;
    if ((status == "valid" || status == "invalid") && detail.find(kRevocationNote) == std::string::npos) {
        out.detail = detail.empty() ? std::string(kRevocationNote) : detail + "; " + kRevocationNote;
    }
    return out;
}

std::vector<Bytes> table_entries(Bytes data, const Layout& layout) {
    // The reference's precheck has already required well-formed, aligned entries.
    std::vector<Bytes> out;
    std::uint64_t position = layout.table.start;
    while (position < layout.table.end) {
        std::uint32_t length = 0;
        if (!rd32(data, position, length) || length <= 8 || position + length > layout.table.end) {
            throw Fail{"SignedPEParseError", "Invalid length in certificate table header"};
        }
        out.push_back(data.subspan(static_cast<std::size_t>(position + 8), static_cast<std::size_t>(length - 8)));
        position += length + (8 - length % 8) % 8;
    }
    if (out.empty()) {
        throw Fail{"SignedPEParseError", "A SignedData structure was not found in the PE file's Certificate Table"};
    }
    return out;
}

Result verify_inner(Bytes data, const Options& options, const Precheck& checked) {
    const std::int64_t now = options.now_unix >= 0 ? options.now_unix : static_cast<std::int64_t>(std::time(nullptr));
    const Roots roots = load_roots(options.roots_pem);

    // PARSE: every entry of the certificate table (signature.py primary_signature).
    const Layout layout = signify_layout(data);
    // SG-6: precheck_data and signify each read the header; they must name the same table. By
    // reading no file makes them differ (SIGNATURE_INTEGRATION.md section 24); the fuzz target
    // stops if this ever fires.
    if (layout.table.start != checked.cert_offset || layout.table.end != data.size()) {
        return make_result("invalid", "the two readings of the executable's header disagree");
    }
    std::vector<SignedData> signatures;
    for (Bytes entry : table_entries(data, layout)) {
        signatures.push_back(
            parse_content_info(entry, DataKind::Authenticode, "ParseError", "ContentInfo does not contain SignedData"));
    }
    const SignedData& primary = signatures.front();

    // VERIFY: the first entry only (signify).
    VerifiedBy verified_by;
    try {
        verified_by = signify_verify(primary, data, layout, roots, now, !options.accept_malformed_page_hashes);
    } catch (const Fail& failure) {
        Result out = make_result("invalid", "signify: " + failure.cls + ": " + failure.text);
        out.error_class = failure.cls;
        return out;
    }

    // D-21 (SG-2): MD5 as the file's or the signer's digest: no cap in the shipped profile.
    if (!options.accept_md5 && (verified_by.file_digest == "md5" || verified_by.signer_digest == "md5")) {
        Result out = make_result("invalid", "the signature uses the MD5 digest, which is not accepted");
        out.file_digest = verified_by.file_digest;
        out.signer_digest = verified_by.signer_digest;
        return out;
    }

    // AFTER: the reference's own checks.
    const std::vector<X509Ptr> certificates = load_certificates(primary.certs);
    const std::vector<X509*> pool = raw(certificates);
    // the positions in `verified_by` were counted in an earlier load of the same list
    if (pool.size() != primary.certs.size()) throw Fail{"ValueError", "the certificate list changed between two loads"};
    // Which certificate is "the signer" from here on (usage, dates, chain, publisher name)?
    // The reference looks it up AGAIN by issuer name and serial number among the signature's
    // certificates and takes the FIRST match (signature.py:297-310), which need not be the
    // certificate whose key verified the signature (signify tries every match and is content
    // with any: pkcs7/signer_info.py:398-411). D-19: by default (shipped) the certificate
    // that verified is used; the reference's second lookup only with the parity switch.
    X509* leaf = nullptr;
    if (options.signer_by_second_lookup) {
        const std::vector<X509*> leaves = find_certificates(pool, primary.signer);
        if (!leaves.empty()) leaf = leaves.front();
    } else if (verified_by.signer >= 0 && static_cast<std::size_t>(verified_by.signer) < pool.size()) {
        leaf = pool[static_cast<std::size_t>(verified_by.signer)];
    }
    if (leaf == nullptr) throw Fail{"ValueError", "signer certificate not in the signature certificate set"};
    // a time-stamp that relies on MD5 is not trusted (D-21): the signer is judged at the present time
    const bool stamp_md5 = !options.accept_md5 && verified_by.countersigner_digest == "md5";
    std::string timestamp_chain;
    const std::optional<std::int64_t> signing_time =
        stamp_md5 ? std::optional<std::int64_t>()
                  : trusted_signing_time(primary, pool, roots, options.signer_by_second_lookup, verified_by.countersigner,
                                         timestamp_chain);

    // _leaf_checks
    bool eku_present = false;
    const std::vector<std::string> usages = extended_key_usages(leaf, eku_present);
    if (!eku_present) return make_result("invalid", "signer certificate has no EKU (code signing required)");
    if (!has_usage(usages, kEkuCodeSigning)) return make_result("invalid", "signer certificate EKU does not allow code signing");
    const std::int64_t when = signing_time ? *signing_time : now;
    std::int64_t not_before = 0;
    std::int64_t not_after = 0;
    if (!asn1_time_epoch(X509_get0_notBefore(leaf), not_before) || !asn1_time_epoch(X509_get0_notAfter(leaf), not_after)) {
        throw Fail{"ValueError", "the signer certificate's validity cannot be read"};
    }
    if (!(not_before <= when && when <= not_after)) {
        return make_result("invalid", std::string("signer certificate not valid at ") +
                                          (signing_time ? "timestamp" : "now") + " (" + iso_utc(when) + ")");
    }

    // _issuing_ca
    std::vector<X509Ptr> chain;
    std::string error;
    if (!build_chain(leaf, pool, roots, when, chain, error)) throw Fail{"PathBuildingError", error};
    if (path_uses_weak_hash(chain)) throw Fail{"PathValidationError", "the path uses a weak hash algorithm"};
    if (!has_usage(usages, kEkuCodeSigning)) throw Fail{"InvalidCertificateError", "not valid for the purpose of code signing"};
    if (chain.size() < 2) throw Fail{"ValueError", "leaf is directly a root"};
    X509* issuer = chain[1].get();

    // D-13 (off in parity): every further entry must verify like the first.
    if (options.verify_every_entry) {
        if (signatures.size() > kMaxEntriesWhenAllVerified) {
            return make_result("invalid", "more than " + std::to_string(kMaxEntriesWhenAllVerified) +
                                              " certificate table entries; not all can be verified");
        }
        for (std::size_t i = 1; i < signatures.size(); ++i) {
            try {
                // D-22 applies to every verified entry (the flag); D-21 too (SG-2b): a further
                // entry that uses MD5 is refused like the first.
                const VerifiedBy other =
                    signify_verify(signatures[i], data, layout, roots, now, !options.accept_malformed_page_hashes);
                if (!options.accept_md5 && (other.file_digest == "md5" || other.signer_digest == "md5")) {
                    throw Fail{"MD5", "the entry uses the MD5 digest, which is not accepted"};
                }
            } catch (const Fail& failure) {
                Result out = make_result("invalid", "certificate table entry " + std::to_string(i + 1) +
                                                        " does not verify (" + failure.cls + ": " + failure.text + ")");
                out.error_class = failure.cls;
                return out;
            }
        }
    }

    const Decision decision = publisher_decision(leaf, issuer, options.policy);
    Result out = make_result("valid", "signify OK (primary signature, pinned store); " + decision.reason);
    std::optional<std::string> publisher = name_field(X509_get_subject_name(leaf), NID_commonName);
    if (!publisher) publisher = name_field(X509_get_subject_name(leaf), NID_organizationName);
    out.has_publisher = publisher.has_value();
    out.publisher = publisher.value_or("");
    out.publisher_allowed = decision.allowed;
    out.issuer = name_field(X509_get_subject_name(issuer), NID_commonName).value_or("");
    out.issuer_spki_sha256 = spki_sha256(issuer);
    out.timestamp = signing_time ? iso_utc(*signing_time) : std::string();
    out.certificate_table_verified = true;
    out.checked_at_unix = when;
    out.file_digest = verified_by.file_digest;
    out.signer_digest = verified_by.signer_digest;
    out.countersigner_digest = verified_by.countersigner_digest;
    out.signer_chain = detail::describe_chain(raw(chain));
    out.timestamp_chain = signing_time ? timestamp_chain : std::string();
    out.cert_offset = checked.cert_offset;
    out.cert_size = checked.cert_size;
    return out;
}

}  // namespace

std::string sha256_hex(std::span<const std::uint8_t> data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &length, EVP_sha256(), nullptr) != 1) return std::string();
    return hex(Bytes(out.data(), length));
}

Precheck precheck(std::span<const std::uint8_t> data) {
    Precheck out;
    const auto answer = [&out](const char* status, std::string detail) {
        out.status = status;
        out.detail = std::move(detail);
        return out;
    };
    const std::uint64_t size = data.size();
    const Bytes head = data.first(std::min<std::size_t>(data.size(), 4096));
    if (head.size() < 0x40 || head[0] != 'M' || head[1] != 'Z') return answer("invalid", "not a PE file");
    std::uint32_t e_lfanew = 0;
    rd32(head, 0x3C, e_lfanew);
    const std::uint64_t pe = e_lfanew;
    if (pe + 24 + 2 > head.size() || head[pe] != 'P' || head[pe + 1] != 'E' || head[pe + 2] != 0 || head[pe + 3] != 0) {
        return answer("invalid", "no PE signature");
    }
    const std::uint64_t optional = pe + 24;
    std::uint32_t magic = 0;
    rd16(head, optional, magic);
    std::uint64_t count_at = 0;
    std::uint64_t directories = 0;
    if (magic == 0x10B) {
        count_at = optional + 92;
        directories = optional + 96;
    } else if (magic == 0x20B) {
        count_at = optional + 108;
        directories = optional + 112;
    } else {
        char text[64];
        std::snprintf(text, sizeof text, "unknown optional header magic 0x%04x", static_cast<unsigned>(magic));
        return answer("invalid", text);
    }
    if (directories + 5 * 8 > head.size()) return answer("invalid", "optional header truncated");
    std::uint32_t count = 0;
    rd32(head, count_at, count);
    if (count < 5) return answer("unsigned", "no security data directory");
    std::uint32_t cert_off = 0;
    std::uint32_t cert_size = 0;
    rd32(head, directories + 4 * 8, cert_off);
    rd32(head, directories + 4 * 8 + 4, cert_size);
    if (cert_off == 0 || cert_size == 0) return answer("unsigned", "no certificate table");
    if (cert_size > kMaxSignatureBytes) {
        return answer("invalid", "certificate table " + std::to_string(cert_size) + " bytes is over the 1 MiB limit");
    }
    const std::uint64_t table_end = std::uint64_t{cert_off} + cert_size;
    if (table_end > size) return answer("invalid", "certificate table runs past the end of the file");
    if (table_end != size) {
        return answer("invalid", std::to_string(size - table_end) +
                                     " bytes follow the certificate table (data outside the signed digest)");
    }
    const Bytes table = data.subspan(cert_off, cert_size);
    std::size_t entries = 0;
    std::size_t pos = 0;
    Bytes primary;
    while (pos + 8 <= table.size()) {
        std::uint32_t length = 0;
        std::uint32_t revision = 0;
        std::uint32_t type = 0;
        rd32(table, pos, length);
        rd16(table, pos + 4, revision);
        rd16(table, pos + 6, type);
        if (length < 12 || pos + std::uint64_t{length} > table.size()) {
            return answer("invalid", "bad WIN_CERTIFICATE dwLength " + std::to_string(length));
        }
        if (revision != 0x0200 || type != 0x0002) {
            return answer("invalid", "WIN_CERTIFICATE is not revision 2.0 PKCS#7 signed data");
        }
        const Bytes body = table.subspan(pos + 8, length - 8);
        // Only 30 82 (a two-byte DER length) is accepted, so a PKCS#7 blob over 64 KiB is refused.
        if (body[0] != 0x30 || body[1] != 0x82) {
            return answer("invalid", "PKCS#7 body is not a DER SEQUENCE (30 82 LL LL)");
        }
        const std::size_t der_length = 4 + ((static_cast<std::size_t>(body[2]) << 8) | body[3]);
        if (der_length > body.size() || body.size() - der_length > 7 || !all_zero(body.subspan(der_length))) {
            return answer("invalid", "PKCS#7 DER length does not match dwLength (truncated or padded)");
        }
        if (entries == 0) primary = body.first(der_length);
        ++entries;
        const std::size_t aligned = (static_cast<std::size_t>(length) + 7) & ~static_cast<std::size_t>(7);
        const std::size_t pad_start = pos + length;
        const std::size_t pad_end = std::min(pos + aligned, table.size());
        if (!all_zero(table.subspan(pad_start, pad_end - pad_start))) {
            return answer("invalid", "non-zero alignment bytes in the certificate table");
        }
        pos += aligned;
    }
    if (entries == 0) return answer("invalid", "empty certificate table");
    if (pos < table.size()) return answer("invalid", "trailing bytes inside the certificate table");
    out.status = "ok";
    out.cert_offset = cert_off;
    out.cert_size = cert_size;
    out.entries = entries;
    out.primary_der = primary;
    return out;
}

bool load_roots_file(const std::string& path, Options& options) {
    options.roots_loaded = false;
    options.roots_pem.clear();
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        options.roots_error = "cannot open " + path;
        return false;
    }
    options.roots_pem.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    if (file.bad()) {
        options.roots_pem.clear();
        options.roots_error = "cannot read " + path;
        return false;
    }
    options.roots_error.clear();
    options.roots_loaded = true;
    return true;
}

Result verify(std::span<const std::uint8_t> data, const Options& options) {
    // core.py only verifies a file that fits in the analysed buffer; the caller enforces
    // that. A larger buffer handed in here is refused the same way.
    if (data.size() > kMaxVerifyBytes) {
        return make_result("unavailable", "file is bigger than the analysed buffer; signature not checked");
    }
    const Precheck checked = precheck(data);
    if (checked.status != "ok") return make_result(checked.status, checked.detail);
    const UnreadFieldsScope unread_fields(options.accept_unread_fields, options.accept_long_lengths);

    // signature.py load_pinned_store
    if (options.pinned_sha256.empty()) {
        return make_result("unavailable", "pinned Authenticode root store not provisioned (PINNED_ROOTS_SHA256 unset)");
    }
    if (!options.roots_loaded) return make_result("unavailable", "pinned root store missing: " + options.roots_error);
    const std::string digest = sha256_hex(
        Bytes(reinterpret_cast<const std::uint8_t*>(options.roots_pem.data()), options.roots_pem.size()));
    if (digest.empty() || digest != lower(options.pinned_sha256)) {
        return make_result("unavailable", "pinned root store sha256 mismatch (" + digest.substr(0, 16) + "...)");
    }

    Result out;
    try {
        out = verify_inner(data, options, checked);
    } catch (const Fail& failure) {
        out = make_result("unavailable", "verification error: " + failure.cls + ": " + failure.text);
        out.error_class = failure.cls;
    } catch (const OverBudget&) {
        // The reference would be past its 2-second limit: 'unavailable' (signature.py:539-543).
        out = make_result("unavailable", "page-hash work over the limit of " + std::to_string(kPageHashBudgetFactor) +
                                             " file sizes; signature not checked");
        out.error_class = "OverBudget";
    } catch (const std::exception& error) {
        out = make_result("unavailable", std::string("verification error: ") + error.what());
        out.error_class = "exception";
    }
    ERR_clear_error();
    return out;
}

// ---- for the second check (second_check.cpp); declared in src/signature/internal.hpp ----
namespace detail {

bool primary_view(std::span<const std::uint8_t> data, PrimaryView& out) {
    try {
        const Precheck checked = precheck(data);
        if (checked.status != "ok") return false;
        const UnreadFieldsScope strict(false, false);
        const SignedData primary =
            parse_content_info(checked.primary_der, DataKind::Authenticode, "ParseError", "not SignedData");
        const IndirectData indirect = parse_indirect_data(primary);
        const DigestAlg algorithm = digest_algorithm(indirect.digest_alg, "SpcIndirectDataContent.digestAlgorithm");
        out.entry_der = checked.primary_der;
        out.content_whole = primary.content.whole;
        out.content_inside = primary.content.content;
        out.digest_name = algorithm.name;
        out.signed_digest.assign(indirect.digest.begin(), indirect.digest.end());
        out.image_digest = fingerprint(data, signify_layout(data), algorithm.md, 0, data.size(), 0);
        return true;
    } catch (const Fail&) {
        return false;
    } catch (const OverBudget&) {
        return false;
    }
}

}  // namespace detail

}  // namespace mie::signature
