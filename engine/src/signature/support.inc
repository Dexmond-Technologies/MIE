// Moved unchanged out of authenticode.cpp (reviewer's ruling on the line limit, 2026-11-23):
// OpenSSL owner types and date arithmetic; nothing here reads bytes of the scanned file.
// Included inside authenticode.cpp's anonymous namespace.

// ---- OpenSSL owners --------------------------------------------------------------------
struct X509Free { void operator()(X509* p) const { X509_free(p); } };
struct StoreFree { void operator()(X509_STORE* p) const { X509_STORE_free(p); } };
struct StoreCtxFree { void operator()(X509_STORE_CTX* p) const { X509_STORE_CTX_free(p); } };
struct MdCtxFree { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct BioFree { void operator()(BIO* p) const { BIO_free(p); } };
struct NameFree { void operator()(X509_NAME* p) const { X509_NAME_free(p); } };
struct IntFree { void operator()(ASN1_INTEGER* p) const { ASN1_INTEGER_free(p); } };
struct TimeFree { void operator()(ASN1_TIME* p) const { ASN1_TIME_free(p); } };
struct EkuFree { void operator()(EXTENDED_KEY_USAGE* p) const { EXTENDED_KEY_USAGE_free(p); } };
struct StackFree { void operator()(STACK_OF(X509)* p) const { sk_X509_free(p); } };  // not the certificates
using X509Ptr = std::unique_ptr<X509, X509Free>;
using StorePtr = std::unique_ptr<X509_STORE, StoreFree>;

std::int64_t days_from_civil(std::int64_t y, int m, int d) {
    y -= m <= 2 ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t yoe = y - era * 400;
    const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

std::string iso_utc(std::int64_t epoch) {
    std::int64_t days = epoch / 86400;
    std::int64_t rest = epoch % 86400;
    if (rest < 0) {
        rest += 86400;
        days -= 1;
    }
    // civil from days
    const std::int64_t z = days + 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const std::int64_t doe = z - era * 146097;
    const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    const int day = static_cast<int>(doy - (153 * mp + 2) / 5 + 1);
    const int month = static_cast<int>(mp < 10 ? mp + 3 : mp - 9);
    const long long year = static_cast<long long>(yoe + era * 400 + (month <= 2 ? 1 : 0));
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%04lld-%02d-%02dT%02d:%02d:%02d+00:00", year, month, day,
                  static_cast<int>(rest / 3600), static_cast<int>((rest % 3600) / 60), static_cast<int>(rest % 60));
    return buffer;
}
