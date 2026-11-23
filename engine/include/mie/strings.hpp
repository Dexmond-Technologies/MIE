// String runs and the four scored string indicators, written to agree with the Python
// reference (dexmond_mie/utils.py, StringExtractor, and core.py, _api_names_outside_spans).
//
// The reference finds printable ASCII runs and UTF-16LE runs of at least five characters
// and applies regular expressions to each run. Only four of its patterns feed the score:
// powershell, suspicious_api, b64_executable and obfuscated_script. They are implemented
// here as explicit matchers, not through a regular-expression library: the patterns are
// fixed, the matchers run in linear time on hostile input, and CI compares them with the
// reference's own regular expressions on generated cases (tests/strings_parity.py).
//
// The reference's other patterns (addresses, URLs, e-mail, base64 runs) are report-only
// and are not part of this module.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace mie::strings {

inline constexpr std::size_t kMinRunLength = 5;

struct Indicators {
    bool powershell = false;         // "powershell", "pwsh", or an -enc ... -EncodedCommand token
    bool suspicious_api = false;     // one of five API names, outside the given import-name spans
    bool b64_executable = false;     // the reference's base64 marker of an executable header
    bool obfuscated_script = false;  // one of five script-obfuscation markers
    std::size_t string_count = 0;    // ASCII runs plus UTF-16 runs (the reference's string_count)
    bool operator==(const Indicators&) const = default;
};

// A half-open range of file offsets [first, second).
using Span = std::pair<std::uint64_t, std::uint64_t>;

// Scans `data`. `skip_api_spans`: ASCII runs whose offsets are exactly one of these spans do
// not count for suspicious_api (the name entries of imports the import analysis has already
// scored); UTF-16 runs always count. The vector need not be sorted.
Indicators scan(std::span<const std::uint8_t> data, const std::vector<Span>& skip_api_spans = {});

// The matchers on one run of text, exposed for tests.
bool has_powershell(std::span<const char> text);
bool has_suspicious_api(std::span<const char> text);
bool has_b64_executable(std::span<const char> text);
bool has_obfuscated_script(std::span<const char> text);

}  // namespace mie::strings
