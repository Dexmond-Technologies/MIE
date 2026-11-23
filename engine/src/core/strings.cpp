#include "mie/strings.hpp"

#include <algorithm>
#include <string_view>

namespace mie::strings {

namespace {

bool printable(std::uint8_t c) { return c >= 0x20 && c <= 0x7E; }

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// \w for ASCII text: letters, digits, underscore.
bool word(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool base64_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

// True if `text` continues with `needle` at `at`, ignoring ASCII case. `needle` is lower-case.
bool at_nocase(std::span<const char> text, std::size_t at, std::string_view needle) {
    if (at > text.size() || text.size() - at < needle.size()) {
        return false;
    }
    for (std::size_t i = 0; i < needle.size(); ++i) {
        if (lower(text[at + i]) != needle[i]) {
            return false;
        }
    }
    return true;
}

bool contains_nocase(std::span<const char> text, std::string_view needle) {
    if (needle.empty() || text.size() < needle.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= text.size(); ++i) {
        if (at_nocase(text, i, needle)) {
            return true;
        }
    }
    return false;
}

// The -enc ... -EncodedCommand token of the reference:
//   (?<![\w-])--?enc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?(?![\w-])
// One or two dashes not preceded by a word character or a dash; "enc" followed by any
// prefix of "odedcommand"; then not a word character and not a dash. Only the longest
// matching prefix can satisfy the last condition (a shorter one is followed by a letter).
bool enc_token_at(std::span<const char> text, std::size_t after_dashes) {
    static constexpr std::string_view rest = "odedcommand";
    if (!at_nocase(text, after_dashes, "enc")) {
        return false;
    }
    std::size_t pos = after_dashes + 3;
    std::size_t k = 0;
    while (k < rest.size() && pos < text.size() && lower(text[pos]) == rest[k]) {
        ++pos;
        ++k;
    }
    return pos == text.size() || !(word(text[pos]) || text[pos] == '-');
}

bool has_enc_token(std::span<const char> text) {
    for (std::size_t s = 0; s < text.size(); ++s) {
        if (text[s] != '-') {
            continue;
        }
        if (s > 0 && (word(text[s - 1]) || text[s - 1] == '-')) {
            continue;
        }
        // "--?": two dashes first, then one.
        if (s + 1 < text.size() && text[s + 1] == '-' && enc_token_at(text, s + 2)) {
            return true;
        }
        if (enc_token_at(text, s + 1)) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool has_powershell(std::span<const char> text) {
    return contains_nocase(text, "powershell") || contains_nocase(text, "pwsh") || has_enc_token(text);
}

bool has_suspicious_api(std::span<const char> text) {
    return contains_nocase(text, "virtualalloc") || contains_nocase(text, "createremotethread") ||
           contains_nocase(text, "writeprocessmemory") || contains_nocase(text, "ldrloaddll") ||
           contains_nocase(text, "reflectiveloader");
}

bool has_b64_executable(std::span<const char> text) {
    // TVqQAAMAAAA4A[A-Za-z0-9+/=]+ : case-sensitive, at least one base64 character after it.
    static constexpr std::string_view marker = "TVqQAAMAAAA4A";
    if (text.size() <= marker.size()) {
        return false;
    }
    for (std::size_t i = 0; i + marker.size() < text.size(); ++i) {
        if (std::equal(marker.begin(), marker.end(), text.begin() + static_cast<std::ptrdiff_t>(i)) &&
            base64_char(text[i + marker.size()])) {
            return true;
        }
    }
    return false;
}

bool has_obfuscated_script(std::span<const char> text) {
    // (\[char\[\]\]|Invoke-Expression|iex\s*\(|FromBase64String|Bypass\s+-noprofile), ignoring case.
    // Inside a run the only white-space character is the space.
    if (contains_nocase(text, "[char[]]") || contains_nocase(text, "invoke-expression") ||
        contains_nocase(text, "frombase64string")) {
        return true;
    }
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (at_nocase(text, i, "iex")) {
            std::size_t pos = i + 3;
            while (pos < text.size() && text[pos] == ' ') {
                ++pos;
            }
            if (pos < text.size() && text[pos] == '(') {
                return true;
            }
        }
        if (at_nocase(text, i, "bypass")) {
            std::size_t pos = i + 6;
            std::size_t spaces = 0;
            while (pos < text.size() && text[pos] == ' ') {
                ++pos;
                ++spaces;
            }
            if (spaces > 0 && at_nocase(text, pos, "-noprofile")) {
                return true;
            }
        }
    }
    return false;
}

Indicators scan(std::span<const std::uint8_t> data, const std::vector<Span>& skip_api_spans) {
    Indicators found;
    std::vector<Span> skip(skip_api_spans);
    std::sort(skip.begin(), skip.end());

    const auto apply = [&](std::span<const char> text, bool counts_for_api) {
        ++found.string_count;
        if (!found.powershell && has_powershell(text)) found.powershell = true;
        if (!found.b64_executable && has_b64_executable(text)) found.b64_executable = true;
        if (!found.obfuscated_script && has_obfuscated_script(text)) found.obfuscated_script = true;
        if (counts_for_api && !found.suspicious_api && has_suspicious_api(text)) found.suspicious_api = true;
    };

    // ASCII runs: maximal runs of printable bytes, at least kMinRunLength long.
    const std::size_t size = data.size();
    std::size_t i = 0;
    while (i < size) {
        if (!printable(data[i])) {
            ++i;
            continue;
        }
        std::size_t end = i;
        while (end < size && printable(data[end])) {
            ++end;
        }
        if (end - i >= kMinRunLength) {
            const bool skipped = std::binary_search(skip.begin(), skip.end(), Span{i, end});
            apply(std::span<const char>(reinterpret_cast<const char*>(data.data()) + i, end - i), !skipped);
        }
        i = end;
    }

    // UTF-16LE runs, as the reference's (?:[ -~]\x00){5,} finds them: from the left, at any
    // byte offset, as many (printable byte, zero byte) pairs as possible; a match of at least
    // kMinRunLength pairs is taken and the search goes on after it, otherwise one byte further.
    std::vector<char> text;
    i = 0;
    while (i + 1 < size) {
        std::size_t pairs = 0;
        while (i + 2 * pairs + 1 < size && printable(data[i + 2 * pairs]) && data[i + 2 * pairs + 1] == 0) {
            ++pairs;
        }
        if (pairs >= kMinRunLength) {
            text.resize(pairs);
            for (std::size_t p = 0; p < pairs; ++p) {
                text[p] = static_cast<char>(data[i + 2 * p]);
            }
            apply(std::span<const char>(text.data(), text.size()), true);
            i += 2 * pairs;
        } else {
            ++i;
        }
    }
    return found;
}

}  // namespace mie::strings
