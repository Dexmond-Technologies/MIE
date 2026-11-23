#include "mie/engine.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <initializer_list>
#include <memory>
#include <optional>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>

#include "mie/entropy.hpp"
#include "mie/hash.hpp"
#include "mie/io.hpp"
#include "mie/pe.hpp"
#include "mie/pe_analysis.hpp"
#include "mie/strings.hpp"
#include "mie/version.hpp"

namespace mie {

namespace {

// The limits of dexmond_mie/core.py the pipeline reads from the scoring table.
constexpr const char* kNeededLimits[] = {
    "MAX_ANALYSIS_BYTES",   "MAX_SCAN_BYTES",          "OVERSIZE_WINDOW_BYTES",
    "SLIDING_HIGH_SHARE",   "REDUCED_ENTROPY_WEIGHT",  "OVERLAY_ENTROPY_MIN_BYTES",
    "MAX_ARCHIVE_MEMBERS",  "MAX_ARCHIVE_MEMBER_BYTES", "MAX_ARCHIVE_TOTAL_BYTES",
    "MAX_ARCHIVE_DEPTH",    "MALICIOUS_FLOOR",         "MAX_TAR_PADDING",
    "ZIP_DESCRIPTOR_SLACK", "MAX_UNCOVERED_ZIP_BYTES", "MAX_UNCOVERED_TAR_HEADER_BYTES",
};

std::string join(const std::vector<std::string>& parts, const char* separator, std::size_t at_most = 0) {
    std::string out;
    std::size_t count = 0;
    for (const std::string& part : parts) {
        if (at_most != 0 && count == at_most) {
            break;
        }
        if (count != 0) {
            out += separator;
        }
        out += part;
        ++count;
    }
    return out;
}

std::string two_decimals(double value) {
    char buffer[64];
    std::snprintf(buffer, sizeof buffer, "%.2f", value);
    return buffer;
}

bool contains(const std::string& text, const char* needle) { return text.find(needle) != std::string::npos; }

bool starts_with(const std::string& text, const char* prefix) { return text.rfind(prefix, 0) == 0; }

bool bytes_at(std::span<const std::uint8_t> data, std::size_t offset, std::string_view magic) {
    if (offset > data.size() || data.size() - offset < magic.size()) {
        return false;
    }
    for (std::size_t i = 0; i < magic.size(); ++i) {
        if (data[offset + i] != static_cast<std::uint8_t>(magic[i])) {
            return false;
        }
    }
    return true;
}

Hashes hashes_of(std::span<const std::uint8_t> data) {
    TripleHasher hasher;
    hasher.update(data);
    return hasher.finish();
}

enum class Reputation { None, Malicious, Trusted };

// reputation.lookup: the known-bad list is asked first, then the trusted list.
Reputation look_up(const std::map<std::string, std::string>& malicious,
                   const std::map<std::string, std::string>& trusted, const std::string& sha256,
                   std::string& label) {
    if (sha256.empty()) {
        return Reputation::None;
    }
    if (const auto it = malicious.find(sha256); it != malicious.end()) {
        label = it->second;
        return Reputation::Malicious;
    }
    if (const auto it = trusted.find(sha256); it != trusted.end()) {
        label = it->second;
        return Reputation::Trusted;
    }
    return Reputation::None;
}

std::string lower_ascii(std::string text) {
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

void load_list(const nlohmann::json& document, const char* key, std::map<std::string, std::string>& out) {
    if (!document.is_object() || !document.contains(key) || !document.at(key).is_object()) {
        return;
    }
    for (auto it = document.at(key).begin(); it != document.at(key).end(); ++it) {
        out[lower_ascii(it.key())] = it.value().is_string() ? it.value().get<std::string>() : std::string();
    }
}

// core._add_yara_findings: a critical rule is its own category; every other rule scores
// by its severity, in the 'imports' family when its category is "imports".
void add_rule_findings(Scorer& scorer, const ScoringTable& table, const std::vector<rules::RuleMatch>& matches,
                       const std::string& where) {
    for (const rules::RuleMatch& match : matches) {
        const std::string& description = match.description.empty() ? match.rule : match.description;
        if (match.severity == "critical") {
            scorer.add_finding("critical_yara",
                               "Critical YARA match" + where + ": " + match.rule + " (" + description + ")");
            continue;
        }
        int weight = 0;
        if (const auto it = table.rule_severity_weights.find(match.severity); it != table.rule_severity_weights.end()) {
            weight = it->second;
        } else if (const auto fallback = table.weights.find("yara_match"); fallback != table.weights.end()) {
            weight = fallback->second;
        } else {
            weight = table.default_weight;
        }
        scorer.add_finding("yara_match", "YARA match" + where + ": " + match.rule + " (" + description + ")",
                           weight, match.category == "imports" ? std::string("imports") : std::string());
    }
}

std::vector<std::string> packer_rule_names(const std::vector<rules::RuleMatch>& matches) {
    std::vector<std::string> names;
    for (const rules::RuleMatch& match : matches) {
        if (match.category == "packer") {
            names.push_back(match.rule);
        }
    }
    return names;
}

std::vector<rules::RuleMatch> without_packer_rules(const std::vector<rules::RuleMatch>& matches) {
    std::vector<rules::RuleMatch> out;
    for (const rules::RuleMatch& match : matches) {
        if (match.category != "packer") {
            out.push_back(match);
        }
    }
    return out;
}

// core._minor_chain_category
const char* minor_chain_category(const std::string& chain) {
    return starts_with(chain, "Dynamic API Resolution") ? "dynamic_resolution_chain" : "api_chain_minor";
}

bool in_set(const std::vector<std::size_t>& set, std::size_t value) {
    return std::find(set.begin(), set.end(), value) != set.end();
}

std::string section_name(const pe::Analysis& analysis, std::size_t index) {
    return index < analysis.section_names.size() ? analysis.section_names[index] : std::string();
}

}  // namespace

SignatureResult UnavailableSignatureVerifier::verify(std::span<const std::uint8_t> /*data*/) const {
    return SignatureResult{};
}

std::string detect_compressed_format(std::span<const std::uint8_t> data) {
    // utils.detect_compressed_format and COMPRESSED_MAGICS (dexmond_mie/utils.py:17-36), in its order.
    if (bytes_at(data, 0, "RIFF") &&
        (bytes_at(data, 8, "WEBP") || bytes_at(data, 8, "AVI ") || bytes_at(data, 8, "WAVE"))) {
        return "riff";
    }
    struct Magic {
        std::size_t offset;
        std::string_view bytes;
        const char* name;
    };
    using namespace std::string_view_literals;
    static const Magic magics[] = {
        {0, "PK\x03\x04"sv, "zip"},   {0, "PK\x05\x06"sv, "zip"},        {0, "PK\x07\x08"sv, "zip"},
        {0, "\x1f\x8b"sv, "gzip"},    {0, "BZh"sv, "bzip2"},             {0, "\xfd" "7zXZ\x00"sv, "xz"},
        {0, "7z\xbc\xaf\x27\x1c"sv, "7z"}, {0, "Rar!\x1a\x07"sv, "rar"}, {0, "\x28\xb5\x2f\xfd"sv, "zstd"},
        {0, "MSCF"sv, "cab"},         {0, "\x5d\x00\x00"sv, "lzma"},     {0, "\x89PNG\r\n\x1a\n"sv, "png"},
        {0, "\xff\xd8\xff"sv, "jpeg"}, {0, "GIF87a"sv, "gif"},           {0, "GIF89a"sv, "gif"},
        {0, "%PDF-"sv, "pdf"},        {0, "OggS"sv, "ogg"},              {0, "fLaC"sv, "flac"},
        {0, "ID3"sv, "mp3"},          {4, "ftyp"sv, "mp4"},              {0, "wOFF"sv, "woff"},
        {0, "wOF2"sv, "woff2"},       {257, "ustar"sv, "tar"},
    };
    for (const Magic& magic : magics) {
        if (bytes_at(data, magic.offset, magic.bytes)) {
            return magic.name;
        }
    }
    return {};
}

bool is_pe_data(std::span<const std::uint8_t> data) {
    if (data.size() < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        return false;
    }
    const std::uint64_t e_lfanew = static_cast<std::uint64_t>(data[0x3c]) | (static_cast<std::uint64_t>(data[0x3d]) << 8) |
                                   (static_cast<std::uint64_t>(data[0x3e]) << 16) |
                                   (static_cast<std::uint64_t>(data[0x3f]) << 24);
    if (e_lfanew > data.size()) {
        return false;
    }
    using namespace std::string_view_literals;
    return bytes_at(data, static_cast<std::size_t>(e_lfanew), "PE\x00\x00"sv);
}

struct Engine::Outcome {
    ScanResult result;
    bool archive_not_unpacked = false;  // an archive at the depth limit: not opened
    bool has_archive = false;           // the reference's details['archive'] exists
    bool archive_complete = false;      // its coverage is complete
};

Engine::Engine(const ScoringTable& table, const rules::RuleSet& rules, std::string_view reputation_json,
               EngineOptions options, const SignatureVerifier* verifier)
    : table_(table), rules_(rules), options_(std::move(options)), verifier_(verifier) {
    for (const char* name : kNeededLimits) {
        if (table_.limits.find(name) == table_.limits.end()) {
            unusable_ = std::string("the scoring table has no limit ") + name;
            return;
        }
    }
    // The archive readers get the reference's limits from the same table.
    options_.archive.max_members_per_archive = limit_int("MAX_ARCHIVE_MEMBERS");
    options_.archive.max_member_bytes = limit_int("MAX_ARCHIVE_MEMBER_BYTES");
    options_.archive.max_tar_padding = limit_int("MAX_TAR_PADDING");
    options_.archive.zip_descriptor_slack = limit_int("ZIP_DESCRIPTOR_SLACK");
    options_.archive.max_uncovered_zip_bytes = limit_int("MAX_UNCOVERED_ZIP_BYTES");
    options_.archive.max_uncovered_tar_header_bytes = limit_int("MAX_UNCOVERED_TAR_HEADER_BYTES");

    // reputation._load: a list that cannot be read is an empty list.
    const nlohmann::json document = nlohmann::json::parse(reputation_json.begin(), reputation_json.end(), nullptr, false);
    if (!document.is_discarded()) {
        load_list(document, "malicious", malicious_);
        load_list(document, "trusted", trusted_);
    }
}

bool Engine::usable(std::string& why) const {
    why = unusable_;
    return unusable_.empty();
}

double Engine::limit(const char* name) const {
    const auto it = table_.limits.find(name);
    return it != table_.limits.end() ? it->second : 0.0;
}

std::int64_t Engine::limit_int(const char* name) const { return static_cast<std::int64_t>(limit(name)); }

archive::Budget Engine::new_budget() const {
    archive::Budget budget;
    budget.members = limit_int("MAX_ARCHIVE_MEMBERS");
    budget.bytes = limit_int("MAX_ARCHIVE_TOTAL_BYTES");
    budget.produced = 0;
    return budget;
}

ScanResult Engine::base_result(const Hashes& hashes, std::uint64_t size, std::string display_name) const {
    ScanResult result;
    result.subject.kind = SubjectKind::File;
    result.subject.sha256 = hashes.sha256;
    result.subject.display_name = std::move(display_name);
    result.hashes = hashes;
    result.size = size;
    result.engine_version = kEngineVersion;
    result.profile = table_.profile;
    result.rules_state = rules_.state();
    result.rules_sha256 = rules_.sha256();
    return result;
}

// Sets the state. The score and the verdict stay what the reference computes, also when
// the scan was not complete (parity); the shipped profile's option changes the verdict text.
void Engine::finish(ScanResult& result, const std::vector<std::string>& incomplete) const {
    std::vector<std::string> reasons;
    if (rules_.state() == RulesState::Degraded) {
        reasons.emplace_back("rule set DEGRADED: some rule files were left out");
    } else if (rules_.state() == RulesState::Off) {
        reasons.emplace_back("rule set OFF: no rules were applied");
    }
    reasons.insert(reasons.end(), incomplete.begin(), incomplete.end());
    if (reasons.empty()) {
        result.state = ScanState::Scanned;
        result.reason.clear();
        return;
    }
    result.state = ScanState::NotFullyScanned;
    result.reason = join(reasons, "; ");
    if (options_.never_clean_when_incomplete && result.verdict == table_.label_clean) {
        result.verdict = kNotFullyScannedVerdict;
    }
}

ScanResult Engine::scan_bytes(std::span<const std::uint8_t> data, std::string display_name, int depth,
                              archive::Budget& budget) const {
    if (!unusable_.empty()) {
        ScanResult refused = base_result(Hashes{}, data.size(), std::move(display_name));
        refused.state = ScanState::NotScanned;
        refused.reason = unusable_;
        return refused;
    }
    return scan_core(data, hashes_of(data), std::move(display_name), depth, budget).result;
}

ScanResult Engine::scan_file(const std::filesystem::path& path) const {
    const std::u8string name_utf8 = path.filename().u8string();
    std::string name(name_utf8.begin(), name_utf8.end());

    const auto not_scanned = [&](const std::string& reason, const Hashes& hashes, std::uint64_t size) {
        ScanResult refused = base_result(hashes, size, name);
        refused.state = ScanState::NotScanned;
        refused.reason = reason;
        return refused;
    };
    if (!unusable_.empty()) {
        return not_scanned(unusable_, Hashes{}, 0);
    }

    // One open, one handle (review finding S-10). The reference's error returns
    // (core.py:96-97, 141-143, 400-402) become "not scanned" with the reason's class.
    io::IoError error;
    const auto file = io::open_regular(path, error);
    if (!file) {
        return not_scanned(io::to_string(error.code), Hashes{}, 0);
    }
    const std::uint64_t size = file->size();
    const std::uint64_t max_scan = static_cast<std::uint64_t>(limit_int("MAX_SCAN_BYTES"));

    if (size > max_scan) {
        // Oversize: hashes over the whole file in a stream, then two windows only.
        Hashes hashes;
        if (!hash_file(*file, hashes, error)) {
            return not_scanned(io::to_string(io::IoErrorCode::ReadFailed), Hashes{}, size);
        }
        std::string label;
        const Reputation reputation = options_.use_reputation ? look_up(malicious_, trusted_, hashes.sha256, label)
                                                              : Reputation::None;
        if (reputation == Reputation::Trusted) {
            ScanResult trusted = base_result(hashes, size, name);
            trusted.score = table_.clean_score;
            trusted.verdict = table_.label_clean;
            finish(trusted, {});
            return trusted;
        }
        const std::uint64_t window = std::min(static_cast<std::uint64_t>(limit_int("OVERSIZE_WINDOW_BYTES")), max_scan);
        std::vector<std::uint8_t> head(static_cast<std::size_t>(std::min(window, size)));
        std::int64_t got = file->read_at(0, head, error);
        if (got < 0) {
            return not_scanned(io::to_string(io::IoErrorCode::ReadFailed), hashes, size);
        }
        head.resize(static_cast<std::size_t>(got));
        // f.seek(max(size - window, len(head))); tail = f.read(window)
        const std::uint64_t tail_offset = std::max(size > window ? size - window : 0, static_cast<std::uint64_t>(head.size()));
        std::vector<std::uint8_t> tail(static_cast<std::size_t>(tail_offset < size ? std::min(window, size - tail_offset) : 0));
        if (!tail.empty()) {
            got = file->read_at(tail_offset, tail, error);
            if (got < 0) {
                return not_scanned(io::to_string(io::IoErrorCode::ReadFailed), hashes, size);
            }
            tail.resize(static_cast<std::size_t>(got));
        }
        return scan_oversize(head, tail, size, hashes, name, reputation == Reputation::Malicious, label).result;
    }

    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    std::uint64_t done = 0;
    while (done < data.size()) {
        const std::int64_t got = file->read_at(
            done, std::span<std::uint8_t>(data.data() + done, data.size() - static_cast<std::size_t>(done)), error);
        if (got < 0) {
            return not_scanned(io::to_string(io::IoErrorCode::ReadFailed), Hashes{}, size);
        }
        if (got == 0) {
            break;
        }
        done += static_cast<std::uint64_t>(got);
    }
    data.resize(static_cast<std::size_t>(done));
    archive::Budget budget = new_budget();
    return scan_core(data, hashes_of(data), name, 0, budget).result;
}

// core._scan_oversize: a bounded partial scan. Rules and string indicators on the first and
// the last window, headers and imports from the first window, nothing else.
Engine::Outcome Engine::scan_oversize(std::span<const std::uint8_t> head, std::span<const std::uint8_t> tail,
                                      std::uint64_t size, const Hashes& hashes, std::string display_name,
                                      bool known_malicious, const std::string& malicious_label) const {
    Outcome outcome;
    outcome.result = base_result(hashes, size, std::move(display_name));
    Scorer scorer(table_);
    std::vector<std::string> incomplete;
    const std::int64_t max_scan = limit_int("MAX_SCAN_BYTES");
    const std::uint64_t window = std::min(static_cast<std::uint64_t>(limit_int("OVERSIZE_WINDOW_BYTES")),
                                          static_cast<std::uint64_t>(max_scan));

    std::vector<std::pair<std::string, std::span<const std::uint8_t>>> windows;
    windows.emplace_back("head", head);
    if (!tail.empty()) {
        windows.emplace_back("tail", tail);
    }

    // Rules on each window (the rules see the window, so sizes and offsets are relative to it).
    for (const auto& [name, chunk] : windows) {
        std::vector<rules::RuleMatch> matches;
        if (rules_.state() != RulesState::Off && !chunk.empty()) {  // scan_data: no rules or no data = no matches
            std::string scan_error;
            if (!rules_.scan(chunk, matches, scan_error)) {
                incomplete.push_back("rule scan failed (" + name + " window): " + scan_error);
                matches.clear();
            }
        }
        const std::vector<std::string> packer = packer_rule_names(matches);
        const bool already = std::any_of(scorer.findings().begin(), scorer.findings().end(),
                                         [](const Finding& f) { return f.category == "packer_detected"; });
        if (!packer.empty() && !already) {
            scorer.add_finding("packer_detected", "Packer detected: " + join(packer, ", "));
        }
        add_rule_findings(scorer, table_, without_packer_rules(matches), " (" + name + " window)");
    }

    // Headers and the import table from the head window only.
    if (is_pe_data(head)) {
        const pe::Image image = pe::parse(head);
        if (image.parsed) {
            const pe::ImportAnalysis imports = pe::analyze_imports(image);
            for (const std::string& chain : imports.api_chains) {
                scorer.add_finding("api_chain", "Behavioral API Chain detected: " + chain);
            }
            for (const std::string& chain : imports.minor_api_chains) {
                scorer.add_finding(minor_chain_category(chain), "Behavioral API Chain detected: " + chain);
            }
            if (!imports.suspicious_imports.empty()) {
                scorer.add_finding("suspicious_import",
                                   "Suspicious API imports: " + join(imports.suspicious_imports, ", ", 10));
            }
        }
    }

    // String indicators on the windows: only these two are scored on this path.
    for (const auto& [name, chunk] : windows) {
        const strings::Indicators found = strings::scan(chunk);
        if (found.b64_executable) {
            scorer.add_finding("b64_executable", "b64_executable pattern in " + name + " window");
        }
        if (found.obfuscated_script) {
            scorer.add_finding("obfuscated_script", "obfuscated_script pattern in " + name + " window");
        }
    }

    scorer.add_finding("oversize_partial_scan",
                       "File is " + std::to_string(size) + " bytes, over the " + std::to_string(max_scan) +
                           "-byte limit: only the first and last " + std::to_string(window) +
                           " bytes and the PE header were scanned");
    if (known_malicious) {
        scorer.add_finding("reputation_malicious", "Known malicious file (reputation: " + malicious_label + ")");
        scorer.set_floor(static_cast<int>(limit_int("MALICIOUS_FLOOR")));
    }

    outcome.result.findings = scorer.findings();
    outcome.result.score = scorer.score();
    std::string verdict = scorer.verdict();
    // The partial-scan verdict text means "nothing found in the windows": only the oversize
    // finding itself. A window finding that scores LOW keeps the normal LOW verdict.
    const bool nothing_found = std::all_of(scorer.findings().begin(), scorer.findings().end(),
                                           [](const Finding& f) { return f.category == "oversize_partial_scan"; });
    if (verdict == table_.label_low && nothing_found) {
        verdict = table_.label_partial;
    }
    outcome.result.verdict = verdict;
    incomplete.insert(incomplete.begin(), "oversize: only the first and last " + std::to_string(window) +
                                              " bytes and the header were scanned");
    finish(outcome.result, incomplete);
    return outcome;
}

// Engine.scan_file for a file of at most MAX_SCAN_BYTES, and for an archive member.
Engine::Outcome Engine::scan_core(std::span<const std::uint8_t> data, const Hashes& hashes, std::string display_name,
                                  int depth, archive::Budget& budget) const {
    Outcome outcome;
    outcome.result = base_result(hashes, data.size(), display_name);
    ScanResult& result = outcome.result;
    std::vector<std::string> incomplete;

    // --- Reputation lookup (core.py:108-127) ---
    std::string malicious_label;
    const Reputation reputation = options_.use_reputation ? look_up(malicious_, trusted_, hashes.sha256, malicious_label)
                                                          : Reputation::None;
    if (reputation == Reputation::Trusted) {
        // A trusted hash is CLEAN at once: nothing else is looked at.
        result.score = table_.clean_score;
        result.verdict = table_.label_clean;
        finish(result, {});
        return outcome;
    }
    const bool known_malicious = reputation == Reputation::Malicious;

    // --- Size limit (core.py:129-131) ---
    const std::uint64_t max_scan = static_cast<std::uint64_t>(limit_int("MAX_SCAN_BYTES"));
    if (data.size() > max_scan) {
        const std::uint64_t window = std::min(static_cast<std::uint64_t>(limit_int("OVERSIZE_WINDOW_BYTES")), max_scan);
        const std::span<const std::uint8_t> head = data.first(static_cast<std::size_t>(std::min<std::uint64_t>(window, data.size())));
        const std::uint64_t tail_offset = std::max<std::uint64_t>(data.size() > window ? data.size() - window : 0, head.size());
        const std::span<const std::uint8_t> tail =
            tail_offset < data.size()
                ? data.subspan(static_cast<std::size_t>(tail_offset),
                               static_cast<std::size_t>(std::min<std::uint64_t>(window, data.size() - tail_offset)))
                : std::span<const std::uint8_t>();
        return scan_oversize(head, tail, data.size(), hashes, std::move(display_name), known_malicious, malicious_label);
    }

    Scorer scorer(table_);

    // The analysis buffer (core.py:137): entropy, compressed-format detection and string
    // indicators see only the first MAX_ANALYSIS_BYTES bytes; the rules and the executable
    // reader see the whole file. The part in between is the reference's blind zone (R-5),
    // reproduced here on purpose.
    const std::uint64_t max_analysis = static_cast<std::uint64_t>(limit_int("MAX_ANALYSIS_BYTES"));
    const std::span<const std::uint8_t> buffer = data.first(static_cast<std::size_t>(std::min<std::uint64_t>(data.size(), max_analysis)));
    const bool whole_file_in_buffer = buffer.size() == data.size();

    // --- Executable parse (core.py:145-158) ---
    const bool claims_pe = is_pe_data(buffer);
    const bool starts_mz = buffer.size() >= 2 && buffer[0] == 'M' && buffer[1] == 'Z';
    pe::Image image;
    if (starts_mz) {
        image = pe::parse(data);
    }
    const bool pe_parsed = starts_mz && image.parsed;
    if (claims_pe && !pe_parsed) {
        scorer.add_finding("malformed_pe", "File has a PE signature but does not parse as PE (" + image.error + ")");
    }

    // --- Entropy, measured here and scored after the archive scan (core.py:160-167) ---
    const double entropy = shannon_entropy(buffer);
    const SlidingEntropy sliding = sliding_window_entropy(buffer);
    const std::string compressed_format = detect_compressed_format(buffer);

    // --- Rules (core.py:169-178) ---
    std::vector<rules::RuleMatch> matches;
    if (rules_.state() != RulesState::Off) {
        std::string scan_error;
        if (!rules_.scan(data, matches, scan_error)) {
            // The reference returns "no matches" here; the failure is reported instead.
            incomplete.push_back("rule scan failed: " + scan_error);
            matches.clear();
        }
    }
    const std::vector<std::string> packer_rules = packer_rule_names(matches);
    add_rule_findings(scorer, table_, without_packer_rules(matches), "");
    if (!packer_rules.empty() && !pe_parsed) {
        scorer.add_finding("packer_detected", "Packer detected: " + join(packer_rules, ", "));
    }

    // --- Executable analysis (core.py:180-256) ---
    std::vector<strings::Span> import_name_spans;
    if (pe_parsed) {
        const pe::Analysis analysis = pe::analyze(image, data, packer_rules);
        for (const pe::Range& range : analysis.scored_import_name_spans) {
            import_name_spans.emplace_back(range.begin, range.end);
        }
        // Signals that packing itself causes go into the capped 'packing' family only when
        // the packer is confirmed, and only for the packer's own sections.
        const std::vector<std::size_t>& own = analysis.confirmed_upx_sections;
        const auto packing = [](bool in_packer) { return in_packer ? std::string("packing") : std::string(); };

        for (const std::size_t index : analysis.high_entropy_sections) {
            scorer.add_finding("high_entropy",
                               "Section " + section_name(analysis, index) + " has very high entropy (packed/encrypted?)",
                               std::nullopt, packing(in_set(own, index)));
        }
        for (const bool in_packer : {true, false}) {
            std::vector<std::string> names;
            for (const std::size_t index : analysis.wx_sections) {
                if (in_set(own, index) == in_packer) {
                    names.push_back(section_name(analysis, index));
                }
            }
            if (!names.empty()) {
                scorer.add_finding("wx_section", "Writable and executable section(s): " + join(names, ", "), std::nullopt,
                                   packing(in_packer));
            }
        }
        const bool any_entropy_warning = std::any_of(analysis.warnings.begin(), analysis.warnings.end(),
                                                     [](const std::string& w) { return contains(w, "entropy"); });
        for (const std::string& warning : analysis.warnings) {
            if (contains(warning, "(packed/encrypted?)") || contains(warning, "Writable and executable")) {
                continue;  // scored per section above
            }
            if (contains(warning, "entropy")) {
                scorer.add_finding("high_entropy", warning);
            } else if (contains(warning, "TLS Callbacks")) {
                // scored only together with a packer or any entropy signal
                if (!analysis.packer_sections.empty() || !packer_rules.empty() || !analysis.high_entropy_sections.empty() ||
                    any_entropy_warning) {
                    const bool in_packer = analysis.tls_callback_section.has_value() && in_set(own, *analysis.tls_callback_section);
                    scorer.add_finding("tls_callback", warning, std::nullopt, packing(in_packer));
                }
            } else if (contains(warning, "overlay")) {
                scorer.add_finding("pe_overlay", warning);
            } else {
                scorer.add_finding("anomaly", warning);
            }
        }
        if (analysis.certificate_present && !analysis.certificate_valid) {
            scorer.add_finding("malformed_certificate_table",
                               "Authenticode certificate table is malformed or oversized: " +
                                   join(analysis.certificate_problems, "; "));
        }
        // Overlay entropy (core.py:235-239). In the parity profile the analysis layer always
        // reports size 0 here, because the reference never sees an overlay (D-14); the
        // finding can therefore not be produced. The condition is kept as the reference has it.
        if (analysis.overlay_entropy.size >= static_cast<std::uint64_t>(limit_int("OVERLAY_ENTROPY_MIN_BYTES")) &&
            analysis.overlay_entropy.entropy > kHighEntropyBits) {
            scorer.add_finding("overlay_high_entropy",
                               "PE overlay (" + std::to_string(analysis.overlay_entropy.size) +
                                   " bytes, certificate excluded) has high entropy (" +
                                   two_decimals(analysis.overlay_entropy.entropy) + "/8.00)");
        }
        for (const std::string& chain : analysis.imports.api_chains) {
            scorer.add_finding("api_chain", "Behavioral API Chain detected: " + chain);
        }
        for (const std::string& chain : analysis.imports.minor_api_chains) {
            const std::string category = minor_chain_category(chain);
            // a confirmed packer stub resolves its imports at run time
            scorer.add_finding(category, "Behavioral API Chain detected: " + chain, std::nullopt,
                               packing(!own.empty() && category == "dynamic_resolution_chain"));
        }
        if (!analysis.imports.suspicious_imports.empty()) {
            scorer.add_finding("suspicious_import",
                               "Suspicious API imports: " + join(analysis.imports.suspicious_imports, ", ", 10));
        }
        std::vector<std::string> packer_evidence = analysis.packer_sections;
        packer_evidence.insert(packer_evidence.end(), packer_rules.begin(), packer_rules.end());
        if (!packer_evidence.empty()) {
            scorer.add_finding("packer_detected", "Packer detected: " + join(packer_evidence, ", "));
        }

        // --- Signature (core.py:258-272). NOT BUILT: the only verifier says "unavailable".
        // The reference also skips the check when the file is bigger than the buffer. ---
        SignatureResult signature;
        if (whole_file_in_buffer && verifier_ != nullptr) {
            signature = verifier_->verify(data);
        }
        if (signature.status == "valid" && signature.publisher_allowed &&
            std::find(options_.trusted_publishers.begin(), options_.trusted_publishers.end(), signature.publisher) !=
                options_.trusted_publishers.end()) {
            scorer.cap_heuristics();
        }
    }

    // --- String indicators on the analysis buffer (core.py:274-305). API names that are
    // only the name entries of imports the import analysis already scored are not counted
    // again; the suppression applies only when such entries exist. ---
    const strings::Indicators indicators = strings::scan(buffer, import_name_spans);
    if (indicators.powershell) {
        scorer.add_finding("suspicious_string", "Suspicious strings (powershell)");
    }
    if (indicators.suspicious_api) {
        scorer.add_finding("suspicious_string", "Suspicious strings (suspicious_api)");
    }
    if (indicators.b64_executable) {
        scorer.add_finding("b64_executable", "Embedded Base64-encoded executable signature detected");
    }
    if (indicators.obfuscated_script) {
        scorer.add_finding("obfuscated_script", "Obfuscated script pattern detected");
    }

    // --- Archive inspection, by content (core.py:307-326, 514-568) ---
    const bool is_archive = archive::detect(data, options_.archive) != archive::Kind::NotArchive;
    const int max_depth = static_cast<int>(limit_int("MAX_ARCHIVE_DEPTH"));
    std::int64_t members_scanned = 0;
    std::vector<std::string> coverage_reasons;
    if (is_archive && depth >= max_depth) {
        outcome.archive_not_unpacked = true;
        incomplete.emplace_back("archive not unpacked: depth limit");
    }
    if (is_archive && depth < max_depth) {
        outcome.has_archive = true;
        int worst_score = 0;
        std::string worst_member;
        std::string worst_verdict = table_.label_clean;
        const archive::Extraction extraction = archive::extract(data, budget, options_.archive);
        coverage_reasons = extraction.reasons;
        for (const archive::Member& member : extraction.members) {
            Outcome sub;
            try {
                static const std::vector<std::uint8_t> nothing;
                const std::vector<std::uint8_t>& bytes = member.bytes ? *member.bytes : nothing;
                sub = scan_core(bytes, hashes_of(bytes), member.name, depth + 1, budget);
            } catch (const std::exception&) {
                coverage_reasons.push_back("member scan failed: " + member.name + " (exception)");
                continue;
            }
            if (sub.result.state == ScanState::NotScanned) {
                coverage_reasons.push_back("member not scanned: " + member.name);
                continue;
            }
            if (sub.archive_not_unpacked) {
                coverage_reasons.push_back("nested archive not unpacked (depth): " + member.name);
            } else if (sub.has_archive && !sub.archive_complete) {
                coverage_reasons.push_back("nested archive incomplete: " + member.name);
            }
            ++members_scanned;
            if (sub.result.score > worst_score) {
                worst_score = sub.result.score;
                worst_member = member.name;
                worst_verdict = sub.result.verdict;
            }
        }
        outcome.archive_complete = coverage_reasons.empty();
        if (worst_score > 0) {
            // The archive's score is at least its worst member's (a floor), not added on top.
            scorer.add_floor_finding("archive_member",
                                     "Archive member " + worst_member + ": " + worst_verdict + " (score " +
                                         std::to_string(worst_score) + ")",
                                     worst_score);
        }
        if (!outcome.archive_complete) {
            incomplete.push_back("archive member scan incomplete: " + join(coverage_reasons, ", "));
        }
    }

    // --- Entropy scoring (core.py:476-503): only for a file that did not parse as an
    // executable. A fully covered archive is exempt; any other archive or compressed format
    // gets the reduced weight; everything else the full weight. ---
    if (!pe_parsed) {
        const bool exempt = is_archive && outcome.has_archive && members_scanned > 0 && outcome.archive_complete;
        if (!exempt) {
            std::optional<int> weight;
            std::string note;
            if (is_archive) {
                weight = static_cast<int>(limit_int("REDUCED_ENTROPY_WEIGHT"));
                const std::string reasons = !coverage_reasons.empty()
                                                ? join(coverage_reasons, ", ")
                                                : (outcome.archive_not_unpacked ? std::string("depth limit")
                                                                                : std::string("archive not unpacked"));
                note = " (archive, member scan incomplete: " + reasons + ")";
            } else if (!compressed_format.empty()) {
                weight = static_cast<int>(limit_int("REDUCED_ENTROPY_WEIGHT"));
                note = " (" + compressed_format + " format, contents not unpacked)";
            }
            const double high_share = sliding.total_windows != 0
                                          ? static_cast<double>(sliding.high_entropy_windows) /
                                                static_cast<double>(sliding.total_windows)
                                          : 0.0;
            if (entropy > kHighEntropyBits) {
                scorer.add_finding("high_entropy",
                                   "File has very high overall entropy (" + two_decimals(entropy) +
                                       "/8.00) - likely packed or encrypted" + note,
                                   weight);
            } else if (high_share > limit("SLIDING_HIGH_SHARE")) {
                scorer.add_finding("sliding_entropy_spike",
                                   std::to_string(sliding.high_entropy_windows) + " of " +
                                       std::to_string(sliding.total_windows) + " windows have high entropy (peak " +
                                       two_decimals(sliding.max) + "/8.00)" + note,
                                   weight);
            }
        }
    }

    // --- Known-bad hash: the finding and the floor come last (core.py:341-344) ---
    if (known_malicious) {
        scorer.add_finding("reputation_malicious", "Known malicious file (reputation: " + malicious_label + ")");
        scorer.set_floor(static_cast<int>(limit_int("MALICIOUS_FLOOR")));
    }

    result.findings = scorer.findings();
    result.score = scorer.score();
    result.verdict = scorer.verdict();
    finish(result, incomplete);
    return outcome;
}

}  // namespace mie
