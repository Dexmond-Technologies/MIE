// The rules engine: an adapter around the YARA C library (version 4.5.1, the version the
// Python reference uses). Loading follows the reference (dexmond_mie/yara_analyzer.py):
// every rule file is compiled alone first, a file that fails is left out, the good ones are
// compiled together, and the state is ON, DEGRADED or OFF.
//
// Unlike the reference, a scan that fails or runs out of time is REPORTED to the caller; the
// reference returns "no matches" in that case, which looks like a clean file. The caller
// turns a failed scan into "not fully scanned".
//
// This code parses untrusted bytes (the scanned data) through YARA. It is meant to run in
// the low-rights worker process only.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "mie/result.hpp"

namespace mie::rules {

struct RuleMatch {
    std::string rule;         // rule name
    std::string name_space;   // the rule file it came from (as the reference names it)
    std::string severity;     // meta "severity", lower-case as written in the rule; empty if absent
    std::string category;     // meta "category"; empty if absent
    std::string description;  // meta "description"; empty if absent
    bool operator==(const RuleMatch&) const = default;
};

struct RuleFileError {
    std::string file;
    std::string error;
};

inline constexpr int kScanTimeoutSeconds = 60;  // the reference's SCAN_TIMEOUT

class RuleSet {
public:
    ~RuleSet();
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;

    // Loads every *.yar and *.yara file under `directory` (not the sub-folder "proposed",
    // not a top-level "auto_generated.yar": the reference never loads those). Never fails:
    // a directory with no usable rules gives a rule set in state Off.
    static std::unique_ptr<RuleSet> load(const std::filesystem::path& directory);

    RulesState state() const;
    std::size_t files_loaded() const;
    const std::vector<RuleFileError>& errors() const;

    // Hash of the rule set (see engine/docs/INTERFACES.md): SHA-256 over one line per loaded
    // rule file, sorted by name, "<name> <SHA-256 of the file>\n". Empty when the state is Off.
    const std::string& sha256() const;

    // SHA-256 of every loaded rule file, by its name below the rules directory.
    const std::map<std::string, std::string>& file_hashes() const;

    // Version of the YARA library this program was built with. YARA has no call that
    // returns its version at run time; this is the version constant of the library's own
    // header, the one installed with the library that is linked.
    static std::string library_version();

    // Matches the rules against `data`. Returns true with the matches in `out` (possibly
    // none). Returns false with `error` set when the scan failed or timed out, or when the
    // state is Off: the caller must not take that for "no matches".
    bool scan(std::span<const std::uint8_t> data, std::vector<RuleMatch>& out, std::string& error) const;

private:
    RuleSet();
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace mie::rules
