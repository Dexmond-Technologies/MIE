// Frozen interface 1 and 2: the finding format and the result format (schema version 1).
// See engine/docs/INTERFACES.md. Changing a field means a new schema version.
//
// This header defines the SHAPE only. No code in the engine computes a score or a
// verdict yet: scoring is not written before the synthetic parity set exists.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace mie {

inline constexpr int kResultSchemaVersion = 1;

// What a verdict is about. Stage 1 knows files only; stage 2 adds further kinds
// (process, chain) without changing the fields below.
enum class SubjectKind { File };

// Scanned: every stage ran over the whole input.
// NotFullyScanned: a limit, a crash or an unsupported part cut the scan. Never CLEAN.
// NotScanned: the input was refused or unreadable. No score.
enum class ScanState { Scanned, NotFullyScanned, NotScanned };

// State of the rule set the scan ran with (the reference's ON / DEGRADED / YARA-OFF).
// On: every rule file compiled. Degraded: some rule files failed and were left out.
// Off: no rules at all.
enum class RulesState { On, Degraded, Off };

struct Hashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
    bool operator==(const Hashes&) const = default;
};

struct Subject {
    SubjectKind kind = SubjectKind::File;
    std::string sha256;        // identity of a file subject
    std::string display_name;  // text for people; never used as a path
    bool operator==(const Subject&) const = default;
};

struct Finding {
    std::string category;     // row of the scoring table, e.g. "high_entropy"
    std::string family;       // family the weight counts in; empty = the category's default
    int weight = 0;
    std::string description;
    bool floor = false;       // true: raises the score to at least `weight` instead of adding
    bool operator==(const Finding&) const = default;
};

struct ScanResult {
    int schema_version = kResultSchemaVersion;
    Subject subject;
    ScanState state = ScanState::NotScanned;
    std::string reason;       // why the state is not Scanned; empty otherwise
    int score = 0;
    std::string verdict;      // empty until a scorer exists
    std::vector<Finding> findings;
    Hashes hashes;
    std::uint64_t size = 0;

    // What produced this result (reviewer's condition W-1, board B-3551). A verdict
    // means nothing without knowing which engine, which profile and which rules.
    std::string engine_version;                 // for example "0.0.1-week0"
    std::string profile;                        // "parity" or "stage1"
    RulesState rules_state = RulesState::Off;
    std::string rules_sha256;                   // hash of the rule set; empty when rules are Off

    bool operator==(const ScanResult&) const = default;
};

const char* to_string(SubjectKind kind);
const char* to_string(ScanState state);
const char* to_string(RulesState state);

// The rules every result must obey. Returns false and says why if it does not.
//   - A scan with rules Degraded or Off is never `scanned`: it is `not_fully_scanned`
//     (or `not_scanned`), so it can never be shown as a clean result.
//   - A state other than `scanned` carries a reason; `scanned` carries none.
//   - `not_scanned` carries no score, no verdict and no findings.
// from_json refuses a result that breaks these rules. Every producer calls this
// before it hands a result on.
bool consistent(const ScanResult& result, std::string& why);

// Canonical JSON: keys sorted, no white space. Two equal results give equal bytes.
std::string to_json(const ScanResult& result);

// Strict parse: unknown fields, wrong types and an unknown schema version are refused.
// Returns false and sets `error` on any problem; `out` is then unchanged.
bool from_json(std::string_view text, ScanResult& out, std::string& error);

}  // namespace mie
