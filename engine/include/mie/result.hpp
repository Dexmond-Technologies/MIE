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
    bool operator==(const ScanResult&) const = default;
};

const char* to_string(SubjectKind kind);
const char* to_string(ScanState state);

// Canonical JSON: keys sorted, no white space. Two equal results give equal bytes.
std::string to_json(const ScanResult& result);

// Strict parse: unknown fields, wrong types and an unknown schema version are refused.
// Returns false and sets `error` on any problem; `out` is then unchanged.
bool from_json(std::string_view text, ScanResult& out, std::string& error);

}  // namespace mie
