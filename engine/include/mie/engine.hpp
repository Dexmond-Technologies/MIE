// The scan pipeline: joins the engine's parts into what the Python reference's
// Engine.scan_file does (dexmond_mie/core.py at ff313e2), step by step and in its order.
//
// PARITY profile: the reference is reproduced with its defects (the blind zone between
// the analysis buffer and the whole-file limit, no overlay findings (D-14), a file that
// begins with zero blocks taken for a tar archive (D-15), and so on). The numbered
// differences of the shipped profile are data (the scoring table, archive::Options and
// EngineOptions), never a second code path.
//
// All weights and limits come from the scoring table (its `limits` by the reference's
// names) and from archive::Options; none is written in this code.
//
// NOT BUILT: Authenticode signature checking. The signature step goes through
// SignatureVerifier, whose only implementation says "unavailable", which means "no cap",
// as the reference does when its signature library is not installed.
//
// This code hands untrusted bytes to the rules library, the executable reader and the
// archive readers. It is meant to run in the confined worker process only; until that
// exists it may be used on test files only.
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mie/archive.hpp"
#include "mie/io.hpp"
#include "mie/result.hpp"
#include "mie/rules.hpp"
#include "mie/scoring.hpp"

namespace mie {

struct SignatureResult {
    std::string status = "unavailable";  // "valid", "invalid", "unsigned" or "unavailable"
    std::string publisher;
    bool publisher_allowed = false;
};

class SignatureVerifier {
public:
    virtual ~SignatureVerifier() = default;
    // `data` is the whole file, exactly the bytes that were scanned.
    virtual SignatureResult verify(std::span<const std::uint8_t> data) const = 0;
};

// The only verifier that exists: every file is "unavailable", so no file ever gets the
// signature cap. Authenticode checking is not built yet.
class UnavailableSignatureVerifier final : public SignatureVerifier {
public:
    SignatureResult verify(std::span<const std::uint8_t> data) const override;
};

struct EngineOptions {
    bool use_reputation = true;  // false: the reference's measuring mode (--no-reputation)
    // Shipped profile's rule, OFF in parity: a result that is not fully scanned is never
    // shown with the CLEAN verdict; its verdict text becomes kNotFullyScannedVerdict.
    bool never_clean_when_incomplete = false;
    archive::Options archive;  // its limits are overwritten from the scoring table's limits
    std::vector<std::string> trusted_publishers;  // publishers whose valid signature gives the cap
};

inline constexpr const char* kNotFullyScannedVerdict = "NOT FULLY SCANNED";

class Engine {
public:
    // `rules` and `table` must outlive the engine. `reputation_json` is the reference's
    // format: {"malicious": {sha256: label}, "trusted": {sha256: label}}; text that cannot
    // be read gives an empty list, as in the reference. `verifier` may be null (then
    // every signature is "unavailable").
    Engine(const ScoringTable& table, const rules::RuleSet& rules, std::string_view reputation_json,
           EngineOptions options = EngineOptions{}, const SignatureVerifier* verifier = nullptr);

    // False when the scoring table lacks a limit the pipeline needs; `why` names it.
    // An unusable engine refuses every scan ("not scanned").
    bool usable(std::string& why) const;

    // Scans one file. The file is opened once through mie::io (links, directories, pipes,
    // devices and cloud-only files are refused: "not scanned").
    ScanResult scan_file(const std::filesystem::path& path) const;

    // Scans a file that is ALREADY OPEN: the confined worker's entry, where the parent opened
    // the file and handed over the one handle. `display_name` is text for people only.
    ScanResult scan_open(io::File& file, std::string display_name) const;

    // Scans bytes that are already in memory (an archive member). `depth` is the nesting
    // depth (0 = a top-level file); `budget` is shared by the whole top-level scan.
    ScanResult scan_bytes(std::span<const std::uint8_t> data, std::string display_name, int depth,
                          archive::Budget& budget) const;

    // A fresh budget for one top-level scan, from the table's limits.
    archive::Budget new_budget() const;

    struct Outcome;  // a result plus what a parent archive needs to know about it

private:
    Outcome scan_core(std::span<const std::uint8_t> data, const Hashes& hashes, std::string display_name,
                      int depth, archive::Budget& budget) const;
    Outcome scan_oversize(std::span<const std::uint8_t> head, std::span<const std::uint8_t> tail,
                          std::uint64_t size, const Hashes& hashes, std::string display_name,
                          bool known_malicious, const std::string& malicious_label) const;
    ScanResult base_result(const Hashes& hashes, std::uint64_t size, std::string display_name) const;
    void finish(ScanResult& result, const std::vector<std::string>& incomplete) const;
    double limit(const char* name) const;
    std::int64_t limit_int(const char* name) const;

    const ScoringTable& table_;
    const rules::RuleSet& rules_;
    EngineOptions options_;
    const SignatureVerifier* verifier_;
    std::map<std::string, std::string> malicious_;
    std::map<std::string, std::string> trusted_;
    std::string unusable_;
};

// utils.detect_compressed_format: the name of a known compressed or archive format by its
// magic bytes, or an empty string.
std::string detect_compressed_format(std::span<const std::uint8_t> data);

// utils.is_pe_data: starts with "MZ" and its e_lfanew points at "PE\0\0" inside `data`.
bool is_pe_data(std::span<const std::uint8_t> data);

}  // namespace mie
