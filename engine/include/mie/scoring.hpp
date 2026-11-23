// The scorer: turns findings into a score and a verdict, with exactly the arithmetic of
// the Python reference (dexmond_mie/scoring.py). The numbers are not in this code: they
// are read from a scoring table (engine/data/scoring.reference.json for the parity
// profile), which CI compares with the reference source on every push.
//
// Gates set by the reviewer (board B-3588), in this order: the direct comparison on the
// scoring vectors, then parity set S, then the corpus sets.
#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "mie/result.hpp"

namespace mie {

struct ScoringTable {
    std::string profile;                               // "parity" or "stage1"
    std::map<std::string, int> weights;                // category -> weight
    int default_weight = 0;                            // weight of a category not in `weights`
    std::map<std::string, std::string> families;       // category -> family (others: own family)
    std::map<std::string, int> rule_severity_weights;  // rule severity -> weight
    std::map<std::string, int> family_caps;            // family -> most it can contribute
    std::set<std::string> uncappable_families;         // never lowered by a trusted signature
    int signed_cap = 0;                                // heuristic ceiling under a trusted signature
    int score_max = 0;
    int clean_score = 0;
    int medium_from = 0;
    int malicious_from = 0;
    std::string label_clean;
    std::string label_low;
    std::string label_medium;
    std::string label_malicious;
    std::string label_partial;
    std::map<std::string, double> limits;              // the engine's limits, by the reference's names
    int alert_threshold = 0;
};

// Strict: every field must be present with the right type; unknown top-level fields are
// refused. Returns false and sets `error` otherwise.
bool load_scoring_table(std::string_view json_text, ScoringTable& out, std::string& error);

class Scorer {
public:
    explicit Scorer(const ScoringTable& table);

    // Adds a finding. Without `weight_override` the category's weight from the table is used
    // (the default weight for an unknown category). A non-empty `family` replaces the
    // category's default family.
    void add_finding(const std::string& category, const std::string& description,
                     std::optional<int> weight_override = std::nullopt, const std::string& family = {});

    // Records a finding that raises the score to at least `floor` instead of adding to it
    // (an archive takes its worst member's score).
    void add_floor_finding(const std::string& category, const std::string& description, int floor);

    // Sets a minimum score (a known-bad hash). The highest floor wins.
    void set_floor(int floor);

    // A valid signature from a trusted publisher: the heuristic families together count at
    // most `cap` (the table's signed cap when no value is given). Uncappable families and
    // floors are not affected.
    void cap_heuristics(std::optional<int> cap = std::nullopt);

    // Score per family after the family caps; floor findings are not included.
    std::map<std::string, int> family_scores() const;

    int score() const;             // final score: caps, heuristic cap, floor, then the maximum
    std::string verdict() const;   // the table's label for score()
    const std::vector<Finding>& findings() const { return findings_; }

private:
    std::string family_of(const Finding& finding) const;

    const ScoringTable& table_;
    std::vector<Finding> findings_;
    int floor_ = 0;
    std::optional<int> heuristic_cap_;
};

}  // namespace mie
