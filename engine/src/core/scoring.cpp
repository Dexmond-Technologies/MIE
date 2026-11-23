#include "mie/scoring.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>

#include <nlohmann/json.hpp>

namespace mie {

using nlohmann::json;

namespace {

bool read_int(const json& obj, const char* key, int& out, std::string& error) {
    if (!obj.is_object() || !obj.contains(key) || !obj.at(key).is_number_integer()) {
        error = std::string("scoring table: missing or not a whole number: ") + key;
        return false;
    }
    const auto value = obj.at(key).get<std::int64_t>();
    if (value < std::numeric_limits<int>::min() || value > std::numeric_limits<int>::max()) {
        error = std::string("scoring table: out of range: ") + key;
        return false;
    }
    out = static_cast<int>(value);
    return true;
}

bool read_text(const json& obj, const char* key, std::string& out, std::string& error) {
    if (!obj.is_object() || !obj.contains(key) || !obj.at(key).is_string()) {
        error = std::string("scoring table: missing or not text: ") + key;
        return false;
    }
    out = obj.at(key).get<std::string>();
    return true;
}

bool read_int_map(const json& obj, const char* key, std::map<std::string, int>& out, std::string& error) {
    if (!obj.is_object() || !obj.contains(key) || !obj.at(key).is_object()) {
        error = std::string("scoring table: missing or not an object: ") + key;
        return false;
    }
    out.clear();
    for (auto it = obj.at(key).begin(); it != obj.at(key).end(); ++it) {
        int value = 0;
        if (!read_int(obj.at(key), it.key().c_str(), value, error)) {
            return false;
        }
        out[it.key()] = value;
    }
    return true;
}

}  // namespace

bool load_scoring_table(std::string_view json_text, ScoringTable& out, std::string& error) {
    const json j = json::parse(json_text.begin(), json_text.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        error = "scoring table: not a JSON object";
        return false;
    }
    static const std::set<std::string> known{
        "schema_version", "profile", "source", "weights", "default_weight", "families",
        "yara_severity_weights", "family_caps", "uncappable_families", "signed_cap", "score_max",
        "verdicts", "limits", "alert_threshold"};
    for (auto it = j.begin(); it != j.end(); ++it) {
        if (known.count(it.key()) == 0) {
            error = "scoring table: unknown field: " + it.key();
            return false;
        }
    }

    ScoringTable t;
    int schema = 0;
    if (!read_int(j, "schema_version", schema, error)) return false;
    if (schema != 1) {
        error = "scoring table: unknown schema version";
        return false;
    }
    if (!read_text(j, "profile", t.profile, error)) return false;
    if (!read_int_map(j, "weights", t.weights, error)) return false;
    if (!read_int(j, "default_weight", t.default_weight, error)) return false;
    if (!read_int_map(j, "yara_severity_weights", t.rule_severity_weights, error)) return false;
    if (!read_int_map(j, "family_caps", t.family_caps, error)) return false;
    if (!read_int(j, "signed_cap", t.signed_cap, error)) return false;
    if (!read_int(j, "score_max", t.score_max, error)) return false;
    if (!read_int(j, "alert_threshold", t.alert_threshold, error)) return false;

    if (!j.contains("families") || !j.at("families").is_object()) {
        error = "scoring table: missing or not an object: families";
        return false;
    }
    for (auto it = j.at("families").begin(); it != j.at("families").end(); ++it) {
        if (!it.value().is_string()) {
            error = "scoring table: family is not text: " + it.key();
            return false;
        }
        t.families[it.key()] = it.value().get<std::string>();
    }

    if (!j.contains("uncappable_families") || !j.at("uncappable_families").is_array()) {
        error = "scoring table: missing or not a list: uncappable_families";
        return false;
    }
    for (const json& item : j.at("uncappable_families")) {
        if (!item.is_string()) {
            error = "scoring table: uncappable family is not text";
            return false;
        }
        t.uncappable_families.insert(item.get<std::string>());
    }

    if (!j.contains("verdicts") || !j.at("verdicts").is_object()) {
        error = "scoring table: missing or not an object: verdicts";
        return false;
    }
    const json& verdicts = j.at("verdicts");
    if (!read_int(verdicts, "clean_score", t.clean_score, error)) return false;
    if (!read_int(verdicts, "medium_from", t.medium_from, error)) return false;
    if (!read_int(verdicts, "malicious_from", t.malicious_from, error)) return false;
    if (!verdicts.contains("labels") || !verdicts.at("labels").is_object()) {
        error = "scoring table: missing or not an object: verdicts.labels";
        return false;
    }
    const json& labels = verdicts.at("labels");
    if (!read_text(labels, "clean", t.label_clean, error)) return false;
    if (!read_text(labels, "low", t.label_low, error)) return false;
    if (!read_text(labels, "medium", t.label_medium, error)) return false;
    if (!read_text(labels, "malicious", t.label_malicious, error)) return false;
    if (!read_text(labels, "partial", t.label_partial, error)) return false;

    if (!j.contains("limits") || !j.at("limits").is_object()) {
        error = "scoring table: missing or not an object: limits";
        return false;
    }
    for (auto it = j.at("limits").begin(); it != j.at("limits").end(); ++it) {
        if (!it.value().is_number()) {
            error = "scoring table: limit is not a number: " + it.key();
            return false;
        }
        t.limits[it.key()] = it.value().get<double>();
    }

    // A table the verdict logic cannot work with is refused here, not discovered later.
    if (!(t.clean_score < t.medium_from && t.medium_from < t.malicious_from && t.malicious_from <= t.score_max)) {
        error = "scoring table: verdict lines are not in order";
        return false;
    }
    out = std::move(t);
    return true;
}

Scorer::Scorer(const ScoringTable& table) : table_(table) {}

void Scorer::add_finding(const std::string& category, const std::string& description,
                         std::optional<int> weight_override, const std::string& family) {
    Finding finding;
    finding.category = category;
    finding.description = description;
    if (weight_override.has_value()) {
        finding.weight = *weight_override;
    } else {
        const auto it = table_.weights.find(category);
        finding.weight = it != table_.weights.end() ? it->second : table_.default_weight;
    }
    finding.family = family;
    finding.floor = false;
    findings_.push_back(std::move(finding));
}

void Scorer::add_floor_finding(const std::string& category, const std::string& description, int floor) {
    set_floor(floor);
    Finding finding;
    finding.category = category;
    finding.description = description;
    finding.weight = floor;
    finding.floor = true;
    findings_.push_back(std::move(finding));
}

void Scorer::set_floor(int floor) { floor_ = std::max(floor_, floor); }

void Scorer::cap_heuristics(std::optional<int> cap) {
    heuristic_cap_ = cap.has_value() ? *cap : table_.signed_cap;
}

std::string Scorer::family_of(const Finding& finding) const {
    if (!finding.family.empty()) {
        return finding.family;
    }
    const auto it = table_.families.find(finding.category);
    return it != table_.families.end() ? it->second : finding.category;
}

std::map<std::string, int> Scorer::family_scores() const {
    std::map<std::string, int> totals;
    for (const Finding& finding : findings_) {
        if (finding.floor) {
            continue;
        }
        totals[family_of(finding)] += finding.weight;
    }
    for (auto& [family, total] : totals) {
        const auto cap = table_.family_caps.find(family);
        if (cap != table_.family_caps.end()) {
            total = std::min(total, cap->second);
        }
    }
    return totals;
}

int Scorer::score() const {
    int hard = 0;
    int soft = 0;
    for (const auto& [family, value] : family_scores()) {
        if (table_.uncappable_families.count(family) != 0) {
            hard += value;
        } else {
            soft += value;
        }
    }
    if (heuristic_cap_.has_value()) {
        soft = std::min(soft, *heuristic_cap_);
    }
    return std::min(std::max(hard + soft, floor_), table_.score_max);
}

std::string Scorer::verdict() const {
    const int value = score();
    if (value == table_.clean_score) {
        return table_.label_clean;
    }
    if (value < table_.medium_from) {
        return table_.label_low;
    }
    if (value < table_.malicious_from) {
        return table_.label_medium;
    }
    return table_.label_malicious;
}

}  // namespace mie
