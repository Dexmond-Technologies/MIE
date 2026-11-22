#include "mie/result.hpp"

#include <initializer_list>
#include <limits>

#include <nlohmann/json.hpp>

namespace mie {

using nlohmann::json;

const char* to_string(SubjectKind kind) {
    switch (kind) {
        case SubjectKind::File: return "file";
    }
    return "file";
}

const char* to_string(ScanState state) {
    switch (state) {
        case ScanState::Scanned: return "scanned";
        case ScanState::NotFullyScanned: return "not_fully_scanned";
        case ScanState::NotScanned: return "not_scanned";
    }
    return "not_scanned";
}

std::string to_json(const ScanResult& r) {
    json findings = json::array();
    for (const Finding& f : r.findings) {
        findings.push_back(json{{"category", f.category},
                                {"family", f.family},
                                {"weight", f.weight},
                                {"description", f.description},
                                {"floor", f.floor}});
    }
    json j = {
        {"schema_version", r.schema_version},
        {"subject", json{{"kind", to_string(r.subject.kind)},
                         {"sha256", r.subject.sha256},
                         {"display_name", r.subject.display_name}}},
        {"state", to_string(r.state)},
        {"reason", r.reason},
        {"score", r.score},
        {"verdict", r.verdict},
        {"findings", findings},
        {"hashes", json{{"md5", r.hashes.md5}, {"sha1", r.hashes.sha1}, {"sha256", r.hashes.sha256}}},
        {"size", r.size},
    };
    // nlohmann::json keeps object keys sorted; dump() without arguments has no white space.
    // Invalid UTF-8 in a text field is replaced, never thrown.
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

namespace {

bool only_keys(const json& obj, std::initializer_list<const char*> allowed, std::string& error) {
    if (!obj.is_object()) {
        error = "not an object";
        return false;
    }
    if (obj.size() != allowed.size()) {
        error = "missing or unknown field";
        return false;
    }
    for (const char* key : allowed) {
        if (!obj.contains(key)) {
            error = std::string("missing field: ") + key;
            return false;
        }
    }
    return true;
}

bool get_string(const json& obj, const char* key, std::string& out, std::string& error) {
    const json& v = obj.at(key);
    if (!v.is_string()) {
        error = std::string("field is not text: ") + key;
        return false;
    }
    out = v.get<std::string>();
    return true;
}

bool get_int(const json& obj, const char* key, int& out, std::string& error) {
    const json& v = obj.at(key);
    if (!v.is_number_integer()) {
        error = std::string("field is not a whole number: ") + key;
        return false;
    }
    const auto n = v.get<std::int64_t>();
    if (n < std::numeric_limits<int>::min() || n > std::numeric_limits<int>::max()) {
        error = std::string("number out of range: ") + key;
        return false;
    }
    out = static_cast<int>(n);
    return true;
}

}  // namespace

bool from_json(std::string_view text, ScanResult& out, std::string& error) {
    const json j = json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded()) {
        error = "not valid JSON";
        return false;
    }
    if (!only_keys(j, {"schema_version", "subject", "state", "reason", "score", "verdict",
                       "findings", "hashes", "size"}, error)) {
        return false;
    }

    ScanResult r;
    if (!get_int(j, "schema_version", r.schema_version, error)) return false;
    if (r.schema_version != kResultSchemaVersion) {
        error = "unknown schema version";
        return false;
    }

    const json& subject = j.at("subject");
    if (!only_keys(subject, {"kind", "sha256", "display_name"}, error)) return false;
    std::string kind;
    if (!get_string(subject, "kind", kind, error)) return false;
    if (kind != "file") {
        error = "unknown subject kind";
        return false;
    }
    r.subject.kind = SubjectKind::File;
    if (!get_string(subject, "sha256", r.subject.sha256, error)) return false;
    if (!get_string(subject, "display_name", r.subject.display_name, error)) return false;

    std::string state;
    if (!get_string(j, "state", state, error)) return false;
    if (state == "scanned") {
        r.state = ScanState::Scanned;
    } else if (state == "not_fully_scanned") {
        r.state = ScanState::NotFullyScanned;
    } else if (state == "not_scanned") {
        r.state = ScanState::NotScanned;
    } else {
        error = "unknown state";
        return false;
    }

    if (!get_string(j, "reason", r.reason, error)) return false;
    if (!get_int(j, "score", r.score, error)) return false;
    if (!get_string(j, "verdict", r.verdict, error)) return false;

    const json& findings = j.at("findings");
    if (!findings.is_array()) {
        error = "findings is not a list";
        return false;
    }
    for (const json& item : findings) {
        if (!only_keys(item, {"category", "family", "weight", "description", "floor"}, error)) return false;
        Finding f;
        if (!get_string(item, "category", f.category, error)) return false;
        if (!get_string(item, "family", f.family, error)) return false;
        if (!get_int(item, "weight", f.weight, error)) return false;
        if (!get_string(item, "description", f.description, error)) return false;
        if (!item.at("floor").is_boolean()) {
            error = "field is not true/false: floor";
            return false;
        }
        f.floor = item.at("floor").get<bool>();
        r.findings.push_back(std::move(f));
    }

    const json& hashes = j.at("hashes");
    if (!only_keys(hashes, {"md5", "sha1", "sha256"}, error)) return false;
    if (!get_string(hashes, "md5", r.hashes.md5, error)) return false;
    if (!get_string(hashes, "sha1", r.hashes.sha1, error)) return false;
    if (!get_string(hashes, "sha256", r.hashes.sha256, error)) return false;

    const json& size = j.at("size");
    if (!size.is_number_unsigned()) {
        error = "field is not a non-negative whole number: size";
        return false;
    }
    r.size = size.get<std::uint64_t>();

    out = std::move(r);
    return true;
}

}  // namespace mie
