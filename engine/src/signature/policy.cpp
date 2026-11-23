// The publisher policy (config/trusted_publishers.json) and a small text helper. This file
// reads OUR policy file's text, never the scanned file. Moved out of authenticode.cpp unchanged
// (reviewer's ruling: the line limit is on the code that parses hostile bytes).
#include "mie/signature.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "internal.hpp"

namespace mie::signature {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c); });
    return text;
}

Policy load_policy(std::string_view json_text) {
    Policy policy;
    const nlohmann::json parsed = nlohmann::json::parse(json_text.begin(), json_text.end(), nullptr, false);
    if (!parsed.is_object()) return policy;
    const auto list = [&parsed](const char* key) -> const nlohmann::json* {
        const auto found = parsed.find(key);
        return found != parsed.end() && found->is_array() ? &*found : nullptr;
    };
    if (const nlohmann::json* publishers = list("publishers")) {
        std::vector<std::string> names;
        for (const nlohmann::json& entry : *publishers) {
            if (!entry.is_string()) continue;
            const std::string name = entry.get<std::string>();
            if (name.find_first_not_of(" \t\r\n\v\f") != std::string::npos) names.push_back(name);
        }
        if (!names.empty()) policy.publishers = std::move(names);
    }
    if (const nlohmann::json* intermediates = list("issuing_intermediates")) {
        for (const nlohmann::json& entry : *intermediates) {
            if (!entry.is_object()) continue;
            const auto cn = entry.find("cn");
            if (cn == entry.end() || !cn->is_string()) continue;
            Intermediate out;
            out.cn = cn->get<std::string>();
            const auto spki = entry.find("spki_sha256");
            if (spki != entry.end() && spki->is_string()) out.spki_sha256 = lower(spki->get<std::string>());
            policy.issuing_intermediates.push_back(std::move(out));
        }
    }
    const auto strings = [&list](const char* key, std::vector<std::string>& into) {
        if (const nlohmann::json* values = list(key)) {
            for (const nlohmann::json& entry : *values) {
                if (entry.is_string()) into.push_back(entry.get<std::string>());
            }
        }
    };
    strings("rejected_issuers", policy.rejected_issuers);
    strings("rejected_leaf_cns", policy.rejected_leaf_cns);
    return policy;
}

}  // namespace mie::signature
