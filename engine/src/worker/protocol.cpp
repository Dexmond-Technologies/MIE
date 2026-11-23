// The job format between the parent and the worker (see mie/worker.hpp). Used by both.
#include "mie/worker.hpp"

#include <cstring>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>

#include "mie/hash.hpp"

namespace mie::worker {

namespace {

using nlohmann::json;

std::span<const std::uint8_t> bytes_of(const std::string& text) {
    return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

bool only_keys(const json& object, const std::set<std::string>& allowed, std::string& error) {
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (allowed.count(it.key()) == 0) {
            error = "job: unknown field '" + printable(it.key(), 64) + "'";
            return false;
        }
    }
    return true;
}

bool get_string(const json& object, const char* key, std::string& out, std::string& error) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) {
        error = std::string("job: field '") + key + "' is missing or not text";
        return false;
    }
    out = it->get<std::string>();
    return true;
}

json section_record(const char* kind, const std::string& name, const std::string& name_space,
                    const std::string& data) {
    return json{{"kind", kind},
                {"name", name},
                {"namespace", name_space},
                {"size", data.size()},
                {"sha256", sha256_hex(bytes_of(data))}};
}

}  // namespace

std::string printable(const std::string& text, std::size_t limit) {
    std::string out;
    out.reserve(text.size() < limit ? text.size() : limit);
    for (const char ch : text) {
        if (out.size() >= limit) {
            out += "...";
            break;
        }
        const unsigned char value = static_cast<unsigned char>(ch);
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            out += ' ';
        } else if (value < 0x20 || value >= 0x7F) {
            out += '?';
        } else {
            out += ch;
        }
    }
    return out;
}

std::string encode_job(const Job& job, std::string& error) {
    error.clear();
    if (job.op != "scan" && job.op != "describe" && job.op != "prepare") {
        error = "job: unknown operation";
        return std::string();
    }
    if (job.display_name.size() > kMaxDisplayNameBytes) {
        error = "job: the display name is too long";
        return std::string();
    }
    if (job.rules.size() > kMaxRuleFiles) {
        error = "job: too many rule files";
        return std::string();
    }
    json sections = json::array();
    std::size_t total = 0;
    sections.push_back(section_record("scoring", "scoring", "", job.scoring_json));
    total += job.scoring_json.size();
    sections.push_back(section_record("reputation", "reputation", "", job.reputation_json));
    total += job.reputation_json.size();
    for (const rules::RuleSource& rule : job.rules) {
        json record = section_record("rule", rule.file, rule.name_space, rule.text);
        record["readable"] = rule.readable;
        sections.push_back(std::move(record));
        total += rule.text.size();
    }
    const json header = {{"v", kJobVersion},
                         {"op", job.op},
                         {"display_name", job.display_name},
                         {"use_reputation", job.use_reputation},
                         {"test_fault", job.test_fault},
                         {"sections", std::move(sections)}};
    // ASCII only; text that is not UTF-8 (a file name) is replaced, it is for people only.
    const std::string header_text = header.dump(-1, ' ', true, json::error_handler_t::replace);
    if (header_text.size() > kMaxJobHeaderBytes) {
        error = "job: the header is too large";
        return std::string();
    }
    const std::size_t prefix = sizeof kJobMagic + 4;
    if (total > kMaxPreparationBytes || prefix + header_text.size() + total > kMaxPreparationBytes) {
        error = "job: scoring table, reputation list and rules together are over the limit";
        return std::string();
    }
    std::string out;
    out.reserve(prefix + header_text.size() + total);
    out.append(kJobMagic, sizeof kJobMagic);
    const std::uint32_t length = static_cast<std::uint32_t>(header_text.size());
    const char length_bytes[4] = {static_cast<char>((length >> 24) & 0xFF), static_cast<char>((length >> 16) & 0xFF),
                                  static_cast<char>((length >> 8) & 0xFF), static_cast<char>(length & 0xFF)};
    out.append(length_bytes, sizeof length_bytes);
    out.append(header_text);
    out.append(job.scoring_json);
    out.append(job.reputation_json);
    for (const rules::RuleSource& rule : job.rules) {
        out.append(rule.text);
    }
    return out;
}

bool decode_job(std::span<const std::uint8_t> bytes, Job& out, std::string& error) {
    error.clear();
    const std::size_t prefix = kJobPrefixBytes;
    if (bytes.size() > kMaxPreparationBytes) {
        error = "job: larger than the limit";
        return false;
    }
    std::size_t header_length = 0;
    if (!job_header_length(bytes, header_length, error)) {
        return false;
    }
    if (header_length > bytes.size() - prefix) {
        error = "job: the header length does not fit";
        return false;
    }
    const char* const header_begin = reinterpret_cast<const char*>(bytes.data()) + prefix;
    const json header = json::parse(header_begin, header_begin + header_length, nullptr, false);
    if (header.is_discarded() || !header.is_object()) {
        error = "job: the header is not a JSON object";
        return false;
    }
    if (!only_keys(header, {"v", "op", "display_name", "use_reputation", "test_fault", "sections"}, error)) {
        return false;
    }
    const auto version = header.find("v");
    if (version == header.end() || !version->is_number_integer() || version->get<std::int64_t>() != kJobVersion) {
        error = "job: unknown version";
        return false;
    }
    Job job;
    if (!get_string(header, "op", job.op, error) || !get_string(header, "display_name", job.display_name, error) ||
        !get_string(header, "test_fault", job.test_fault, error)) {
        return false;
    }
    if (job.op != "scan" && job.op != "describe" && job.op != "prepare") {
        error = "job: unknown operation";
        return false;
    }
    if (job.display_name.size() > kMaxDisplayNameBytes) {
        error = "job: the display name is too long";
        return false;
    }
    const auto reputation_flag = header.find("use_reputation");
    if (reputation_flag == header.end() || !reputation_flag->is_boolean()) {
        error = "job: field 'use_reputation' is missing or not a truth value";
        return false;
    }
    job.use_reputation = reputation_flag->get<bool>();
    const auto sections = header.find("sections");
    if (sections == header.end() || !sections->is_array() || sections->size() > kMaxRuleFiles + 2) {
        error = "job: the list of sections is missing or too long";
        return false;
    }

    std::size_t offset = prefix + header_length;
    bool have_scoring = false;
    bool have_reputation = false;
    for (const json& record : *sections) {
        if (!record.is_object() || !only_keys(record, {"kind", "name", "namespace", "size", "sha256", "readable"}, error)) {
            if (error.empty()) {
                error = "job: a section record is not an object";
            }
            return false;
        }
        std::string kind;
        std::string name;
        std::string name_space;
        std::string digest;
        if (!get_string(record, "kind", kind, error) || !get_string(record, "name", name, error) ||
            !get_string(record, "namespace", name_space, error) || !get_string(record, "sha256", digest, error)) {
            return false;
        }
        const auto size_field = record.find("size");
        if (size_field == record.end() || !size_field->is_number_unsigned()) {
            error = "job: a section has no size";
            return false;
        }
        const std::uint64_t size = size_field->get<std::uint64_t>();
        if (size > bytes.size() - offset) {
            error = "job: a section runs past the end of the job";
            return false;
        }
        std::string data(reinterpret_cast<const char*>(bytes.data()) + offset, static_cast<std::size_t>(size));
        offset += static_cast<std::size_t>(size);
        if (sha256_hex(bytes_of(data)) != digest) {
            error = "job: a section's bytes do not have the hash the header gives";
            return false;
        }
        if (kind == "scoring" && !have_scoring) {
            job.scoring_json = std::move(data);
            have_scoring = true;
        } else if (kind == "reputation" && !have_reputation) {
            job.reputation_json = std::move(data);
            have_reputation = true;
        } else if (kind == "rule") {
            rules::RuleSource rule;
            rule.file = std::move(name);
            rule.name_space = std::move(name_space);
            rule.text = std::move(data);
            const auto readable = record.find("readable");
            if (readable == record.end() || !readable->is_boolean()) {
                error = "job: a rule section does not say whether the file was readable";
                return false;
            }
            rule.readable = readable->get<bool>();
            job.rules.push_back(std::move(rule));
        } else {
            error = "job: an unknown or repeated kind of section";
            return false;
        }
    }
    if (offset != bytes.size()) {
        error = "job: bytes follow the last section";
        return false;
    }
    if (!have_scoring || !have_reputation) {
        error = "job: the scoring table or the reputation list is missing";
        return false;
    }
    out = std::move(job);
    return true;
}

bool job_header_length(std::span<const std::uint8_t> prefix, std::size_t& header_length, std::string& error) {
    if (prefix.size() < kJobPrefixBytes || std::memcmp(prefix.data(), kJobMagic, sizeof kJobMagic) != 0) {
        error = "job: not a job (wrong first bytes)";
        return false;
    }
    header_length = (static_cast<std::size_t>(prefix[8]) << 24) | (static_cast<std::size_t>(prefix[9]) << 16) |
                    (static_cast<std::size_t>(prefix[10]) << 8) | static_cast<std::size_t>(prefix[11]);
    if (header_length == 0 || header_length > kMaxJobHeaderBytes) {
        error = "job: the header length is not allowed";
        return false;
    }
    return true;
}

bool job_sections_length(std::span<const std::uint8_t> header_text, std::size_t& sections_length, std::string& error) {
    const char* const begin = reinterpret_cast<const char*>(header_text.data());
    const json header = json::parse(begin, begin + header_text.size(), nullptr, false);
    if (header.is_discarded() || !header.is_object()) {
        error = "job: the header is not a JSON object";
        return false;
    }
    const auto sections = header.find("sections");
    if (sections == header.end() || !sections->is_array() || sections->size() > kMaxRuleFiles + 2) {
        error = "job: the list of sections is missing or too long";
        return false;
    }
    std::size_t total = 0;
    for (const json& record : *sections) {
        const auto size = record.is_object() ? record.find("size") : record.end();
        if (!record.is_object() || size == record.end() || !size->is_number_unsigned()) {
            error = "job: a section has no size";
            return false;
        }
        const std::uint64_t value = size->get<std::uint64_t>();
        if (value > kMaxPreparationBytes || total + value > kMaxPreparationBytes) {
            error = "job: the sections are over the limit";
            return false;
        }
        total += static_cast<std::size_t>(value);
    }
    if (kJobPrefixBytes + header_text.size() + total > kMaxPreparationBytes) {
        error = "job: larger than the limit";
        return false;
    }
    sections_length = total;
    return true;
}

std::string encode_file_job(const FileJob& job, std::string& error) {
    error.clear();
    // The display name is text for people only: it is cut until the ENCODED job fits (escaping
    // can make a name several times longer); a cut character is replaced by the encoder.
    std::string name = job.display_name;
    if (name.size() > kMaxFileJobDisplayNameBytes) {
        name.resize(kMaxFileJobDisplayNameBytes);
    }
    for (;;) {
        const json body = {{"v", kJobVersion}, {"display_name", name}, {"test_fault", job.test_fault}};
        std::string text = body.dump(-1, ' ', true, json::error_handler_t::replace);
        if (text.size() <= sandbox::kMaxJobBytes) {
            return text;
        }
        if (name.empty()) {
            error = "file job: larger than the hand-over allows even without a display name";
            return std::string();
        }
        name.resize(name.size() / 2);
    }
}

bool decode_file_job(std::span<const std::uint8_t> bytes, FileJob& out, std::string& error) {
    if (bytes.empty() || bytes.size() > sandbox::kMaxJobBytes) {
        error = "file job: empty or too large";
        return false;
    }
    const char* const begin = reinterpret_cast<const char*>(bytes.data());
    const json body = json::parse(begin, begin + bytes.size(), nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        error = "file job: not a JSON object";
        return false;
    }
    if (!only_keys(body, {"v", "display_name", "test_fault"}, error)) {
        return false;
    }
    const auto version = body.find("v");
    if (version == body.end() || !version->is_number_integer() || version->get<std::int64_t>() != kJobVersion) {
        error = "file job: unknown version";
        return false;
    }
    FileJob job;
    if (!get_string(body, "display_name", job.display_name, error) || !get_string(body, "test_fault", job.test_fault, error)) {
        return false;
    }
    out = std::move(job);
    return true;
}

}  // namespace mie::worker
