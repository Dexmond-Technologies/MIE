#include "mie/rules.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <system_error>
#include <utility>

// YARA's C headers are not written for a C++ compiler at a high warning level.
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <yara.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "mie/hash.hpp"

namespace mie::rules {

namespace {

// YARA has one global initialisation. It is done once and kept for the life of the process.
bool yara_ready() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] { ok = (yr_initialize() == ERROR_SUCCESS); });
    return ok;
}

bool read_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

struct CompileErrors {
    std::string first;
};

void on_compile_message(int error_level, const char* /*file_name*/, int line_number, const YR_RULE* /*rule*/,
                        const char* message, void* user_data) {
    if (error_level != YARA_ERROR_LEVEL_ERROR) {
        return;  // warnings do not make a rule file unusable (as in the reference)
    }
    auto* errors = static_cast<CompileErrors*>(user_data);
    if (errors->first.empty()) {
        errors->first = "line " + std::to_string(line_number) + ": " + (message != nullptr ? message : "error");
    }
}

// Compiles the given (name space, rule text) pairs together. Returns nullptr and sets
// `error` if any of them does not compile.
YR_RULES* compile(const std::vector<std::pair<std::string, std::string>>& sources, std::string& error) {
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        error = "cannot create a rule compiler";
        return nullptr;
    }
    CompileErrors errors;
    yr_compiler_set_callback(compiler, on_compile_message, &errors);
    // Rules enter only as the rule files that were handed in. A rule's "include" directive
    // is not followed: with no include callback YARA refuses the directive, and the file
    // that uses it does not compile (reviewer's condition, board B-3616).
    yr_compiler_set_include_callback(compiler, nullptr, nullptr, nullptr);
    for (const auto& [name_space, text] : sources) {
        if (yr_compiler_add_string(compiler, text.c_str(), name_space.c_str()) != 0) {
            error = errors.first.empty() ? "does not compile" : errors.first;
            yr_compiler_destroy(compiler);
            return nullptr;
        }
    }
    YR_RULES* rules = nullptr;
    const int result = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (result != ERROR_SUCCESS || rules == nullptr) {
        error = "cannot build the compiled rules";
        return nullptr;
    }
    return rules;
}

struct ScanState {
    std::vector<RuleMatch>* out = nullptr;
};

int on_scan_message(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data, void* user_data) {
    if (message != CALLBACK_MSG_RULE_MATCHING) {
        return CALLBACK_CONTINUE;
    }
    auto* rule = static_cast<YR_RULE*>(message_data);
    auto* state = static_cast<ScanState*>(user_data);
    RuleMatch match;
    match.rule = rule->identifier != nullptr ? rule->identifier : "";
    match.name_space = (rule->ns != nullptr && rule->ns->name != nullptr) ? rule->ns->name : "";
    YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type != META_TYPE_STRING || meta->identifier == nullptr || meta->string == nullptr) {
            continue;
        }
        const std::string key = meta->identifier;
        if (key == "severity") {
            match.severity = meta->string;
        } else if (key == "category") {
            match.category = meta->string;
        } else if (key == "description") {
            match.description = meta->string;
        }
    }
    state->out->push_back(std::move(match));
    return CALLBACK_CONTINUE;
}

std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
    });
    return text;
}

}  // namespace

struct RuleSet::Impl {
    YR_RULES* rules = nullptr;
    RulesState state = RulesState::Off;
    std::size_t files_loaded = 0;
    std::vector<RuleFileError> errors;
    std::string sha256;
    std::map<std::string, std::string> file_hashes;
};

RuleSet::RuleSet() : impl_(std::make_unique<Impl>()) {}

RuleSet::~RuleSet() {
    if (impl_->rules != nullptr) {
        yr_rules_destroy(impl_->rules);
    }
}

RulesState RuleSet::state() const { return impl_->state; }
std::size_t RuleSet::files_loaded() const { return impl_->files_loaded; }
const std::vector<RuleFileError>& RuleSet::errors() const { return impl_->errors; }
const std::string& RuleSet::sha256() const { return impl_->sha256; }
const std::map<std::string, std::string>& RuleSet::file_hashes() const { return impl_->file_hashes; }
std::string RuleSet::library_version() { return YR_VERSION; }

std::unique_ptr<RuleSet> RuleSet::load(const std::filesystem::path& directory) {
    std::unique_ptr<RuleSet> set(new RuleSet());
    Impl& impl = *set->impl_;
    if (!yara_ready()) {
        impl.errors.push_back({"(yara)", "the rule library could not be initialised"});
        return set;
    }

    // Name space -> path, as the reference builds it: the path below the rules directory
    // without its extension, separators turned into '_'. std::map keeps them sorted.
    std::map<std::string, std::filesystem::path> files;
    std::error_code ec;
    if (std::filesystem::is_directory(directory, ec)) {
        std::filesystem::recursive_directory_iterator it(directory, ec);
        const std::filesystem::recursive_directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            const std::filesystem::path path = it->path();
            if (it->is_directory(ec)) {
                if (path.filename() == "proposed") {
                    it.disable_recursion_pending();  // unreviewed generated rules: never loaded
                }
                continue;
            }
            const std::string extension = path.extension().string();
            if (extension != ".yar" && extension != ".yara") {
                continue;
            }
            const std::filesystem::path relative = std::filesystem::relative(path, directory, ec);
            if (ec) {
                continue;
            }
            if (relative.generic_string() == "auto_generated.yar") {
                continue;  // legacy unreviewed rules: never loaded
            }
            std::filesystem::path stem = relative;
            stem.replace_extension();
            std::string name_space = stem.generic_string();
            std::replace(name_space.begin(), name_space.end(), '/', '_');
            files[name_space] = path;
        }
    }
    if (files.empty()) {
        return set;  // Off: no rule files
    }

    // Every file alone first; a file that fails is left out and recorded.
    std::vector<std::pair<std::string, std::string>> good;
    std::map<std::string, std::string> hashes;  // file name below the directory -> SHA-256
    for (const auto& [name_space, path] : files) {
        std::string text;
        if (!read_file(path, text)) {
            impl.errors.push_back({path.generic_string(), "cannot be read"});
            continue;
        }
        std::string error;
        YR_RULES* alone = compile({{name_space, text}}, error);
        if (alone == nullptr) {
            impl.errors.push_back({path.generic_string(), error});
            continue;
        }
        yr_rules_destroy(alone);
        hashes[std::filesystem::relative(path, directory, ec).generic_string()] =
            sha256_hex(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
        good.emplace_back(name_space, std::move(text));
    }
    if (good.empty()) {
        return set;  // Off: every rule file failed
    }

    std::string error;
    impl.rules = compile(good, error);
    if (impl.rules == nullptr) {
        impl.errors.push_back({"(combined)", error});
        return set;  // Off: the good files do not compile together
    }
    impl.files_loaded = good.size();
    impl.state = impl.errors.empty() ? RulesState::On : RulesState::Degraded;

    std::string lines;
    for (const auto& [name, digest] : hashes) {
        lines += name + " " + digest + "\n";
    }
    impl.file_hashes = hashes;
    impl.sha256 = sha256_hex(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(lines.data()), lines.size()));
    return set;
}

bool RuleSet::scan(std::span<const std::uint8_t> data, std::vector<RuleMatch>& out, std::string& error) const {
    out.clear();
    if (impl_->rules == nullptr) {
        error = "no rules loaded";
        return false;
    }
    static const std::uint8_t nothing = 0;
    const std::uint8_t* buffer = data.empty() ? &nothing : data.data();
    ScanState state;
    state.out = &out;
    const int result = yr_rules_scan_mem(impl_->rules, buffer, data.size(), SCAN_FLAGS_REPORT_RULES_MATCHING,
                                         on_scan_message, &state, kScanTimeoutSeconds);
    if (result == ERROR_SCAN_TIMEOUT) {
        out.clear();
        error = "rule scan ran out of time";
        return false;
    }
    if (result != ERROR_SUCCESS) {
        out.clear();
        error = "rule scan failed (YARA error " + std::to_string(result) + ")";
        return false;
    }
    for (RuleMatch& match : out) {
        match.severity = to_lower(match.severity);
        match.category = to_lower(match.category);
    }
    return true;
}

}  // namespace mie::rules
