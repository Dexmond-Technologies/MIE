#include "mie/rule_sources.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <system_error>
#include <utility>

namespace mie::rules {

namespace {

bool read_whole_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return !in.bad();
}

}  // namespace

std::vector<RuleSource> collect_rule_sources(const std::filesystem::path& directory) {
    // Name space -> path, as the reference builds it. std::map keeps them sorted.
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

    std::vector<RuleSource> sources;
    sources.reserve(files.size());
    for (const auto& [name_space, path] : files) {
        RuleSource source;
        std::error_code relative_error;
        source.file = std::filesystem::relative(path, directory, relative_error).generic_string();
        if (relative_error) {
            source.file = path.generic_string();
        }
        source.name_space = name_space;
        source.readable = read_whole_file(path, source.text);
        if (!source.readable) {
            source.text.clear();
        }
        sources.push_back(std::move(source));
    }
    return sources;
}

}  // namespace mie::rules
