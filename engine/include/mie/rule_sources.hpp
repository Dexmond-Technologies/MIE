// The rule files of a rules directory, as text, chosen and named exactly as the Python
// reference chooses and names them (dexmond_mie/yara_analyzer.py). No rule library is
// needed for this: the service reads the files and hands their text to the confined
// worker, which compiles them (the worker opens no path).
#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace mie::rules {

struct RuleSource {
    std::string file;        // path below the rules directory, forward slashes
    std::string name_space;  // that path without its extension, separators turned into '_'
    std::string text;        // the rule source; empty when `readable` is false
    bool readable = true;
};

// Every *.yar and *.yara file under `directory`: not the sub-folder "proposed", not a
// top-level "auto_generated.yar" (the reference never loads those). Sorted by name space;
// of two files with the same name space one is kept. A directory that does not exist gives
// an empty list.
std::vector<RuleSource> collect_rule_sources(const std::filesystem::path& directory);

}  // namespace mie::rules
