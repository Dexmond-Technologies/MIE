// mie-scoring-check: the direct comparison of the scoring function (reviewer's ruling,
// board B-3488). A test tool, not a product program.
//
// Reads the scoring table and a file of scoring vectors written by
// engine/tools/parity/scoring_vectors.py (lists of calls with the answers of the PYTHON
// reference scorer), makes the same calls on the C++ scorer, and compares score, verdict
// and the score of every family. Exit code 0 only if every vector agrees.
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "mie/scoring.hpp"

namespace {

bool read_file(const char* path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    using nlohmann::json;
    if (argc != 3) {
        std::fputs("usage: mie-scoring-check SCORING_TABLE.json VECTORS.json\n", stderr);
        return 2;
    }
    std::string table_text;
    std::string vectors_text;
    if (!read_file(argv[1], table_text) || !read_file(argv[2], vectors_text)) {
        std::fputs("mie-scoring-check: cannot read an input file\n", stderr);
        return 2;
    }
    mie::ScoringTable table;
    std::string error;
    if (!mie::load_scoring_table(table_text, table, error)) {
        std::fprintf(stderr, "mie-scoring-check: %s\n", error.c_str());
        return 2;
    }
    const json document = json::parse(vectors_text, nullptr, false);
    if (document.is_discarded() || !document.contains("vectors") || !document.at("vectors").is_array()) {
        std::fputs("mie-scoring-check: the vectors file is not valid\n", stderr);
        return 2;
    }

    std::size_t compared = 0;
    std::size_t different = 0;
    for (const json& vector : document.at("vectors")) {
        mie::Scorer scorer(table);
        bool usable = true;
        for (const json& call : vector.at("calls")) {
            const std::string kind = call.at(0).get<std::string>();
            if (kind == "finding") {
                std::optional<int> weight;
                if (!call.at(2).is_null()) {
                    weight = call.at(2).get<int>();
                }
                const std::string family = call.at(3).is_null() ? std::string() : call.at(3).get<std::string>();
                scorer.add_finding(call.at(1).get<std::string>(), "vector", weight, family);
            } else if (kind == "floor_finding") {
                scorer.add_floor_finding(call.at(1).get<std::string>(), "vector", call.at(2).get<int>());
            } else if (kind == "set_floor") {
                scorer.set_floor(call.at(1).get<int>());
            } else if (kind == "cap_heuristics") {
                std::optional<int> cap;
                if (!call.at(1).is_null()) {
                    cap = call.at(1).get<int>();
                }
                scorer.cap_heuristics(cap);
            } else {
                usable = false;
            }
        }
        const json& expected = vector.at("expected");
        std::map<std::string, int> expected_families;
        for (auto it = expected.at("family_scores").begin(); it != expected.at("family_scores").end(); ++it) {
            expected_families[it.key()] = it.value().get<int>();
        }
        const int score = scorer.score();
        const std::string verdict = scorer.verdict();
        ++compared;
        if (!usable || score != expected.at("score").get<int>() ||
            verdict != expected.at("verdict").get<std::string>() || scorer.family_scores() != expected_families) {
            ++different;
            if (different <= 25) {
                std::printf("DIFFERENT vector %s (%s): reference score %d verdict %s; C++ score %d verdict %s; calls %s\n",
                            vector.at("id").dump().c_str(), vector.at("group").get<std::string>().c_str(),
                            expected.at("score").get<int>(), expected.at("verdict").get<std::string>().c_str(),
                            score, verdict.c_str(), vector.at("calls").dump().c_str());
            }
        }
    }
    std::printf("scoring vectors: %zu compared, %zu different (score, verdict and every family score compared)\n",
                compared, different);
    if (compared == 0) {
        std::fputs("mie-scoring-check: no vectors\n", stderr);
        return 2;
    }
    return different == 0 ? 0 : 1;
}
