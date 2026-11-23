// Unit tests of the scorer against the parity table. The expected numbers here are worked
// out by hand from the reference's rules (dexmond_mie/scoring.py); the full comparison with
// the reference scorer itself is the scoring_vectors test.
#include <fstream>
#include <iterator>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "mie/scoring.hpp"

namespace {

std::string table_text() {
    std::ifstream in(MIE_SCORING_TABLE_FILE, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

mie::ScoringTable table() {
    mie::ScoringTable t;
    std::string error;
    const bool ok = mie::load_scoring_table(table_text(), t, error);
    INFO(error);
    REQUIRE(ok);
    return t;
}

}  // namespace

TEST_CASE("the parity table loads with all its parts", "[scoring]") {
    const mie::ScoringTable t = table();
    REQUIRE(t.profile == "parity");
    REQUIRE(t.weights.size() == 21);
    REQUIRE(t.weights.at("api_chain") == 35);
    REQUIRE(t.default_weight == 5);
    REQUIRE(t.family_caps.size() == 4);
    REQUIRE(t.family_caps.at("imports") == 35);
    REQUIRE(t.uncappable_families.count("critical_yara") == 1);
    REQUIRE(t.signed_cap == 29);
    REQUIRE(t.score_max == 100);
    REQUIRE(t.medium_from == 30);
    REQUIRE(t.malicious_from == 70);
    REQUIRE(t.label_partial == "SUSPICIOUS (LOW): oversize, partially scanned");
    REQUIRE(t.limits.at("MAX_ARCHIVE_DEPTH") == 3.0);
    REQUIRE(t.limits.at("SLIDING_HIGH_SHARE") == 0.25);
}

TEST_CASE("a broken table is refused", "[scoring]") {
    mie::ScoringTable t;
    std::string error;
    REQUIRE_FALSE(mie::load_scoring_table("", t, error));
    REQUIRE_FALSE(mie::load_scoring_table("[]", t, error));
    REQUIRE_FALSE(mie::load_scoring_table("{}", t, error));

    std::string text = table_text();
    text.insert(1, "\"surprise\": 1,");
    REQUIRE_FALSE(mie::load_scoring_table(text, t, error));
    REQUIRE(error == "scoring table: unknown field: surprise");

    text = table_text();
    const std::string needle = "\"signed_cap\": 29";
    const std::size_t at = text.find(needle);
    REQUIRE(at != std::string::npos);
    text.replace(at, needle.size(), "\"signed_cap\": \"29\"");
    REQUIRE_FALSE(mie::load_scoring_table(text, t, error));
}

TEST_CASE("no findings is score 0 and CLEAN", "[scoring]") {
    const mie::ScoringTable t = table();
    const mie::Scorer scorer(t);
    REQUIRE(scorer.score() == 0);
    REQUIRE(scorer.verdict() == "CLEAN");
    REQUIRE(scorer.family_scores().empty());
}

TEST_CASE("verdict lines: 29 is LOW, 30 is MEDIUM, 69 is MEDIUM, 70 is MALICIOUS", "[scoring]") {
    const mie::ScoringTable t = table();
    const auto verdict_at = [&](int points) {
        mie::Scorer scorer(t);
        scorer.add_finding("obfuscated_script", "x", points);
        REQUIRE(scorer.score() == points);
        return scorer.verdict();
    };
    REQUIRE(verdict_at(1) == "SUSPICIOUS (LOW)");
    REQUIRE(verdict_at(29) == "SUSPICIOUS (LOW)");
    REQUIRE(verdict_at(30) == "SUSPICIOUS (MEDIUM)");
    REQUIRE(verdict_at(69) == "SUSPICIOUS (MEDIUM)");
    REQUIRE(verdict_at(70) == "MALICIOUS");
    REQUIRE(verdict_at(100) == "MALICIOUS");
}

TEST_CASE("an unknown category gets the default weight", "[scoring]") {
    const mie::ScoringTable t = table();
    mie::Scorer scorer(t);
    scorer.add_finding("never_heard_of_it", "x");
    REQUIRE(scorer.score() == 5);
    REQUIRE(scorer.family_scores().at("never_heard_of_it") == 5);
}

TEST_CASE("a family cap holds at the cap and above it, not below", "[scoring]") {
    const mie::ScoringTable t = table();
    {
        mie::Scorer scorer(t);  // imports: 15 + 10 = 25, below the cap of 35
        scorer.add_finding("api_chain_minor", "x");
        scorer.add_finding("suspicious_import", "x");
        REQUIRE(scorer.score() == 25);
    }
    {
        mie::Scorer scorer(t);  // imports: exactly 35
        scorer.add_finding("api_chain", "x");
        REQUIRE(scorer.score() == 35);
    }
    {
        mie::Scorer scorer(t);  // imports: 35 + 10 + 15 = 60, capped at 35
        scorer.add_finding("api_chain", "x");
        scorer.add_finding("suspicious_import", "x");
        scorer.add_finding("dynamic_resolution_chain", "x");
        REQUIRE(scorer.score() == 35);
        REQUIRE(scorer.family_scores().at("imports") == 35);
    }
    {
        mie::Scorer scorer(t);  // three rule matches of 20: yara family capped at 40
        scorer.add_finding("yara_match", "x", 20);
        scorer.add_finding("yara_match", "x", 20);
        scorer.add_finding("yara_match", "x", 20);
        REQUIRE(scorer.score() == 40);
    }
}

TEST_CASE("a family given with the finding replaces the category's family", "[scoring]") {
    const mie::ScoringTable t = table();
    mie::Scorer scorer(t);
    scorer.add_finding("high_entropy", "x", std::nullopt, "packing");  // 15
    scorer.add_finding("wx_section", "x", std::nullopt, "packing");    // 10
    scorer.add_finding("packer_detected", "x");                         // 15, packing by default
    REQUIRE(scorer.family_scores().at("packing") == 25);                // 40 capped at 25
    REQUIRE(scorer.family_scores().count("entropy") == 0);
    REQUIRE(scorer.score() == 25);
}

TEST_CASE("the signature cap limits heuristics to 29 but not hard evidence", "[scoring]") {
    const mie::ScoringTable t = table();
    {
        mie::Scorer scorer(t);
        scorer.add_finding("api_chain", "x");          // 35
        scorer.add_finding("b64_executable", "x");     // 30
        scorer.cap_heuristics();
        REQUIRE(scorer.score() == 29);
        REQUIRE(scorer.verdict() == "SUSPICIOUS (LOW)");
    }
    {
        mie::Scorer scorer(t);
        scorer.add_finding("api_chain", "x");          // heuristic, capped to 29 with the rest
        scorer.add_finding("critical_yara", "x");      // 70, uncappable
        scorer.cap_heuristics();
        REQUIRE(scorer.score() == 99);
    }
    {
        mie::Scorer scorer(t);
        scorer.add_finding("suspicious_string", "x");  // 5: below the cap, unchanged
        scorer.cap_heuristics();
        REQUIRE(scorer.score() == 5);
    }
    {
        mie::Scorer scorer(t);
        scorer.add_finding("api_chain", "x");
        scorer.cap_heuristics(0);                       // an explicit cap of 0 is a cap, not "none"
        REQUIRE(scorer.score() == 0);
        REQUIRE(scorer.verdict() == "CLEAN");
    }
}

TEST_CASE("a floor raises the score and never lowers it", "[scoring]") {
    const mie::ScoringTable t = table();
    {
        mie::Scorer scorer(t);
        scorer.add_finding("suspicious_string", "x");          // 5
        scorer.add_floor_finding("archive_member", "x", 70);    // floor 70, not added
        REQUIRE(scorer.score() == 70);
        REQUIRE(scorer.verdict() == "MALICIOUS");
        REQUIRE(scorer.family_scores().count("archive_member") == 0);
        REQUIRE(scorer.findings().size() == 2);
        REQUIRE(scorer.findings().back().floor);
    }
    {
        mie::Scorer scorer(t);
        scorer.add_finding("critical_yara", "x");               // 70
        scorer.add_finding("b64_executable", "x");              // 30 -> 100
        scorer.set_floor(30);
        REQUIRE(scorer.score() == 100);
    }
    {
        mie::Scorer scorer(t);
        scorer.set_floor(70);
        scorer.set_floor(30);                                    // the highest floor wins
        scorer.cap_heuristics();                                 // a floor is not lowered by the signature cap
        REQUIRE(scorer.score() == 70);
    }
}

TEST_CASE("the score never exceeds the maximum", "[scoring]") {
    const mie::ScoringTable t = table();
    mie::Scorer scorer(t);
    scorer.add_finding("critical_yara", "x");
    scorer.add_finding("critical_yara", "x");
    scorer.add_finding("reputation_malicious", "x");
    scorer.add_floor_finding("archive_member", "x", 130);
    REQUIRE(scorer.score() == 100);
    REQUIRE(scorer.verdict() == "MALICIOUS");
}
