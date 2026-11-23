#include <initializer_list>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "mie/result.hpp"

namespace {

mie::ScanResult sample() {
    mie::ScanResult r;
    r.subject.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    r.subject.display_name = "example.bin";
    r.state = mie::ScanState::NotFullyScanned;
    r.reason = "worker stopped at the time limit";
    r.score = 0;
    r.verdict = "";
    r.findings.push_back(mie::Finding{"high_entropy", "entropy", 15, "whole-file entropy 7.9", false});
    r.findings.push_back(mie::Finding{"archive_member", "", 70, "worst member", true});
    r.hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e";
    r.hashes.sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    r.hashes.sha256 = r.subject.sha256;
    r.size = 123456789012ull;
    r.engine_version = "0.0.1-test";
    r.profile = "parity";
    r.rules_state = mie::RulesState::On;
    r.rules_sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    return r;
}

// A fully scanned result: rules ON, no reason.
mie::ScanResult scanned_sample() {
    mie::ScanResult r = sample();
    r.state = mie::ScanState::Scanned;
    r.reason.clear();
    r.score = 15;
    r.verdict = "SUSPICIOUS (LOW)";
    return r;
}

}  // namespace

TEST_CASE("a result survives JSON and back unchanged", "[result]") {
    const mie::ScanResult before = sample();
    const std::string text = mie::to_json(before);
    mie::ScanResult after;
    std::string error;
    REQUIRE(mie::from_json(text, after, error));
    REQUIRE(error.empty());
    REQUIRE(after == before);
    REQUIRE(mie::to_json(after) == text);  // canonical: equal results give equal bytes
}

TEST_CASE("the JSON text has no white space and sorted keys", "[result]") {
    const std::string text = mie::to_json(sample());
    REQUIRE(text.find('\n') == std::string::npos);
    REQUIRE(text.find("\": ") == std::string::npos);
    REQUIRE(text.find("\"engine\":{\"profile\":\"parity\",\"version\":\"0.0.1-test\"}") != std::string::npos);
    REQUIRE(text.find("\"rules\":{\"sha256\":") != std::string::npos);
    REQUIRE(text.find("\"state\":\"ON\"") != std::string::npos);
    REQUIRE(text.find("\"findings\"") < text.find("\"hashes\""));
    REQUIRE(text.find("\"hashes\"") < text.find("\"reason\""));
    REQUIRE(text.find("\"state\":\"not_fully_scanned\"") != std::string::npos);
}

TEST_CASE("unknown fields are refused", "[result]") {
    std::string text = mie::to_json(sample());
    text.insert(1, "\"extra\":1,");
    mie::ScanResult out;
    std::string error;
    REQUIRE_FALSE(mie::from_json(text, out, error));
    REQUIRE_FALSE(error.empty());
}

TEST_CASE("an unknown schema version is refused", "[result]") {
    mie::ScanResult r = sample();
    r.schema_version = 2;
    mie::ScanResult out;
    std::string error;
    REQUIRE_FALSE(mie::from_json(mie::to_json(r), out, error));
    REQUIRE(error == "unknown schema version");
}

TEST_CASE("broken JSON and wrong types are refused", "[result]") {
    mie::ScanResult out;
    std::string error;
    REQUIRE_FALSE(mie::from_json("", out, error));
    REQUIRE_FALSE(mie::from_json("{", out, error));
    REQUIRE_FALSE(mie::from_json("[]", out, error));
    REQUIRE_FALSE(mie::from_json("{\"schema_version\":1}", out, error));

    std::string text = mie::to_json(sample());
    const std::string needle = "\"score\":0";
    const std::size_t at = text.find(needle);
    REQUIRE(at != std::string::npos);
    text.replace(at, needle.size(), "\"score\":\"0\"");
    REQUIRE_FALSE(mie::from_json(text, out, error));
}

TEST_CASE("a failed parse leaves the output untouched", "[result]") {
    mie::ScanResult out = sample();
    const mie::ScanResult before = out;
    std::string error;
    REQUIRE_FALSE(mie::from_json("{\"schema_version\":1}", out, error));
    REQUIRE(out == before);
}

TEST_CASE("a fully scanned result with rules ON is consistent and survives JSON", "[result][rules]") {
    const mie::ScanResult r = scanned_sample();
    std::string why;
    REQUIRE(mie::consistent(r, why));
    mie::ScanResult back;
    std::string error;
    REQUIRE(mie::from_json(mie::to_json(r), back, error));
    REQUIRE(back == r);
}

TEST_CASE("a scan with rules DEGRADED or OFF can never be 'scanned'", "[result][rules]") {
    for (const mie::RulesState state : {mie::RulesState::Degraded, mie::RulesState::Off}) {
        mie::ScanResult r = scanned_sample();
        r.rules_state = state;
        if (state == mie::RulesState::Off) {
            r.rules_sha256.clear();
        }
        std::string why;
        REQUIRE_FALSE(mie::consistent(r, why));
        REQUIRE_FALSE(why.empty());

        // ... and a reader refuses such a result, whoever wrote it
        mie::ScanResult out;
        std::string error;
        REQUIRE_FALSE(mie::from_json(mie::to_json(r), out, error));

        // the same scan reported honestly is accepted
        r.state = mie::ScanState::NotFullyScanned;
        r.reason = "rules not fully loaded";
        REQUIRE(mie::consistent(r, why));
        REQUIRE(mie::from_json(mie::to_json(r), out, error));
        REQUIRE(out.state == mie::ScanState::NotFullyScanned);
    }
}

TEST_CASE("states and reasons must agree", "[result][rules]") {
    std::string why;

    mie::ScanResult with_reason = scanned_sample();
    with_reason.reason = "something";
    REQUIRE_FALSE(mie::consistent(with_reason, why));

    mie::ScanResult no_reason = sample();  // not_fully_scanned
    no_reason.reason.clear();
    REQUIRE_FALSE(mie::consistent(no_reason, why));

    mie::ScanResult refused;
    refused.state = mie::ScanState::NotScanned;
    refused.reason = "link";
    REQUIRE(mie::consistent(refused, why));
    refused.verdict = "CLEAN";
    REQUIRE_FALSE(mie::consistent(refused, why));
    refused.verdict.clear();
    refused.score = 1;
    REQUIRE_FALSE(mie::consistent(refused, why));
    refused.score = 0;
    refused.findings.push_back(mie::Finding{"anomaly", "", 10, "x", false});
    REQUIRE_FALSE(mie::consistent(refused, why));
}

TEST_CASE("rules OFF carries no rule-set hash; unknown rules state is refused", "[result][rules]") {
    mie::ScanResult r = sample();
    r.rules_state = mie::RulesState::Off;
    std::string why;
    REQUIRE_FALSE(mie::consistent(r, why));  // hash still set
    r.rules_sha256.clear();
    REQUIRE(mie::consistent(r, why));

    std::string text = mie::to_json(sample());
    const std::string needle = "\"state\":\"ON\"";
    const std::size_t at = text.find(needle);
    REQUIRE(at != std::string::npos);
    text.replace(at, needle.size(), "\"state\":\"MAYBE\"");
    mie::ScanResult out;
    std::string error;
    REQUIRE_FALSE(mie::from_json(text, out, error));
    REQUIRE(error == "unknown rules state");
}

TEST_CASE("a result without the engine or rules fields is refused", "[result][rules]") {
    std::string text = mie::to_json(sample());
    const std::size_t at = text.find("\"engine\":");
    REQUIRE(at != std::string::npos);
    const std::size_t end = text.find('}', at);
    text.erase(at, end - at + 2);  // the object and the comma after it
    mie::ScanResult out;
    std::string error;
    REQUIRE_FALSE(mie::from_json(text, out, error));
}
