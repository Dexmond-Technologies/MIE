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
