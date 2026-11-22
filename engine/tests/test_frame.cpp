#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "mie/channel/frame.hpp"

using namespace mie::channel;

namespace {

std::span<const std::uint8_t> bytes(const std::string& text) {
    return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

// A frame around arbitrary JSON text, with a correct length prefix.
std::string frame_of(const std::string& json_text) {
    const auto n = static_cast<std::uint32_t>(json_text.size());
    std::string out;
    out.push_back(static_cast<char>((n >> 24) & 0xFF));
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    out.push_back(static_cast<char>((n >> 8) & 0xFF));
    out.push_back(static_cast<char>(n & 0xFF));
    out += json_text;
    return out;
}

DecodeResult decode_text(const std::string& json_text) {
    const std::string frame = frame_of(json_text);
    return decode_frame(bytes(frame));
}

}  // namespace

TEST_CASE("a message survives encode and decode", "[frame]") {
    Message m;
    m.id = 42;
    m.type = MessageType::Request;
    m.op = "status";
    m.body = nlohmann::json{{"path", "C:\\x\\y"}, {"n", 3}};
    const std::string frame = encode_frame(m);
    REQUIRE(frame.size() > kFrameHeaderBytes);

    const DecodeResult r = decode_frame(bytes(frame));
    REQUIRE(r.status == DecodeStatus::Ok);
    REQUIRE(r.consumed == frame.size());
    REQUIRE(r.message.id == 42);
    REQUIRE(r.message.type == MessageType::Request);
    REQUIRE(r.message.op == "status");
    REQUIRE(r.message.body == m.body);
}

TEST_CASE("an incomplete frame asks for more bytes", "[frame]") {
    Message m;
    m.op = "ping";
    const std::string frame = encode_frame(m);
    for (std::size_t cut = 0; cut < frame.size(); ++cut) {
        const DecodeResult r = decode_frame(bytes(frame.substr(0, cut)));
        REQUIRE(r.status == DecodeStatus::NeedMore);
    }
}

TEST_CASE("two frames in one buffer are decoded one after the other", "[frame]") {
    Message a;
    a.id = 1;
    a.op = "ping";
    Message b;
    b.id = 2;
    b.op = "status";
    const std::string both = encode_frame(a) + encode_frame(b);
    const DecodeResult first = decode_frame(bytes(both));
    REQUIRE(first.status == DecodeStatus::Ok);
    REQUIRE(first.message.id == 1);
    const DecodeResult second = decode_frame(bytes(both.substr(first.consumed)));
    REQUIRE(second.status == DecodeStatus::Ok);
    REQUIRE(second.message.id == 2);
    REQUIRE(first.consumed + second.consumed == both.size());
}

TEST_CASE("a length above the limit is refused before any data arrives", "[frame]") {
    const std::vector<std::uint8_t> header{0x00, 0x10, 0x00, 0x01};  // 1 MiB + 1
    const DecodeResult r = decode_frame(header);
    REQUIRE(r.status == DecodeStatus::Error);
    REQUIRE(r.error == "frame_too_large");
}

TEST_CASE("a length of exactly the limit is not refused by size", "[frame]") {
    const std::vector<std::uint8_t> header{0x00, 0x10, 0x00, 0x00};  // 1 MiB
    const DecodeResult r = decode_frame(header);
    REQUIRE(r.status == DecodeStatus::NeedMore);
}

TEST_CASE("an empty frame is refused", "[frame]") {
    const std::vector<std::uint8_t> header{0x00, 0x00, 0x00, 0x00};
    const DecodeResult r = decode_frame(header);
    REQUIRE(r.status == DecodeStatus::Error);
    REQUIRE(r.error == "empty_frame");
}

TEST_CASE("unknown fields are refused, not ignored", "[frame]") {
    const DecodeResult r = decode_text(R"({"v":1,"id":1,"type":"request","op":"ping","extra":true})");
    REQUIRE(r.status == DecodeStatus::Error);
    REQUIRE(r.error == "unknown_field");
}

TEST_CASE("wrong version, type, id, op and body are refused", "[frame]") {
    REQUIRE(decode_text(R"({"v":2,"id":1,"type":"request","op":"ping"})").error == "bad_version");
    REQUIRE(decode_text(R"({"v":"1","id":1,"type":"request","op":"ping"})").error == "bad_version");
    REQUIRE(decode_text(R"({"v":1,"id":-1,"type":"request","op":"ping"})").error == "bad_id");
    REQUIRE(decode_text(R"({"v":1,"id":1.5,"type":"request","op":"ping"})").error == "bad_id");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"command","op":"ping"})").error == "bad_type");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"request","op":"Ping"})").error == "bad_op");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"request","op":""})").error == "bad_op");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"request","op":"a/b"})").error == "bad_op");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"request","op":"ping","body":[]})").error == "bad_body");
    REQUIRE(decode_text(R"({"v":1,"id":1,"type":"request"})").error == "missing_field");
    REQUIRE(decode_text(R"([1,2,3])").error == "not_an_object");
    REQUIRE(decode_text(R"({"v":1,)").error == "not_json");
}

TEST_CASE("a body is optional and defaults to an empty object", "[frame]") {
    const DecodeResult r = decode_text(R"({"v":1,"id":7,"type":"event","op":"scan.done"})");
    REQUIRE(r.status == DecodeStatus::Ok);
    REQUIRE(r.message.type == MessageType::Event);
    REQUIRE(r.message.body.is_object());
    REQUIRE(r.message.body.empty());
}

TEST_CASE("deep nesting is refused before parsing", "[frame]") {
    std::string body(40, '[');
    body += std::string(40, ']');
    const DecodeResult r =
        decode_text(std::string(R"({"v":1,"id":1,"type":"request","op":"ping","body":{"a":)") + body + "}}");
    REQUIRE(r.status == DecodeStatus::Error);
    REQUIRE(r.error == "nesting_too_deep");
}

TEST_CASE("brackets inside strings do not count as nesting", "[frame]") {
    const std::string many(200, '[');
    const DecodeResult r = decode_text(
        std::string(R"({"v":1,"id":1,"type":"request","op":"ping","body":{"a":")") + many + R"("}})");
    REQUIRE(r.status == DecodeStatus::Ok);
}

TEST_CASE("messages that cannot be sent are not encoded", "[frame]") {
    Message bad_op;
    bad_op.op = "Not Allowed";
    REQUIRE(encode_frame(bad_op).empty());

    Message bad_body;
    bad_body.op = "ping";
    bad_body.body = nlohmann::json::array();
    REQUIRE(encode_frame(bad_body).empty());

    Message too_big;
    too_big.op = "ping";
    too_big.body = nlohmann::json{{"blob", std::string(kMaxFrameBytes, 'x')}};
    REQUIRE(encode_frame(too_big).empty());
}

TEST_CASE("valid_op accepts the documented alphabet only", "[frame]") {
    REQUIRE(valid_op("ping"));
    REQUIRE(valid_op("quarantine.list"));
    REQUIRE(valid_op("scan_file-2"));
    REQUIRE_FALSE(valid_op(""));
    REQUIRE_FALSE(valid_op("Status"));
    REQUIRE_FALSE(valid_op("a b"));
    REQUIRE_FALSE(valid_op(std::string(kMaxOpLength + 1, 'a')));
    REQUIRE(valid_op(std::string(kMaxOpLength, 'a')));
}
