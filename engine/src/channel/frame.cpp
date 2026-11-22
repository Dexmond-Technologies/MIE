#include "mie/channel/frame.hpp"

#include <limits>

namespace mie::channel {

using nlohmann::json;

const char* to_string(MessageType type) {
    switch (type) {
        case MessageType::Request: return "request";
        case MessageType::Response: return "response";
        case MessageType::Event: return "event";
    }
    return "request";
}

bool valid_op(const std::string& op) {
    if (op.empty() || op.size() > kMaxOpLength) {
        return false;
    }
    for (const char c : op) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    return true;
}

std::string encode_frame(const Message& message) {
    if (!valid_op(message.op) || !message.body.is_object() || message.v != kProtocolVersion) {
        return {};
    }
    const json j = {
        {"v", message.v},
        {"id", message.id},
        {"type", to_string(message.type)},
        {"op", message.op},
        {"body", message.body},
    };
    const std::string text = j.dump(-1, ' ', false, json::error_handler_t::replace);
    if (text.empty() || text.size() > kMaxFrameBytes) {
        return {};
    }
    const auto length = static_cast<std::uint32_t>(text.size());
    std::string frame;
    frame.reserve(kFrameHeaderBytes + text.size());
    frame.push_back(static_cast<char>((length >> 24) & 0xFF));
    frame.push_back(static_cast<char>((length >> 16) & 0xFF));
    frame.push_back(static_cast<char>((length >> 8) & 0xFF));
    frame.push_back(static_cast<char>(length & 0xFF));
    frame.append(text);
    return frame;
}

namespace {

DecodeResult fail(const char* why) {
    DecodeResult r;
    r.status = DecodeStatus::Error;
    r.error = why;
    return r;
}

// Nesting depth of the JSON text, counted outside strings. Checked before parsing so
// that a frame of a million '[' never reaches the parser.
bool depth_within_limit(std::span<const std::uint8_t> text) {
    std::size_t depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const std::uint8_t c : text) {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
        } else if (c == '{' || c == '[') {
            if (++depth > kMaxJsonDepth) {
                return false;
            }
        } else if (c == '}' || c == ']') {
            if (depth > 0) {
                --depth;
            }
        }
    }
    return true;
}

}  // namespace

DecodeResult decode_frame(std::span<const std::uint8_t> buffer) {
    if (buffer.size() < kFrameHeaderBytes) {
        return DecodeResult{};
    }
    const std::size_t length = (static_cast<std::size_t>(buffer[0]) << 24) |
                               (static_cast<std::size_t>(buffer[1]) << 16) |
                               (static_cast<std::size_t>(buffer[2]) << 8) |
                               static_cast<std::size_t>(buffer[3]);
    if (length == 0) {
        return fail("empty_frame");
    }
    if (length > kMaxFrameBytes) {
        return fail("frame_too_large");
    }
    if (buffer.size() - kFrameHeaderBytes < length) {
        return DecodeResult{};
    }
    const std::span<const std::uint8_t> text = buffer.subspan(kFrameHeaderBytes, length);
    if (!depth_within_limit(text)) {
        return fail("nesting_too_deep");
    }

    const json j = json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded()) {
        return fail("not_json");
    }
    if (!j.is_object()) {
        return fail("not_an_object");
    }
    for (auto it = j.begin(); it != j.end(); ++it) {
        const std::string& key = it.key();
        if (key != "v" && key != "id" && key != "type" && key != "op" && key != "body") {
            return fail("unknown_field");
        }
    }
    if (!j.contains("v") || !j.contains("id") || !j.contains("type") || !j.contains("op")) {
        return fail("missing_field");
    }

    DecodeResult r;
    const json& v = j.at("v");
    if (!v.is_number_integer() || v.get<std::int64_t>() != kProtocolVersion) {
        return fail("bad_version");
    }
    r.message.v = kProtocolVersion;

    const json& id = j.at("id");
    if (!id.is_number_unsigned()) {
        return fail("bad_id");
    }
    r.message.id = id.get<std::uint64_t>();

    const json& type = j.at("type");
    if (!type.is_string()) {
        return fail("bad_type");
    }
    const std::string type_text = type.get<std::string>();
    if (type_text == "request") {
        r.message.type = MessageType::Request;
    } else if (type_text == "response") {
        r.message.type = MessageType::Response;
    } else if (type_text == "event") {
        r.message.type = MessageType::Event;
    } else {
        return fail("bad_type");
    }

    const json& op = j.at("op");
    if (!op.is_string()) {
        return fail("bad_op");
    }
    r.message.op = op.get<std::string>();
    if (!valid_op(r.message.op)) {
        return fail("bad_op");
    }

    if (j.contains("body")) {
        if (!j.at("body").is_object()) {
            return fail("bad_body");
        }
        r.message.body = j.at("body");
    }

    r.status = DecodeStatus::Ok;
    r.consumed = kFrameHeaderBytes + length;
    return r;
}

}  // namespace mie::channel
