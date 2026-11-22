// Frozen interface 3: the messages on the local channel (protocol version 1).
// See engine/docs/INTERFACES.md.
//
// One frame = 4 bytes (length of the JSON text, big-endian) + the JSON text (UTF-8).
// The JSON text is one object: {"v":1,"id":<number>,"type":"request"|"response"|"event",
// "op":"<name>","body":{...}}. Unknown fields are refused, not ignored.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include <nlohmann/json.hpp>

namespace mie::channel {

inline constexpr int kProtocolVersion = 1;
inline constexpr std::size_t kMaxFrameBytes = 1024 * 1024;  // JSON text, without the 4 length bytes
inline constexpr std::size_t kFrameHeaderBytes = 4;
inline constexpr std::size_t kMaxOpLength = 64;
inline constexpr std::size_t kMaxJsonDepth = 32;

enum class MessageType { Request, Response, Event };

struct Message {
    int v = kProtocolVersion;
    std::uint64_t id = 0;
    MessageType type = MessageType::Request;
    std::string op;
    nlohmann::json body = nlohmann::json::object();
};

const char* to_string(MessageType type);

// Returns the frame bytes, or an empty string if the message cannot be sent
// (op not allowed, body not an object, text larger than kMaxFrameBytes).
std::string encode_frame(const Message& message);

enum class DecodeStatus {
    NeedMore,  // the buffer does not hold a whole frame yet
    Ok,        // `message` is filled, `consumed` bytes belong to this frame
    Error,     // the stream is not usable any more; `error` says why
};

struct DecodeResult {
    DecodeStatus status = DecodeStatus::NeedMore;
    Message message;
    std::size_t consumed = 0;
    std::string error;
};

// Decodes the first frame of `buffer`. Never reads past buffer.size().
DecodeResult decode_frame(std::span<const std::uint8_t> buffer);

// True if `op` is 1 to kMaxOpLength characters of a-z, 0-9, '.', '_' or '-'.
bool valid_op(const std::string& op);

}  // namespace mie::channel
