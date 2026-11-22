// Shared by the POSIX and Windows transports: turns a byte stream into messages.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "mie/channel/transport.hpp"

namespace mie::channel {

class StreamConnection : public Connection {
public:
    bool send(const Message& message, std::string& error) final {
        const std::string frame = encode_frame(message);
        if (frame.empty()) {
            error = "message cannot be encoded";
            return false;
        }
        return write_all(frame.data(), frame.size(), error);
    }

    bool receive(Message& out, int timeout_ms, std::string& error) final {
        for (;;) {
            DecodeResult decoded = decode_frame(buffer_);
            if (decoded.status == DecodeStatus::Ok) {
                out = std::move(decoded.message);
                buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(decoded.consumed));
                return true;
            }
            if (decoded.status == DecodeStatus::Error) {
                error = decoded.error;
                return false;
            }
            std::uint8_t chunk[16 * 1024];
            const long n = read_some(chunk, sizeof chunk, timeout_ms, error);
            if (n < 0) {
                return false;  // error already set ("timeout" or a system error)
            }
            if (n == 0) {
                error = "closed";
                return false;
            }
            buffer_.insert(buffer_.end(), chunk, chunk + n);
        }
    }

protected:
    // Reads up to `size` bytes. Returns the count, 0 when the peer closed, -1 with
    // `error` set on timeout ("timeout") or failure.
    virtual long read_some(std::uint8_t* data, std::size_t size, int timeout_ms, std::string& error) = 0;
    virtual bool write_all(const char* data, std::size_t size, std::string& error) = 0;

private:
    std::vector<std::uint8_t> buffer_;
};

}  // namespace mie::channel
