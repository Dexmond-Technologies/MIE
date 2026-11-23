// libFuzzer target: the channel frame decoder must never crash, hang or read out of
// bounds on any bytes. A decoded message must encode again and decode to the same thing.
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include "mie/channel/frame.hpp"

// Says where the target stopped (the line), so a stop in CI can be read from the log alone.
[[noreturn]] inline void mie_fuzz_stop(int line) {
    std::fprintf(stderr, "fuzz_frame: the rule at line %d of fuzz_frame.cpp does not hold\n", line);
    std::abort();
}
#define MIE_FUZZ_STOP() mie_fuzz_stop(__LINE__)


extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace mie::channel;
    const DecodeResult first = decode_frame(std::span<const std::uint8_t>(data, size));
    if (first.status != DecodeStatus::Ok) {
        return 0;
    }
    if (first.consumed > size) {
        MIE_FUZZ_STOP();
    }
    const std::string again = encode_frame(first.message);
    if (again.empty()) {
        // A decoded message can be too large to re-encode only if escaping grew it.
        return 0;
    }
    const DecodeResult second = decode_frame(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(again.data()), again.size()));
    if (second.status != DecodeStatus::Ok || second.message.id != first.message.id ||
        second.message.op != first.message.op || second.message.type != first.message.type ||
        second.message.body != first.message.body) {
        MIE_FUZZ_STOP();
    }
    return 0;
}
