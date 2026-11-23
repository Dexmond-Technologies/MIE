// mie-sandbox-testparent: TEST PROGRAM, never shipped.
//
//   mie-sandbox-testparent --sid
//       prints {"sid": "..."}: the worker's AppContainer SID (Windows), so that the test can
//       give it read access to the folder of the test child.
//   mie-sandbox-testparent CHILD [options] -- ACTION [arguments]
//       runs CHILD ACTION [arguments] through mie::sandbox::run_confined and prints the
//       ChildResult as one line of ASCII JSON.
// Options: --unconfined, --allow-weaker, --break (test hook: the confinement fails),
//   --wall SECONDS, --memory BYTES, --file PATH (opened here, handed over as a handle),
//   --stdin TEXT, --max-output BYTES, --then-echo (after the run, a second run of "echo" in
//   the same parent process: shows the parent carries on).
#include "mie/io.hpp"
#include "mie/sandbox.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

std::string json_text(const std::string& text) {
    std::string out = "\"";
    for (const char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (u < 0x20 || u >= 0x7f) {
            char escaped[8];
            std::snprintf(escaped, sizeof escaped, "\\u%04x", static_cast<unsigned>(u));
            out += escaped;
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

std::string json_result(const mie::sandbox::ChildResult& result) {
    char seconds[32];
    std::snprintf(seconds, sizeof seconds, "%.3f", result.seconds);
    return std::string("{\"end\":") + json_text(mie::sandbox::to_string(result.end)) +
           ",\"exit_code\":" + std::to_string(result.exit_code) + ",\"output\":" + json_text(result.output) +
           ",\"detail\":" + json_text(result.detail) + ",\"confinement\":" + json_text(result.confinement) +
           ",\"peak_memory_bytes\":" + std::to_string(result.peak_memory_bytes) + ",\"seconds\":" + seconds + "}";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--sid") {
        std::string error;
        const std::string sid = mie::sandbox::appcontainer_sid_text(error);
        std::printf("{\"sid\":%s,\"error\":%s}\n", json_text(sid).c_str(), json_text(error).c_str());
        return 0;
    }
    if (argc < 4) {
        std::fprintf(stderr, "usage: mie-sandbox-testparent CHILD [options] -- ACTION [arguments]\n");
        return 2;
    }
    const std::string child = argv[1];
    mie::sandbox::Limits limits;
    mie::sandbox::RunOptions options;
    std::string file_path;
    std::string input_text;
    std::size_t max_output = 64 * 1024;
    bool then_echo = false;
    std::vector<std::string> child_arguments;
    int i = 2;
    for (; i < argc; ++i) {
        const std::string argument = argv[i];
        const bool has_value = i + 1 < argc;
        if (argument == "--") {
            ++i;
            break;
        } else if (argument == "--unconfined") {
            options.confine = false;
        } else if (argument == "--allow-weaker") {
            options.allow_weaker = true;
        } else if (argument == "--break") {
            options.test_break_confinement = true;
        } else if (argument == "--then-echo") {
            then_echo = true;
        } else if (argument == "--wall" && has_value) {
            limits.wall_seconds = std::atoi(argv[++i]);
        } else if (argument == "--memory" && has_value) {
            limits.memory_bytes = std::strtoull(argv[++i], nullptr, 10);
        } else if (argument == "--max-output" && has_value) {
            max_output = static_cast<std::size_t>(std::strtoull(argv[++i], nullptr, 10));
        } else if (argument == "--file" && has_value) {
            file_path = argv[++i];
        } else if (argument == "--stdin" && has_value) {
            input_text = argv[++i];
        } else {
            std::fprintf(stderr, "unknown option: %s\n", argument.c_str());
            return 2;
        }
    }
    for (; i < argc; ++i) {
        child_arguments.emplace_back(argv[i]);
    }

    std::unique_ptr<mie::io::File> file;
    if (!file_path.empty()) {
        mie::io::IoError error;
        file = mie::io::open_regular(file_path, error);
        if (!file) {
            std::printf("{\"end\":\"test_setup_failed\",\"detail\":%s}\n",
                        json_text(std::string("cannot open the file to hand over: ") + mie::io::to_string(error.code))
                            .c_str());
            return 2;
        }
    }
    const std::span<const std::uint8_t> input(reinterpret_cast<const std::uint8_t*>(input_text.data()),
                                              input_text.size());
    const mie::sandbox::ChildResult result =
        mie::sandbox::run_confined(child, child_arguments, file.get(), input, limits, max_output, options);
    std::string line = json_result(result);
    line.pop_back();  // reopen the object
    line += std::string(",\"sanitizer_build\":") + (mie::sandbox::sanitizer_build() ? "true" : "false");
    if (then_echo) {
        static const std::uint8_t kAgain[] = {'a', 'g', 'a', 'i', 'n'};
        mie::sandbox::Limits short_limits;
        short_limits.wall_seconds = 20;
        const mie::sandbox::ChildResult after =
            mie::sandbox::run_confined(child, {"echo"}, nullptr, kAgain, short_limits, max_output, options);
        line += ",\"after\":" + json_result(after);
    }
    line += "}";
    std::printf("%s\n", line.c_str());
    return 0;
}
