// mie-sandbox-testparent: TEST PROGRAM, never shipped.
//
//   mie-sandbox-testparent --sid
//       prints {"sid": "..."}: the worker's AppContainer SID (Windows), so that the test can
//       give it read access to the folder of the test child.
//   mie-sandbox-testparent CHILD [options] -- ACTION [arguments]
//       runs CHILD ACTION [arguments] through mie::sandbox::run_confined and prints the
//       ChildResult as one line of ASCII JSON.
// Options: --unconfined, --allow-weaker, --break (test hook: the confinement fails),
//   --no-mitigations (test hook, Windows: container without the policies),
//   --wall SECONDS, --memory BYTES, --file PATH (opened here, handed over as a handle),
//   --stdin TEXT, --max-output BYTES, --then-echo (after the run, a second run of "echo" in
//   the same parent process: shows the parent carries on).
// The waiting shape (ruling M-13), with --waiting: the child is started with start_waiting
//   (as CHILD waiting <preparation bytes> ACTION [arguments]), sent --prep TEXT as its
//   preparation, awaited until its first line of output, handed --file with --job TEXT, and
//   collected. More switches: --second-hand-over (try to hand over twice), --malformed KIND
//   (none | two | notfile | writable | short: a hand-over that is not as required),
//   --end-unused (end the waiting worker without using it), --delay-hand-over SECONDS,
//   --abandon (print the worker's first line and leave at once without ending it: the worker
//   must end by itself).
#include "mie/io.hpp"
#include "mie/sandbox.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <chrono>
#include <span>
#include <string>
#include <thread>
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
           ",\"container_folder_note\":" + json_text(result.container_folder_note) +
           ",\"peak_memory_bytes\":" + std::to_string(result.peak_memory_bytes) + ",\"seconds\":" + seconds + "}";
}

const char* state_text(mie::sandbox::WaitingState state) {
    switch (state) {
        case mie::sandbox::WaitingState::Starting: return "starting";
        case mie::sandbox::WaitingState::Waiting: return "waiting";
        case mie::sandbox::WaitingState::HandedOver: return "handed_over";
        case mie::sandbox::WaitingState::Ended: return "ended";
    }
    return "ended";
}

struct WaitingRun {
    std::string child;
    std::vector<std::string> child_arguments;
    mie::sandbox::Limits limits;
    mie::sandbox::RunOptions options;
    std::size_t max_output = 64 * 1024;
    std::string file_path;
    std::string preparation;
    std::string job = "job";
    std::string malformed;
    bool second_hand_over = false;
    bool end_unused = false;
    bool abandon = false;
    int delay_seconds = 0;
};

// The waiting shape: start, prepare, wait for the worker's first line, hand over, collect.
int run_waiting(const WaitingRun& run) {
    namespace sandbox = mie::sandbox;
    const auto pause = [] { std::this_thread::sleep_for(std::chrono::milliseconds(10)); };
    const auto since = [](std::chrono::steady_clock::time_point from) {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - from).count();
    };
    sandbox::WaitingOptions waiting_options;
    waiting_options.memory_bytes = run.limits.memory_bytes;
    waiting_options.max_output_bytes = run.max_output;
    waiting_options.run = run.options;
    std::vector<std::string> arguments = {"waiting", std::to_string(run.preparation.size())};
    arguments.insert(arguments.end(), run.child_arguments.begin(), run.child_arguments.end());

    const auto started = std::chrono::steady_clock::now();
    const std::unique_ptr<sandbox::WaitingChild> worker = sandbox::start_waiting(run.child, arguments, waiting_options);
    sandbox::WaitingState state = sandbox::poll(*worker);
    while (state == sandbox::WaitingState::Starting && since(started) < 10.0) {
        pause();
        state = sandbox::poll(*worker);
    }
    std::string extra = std::string(",\"sanitizer_build\":") + (sandbox::sanitizer_build() ? "true" : "false") +
                        ",\"shape\":\"waiting\",\"state_after_start\":" + json_text(state_text(state)) +
                        ",\"confinement_at_start\":" + json_text(sandbox::confinement_at_start(*worker));

    // The preparation (OUR bytes), then the worker's first line: its "ready" message.
    std::string first_output;
    std::string preparation_error;
    if (state == sandbox::WaitingState::Waiting) {
        const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(run.preparation.data()),
                                                  run.preparation.size());
        if (!bytes.empty()) {
            sandbox::send_preparation(*worker, bytes, 10, preparation_error);
        }
        const auto asked = std::chrono::steady_clock::now();
        while (first_output.find('\n') == std::string::npos && since(asked) < 10.0 &&
               sandbox::poll(*worker) == sandbox::WaitingState::Waiting) {
            first_output += sandbox::take_output(*worker);
            if (first_output.find('\n') == std::string::npos) {
                pause();
            }
        }
        first_output += sandbox::take_output(*worker);
    }
    extra += ",\"first_output\":" + json_text(first_output) + ",\"preparation_error\":" + json_text(preparation_error);

    if (run.abandon) {
        // Leave without ending the worker: no destructor runs. The worker must end by itself.
        std::printf("{\"end\":\"abandoned\"%s}\n", extra.c_str());
        std::fflush(stdout);
        std::_Exit(0);
    }
    if (run.end_unused) {
        sandbox::end_waiting(*worker);
        extra += ",\"state_after_end\":" + json_text(state_text(sandbox::poll(*worker))) +
                 ",\"failure\":" + json_text(sandbox::failure(*worker));
        // A file handed to an ended worker must be refused.
    }
    if (run.delay_seconds > 0) {
        const auto from = std::chrono::steady_clock::now();
        while (since(from) < run.delay_seconds) {
            sandbox::poll(*worker);
            pause();
        }
    }

    std::unique_ptr<mie::io::File> file;
    if (!run.file_path.empty()) {
        mie::io::IoError io_error;
        file = mie::io::open_regular(run.file_path, io_error);
    }
    if (!file) {
        std::printf("{\"end\":\"test_setup_failed\",\"detail\":\"the waiting shape needs --file with a readable file\"}\n");
        return 2;
    }
    const std::span<const std::uint8_t> job(reinterpret_cast<const std::uint8_t*>(run.job.data()), run.job.size());
    std::string hand_over_error;
    bool handed = false;
    if (run.malformed.empty()) {
        handed = sandbox::hand_over_file(*worker, *file, job, hand_over_error);
    } else {
        const sandbox::MalformedHandOver kind =
            run.malformed == "none"       ? sandbox::MalformedHandOver::NoDescriptor
            : run.malformed == "two"      ? sandbox::MalformedHandOver::TwoDescriptors
            : run.malformed == "notfile"  ? sandbox::MalformedHandOver::NotARegularFile
            : run.malformed == "writable" ? sandbox::MalformedHandOver::Writable
                                          : sandbox::MalformedHandOver::ShortMessage;
        handed = sandbox::hand_over_malformed(*worker, kind, run.file_path, hand_over_error);
    }
    extra += std::string(",\"hand_over_ok\":") + (handed ? "true" : "false") + ",\"hand_over_error\":" +
             json_text(hand_over_error);
    if (run.second_hand_over) {
        std::string second_error;
        const bool second = sandbox::hand_over_file(*worker, *file, job, second_error);
        extra += std::string(",\"second_hand_over_ok\":") + (second ? "true" : "false") +
                 ",\"second_hand_over_error\":" + json_text(second_error);
    }
    const sandbox::ChildResult result = sandbox::collect(*worker, run.limits);
    std::string line = json_result(result);
    line.pop_back();  // reopen the object
    line += extra + ",\"failure_text\":" + json_text(sandbox::failure(*worker)) + "}";
    std::printf("%s\n", line.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--sid") {
        std::string error;
        const std::string sid = mie::sandbox::appcontainer_sid_text(error);
        std::printf("{\"sid\":%s,\"folder\":%s,\"error\":%s}\n", json_text(sid).c_str(),
                    json_text(mie::sandbox::appcontainer_folder_text()).c_str(), json_text(error).c_str());
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
    bool waiting = false;
    WaitingRun waiting_run;
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
        } else if (argument == "--waiting") {
            waiting = true;
        } else if (argument == "--second-hand-over") {
            waiting_run.second_hand_over = true;
        } else if (argument == "--end-unused") {
            waiting_run.end_unused = true;
        } else if (argument == "--abandon") {
            waiting_run.abandon = true;
        } else if (argument == "--prep" && has_value) {
            waiting_run.preparation = argv[++i];
        } else if (argument == "--job" && has_value) {
            waiting_run.job = argv[++i];
        } else if (argument == "--malformed" && has_value) {
            waiting_run.malformed = argv[++i];
        } else if (argument == "--delay-hand-over" && has_value) {
            waiting_run.delay_seconds = std::atoi(argv[++i]);
        } else if (argument == "--no-mitigations") {
            options.test_without_mitigations = true;
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

    if (waiting) {
        waiting_run.child = child;
        waiting_run.child_arguments = child_arguments;
        waiting_run.limits = limits;
        waiting_run.options = options;
        waiting_run.max_output = max_output;
        waiting_run.file_path = file_path;
        return run_waiting(waiting_run);
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
