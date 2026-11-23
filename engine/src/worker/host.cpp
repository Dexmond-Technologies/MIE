// The parent's side of the worker (see mie/worker.hpp): starts one confined worker per
// file, hands over the one open handle, collects the answer, and turns every abnormal end
// into a result. Runs in the service; it parses nothing of the scanned file. What it does
// parse is the worker's answer, which it treats as untrusted: bounded frame, strict
// result, consistency rules, and the identity of the file.
#include "mie/worker.hpp"

#include <chrono>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/channel/frame.hpp"
#include "mie/hash.hpp"
#include "mie/scoring.hpp"
#include "mie/version.hpp"

namespace mie::worker {

namespace {

using nlohmann::json;

// The verdict text of a result the parent writes itself. The same text as the pipeline's
// kNotFullyScannedVerdict (mie/engine.hpp); the parent does not link the pipeline.
constexpr const char* kNotFullyScanned = "NOT FULLY SCANNED";

bool read_whole_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return !in.bad();
}

std::string text_field(const json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() && it->is_string() ? it->get<std::string>() : std::string();
}

double number_field(const json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() && it->is_number() ? it->get<double>() : 0.0;
}

// What was received, for a log: how many bytes, the length the first four claim, the first
// sixteen in hex. Never the content as text.
std::string describe_output(const std::string& output) {
    std::string text = std::to_string(output.size()) + " bytes received";
    if (output.size() >= channel::kFrameHeaderBytes) {
        const auto byte = [&](std::size_t i) { return static_cast<std::uint32_t>(static_cast<unsigned char>(output[i])); };
        text += ", the frame says " + std::to_string((byte(0) << 24) | (byte(1) << 16) | (byte(2) << 8) | byte(3)) +
                " bytes of text";
    }
    static const char kHex[] = "0123456789abcdef";
    text += ", first bytes ";
    for (std::size_t i = 0; i < output.size() && i < 16; ++i) {
        const unsigned char value = static_cast<unsigned char>(output[i]);
        text += kHex[value >> 4];
        text += kHex[value & 0x0F];
    }
    return text;
}

// How a worker ended, for a log: end state, exit code, what the sandbox says (which holds the
// first part of the worker's standard error), time and memory.
std::string describe_child(const sandbox::ChildResult& child) {
    return std::string("worker end ") + sandbox::to_string(child.end) + ", exit code " + std::to_string(child.exit_code) +
           ", " + std::to_string(child.seconds) + " s, peak memory " + std::to_string(child.peak_memory_bytes) +
           " bytes; " + printable(child.detail, 600);
}

double milliseconds_since(std::chrono::steady_clock::time_point start) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

// The one frame a worker writes. False with `why` set if the output is not exactly one
// usable answer frame.
bool decode_answer(const std::string& output, json& body, std::string& why) {
    const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(output.data()), output.size());
    const channel::DecodeResult decoded = channel::decode_frame(bytes);
    if (decoded.status != channel::DecodeStatus::Ok) {
        why = (decoded.status == channel::DecodeStatus::NeedMore ? std::string("the answer is cut short")
                                                                  : "the answer is not a frame: " + printable(decoded.error)) +
              " (" + describe_output(output) + ")";
        return false;
    }
    if (decoded.consumed != output.size()) {
        why = "bytes follow the answer";
        return false;
    }
    if (decoded.message.type != channel::MessageType::Response || decoded.message.op != kAnswerOp ||
        !decoded.message.body.is_object()) {
        why = "the answer is not a worker result";
        return false;
    }
    body = decoded.message.body;
    return true;
}

bool rules_state_of(const std::string& text, RulesState& out) {
    for (const RulesState state : {RulesState::On, RulesState::Degraded, RulesState::Off}) {
        if (text == to_string(state)) {
            out = state;
            return true;
        }
    }
    return false;
}

std::string exit_meaning(int code) {
    switch (code) {
        case kExitUsage: return "it was started with an argument it does not take";
        case kExitNotConfined: return "it could not be confined and refused to run";
        case kExitBadJob: return "it could not read its job";
        case kExitTestSwitch: return "the job carried a test switch and this worker has no test hooks";
        case kExitNoFile: return "it found no handed-over file";
        case kExitInternal: return "an internal error";
        default: return "exit code " + std::to_string(code);
    }
}

}  // namespace

bool load_config(const std::filesystem::path& scoring, const std::filesystem::path& reputation,
                 const std::filesystem::path& rules_directory, Config& out, std::string& error) {
    Config config;
    if (!read_whole_file(scoring, config.scoring_json)) {
        error = "the scoring table cannot be read";
        return false;
    }
    if (!read_whole_file(reputation, config.reputation_json)) {
        error = "the reputation list cannot be read";
        return false;
    }
    ScoringTable table;
    if (!load_scoring_table(config.scoring_json, table, error)) {
        return false;
    }
    config.rules = rules::collect_rule_sources(rules_directory);
    if (config.rules.size() > kMaxRuleFiles) {
        error = "too many rule files";
        return false;
    }
    out = std::move(config);
    return true;
}

Host::Host(Config config, HostOptions options) : config_(std::move(config)), options_(std::move(options)) {}

sandbox::ChildResult Host::run(const Job& job, const io::File* file, std::string& error) {
    const std::string bytes = encode_job(job, error);
    if (bytes.empty()) {
        sandbox::ChildResult failed;
        failed.end = sandbox::ChildResult::End::StartFailed;
        failed.detail = error;
        return failed;
    }
    std::vector<std::string> arguments;
    if (!options_.run.confine) {
        arguments.emplace_back("--test-allow-unconfined");  // tests only; the shipped worker refuses it
    }
    ++workers_started_;
    const std::span<const std::uint8_t> input(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
    return sandbox::run_confined(options_.worker_program, arguments, file, input, options_.limits,
                                 channel::kMaxFrameBytes + channel::kFrameHeaderBytes + 64, options_.run);
}

bool Host::describe(Description& out, std::string& error) {
    Job job;
    job.op = "describe";
    job.use_reputation = config_.use_reputation;
    job.scoring_json = config_.scoring_json;
    job.reputation_json = config_.reputation_json;
    job.rules = config_.rules;
    const sandbox::ChildResult child = run(job, nullptr, error);
    if (child.end != sandbox::ChildResult::End::Exited || child.exit_code != kExitOk) {
        error = std::string("the worker did not describe itself: ") + sandbox::to_string(child.end) +
                (child.end == sandbox::ChildResult::End::Exited ? ", " + exit_meaning(child.exit_code) : std::string()) +
                "; " + printable(child.detail);
        return false;
    }
    json body;
    if (!decode_answer(child.output, body, error)) {
        error = "the worker's description is unusable: " + error + "; " + describe_child(child);
        return false;
    }
    Description description;
    if (text_field(body, "kind") != "describe" || !rules_state_of(text_field(body, "rules_state"), description.rules_state)) {
        error = "the worker's description is not usable";
        return false;
    }
    description.engine_version = text_field(body, "engine_version");
    description.profile = text_field(body, "profile");
    description.rules_sha256 = text_field(body, "rules_sha256");
    description.rules_library = text_field(body, "rules_library");
    description.why_unusable = text_field(body, "why_unusable");
    description.confinement = text_field(body, "confinement");
    const auto usable = body.find("usable");
    description.usable = usable != body.end() && usable->is_boolean() && usable->get<bool>();
    const auto files = body.find("rule_files");
    if (files != body.end() && files->is_object()) {
        for (auto it = files->begin(); it != files->end(); ++it) {
            if (it.value().is_string()) {
                description.rule_files[it.key()] = it.value().get<std::string>();
            }
        }
    }
    const auto errors = body.find("rule_errors");
    if (errors != body.end() && errors->is_array()) {
        for (const json& entry : *errors) {
            if (entry.is_string()) {
                description.rule_errors.push_back(printable(entry.get<std::string>(), 400));
            }
        }
    }
    if (description.engine_version != kEngineVersion) {
        error = "the worker is another version of the engine than this program";
        return false;
    }
    description_ = description;
    described_ = true;
    out = std::move(description);
    return true;
}

// What every result the parent writes itself starts from: which engine, which profile
// and which rules (condition W-1). Taken from the worker's description when there is one.
ScanResult Host::base_result(const std::string& display_name) const {
    ScanResult result;
    result.subject.kind = SubjectKind::File;
    result.subject.display_name = display_name;
    result.engine_version = kEngineVersion;
    if (described_) {
        result.profile = description_.profile;
        result.rules_state = description_.rules_state;
        result.rules_sha256 = description_.rules_state == RulesState::Off ? std::string() : description_.rules_sha256;
    } else {
        ScoringTable table;
        std::string ignored;
        if (load_scoring_table(config_.scoring_json, table, ignored)) {
            result.profile = table.profile;
        }
        result.rules_state = RulesState::Off;  // not known: nothing was scanned with any rule
    }
    return result;
}

// A worker that was killed, crashed, could not be started or confined, or answered
// something unusable: the file is "not fully scanned", never CLEAN, with the reason.
JobOutcome Host::abnormal(const sandbox::ChildResult& child, const std::string& reason, ScanResult base) const {
    JobOutcome outcome;
    outcome.answered = false;
    outcome.end = child.end;
    outcome.exit_code = child.exit_code;
    outcome.detail = printable(child.detail);
    outcome.confinement = printable(child.confinement, 600);
    outcome.peak_memory_bytes = child.peak_memory_bytes;
    outcome.seconds = child.seconds;
    base.state = ScanState::NotFullyScanned;
    base.reason = "worker: " + reason;
    base.score = 0;
    base.verdict = kNotFullyScanned;
    base.findings.clear();
    outcome.result = std::move(base);
    return outcome;
}

JobOutcome Host::scan_file(const std::filesystem::path& path) {
    const std::u8string name_utf8 = path.filename().u8string();
    const std::string name(name_utf8.begin(), name_utf8.end());
    io::IoError error;
    const std::unique_ptr<io::File> file = io::open_regular(path, error);
    if (!file) {
        // The engine's own refusal (links, directories, devices, cloud-only files, no such
        // file, no access): "not scanned" with the code as the reason. No worker is started.
        JobOutcome outcome;
        outcome.result = base_result(name);
        outcome.result.state = ScanState::NotScanned;
        outcome.result.reason = io::to_string(error.code);
        outcome.detail = "refused before any worker was started";
        return outcome;
    }
    return scan_open(*file, name);
}

JobOutcome Host::scan_open(io::File& file, const std::string& display_name) {
    const std::chrono::steady_clock::time_point job_start = std::chrono::steady_clock::now();
    ScanResult base = base_result(display_name);
    base.size = file.size();
    double hash_ms = 0.0;

    // The parent's own hash of the file: plain hashing, no parsing. It is the identity the
    // worker's answer must name, and the identity of a result the parent writes itself.
    if (options_.verify_identity) {
        io::IoError hash_error;
        Hashes hashes;
        if (!hash_file(file, hashes, hash_error)) {
            JobOutcome outcome;
            outcome.result = std::move(base);
            outcome.result.state = ScanState::NotScanned;
            outcome.result.reason = io::to_string(io::IoErrorCode::ReadFailed);
            outcome.result.size = 0;
            outcome.detail = "the file could not be read by the parent";
            return outcome;
        }
        base.hashes = hashes;
        base.subject.sha256 = hashes.sha256;
        hash_ms = milliseconds_since(job_start);
    }

    Job job;
    job.op = "scan";
    job.display_name = display_name.size() > kMaxDisplayNameBytes ? display_name.substr(0, kMaxDisplayNameBytes)
                                                                  : display_name;
    job.use_reputation = config_.use_reputation;
    job.test_fault = options_.test_fault;
    job.scoring_json = config_.scoring_json;
    job.reputation_json = config_.reputation_json;
    job.rules = config_.rules;

    std::string error;
    const std::chrono::steady_clock::time_point run_start = std::chrono::steady_clock::now();
    const sandbox::ChildResult child = run(job, &file, error);
    const double worker_run_ms = milliseconds_since(run_start);
    // Every abnormal end is a result for THIS file; the parent's times and the full account
    // of how the worker ended go with it.
    const auto failed = [&](const std::string& reason) {
        JobOutcome outcome = abnormal(child, reason, std::move(base));
        outcome.detail = describe_child(child);
        outcome.hash_ms = hash_ms;
        outcome.worker_run_ms = worker_run_ms;
        outcome.total_ms = milliseconds_since(job_start);
        return outcome;
    };
    const std::string seconds = std::to_string(options_.limits.wall_seconds);
    switch (child.end) {
        case sandbox::ChildResult::End::Exited:
            break;
        case sandbox::ChildResult::End::KilledByTimeLimit:
            return failed("killed at the time limit of " + seconds + " seconds");
        case sandbox::ChildResult::End::KilledByMemoryLimit:
            return failed("ended at the memory limit of " + std::to_string(options_.limits.memory_bytes) + " bytes");
        case sandbox::ChildResult::End::Crashed:
            return failed("crashed (" + printable(child.detail, 200) + ")");
        case sandbox::ChildResult::End::StartFailed:
            return failed("could not be started confined (" + printable(child.detail, 200) + ")");
    }
    if (child.exit_code != kExitOk) {
        return failed("ended without an answer: " + exit_meaning(child.exit_code));
    }

    json body;
    std::string why;
    if (!decode_answer(child.output, body, why)) {
        return failed("unusable answer: " + why);
    }
    const auto result_field = body.find("result");
    if (text_field(body, "kind") != "scan" || result_field == body.end() || !result_field->is_object()) {
        return failed("unusable answer: no result in it");
    }
    ScanResult result;
    if (!from_json(result_field->dump(-1, ' ', false, json::error_handler_t::replace), result, why)) {
        return failed("unusable answer: " + printable(why, 200));
    }
    if (!consistent(result, why)) {
        return failed("unusable answer: " + printable(why, 200));
    }
    if (result.engine_version != kEngineVersion) {
        return failed("unusable answer: another engine version");
    }
    if (options_.verify_identity && result.state != ScanState::NotScanned &&
        (result.hashes.sha256 != base.hashes.sha256 || result.size != base.size)) {
        return failed("unusable answer: it names another file than the one handed over");
    }
    const std::string worker_confinement = text_field(body, "confinement");
    if (options_.run.confine && !options_.run.allow_weaker && worker_confinement.rfind("WEAKER", 0) == 0) {
        return failed("it says it ran with a weaker confinement");
    }

    JobOutcome outcome;
    outcome.result = std::move(result);
    outcome.answered = true;
    outcome.end = child.end;
    outcome.exit_code = child.exit_code;
    outcome.detail = printable(child.detail, 600);
    outcome.confinement = printable(child.confinement, 600);
    outcome.worker_confinement = printable(worker_confinement, 600);
    outcome.peak_memory_bytes = child.peak_memory_bytes;
    outcome.seconds = child.seconds;
    const auto pid = body.find("pid");
    outcome.worker_pid = pid != body.end() && pid->is_number_integer() ? pid->get<std::int64_t>() : 0;
    outcome.setup_ms = number_field(body, "setup_ms");
    outcome.scan_ms = number_field(body, "scan_ms");
    outcome.worker_alive_ms = number_field(body, "alive_ms");
    outcome.hash_ms = hash_ms;
    outcome.worker_run_ms = worker_run_ms;
    outcome.start_overhead_ms = worker_run_ms > outcome.worker_alive_ms ? worker_run_ms - outcome.worker_alive_ms : 0.0;
    outcome.total_ms = milliseconds_since(job_start);
    return outcome;
}

}  // namespace mie::worker
