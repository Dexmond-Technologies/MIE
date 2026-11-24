// The parent's side of the worker (see mie/worker.hpp). Runs in the service; it parses
// nothing of the scanned file. What it does parse is the worker's frames, which it treats as
// untrusted: bounded frame, strict result, consistency rules, the identity of the file, and in
// shape B the configuration the worker was prepared with.
//
// Single-threaded. In shape B the waiting workers prepare in their own processes; the parent
// moves their output along with sandbox::poll between files and while it waits for one. Two
// costs of having no thread, stated (WORKER_NOTES.md section 18): send_preparation blocks the
// parent while a new worker's preparation is written, and while collect() waits for the
// current file the waiting workers are not polled (on Linux their resident-memory watch is
// paused then; their address-space limit still holds).
#include "mie/worker.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <span>
#include <thread>
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
using Clock = std::chrono::steady_clock;

// The verdict text of a result the parent writes itself. The same text as the pipeline's
// kNotFullyScannedVerdict (mie/engine.hpp); the parent does not link the pipeline.
constexpr const char* kNotFullyScanned = "NOT FULLY SCANNED";
// The most bytes one frame takes on the pipe.
constexpr std::size_t kFrameBytes = channel::kMaxFrameBytes + channel::kFrameHeaderBytes;
// Starts that fail in a row before a file gives up waiting for a worker (shape B).
constexpr int kStartFailuresBeforeGivingUp = 3;
// The most a new worker may take to reach the state in which it may be prepared.
constexpr int kStartSeconds = 30;

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

double milliseconds_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

std::int64_t steady_ns(Clock::time_point moment) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(moment.time_since_epoch()).count();
}

// A worker's steady-clock stamp, as milliseconds after `origin_ns`; -1 when absent or absurd.
double stamp_after(std::int64_t stamp_ns, std::int64_t origin_ns) {
    if (stamp_ns <= 0) {
        return -1.0;
    }
    const double ms = static_cast<double>(stamp_ns - origin_ns) / 1e6;
    return ms > -1000.0 && ms < 1e7 ? ms : -1.0;
}

// The number after `label` in the worker's standard error (as the sandbox kept it), or 0.
std::int64_t stamp_in(const std::string& text, const char* label) {
    const std::size_t at = text.rfind(label);
    if (at == std::string::npos) {
        return 0;
    }
    std::int64_t value = 0;
    for (std::size_t i = at + std::strlen(label); i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i) {
        if (value > (INT64_MAX - 9) / 10) {
            return 0;
        }
        value = value * 10 + (text[i] - '0');
    }
    return value;
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

// The one frame `op` a worker writes. False with `why` set if `output` is not exactly one usable frame.
bool decode_one_frame(const std::string& output, const char* op, json& body, std::string& why) {
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
    if (decoded.message.type != channel::MessageType::Response || decoded.message.op != op ||
        !decoded.message.body.is_object()) {
        why = std::string("the frame is not a worker's ") + op;
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

// The describe answer (shape A) and the ready frame (shape B) carry the same fields.
bool description_from(const json& body, const char* kind, Description& out, std::string& error) {
    Description description;
    if (text_field(body, "kind") != kind || !rules_state_of(text_field(body, "rules_state"), description.rules_state)) {
        error = std::string("the worker's ") + kind + " is not usable";
        return false;
    }
    description.engine_version = text_field(body, "engine_version");
    description.profile = text_field(body, "profile");
    description.rules_sha256 = text_field(body, "rules_sha256");
    description.rules_library = text_field(body, "rules_library");
    description.why_unusable = text_field(body, "why_unusable");
    description.confinement = text_field(body, "confinement");
    description.preparation_sha256 = text_field(body, "preparation_sha256");
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
    out = std::move(description);
    return true;
}

std::string exit_meaning(int code) {
    switch (code) {
        case kExitUsage: return "it was started with an argument it does not take";
        case kExitNotConfined: return "it could not be confined and refused to run";
        case kExitBadJob: return "it could not read its job";
        case kExitTestSwitch: return "the job carried a test switch and this worker has no test hooks";
        case kExitNoFile: return "it found no handed-over file";
        case kExitInternal: return "an internal error";
        case sandbox::kHandOverRefusedExitCode:
            return "it refused the hand-over (the file was not as required, or its full confinement could not be applied)";
        case sandbox::kNoJobExitCode: return "it was ended unused";
        default: return "exit code " + std::to_string(code);
    }
}

}  // namespace

// ---- configuration ----------------------------------------------------------------------------

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

int proposed_pool_size() {
    const unsigned int cores = std::thread::hardware_concurrency();
    const int usable = cores == 0 ? 1 : static_cast<int>(std::min(cores, 64u));
    return std::min(kProposedPoolSize, usable);
}

// ---- a waiting worker (shape B) -----------------------------------------------------------------

struct Host::Slot {
    std::unique_ptr<sandbox::WaitingChild> child;
    std::uint64_t generation = 0;
    std::uint64_t round = 0;         // the maintain round in which it was started
    bool preparation_sent = false;
    std::string preparation_sha256;  // of the preparation it was sent
    std::string buffer;              // what came on its standard output before the hand-over
    bool ready = false;
    bool gone = false;               // ended, retired, or found dead: never to be used
    Description ready_info;
};

Host::Host(Config config, HostOptions options) : config_(std::move(config)), options_(std::move(options)) {
    test_dying_left_ = options_.test_die_while_waiting;
    if (options_.pool_size > 0) {
        Job job;
        job.op = "prepare";
        job.use_reputation = config_.use_reputation;
        job.scoring_json = config_.scoring_json;
        job.reputation_json = config_.reputation_json;
        job.rules = config_.rules;
        preparation_ = encode_job(job, preparation_error_);
        preparation_sha256_ = preparation_.empty()
                                  ? std::string()
                                  : sha256_hex(std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(preparation_.data()), preparation_.size()));
    }
}

Host::~Host() { shutdown(); }

void Host::shutdown() {
    for (const std::unique_ptr<Slot>& slot : pool_) {
        if (!slot->gone) {
            sandbox::end_waiting(*slot->child);
        }
    }
    pool_.clear();
}

std::vector<PoolEvent> Host::take_events() {
    std::vector<PoolEvent> out;
    out.swap(events_);
    return out;
}

void Host::event(const std::string& what, const std::string& detail, double age_seconds) {
    events_.push_back(PoolEvent{what, printable(detail, 600), generation_, age_seconds});
}

void Host::retire(Slot& slot, const std::string& what, const std::string& detail) {
    if (!slot.gone) {
        sandbox::end_waiting(*slot.child);
        slot.gone = true;
    }
    event(what, detail, sandbox::seconds_since_start(*slot.child));
    if (what == "unusable" || what == "died_waiting" || what == "start_failed") {
        ++start_failures_in_a_row_;
        last_failure_ = detail;
    }
}

void Host::set_config(Config config) {
    config_ = std::move(config);
    ++generation_;
    if (options_.pool_size > 0) {
        Job job;
        job.op = "prepare";
        job.use_reputation = config_.use_reputation;
        job.scoring_json = config_.scoring_json;
        job.reputation_json = config_.reputation_json;
        job.rules = config_.rules;
        preparation_ = encode_job(job, preparation_error_);
        preparation_sha256_ = preparation_.empty()
                                  ? std::string()
                                  : sha256_hex(std::span<const std::uint8_t>(
                                        reinterpret_cast<const std::uint8_t*>(preparation_.data()), preparation_.size()));
    }
    std::size_t ended = 0;
    for (const std::unique_ptr<Slot>& slot : pool_) {
        if (!slot->gone) {
            sandbox::end_waiting(*slot->child);
            slot->gone = true;
            ++ended;
        }
    }
    pool_.clear();
    described_ = false;
    event("config_changed", "waiting workers ended: " + std::to_string(ended));
}

bool Host::start_slot(std::string& error) {
    if (preparation_.empty()) {
        error = "the preparation cannot be made: " + preparation_error_;
        event("start_failed", error);
        ++start_failures_in_a_row_;
        last_failure_ = error;
        return false;
    }
    std::vector<std::string> arguments{kPrestartedArgument};
    const std::uint64_t number = workers_started_ + 1;
    const bool die_from_here = options_.test_die_while_waiting_from > 0 &&
                               number >= static_cast<std::uint64_t>(options_.test_die_while_waiting_from);
    if (test_dying_left_ > 0 || die_from_here) {
        arguments.emplace_back("--test-die-while-waiting");  // tests only: the test-hooks worker
        if (test_dying_left_ > 0) {
            --test_dying_left_;
        }
    }
    sandbox::WaitingOptions waiting;
    waiting.memory_bytes = options_.limits.memory_bytes;
    waiting.max_output_bytes = 2 * kFrameBytes + 64;  // the ready frame and the answer
    waiting.run = options_.run;
    auto slot = std::make_unique<Slot>();
    slot->child = sandbox::start_waiting(options_.worker_program, arguments, waiting);
    slot->generation = generation_;
    slot->round = maintain_round_;
    slot->preparation_sha256 = preparation_sha256_;
    ++workers_started_;
    // No waiting here for the worker to start: its preparation is sent by advance() in a later
    // round, once it has reached its first stage of confinement. So starting a replacement never
    // puts the start cost on the path of the file being scanned.
    if (sandbox::poll(*slot->child) == sandbox::WaitingState::Ended) {
        error = "the worker could not be started: " + sandbox::failure(*slot->child);
        slot->gone = true;
        retire(*slot, "start_failed", error);
        return false;
    }
    event("started", sandbox::confinement_at_start(*slot->child));
    pool_.push_back(std::move(slot));
    return true;
}

// Moves one waiting worker along: its preparation, its output, its death, its ready frame.
void Host::advance(Slot& slot, bool send_preparations) {
    if (slot.gone) {
        return;
    }
    const sandbox::WaitingState state = sandbox::poll(*slot.child);
    slot.buffer += sandbox::take_output(*slot.child);
    if (state == sandbox::WaitingState::Ended) {
        slot.gone = true;
        retire(slot, slot.preparation_sent ? "died_waiting" : "start_failed",
               (slot.ready ? "a ready worker ended while it waited: " : "a worker ended before it was ready: ") +
                   sandbox::failure(*slot.child));
        return;
    }
    if (!slot.preparation_sent) {
        if (state == sandbox::WaitingState::Waiting && send_preparations && slot.round != maintain_round_) {
            // Linux: stage 1 reported; Windows: created in its container. The worker reads the
            // preparation while it is written.
            std::string error;
            const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(preparation_.data()),
                                                      preparation_.size());
            if (!sandbox::send_preparation(*slot.child, bytes, kPreparationSendTimeoutSeconds, error)) {
                retire(slot, "start_failed",
                       "the preparation could not be sent: " + error + "; " + sandbox::failure(*slot.child));
                return;
            }
            slot.preparation_sent = true;
        } else if (state == sandbox::WaitingState::Starting &&
                   sandbox::seconds_since_start(*slot.child) > static_cast<double>(kStartSeconds)) {
            retire(slot, "start_failed", "the worker did not reach its first stage of confinement in time");
        }
        return;
    }
    if (slot.ready) {
        if (!slot.buffer.empty()) {
            retire(slot, "unusable", "it wrote more than its ready frame before it was given a file");
        }
        return;
    }
    if (slot.buffer.empty()) {
        return;
    }
    const std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(slot.buffer.data()),
                                              slot.buffer.size());
    const channel::DecodeResult decoded = channel::decode_frame(bytes);
    if (decoded.status == channel::DecodeStatus::NeedMore) {
        if (slot.buffer.size() > kFrameBytes) {
            retire(slot, "unusable", "its ready frame is longer than a frame may be");
        }
        return;  // the rest of the frame has not come yet
    }
    std::string why;
    json body;
    if (!decode_one_frame(slot.buffer, kReadyOp, body, why)) {
        retire(slot, "unusable", "its ready frame is unusable: " + why);
        return;
    }
    slot.buffer.clear();
    Description info;
    if (!description_from(body, "ready", info, why)) {
        retire(slot, "unusable", why);
        return;
    }
    if (slot.generation != generation_ || info.preparation_sha256 != slot.preparation_sha256 ||
        info.preparation_sha256 != preparation_sha256_) {
        retire(slot, "retired", "it was prepared with another configuration than the current one");
        return;
    }
    if (!info.usable) {
        retire(slot, "unusable", "the engine it built is not usable: " + info.why_unusable);
        return;
    }
    if (!described_) {
        description_ = info;  // the first ready worker of this configuration names it
        described_ = true;
    } else if (info.rules_state != description_.rules_state || info.rules_sha256 != description_.rules_sha256 ||
               info.profile != description_.profile) {
        retire(slot, "retired", "its rules or profile are not those of the first worker of this configuration");
        return;
    }
    slot.ready_info = std::move(info);
    slot.ready = true;
    start_failures_in_a_row_ = 0;
    event("ready", "setup " + std::to_string(number_field(body, "setup_ms")) + " ms",
          sandbox::seconds_since_start(*slot.child));
}

void Host::maintain(bool send_preparations) {
    if (options_.pool_size <= 0) {
        return;
    }
    ++maintain_round_;
    for (const std::unique_ptr<Slot>& slot : pool_) {
        advance(*slot, send_preparations);
        if (!slot->gone && sandbox::seconds_since_start(*slot->child) > options_.max_waiting_age_seconds) {
            retire(*slot, "too_old", "waited longer than " + std::to_string(options_.max_waiting_age_seconds) + " s");
        }
    }
    pool_.erase(std::remove_if(pool_.begin(), pool_.end(), [](const std::unique_ptr<Slot>& slot) { return slot->gone; }),
                pool_.end());
    while (static_cast<int>(pool_.size()) < options_.pool_size &&
           start_failures_in_a_row_ < kStartFailuresBeforeGivingUp) {
        std::string error;
        if (!start_slot(error)) {
            break;
        }
    }
}

bool Host::pool_full() {
    maintain();
    if (static_cast<int>(pool_.size()) < options_.pool_size) {
        return false;
    }
    return std::all_of(pool_.begin(), pool_.end(), [](const std::unique_ptr<Slot>& slot) { return slot->ready; });
}

std::unique_ptr<Host::Slot> Host::take_ready(std::string& error, double& waited_ms) {
    const Clock::time_point start = Clock::now();
    start_failures_in_a_row_ = 0;
    for (;;) {
        maintain();
        for (auto it = pool_.begin(); it != pool_.end(); ++it) {
            Slot& slot = **it;
            // Age and state are looked at again right here: a worker may have grown old or died
            // while the previous file was being scanned.
            if (slot.gone || !slot.ready || slot.generation != generation_) {
                continue;
            }
            if (sandbox::seconds_since_start(*slot.child) > options_.max_waiting_age_seconds) {
                retire(slot, "too_old", "found too old when a file came");
                continue;
            }
            if (sandbox::poll(*slot.child) != sandbox::WaitingState::Waiting) {
                retire(slot, "died_waiting", "found ended when a file came: " + sandbox::failure(*slot.child));
                continue;
            }
            std::unique_ptr<Slot> taken = std::move(*it);
            pool_.erase(it);
            waited_ms = milliseconds_since(start);
            return taken;
        }
        if (pool_.empty() && start_failures_in_a_row_ >= kStartFailuresBeforeGivingUp) {
            error = "no worker could be started (" + std::to_string(start_failures_in_a_row_) +
                    " attempts in a row failed; the last: " + last_failure_ + ")";
            waited_ms = milliseconds_since(start);
            return nullptr;
        }
        if (milliseconds_since(start) > options_.ready_timeout_seconds * 1000.0) {
            error = "no worker was ready within " + std::to_string(options_.ready_timeout_seconds) + " s" +
                    (last_failure_.empty() ? std::string() : " (the last failure: " + last_failure_ + ")");
            waited_ms = milliseconds_since(start);
            return nullptr;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// ---- describing --------------------------------------------------------------------------------

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
    return sandbox::run_confined(options_.worker_program, arguments, file, input, options_.limits, kFrameBytes + 64,
                                 options_.run);
}

bool Host::describe(Description& out, std::string& error) {
    if (options_.pool_size <= 0) {
        return describe_one_shot(out, error);
    }
    const Clock::time_point start = Clock::now();
    start_failures_in_a_row_ = 0;
    while (!described_) {
        maintain();
        if (described_) {
            break;
        }
        if ((pool_.empty() && start_failures_in_a_row_ >= kStartFailuresBeforeGivingUp) ||
            milliseconds_since(start) > options_.ready_timeout_seconds * 1000.0) {
            error = "no pre-started worker became ready: " + last_failure_;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    out = description_;
    return true;
}

bool Host::describe_one_shot(Description& out, std::string& error) {
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
    if (!decode_one_frame(child.output, kAnswerOp, body, error)) {
        error = "the worker's description is unusable: " + error + "; " + describe_child(child);
        return false;
    }
    Description description;
    if (!description_from(body, "describe", description, error)) {
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
    outcome.detail = describe_child(child);
    outcome.confinement = printable(child.confinement, 600);
    outcome.container_folder_note = printable(child.container_folder_note, 600);
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

// ---- scanning -------------------------------------------------------------------------------------

JobOutcome Host::scan_file(const std::filesystem::path& path) {
    const std::u8string name_utf8 = path.filename().u8string();
    const std::string name(name_utf8.begin(), name_utf8.end());
    io::IoError error;
    const std::unique_ptr<io::File> file = io::open_regular(path, error);
    if (!file) {
        // The engine's own refusal (links, directories, devices, cloud-only files, no such
        // file, no access): "not scanned" with the code as the reason. No worker is used.
        JobOutcome outcome;
        outcome.result = base_result(name);
        outcome.result.state = ScanState::NotScanned;
        outcome.result.reason = io::to_string(error.code);
        outcome.detail = "refused before any worker was used";
        return outcome;
    }
    return scan_open(*file, name);
}

JobOutcome Host::scan_open(io::File& file, const std::string& display_name) {
    return options_.pool_size > 0 ? scan_pooled(file, display_name) : scan_one_shot(file, display_name);
}

bool Host::hash_for_identity(io::File& file, ScanResult& base, double& hash_ms, JobOutcome& refused) {
    // The parent's own hash of the file: plain hashing through read_at (by position), no
    // parsing, BEFORE any worker gets the file. It is the identity the worker's answer must name.
    if (!options_.verify_identity) {
        return true;
    }
    const Clock::time_point start = Clock::now();
    io::IoError hash_error;
    Hashes hashes;
    if (!hash_file(file, hashes, hash_error)) {
        refused.result = base;
        refused.result.state = ScanState::NotScanned;
        refused.result.reason = io::to_string(io::IoErrorCode::ReadFailed);
        refused.result.size = 0;
        refused.detail = "the file could not be read by the parent";
        return false;
    }
    base.hashes = hashes;
    base.subject.sha256 = hashes.sha256;
    hash_ms = milliseconds_since(start);
    return true;
}

// The checks every answer passes, in both shapes: `ok`, or the reason (and
// `changed_during_scan` when it is the "file changed" rule).
namespace {
struct Checked {
    bool ok = false;
    bool changed_during_scan = false;
    std::string why;
    json body;
    ScanResult result;
};

Checked check_answer(const sandbox::ChildResult& child, const ScanResult& base, bool verify_identity,
                     bool confined_strictly) {
    Checked checked;
    std::string why;
    if (!decode_one_frame(child.output, kAnswerOp, checked.body, why)) {
        checked.why = "unusable answer: " + why;
        return checked;
    }
    const auto result_field = checked.body.find("result");
    if (text_field(checked.body, "kind") != "scan" || result_field == checked.body.end() || !result_field->is_object()) {
        checked.why = "unusable answer: no result in it";
        return checked;
    }
    if (!from_json(result_field->dump(-1, ' ', false, json::error_handler_t::replace), checked.result, why) ||
        !consistent(checked.result, why)) {
        checked.why = "unusable answer: " + printable(why, 200);
        return checked;
    }
    if (checked.result.engine_version != kEngineVersion) {
        checked.why = "unusable answer: another engine version";
        return checked;
    }
    // THE RULE against a file that changes while it is scanned (the file stays shared for
    // reading, writing and deleting): the parent's hash, taken BEFORE the worker got the
    // file, and the hash of the bytes the WORKER read must be equal, and so must the sizes.
    if (verify_identity && checked.result.state != ScanState::NotScanned &&
        (checked.result.hashes.sha256 != base.hashes.sha256 || checked.result.size != base.size)) {
        checked.changed_during_scan = true;
        checked.why = "its answer is about other bytes than the parent hashed before it got the file";
        return checked;
    }
    if (confined_strictly && text_field(checked.body, "confinement").rfind("WEAKER", 0) == 0) {
        checked.why = "it says it ran with a weaker confinement";
        return checked;
    }
    checked.ok = true;
    return checked;
}

constexpr const char* kChangedReason =
    "the file changed during the scan (the bytes the worker read do not have the hash or size the "
    "parent took before the worker got the file)";
}  // namespace

JobOutcome Host::scan_one_shot(io::File& file, const std::string& display_name) {
    const Clock::time_point job_start = Clock::now();
    ScanResult base = base_result(display_name);
    base.size = file.size();
    double hash_ms = 0.0;
    JobOutcome refused;
    if (!hash_for_identity(file, base, hash_ms, refused)) {
        return refused;
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
    const Clock::time_point run_start = Clock::now();
    const sandbox::ChildResult child = run(job, &file, error);
    const double worker_run_ms = milliseconds_since(run_start);
    // Every abnormal end is a result for THIS file; the parent's times and the full account
    // of how the worker ended go with it.
    const auto failed = [&](const std::string& reason) {
        JobOutcome outcome = abnormal(child, reason, base);
        outcome.attempts = 1;
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
    Checked checked = check_answer(child, base, options_.verify_identity, options_.run.confine && !options_.run.allow_weaker);
    if (!checked.ok) {
        JobOutcome outcome = failed(checked.why);
        if (checked.changed_during_scan) {
            outcome.result.reason = kChangedReason;
        }
        return outcome;
    }

    JobOutcome outcome;
    outcome.result = std::move(checked.result);
    outcome.answered = true;
    outcome.attempts = 1;
    outcome.end = child.end;
    outcome.exit_code = child.exit_code;
    outcome.detail = printable(child.detail, 600);
    outcome.confinement = printable(child.confinement, 600);
    outcome.container_folder_note = printable(child.container_folder_note, 600);
    outcome.worker_confinement = printable(text_field(checked.body, "confinement"), 600);
    outcome.peak_memory_bytes = child.peak_memory_bytes;
    outcome.seconds = child.seconds;
    const auto pid = checked.body.find("pid");
    outcome.worker_pid = pid != checked.body.end() && pid->is_number_integer() ? pid->get<std::int64_t>() : 0;
    outcome.setup_ms = number_field(checked.body, "setup_ms");
    outcome.scan_ms = number_field(checked.body, "scan_ms");
    outcome.worker_alive_ms = number_field(checked.body, "alive_ms");
    outcome.hash_ms = hash_ms;
    outcome.worker_run_ms = worker_run_ms;
    outcome.start_overhead_ms = worker_run_ms > outcome.worker_alive_ms ? worker_run_ms - outcome.worker_alive_ms : 0.0;
    outcome.total_ms = milliseconds_since(job_start);
    return outcome;
}

JobOutcome Host::scan_pooled(io::File& file, const std::string& display_name) {
    const Clock::time_point start = Clock::now();
    JobOutcome outcome;
    for (int attempt = 1; attempt <= 2; ++attempt) {
        bool config_mismatch = false;
        outcome = pooled_attempt(file, display_name, attempt, config_mismatch);
        outcome.attempts = attempt;
        if (!config_mismatch) {
            break;
        }
        // The answer came from a worker prepared with another configuration: it is discarded
        // and the file is scanned once more by a fresh worker (reviewer's condition 5 of M-13).
        event("config_mismatch", "attempt " + std::to_string(attempt) + ": " + outcome.result.reason);
    }
    outcome.total_ms = milliseconds_since(start);
    return outcome;
}

JobOutcome Host::pooled_attempt(io::File& file, const std::string& display_name, int attempt, bool& config_mismatch) {
    config_mismatch = false;
    const Clock::time_point job_start = Clock::now();
    ScanResult base = base_result(display_name);
    base.size = file.size();
    double hash_ms = 0.0;
    JobOutcome refused;
    if (!hash_for_identity(file, base, hash_ms, refused)) {  // again on a second attempt: the file may have changed
        return refused;
    }

    FileJob file_job;
    file_job.display_name = display_name;
    file_job.test_fault = options_.test_fault;
    // TESTS: a fault named "...-once" is sent with the first attempt only.
    if (attempt > 1 && file_job.test_fault.size() > 5 &&
        file_job.test_fault.compare(file_job.test_fault.size() - 5, 5, "-once") == 0) {
        file_job.test_fault.clear();
    }
    std::string error;
    const std::string job_text = encode_file_job(file_job, error);
    const std::span<const std::uint8_t> job_bytes(reinterpret_cast<const std::uint8_t*>(job_text.data()), job_text.size());
    if (job_text.empty()) {
        JobOutcome outcome;
        outcome.result = std::move(base);
        outcome.result.state = ScanState::NotScanned;
        outcome.result.reason = "the file job could not be made: " + printable(error, 200);
        outcome.detail = outcome.result.reason;
        outcome.hash_ms = hash_ms;
        outcome.total_ms = milliseconds_since(job_start);
        return outcome;
    }

    // A ready worker, and the hand-over. Before the hand-over nothing of the file has reached
    // any worker: if no worker can be had the file is "not scanned" (condition 6), never clean.
    std::unique_ptr<Slot> slot;
    double waited_ms = 0.0;
    bool handed = false;
    Clock::time_point hand_over_start = Clock::now();
    Clock::time_point hand_over_returned = hand_over_start;
    for (int tries = 0; tries < 3 && !handed; ++tries) {
        double waited = 0.0;
        slot = take_ready(error, waited);
        waited_ms += waited;
        if (!slot) {
            break;
        }
        hand_over_start = Clock::now();
        if (sandbox::hand_over_file(*slot->child, file, job_bytes, error)) {
            hand_over_returned = Clock::now();
            handed = true;
        } else {
            retire(*slot, "unusable", "the hand-over failed: " + error);
            slot.reset();
        }
    }
    if (!handed) {
        JobOutcome outcome;
        outcome.result = std::move(base);
        outcome.result.state = ScanState::NotScanned;
        outcome.result.reason = "no worker could be had: " + printable(error, 400);
        outcome.result.score = 0;
        outcome.result.verdict.clear();
        outcome.result.findings.clear();
        outcome.detail = outcome.result.reason;
        outcome.hash_ms = hash_ms;
        outcome.wait_ready_ms = waited_ms;
        outcome.total_ms = milliseconds_since(job_start);
        return outcome;
    }

    std::string second;
    if (options_.test_second_hand_over) {
        // TESTS (condition 3 of M-13): the same worker must refuse a second file.
        std::string refused_why;
        second = sandbox::hand_over_file(*slot->child, file, job_bytes, refused_why)
                     ? "right after the first: ACCEPTED"
                     : "right after the first: refused (" + printable(refused_why, 200) + ")";
    }
    // While this file is scanned, the places of the pool are filled again: new workers are
    // started (not waited for; their preparation is sent between files) and the ready ones are
    // polled. The time this takes is on the file's path and is reported as refill_ms.
    const Clock::time_point refill_start = Clock::now();
    if (options_.refill_during_scan) {
        maintain(false);
    }
    const double refill_ms = milliseconds_since(refill_start);

    const sandbox::ChildResult child = sandbox::collect(*slot->child, options_.limits);
    const Clock::time_point collect_returned = Clock::now();
    const double worker_run_ms = std::chrono::duration<double, std::milli>(collect_returned - hand_over_start).count();
    // The breakdown from the start of the hand-over call (reviewer's A-8 question: where the
    // time of a file goes when a worker was ready).
    const std::int64_t origin = steady_ns(hand_over_start);
    const auto in_ms = [](Clock::time_point from, Clock::time_point to) {
        return std::chrono::duration<double, std::milli>(to - from).count();
    };
    const auto breakdown = [&](JobOutcome& outcome, const json* body) {
        outcome.t_hand_over_returned_ms = in_ms(hand_over_start, hand_over_returned);
        outcome.t_collect_returned_ms = in_ms(hand_over_start, collect_returned);
        outcome.t_answer_written_ms = stamp_after(stamp_in(child.detail, "answer written at "), origin);
        outcome.t_main_ended_ms = stamp_after(stamp_in(child.detail, "main ends at "), origin);
        if (body != nullptr) {
            const auto sealed = body->find("sealed_ns");
            const auto done = body->find("scan_done_ns");
            outcome.t_sealed_ms =
                sealed != body->end() && sealed->is_number_integer() ? stamp_after(sealed->get<std::int64_t>(), origin) : -1.0;
            outcome.t_scan_done_ms =
                done != body->end() && done->is_number_integer() ? stamp_after(done->get<std::int64_t>(), origin) : -1.0;
        }
        outcome.from_hand_over_ms = milliseconds_since(hand_over_start);
    };
    if (options_.test_second_hand_over) {
        std::string refused_why;
        second += sandbox::hand_over_file(*slot->child, file, job_bytes, refused_why)
                      ? "; after the answer: ACCEPTED"
                      : "; after the answer: refused (" + printable(refused_why, 200) + ")";
    }
    const std::uint64_t worker_generation = slot->generation;

    const auto failed = [&](const std::string& reason) {
        JobOutcome outcome = abnormal(child, reason, base);
        outcome.hash_ms = hash_ms;
        outcome.wait_ready_ms = waited_ms;
        outcome.refill_ms = refill_ms;
        outcome.worker_run_ms = worker_run_ms;
        outcome.worker_generation = worker_generation;
        outcome.second_hand_over = second;
        breakdown(outcome, nullptr);
        outcome.total_ms = milliseconds_since(job_start);
        return outcome;
    };
    const std::string seconds = std::to_string(options_.limits.wall_seconds);
    switch (child.end) {
        case sandbox::ChildResult::End::Exited:
            break;
        case sandbox::ChildResult::End::KilledByTimeLimit:
            return failed("killed at the time limit of " + seconds + " seconds after the hand-over");
        case sandbox::ChildResult::End::KilledByMemoryLimit:
            return failed("ended at the memory limit of " + std::to_string(options_.limits.memory_bytes) + " bytes");
        case sandbox::ChildResult::End::Crashed:
            return failed("crashed (" + printable(child.detail, 200) + ")");
        case sandbox::ChildResult::End::StartFailed:
            // After a hand-over this means: the worker did not report its full confinement, so
            // whatever it wrote was discarded by the sandbox (condition 1 of M-13).
            return failed("its answer was discarded: it did not report its full confinement (" +
                          printable(child.detail, 200) + ")");
    }
    if (child.exit_code != kExitOk) {
        return failed("ended without an answer: " + exit_meaning(child.exit_code));
    }
    Checked checked = check_answer(child, base, options_.verify_identity, true);
    if (!checked.ok) {
        JobOutcome outcome = failed(checked.why);
        if (checked.changed_during_scan) {
            outcome.result.reason = kChangedReason;
        }
        return outcome;
    }
    // Condition 5 of M-13: the answer must come from the CURRENT configuration: the same
    // preparation (rules texts, table, reputation list: its SHA-256), the same rules state,
    // rule-set hash and profile as the current configuration's description.
    const std::string answer_preparation = text_field(checked.body, "preparation_sha256");
    const std::string current_rules = description_.rules_state == RulesState::Off ? std::string() : description_.rules_sha256;
    if (!described_ || worker_generation != generation_ || answer_preparation != preparation_sha256_ ||
        checked.result.rules_state != description_.rules_state || checked.result.rules_sha256 != current_rules ||
        checked.result.profile != description_.profile) {
        config_mismatch = true;
        JobOutcome outcome = failed("its answer is not from the current configuration");
        outcome.result.reason =
            attempt == 1 ? "worker: its answer is not from the current configuration (discarded; scanned again)"
                         : "worker: the answer was not from the current configuration twice (rules state " +
                               std::string(to_string(checked.result.rules_state)) + ", rule-set hash " +
                               printable(checked.result.rules_sha256, 64) + "; current " +
                               std::string(to_string(description_.rules_state)) + ", " + printable(current_rules, 64) +
                               ")";
        if (attempt > 1) {
            config_mismatch = false;  // no third attempt: this is the result
        }
        return outcome;
    }

    JobOutcome outcome;
    outcome.result = std::move(checked.result);
    outcome.answered = true;
    outcome.end = child.end;
    outcome.exit_code = child.exit_code;
    outcome.detail = printable(child.detail, 600);
    outcome.confinement = printable(child.confinement, 600);
    outcome.container_folder_note = printable(child.container_folder_note, 600);
    outcome.worker_confinement = printable(text_field(checked.body, "confinement"), 600);
    outcome.peak_memory_bytes = child.peak_memory_bytes;
    outcome.seconds = child.seconds;
    const auto pid = checked.body.find("pid");
    outcome.worker_pid = pid != checked.body.end() && pid->is_number_integer() ? pid->get<std::int64_t>() : 0;
    outcome.worker_generation = worker_generation;
    outcome.second_hand_over = second;
    outcome.setup_ms = number_field(checked.body, "setup_ms");
    outcome.scan_ms = number_field(checked.body, "scan_ms");
    outcome.after_seal_ms = number_field(checked.body, "after_seal_ms");
    outcome.hash_ms = hash_ms;
    outcome.wait_ready_ms = waited_ms;
    outcome.refill_ms = refill_ms;
    outcome.worker_run_ms = worker_run_ms;
    breakdown(outcome, &checked.body);
    outcome.total_ms = milliseconds_since(job_start);
    return outcome;
}

}  // namespace mie::worker
