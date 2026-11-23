#include "service_client.hpp"

#include <initializer_list>
#include <utility>

#include <QMetaObject>

namespace mie::ui {

namespace {

bool is_unknown_op_body(const nlohmann::json& body) {
    if (!body.is_object() || body.size() != 2) {
        return false;
    }
    const auto ok_it = body.find("ok");
    const auto err_it = body.find("error");
    if (ok_it == body.end() || err_it == body.end()) {
        return false;
    }
    return ok_it->is_boolean() && !ok_it->get<bool>() &&
           err_it->is_string() && err_it->get<std::string>() == "unknown_op";
}

bool parse_status_body(const nlohmann::json& body, ServiceStatusData& out) {
    if (!body.is_object()) {
        return false;
    }
    const std::initializer_list<const char*> required = {
        "ok", "service", "version", "protocol", "result_schema",
        "pid", "engine", "monitoring", "rules", "profile", "rules_sha256"
    };
    for (const char* key : required) {
        if (!body.contains(key)) {
            return false;
        }
    }
    // Every field in status must be known (the week 0 skeleton also sends "note").
    for (auto it = body.begin(); it != body.end(); ++it) {
        const std::string& k = it.key();
        bool allowed = (k == "note");
        for (const char* req : required) {
            if (k == req) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return false;
        }
    }
    if (body.contains("note") && !body.at("note").is_string()) {
        return false;
    }
    if (!body.at("ok").is_boolean() || !body.at("ok").get<bool>()) {
        return false;
    }
    if (!body.at("service").is_string() || body.at("service").get<std::string>().empty()) {
        return false;
    }
    if (!body.at("version").is_string() || body.at("version").get<std::string>().empty()) {
        return false;
    }
    if (!body.at("protocol").is_number_integer() ||
        body.at("protocol").get<std::int64_t>() != mie::channel::kProtocolVersion) {
        return false;
    }
    if (!body.at("result_schema").is_number_integer() ||
        body.at("result_schema").get<std::int64_t>() != mie::kResultSchemaVersion) {
        return false;
    }
    if (!body.at("pid").is_number_integer()) {
        return false;
    }
    if (!body.at("engine").is_string() || body.at("engine").get<std::string>().empty()) {
        return false;
    }
    if (!body.at("monitoring").is_boolean()) {
        return false;
    }
    if (!body.at("rules").is_string()) {
        return false;
    }
    if (!body.at("profile").is_string() || !body.at("rules_sha256").is_string()) {
        return false;
    }

    const std::string rules_text = body.at("rules").get<std::string>();
    mie::RulesState rules_state = mie::RulesState::Off;
    if (rules_text == "ON") {
        rules_state = mie::RulesState::On;
    } else if (rules_text == "DEGRADED") {
        rules_state = mie::RulesState::Degraded;
    } else if (rules_text == "OFF") {
        rules_state = mie::RulesState::Off;
    } else {
        return false;
    }

    out.version = body.at("version").get<std::string>();
    out.engine = body.at("engine").get<std::string>();
    out.monitoring = body.at("monitoring").get<bool>();
    out.rules = rules_state;
    out.profile = body.at("profile").get<std::string>();
    out.rules_sha256 = body.at("rules_sha256").get<std::string>();
    return true;
}

}  // namespace

ServiceClient::ServiceClient(std::string endpoint_override,
                             ConnectFunction connect_fn,
                             QObject* parent)
    : QObject(parent),
      endpoint_override_(std::move(endpoint_override)),
      connect_fn_(std::move(connect_fn)) {
    if (!connect_fn_) {
        connect_fn_ = [](const mie::channel::Endpoint& ep,
                         mie::channel::ConnectStatus& st,
                         std::string& err) {
            return mie::channel::connect(ep, st, err);
        };
    }
    worker_ = std::thread(&ServiceClient::workerLoop, this);
}

ServiceClient::~ServiceClient() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void ServiceClient::setConnectFunction(ConnectFunction connect_fn) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connect_fn) {
        connect_fn_ = std::move(connect_fn);
    } else {
        connect_fn_ = [](const mie::channel::Endpoint& ep,
                         mie::channel::ConnectStatus& st,
                         std::string& err) {
            return mie::channel::connect(ep, st, err);
        };
    }
}

void ServiceClient::setEndpointOverride(std::string endpoint_override) {
    std::lock_guard<std::mutex> lock(mutex_);
    endpoint_override_ = std::move(endpoint_override);
}

void ServiceClient::setReceiveTimeoutMs(int timeout_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    receive_timeout_ms_ = timeout_ms;
}

void ServiceClient::requestStatus() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (status_queued_) {
            return;
        }
        status_queued_ = true;
        queue_.push_back(Task{TaskKind::Status, {}});
    }
    cv_.notify_one();
}

void ServiceClient::requestScan(const QString& path) {
    // Send the path as UTF-8 text ONLY; never open, stat or touch the file.
    const QByteArray utf8 = path.toUtf8();
    std::string path_str(utf8.constData(), static_cast<std::size_t>(utf8.size()));
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(Task{TaskKind::Scan, std::move(path_str)});
    }
    cv_.notify_one();
}

void ServiceClient::requestQuarantineList() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(Task{TaskKind::QuarantineList, {}});
    }
    cv_.notify_one();
}

void ServiceClient::requestTrustedList() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push_back(Task{TaskKind::TrustedList, {}});
    }
    cv_.notify_one();
}

void ServiceClient::workerLoop() {
    for (;;) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (stop_) {
                return;
            }
            task = std::move(queue_.front());
            queue_.pop_front();
            if (task.kind == TaskKind::Status) {
                status_queued_ = false;
            }
        }

        switch (task.kind) {
            case TaskKind::Status: {
                StatusReply reply = executeStatus();
                QMetaObject::invokeMethod(
                    this,
                    [this, reply = std::move(reply)]() { emit statusFinished(reply); },
                    Qt::QueuedConnection);
                break;
            }
            case TaskKind::Scan: {
                ScanReply reply = executeScan(task.argument);
                QMetaObject::invokeMethod(
                    this,
                    [this, reply = std::move(reply)]() { emit scanFinished(reply); },
                    Qt::QueuedConnection);
                break;
            }
            case TaskKind::QuarantineList: {
                ReservedOpReply reply = executeReservedOp("quarantine.list");
                QMetaObject::invokeMethod(
                    this,
                    [this, reply]() { emit quarantineListFinished(reply); },
                    Qt::QueuedConnection);
                break;
            }
            case TaskKind::TrustedList: {
                ReservedOpReply reply = executeReservedOp("trusted.list");
                QMetaObject::invokeMethod(
                    this,
                    [this, reply]() { emit trustedListFinished(reply); },
                    Qt::QueuedConnection);
                break;
            }
        }
    }
}

ServiceClient::RawCallOutcome ServiceClient::performCall(const std::string& op,
                                                         const nlohmann::json& body) {
    std::string endpoint_override;
    ConnectFunction connect_fn;
    int timeout_ms = 5000;
    std::uint64_t req_id = 1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        endpoint_override = endpoint_override_;
        connect_fn = connect_fn_;
        timeout_ms = receive_timeout_ms_;
        req_id = next_id_++;
    }

    RawCallOutcome out;
    std::string error;
    mie::channel::Endpoint endpoint{endpoint_override};
    if (endpoint.name.empty()) {
        endpoint = mie::channel::default_endpoint(error);
        if (endpoint.name.empty()) {
            out.channel = ChannelState::ServiceNotRunning;
            return out;
        }
    }

    mie::channel::ConnectStatus connect_status = mie::channel::ConnectStatus::Error;
    std::unique_ptr<mie::channel::Connection> conn = connect_fn(endpoint, connect_status, error);
    if (!conn) {
        if (connect_status == mie::channel::ConnectStatus::HeldByOtherAccount) {
            out.channel = ChannelState::HeldByOtherAccount;
        } else {
            out.channel = ChannelState::ServiceNotRunning;
        }
        return out;
    }

    mie::channel::Message request;
    request.v = mie::channel::kProtocolVersion;
    request.id = req_id;
    request.type = mie::channel::MessageType::Request;
    request.op = op;
    request.body = body;

    if (!conn->send(request, error)) {
        out.channel = ChannelState::BadServiceAnswer;
        return out;
    }

    mie::channel::Message response;
    if (!conn->receive(response, timeout_ms, error)) {
        out.channel = ChannelState::BadServiceAnswer;
        return out;
    }

    if (response.v != mie::channel::kProtocolVersion ||
        response.type != mie::channel::MessageType::Response ||
        response.id != request.id ||
        response.op != request.op ||
        !response.body.is_object()) {
        out.channel = ChannelState::BadServiceAnswer;
        return out;
    }

    out.channel = ChannelState::Ok;
    out.response = std::move(response);
    return out;
}

StatusReply ServiceClient::executeStatus() {
    StatusReply reply;
    const RawCallOutcome raw = performCall("status", nlohmann::json::object());
    if (raw.channel != ChannelState::Ok) {
        reply.channel = raw.channel;
        return reply;
    }
    if (!parse_status_body(raw.response.body, reply.status)) {
        reply.channel = ChannelState::BadServiceAnswer;
        return reply;
    }
    reply.channel = ChannelState::Ok;
    return reply;
}

ScanReply ServiceClient::executeScan(const std::string& path_utf8) {
    ScanReply reply;
    const nlohmann::json req_body = {{"path", path_utf8}};
    const RawCallOutcome raw = performCall("scan", req_body);
    switch (raw.channel) {
        case ChannelState::ServiceNotRunning:
            reply.kind = ScanReplyKind::ServiceNotRunning;
            return reply;
        case ChannelState::HeldByOtherAccount:
            reply.kind = ScanReplyKind::HeldByOtherAccount;
            return reply;
        case ChannelState::BadServiceAnswer:
            reply.kind = ScanReplyKind::BadServiceAnswer;
            return reply;
        case ChannelState::Ok:
            break;
    }

    if (is_unknown_op_body(raw.response.body)) {
        reply.kind = ScanReplyKind::NotAvailableInBuild;
        return reply;
    }

    // Parse scan results strictly through mie::from_json ONLY.
    const std::string serialized =
        raw.response.body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::string parse_error;
    if (!mie::from_json(serialized, reply.result, parse_error)) {
        reply.kind = ScanReplyKind::BadServiceAnswer;
        return reply;
    }
    reply.kind = ScanReplyKind::Result;
    return reply;
}

ReservedOpReply ServiceClient::executeReservedOp(const std::string& op) {
    ReservedOpReply reply;
    const RawCallOutcome raw = performCall(op, nlohmann::json::object());
    switch (raw.channel) {
        case ChannelState::ServiceNotRunning:
            reply.kind = ReservedOpReplyKind::ServiceNotRunning;
            return reply;
        case ChannelState::HeldByOtherAccount:
            reply.kind = ReservedOpReplyKind::HeldByOtherAccount;
            return reply;
        case ChannelState::BadServiceAnswer:
            reply.kind = ReservedOpReplyKind::BadServiceAnswer;
            return reply;
        case ChannelState::Ok:
            break;
    }

    if (is_unknown_op_body(raw.response.body)) {
        reply.kind = ReservedOpReplyKind::NotAvailableInBuild;
        return reply;
    }

    // Protocol version 1 reserves quarantine.* and trusted.* without defining a response body;
    // do not invent fields not present in INTERFACES.md version 1.
    reply.kind = ReservedOpReplyKind::BadServiceAnswer;
    return reply;
}

}  // namespace mie::ui
