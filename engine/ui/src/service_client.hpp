// Off-GUI-thread client for protocol version 1 over mie::channel.
// Blocking connect/send/receive calls execute strictly on a dedicated worker thread.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <QObject>
#include <QString>

#include "mie/channel/transport.hpp"
#include "mie/result.hpp"

namespace mie::ui {

enum class ChannelState {
    Ok,
    ServiceNotRunning,
    HeldByOtherAccount,
    BadServiceAnswer,
};

struct ServiceStatusData {
    std::string version;
    std::string engine;
    bool monitoring = false;
    mie::RulesState rules = mie::RulesState::Off;
    std::string profile;
    std::string rules_sha256;
};

struct StatusReply {
    ChannelState channel = ChannelState::ServiceNotRunning;
    ServiceStatusData status;
};

enum class ScanReplyKind {
    Result,
    NotAvailableInBuild,
    ServiceNotRunning,
    HeldByOtherAccount,
    BadServiceAnswer,
};

struct ScanReply {
    ScanReplyKind kind = ScanReplyKind::ServiceNotRunning;
    mie::ScanResult result;
};

enum class ReservedOpReplyKind {
    NotAvailableInBuild,
    ServiceNotRunning,
    HeldByOtherAccount,
    BadServiceAnswer,
};

struct ReservedOpReply {
    ReservedOpReplyKind kind = ReservedOpReplyKind::ServiceNotRunning;
};

using ConnectFunction = std::function<std::unique_ptr<mie::channel::Connection>(
    const mie::channel::Endpoint&, mie::channel::ConnectStatus&, std::string&)>;

class ServiceClient : public QObject {
    Q_OBJECT

public:
    explicit ServiceClient(std::string endpoint_override = {},
                           ConnectFunction connect_fn = {},
                           QObject* parent = nullptr);
    ~ServiceClient() override;

    ServiceClient(const ServiceClient&) = delete;
    ServiceClient& operator=(const ServiceClient&) = delete;

    void setConnectFunction(ConnectFunction connect_fn);
    void setEndpointOverride(std::string endpoint_override);
    void setReceiveTimeoutMs(int timeout_ms);

    void requestStatus();
    void requestScan(const QString& path);
    void requestQuarantineList();
    void requestTrustedList();

signals:
    void statusFinished(const mie::ui::StatusReply& reply);
    void scanFinished(const mie::ui::ScanReply& reply);
    void quarantineListFinished(const mie::ui::ReservedOpReply& reply);
    void trustedListFinished(const mie::ui::ReservedOpReply& reply);

private:
    enum class TaskKind {
        Status,
        Scan,
        QuarantineList,
        TrustedList,
    };

    struct Task {
        TaskKind kind = TaskKind::Status;
        std::string argument;
    };

    struct RawCallOutcome {
        ChannelState channel = ChannelState::ServiceNotRunning;
        mie::channel::Message response;
    };

    void workerLoop();
    RawCallOutcome performCall(const std::string& op, const nlohmann::json& body);
    StatusReply executeStatus();
    ScanReply executeScan(const std::string& path_utf8);
    ReservedOpReply executeReservedOp(const std::string& op);

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Task> queue_;
    bool stop_ = false;
    bool status_queued_ = false;
    std::uint64_t next_id_ = 1;
    std::string endpoint_override_;
    ConnectFunction connect_fn_;
    int receive_timeout_ms_ = 5000;
    std::thread worker_;
};

}  // namespace mie::ui
