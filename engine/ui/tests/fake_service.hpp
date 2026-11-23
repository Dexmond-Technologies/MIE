// Private test endpoints, fake protocol-v1 service, and raw malformed-frame server
// for mie-ui acceptance tests (T-1 .. T-14).
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "mie/channel/transport.hpp"
#include "mie/result.hpp"

namespace mie::ui::test {

struct TestEndpoint {
    mie::channel::Endpoint endpoint;
    std::string directory;

    explicit TestEndpoint(const std::string& tag);
    ~TestEndpoint();

    TestEndpoint(const TestEndpoint&) = delete;
    TestEndpoint& operator=(const TestEndpoint&) = delete;
};

struct FakeStatusConfig {
    std::string version = "0.1.0-fake";
    std::string engine = "ready";
    bool monitoring = false;
    std::string rules = "ON";
    std::string profile = "stage1";
    std::string rules_sha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    bool extra_unknown_field = false;
    int response_delay_ms = 0;
};

class FakeService {
public:
    explicit FakeService(const mie::channel::Endpoint& endpoint);
    ~FakeService();

    FakeService(const FakeService&) = delete;
    FakeService& operator=(const FakeService&) = delete;

    bool isListening() const { return listening_; }
    const std::string& listenError() const { return listen_error_; }

    void setStatusConfig(FakeStatusConfig config);
    void setScanUnknownOp();
    void setScanResult(const mie::ScanResult& result);
    void setScanRawBody(nlohmann::json body);
    void setOnScanCallback(std::function<void(const nlohmann::json&)> callback);

    std::vector<nlohmann::json> recordedScanBodies() const;
    void clearRecordedScans();

private:
    enum class ScanMode {
        UnknownOp,
        RawBody,
    };

    void runLoop();
    void serveClient(mie::channel::Connection& conn);
    void sleepInterruptibly(int total_ms) const;

    std::unique_ptr<mie::channel::Server> server_;
    bool listening_ = false;
    std::string listen_error_;
    std::atomic<bool> stop_{false};

    mutable std::mutex mutex_;
    FakeStatusConfig status_cfg_;
    ScanMode scan_mode_ = ScanMode::UnknownOp;
    nlohmann::json scan_raw_body_;
    std::function<void(const nlohmann::json&)> on_scan_cb_;
    std::vector<nlohmann::json> scan_bodies_;

    std::thread thread_;
};

// Prepends 4-byte big-endian length header to raw JSON text (allows crafting v=2 or unknown keys).
std::string make_raw_frame(std::string_view payload);

// Accepts one connection on a private endpoint, reads the request, and writes raw bytes back.
class RawFrameServer {
public:
    RawFrameServer(const mie::channel::Endpoint& endpoint, std::string raw_reply);
    ~RawFrameServer();

    RawFrameServer(const RawFrameServer&) = delete;
    RawFrameServer& operator=(const RawFrameServer&) = delete;

    bool isReady() const { return ready_.load(); }
    const std::string& startError() const { return error_; }

private:
    void runPosix(std::string path, std::string raw_reply);
    void runWin(std::string pipe_name, std::string raw_reply);

    std::atomic<bool> ready_{false};
    std::atomic<bool> stop_{false};
    std::string error_;
    std::thread thread_;
};

}  // namespace mie::ui::test
