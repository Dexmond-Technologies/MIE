// mie-service: week 0 skeleton of the per-user background service.
//
// It owns the local channel (no network listener), enforces single instance, and
// answers three operations: ping, status, shutdown. It has NO scan engine yet and
// says so in its status answer.
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <string>
#include <thread>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

#include "mie/channel/transport.hpp"
#include "mie/result.hpp"
#include "mie/version.hpp"

namespace {

std::atomic<bool> g_stop{false};

extern "C" void on_signal(int) { g_stop.store(true); }

long current_pid() {
#ifdef _WIN32
    return static_cast<long>(_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

// Handles one client until it closes, sends something invalid, or asks for shutdown.
void serve(mie::channel::Connection& connection) {
    using mie::channel::Message;
    using mie::channel::MessageType;
    using nlohmann::json;
    for (;;) {
        Message request;
        std::string error;
        if (!connection.receive(request, 5000, error)) {
            return;
        }
        if (request.type != MessageType::Request) {
            return;
        }
        Message response;
        response.id = request.id;
        response.type = MessageType::Response;
        response.op = request.op;
        if (request.op == "ping") {
            response.body = json{{"ok", true}, {"pong", true}};
        } else if (request.op == "status") {
            response.body = json{
                {"ok", true},
                {"service", "mie-service"},
                {"version", mie::kEngineVersion},
                {"protocol", mie::channel::kProtocolVersion},
                {"result_schema", mie::kResultSchemaVersion},
                {"pid", current_pid()},
                {"engine", "absent"},
                {"monitoring", false},
                {"rules", "OFF"},
                {"note", "week 0 skeleton: no scan engine yet; nothing is scanned"},
            };
        } else if (request.op == "shutdown") {
            response.body = json{{"ok", true}, {"stopping", true}};
            g_stop.store(true);
        } else {
            response.body = json{{"ok", false}, {"error", "unknown_op"}};
        }
        if (!connection.send(response, error)) {
            return;
        }
        if (g_stop.load()) {
            return;
        }
    }
}

void usage() {
    std::fputs("usage: mie-service [--endpoint NAME]\n"
               "  NAME: socket path (Linux, macOS) or full pipe name (Windows).\n"
               "  Without --endpoint the current user's default endpoint is used.\n",
               stderr);
}

}  // namespace

int main(int argc, char** argv) {
    std::string endpoint_name;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--endpoint" && i + 1 < argc) {
            endpoint_name = argv[++i];
        } else if (arg == "--version") {
            std::printf("mie-service %s\n", mie::kEngineVersion);
            return 0;
        } else {
            usage();
            return 2;
        }
    }

    std::string error;
    mie::channel::Endpoint endpoint{endpoint_name};
    if (endpoint.name.empty()) {
        endpoint = mie::channel::default_endpoint(error);
        if (endpoint.name.empty()) {
            std::fprintf(stderr, "mie-service: no endpoint: %s\n", error.c_str());
            return 2;
        }
    }

    mie::channel::ListenStatus status = mie::channel::ListenStatus::Error;
    const auto server = mie::channel::listen(endpoint, status, error);
    if (!server) {
        if (status == mie::channel::ListenStatus::AlreadyRunning) {
            std::fputs("mie-service: already running for this user\n", stderr);
            return 3;
        }
        std::fprintf(stderr, "mie-service: cannot listen: %s\n", error.c_str());
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::puts("mie-service: listening");
    std::fflush(stdout);

    while (!g_stop.load()) {
        const auto connection = server->accept(250, error);
        if (!connection) {
            if (!error.empty()) {
                std::fprintf(stderr, "mie-service: accept: %s\n", error.c_str());
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }
        serve(*connection);
    }
    std::puts("mie-service: stopped");
    return 0;
}
