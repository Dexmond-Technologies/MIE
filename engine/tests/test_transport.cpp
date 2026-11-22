// The local channel end to end, inside one process: a server thread and a client.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <system_error>
#include <string>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include "mie/channel/transport.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <stdlib.h>
#include <unistd.h>
#endif

using namespace mie::channel;

namespace {

// A private endpoint for one test. POSIX: a socket in a fresh 0700 directory.
// Windows: a pipe name unique to this process and test.
struct TestEndpoint {
    Endpoint endpoint;
    std::string directory;

    explicit TestEndpoint(const std::string& tag) {
#ifdef _WIN32
        endpoint.name = "\\\\.\\pipe\\DexmondMIE.test." + std::to_string(_getpid()) + "." + tag;
#else
        std::string pattern = (std::filesystem::temp_directory_path() / "mie-test-XXXXXX").string();
        char* made = ::mkdtemp(pattern.data());
        REQUIRE(made != nullptr);
        directory = made;
        endpoint.name = directory + "/" + tag + ".sock";
#endif
    }

    ~TestEndpoint() {
#ifndef _WIN32
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
#endif
    }
};

}  // namespace

TEST_CASE("a request reaches the server and the answer comes back", "[transport]") {
    TestEndpoint test("roundtrip");
    ListenStatus status = ListenStatus::Error;
    std::string error;
    auto server = listen(test.endpoint, status, error);
    INFO(error);
    REQUIRE(server != nullptr);
    REQUIRE(status == ListenStatus::Ok);

    std::atomic<bool> served{false};
    std::thread server_thread([&] {
        std::string server_error;
        std::unique_ptr<Connection> connection;
        for (int i = 0; i < 100 && !connection; ++i) {
            connection = server->accept(100, server_error);
        }
        if (!connection) {
            return;
        }
        Message request;
        if (!connection->receive(request, 5000, server_error)) {
            return;
        }
        Message response;
        response.id = request.id;
        response.type = MessageType::Response;
        response.op = request.op;
        response.body = nlohmann::json{{"ok", true}, {"echo", request.body}};
        served = connection->send(response, server_error);
        // Wait for the client to close, so the answer is read before we hang up.
        Message ignored;
        connection->receive(ignored, 5000, server_error);
    });

    std::string client_error;
    auto client = connect(test.endpoint, client_error);
    INFO(client_error);
    REQUIRE(client != nullptr);

    Message request;
    request.id = 99;
    request.op = "ping";
    request.body = nlohmann::json{{"text", "hello"}};
    REQUIRE(client->send(request, client_error));

    Message response;
    const bool got = client->receive(response, 5000, client_error);
    INFO(client_error);
    REQUIRE(got);
    REQUIRE(response.id == 99);
    REQUIRE(response.type == MessageType::Response);
    REQUIRE(response.op == "ping");
    REQUIRE(response.body.at("echo").at("text") == "hello");

    client.reset();
    server_thread.join();
    REQUIRE(served.load());
}

TEST_CASE("a second listener on the same endpoint is told one is running", "[transport]") {
    TestEndpoint test("single");
    ListenStatus status = ListenStatus::Error;
    std::string error;
    auto first = listen(test.endpoint, status, error);
    INFO(error);
    REQUIRE(first != nullptr);

    ListenStatus second_status = ListenStatus::Ok;
    auto second = listen(test.endpoint, second_status, error);
    REQUIRE(second == nullptr);
    REQUIRE(second_status == ListenStatus::AlreadyRunning);

    // After the first one is gone the endpoint can be taken again.
    first.reset();
    ListenStatus third_status = ListenStatus::Error;
    auto third = listen(test.endpoint, third_status, error);
    INFO(error);
    REQUIRE(third != nullptr);
    REQUIRE(third_status == ListenStatus::Ok);
}

TEST_CASE("connecting where nobody listens fails cleanly", "[transport]") {
    TestEndpoint test("nobody");
    std::string error;
    auto client = connect(test.endpoint, error);
    REQUIRE(client == nullptr);
    REQUIRE_FALSE(error.empty());
}

TEST_CASE("accept returns without a client when the wait runs out", "[transport]") {
    TestEndpoint test("timeout");
    ListenStatus status = ListenStatus::Error;
    std::string error;
    auto server = listen(test.endpoint, status, error);
    INFO(error);
    REQUIRE(server != nullptr);
    const auto start = std::chrono::steady_clock::now();
    auto connection = server->accept(200, error);
    const auto waited = std::chrono::steady_clock::now() - start;
    REQUIRE(connection == nullptr);
    REQUIRE(error.empty());
    REQUIRE(waited < std::chrono::seconds(5));
}

TEST_CASE("receive reports a timeout when the peer stays silent", "[transport]") {
    TestEndpoint test("silent");
    ListenStatus status = ListenStatus::Error;
    std::string error;
    auto server = listen(test.endpoint, status, error);
    INFO(error);
    REQUIRE(server != nullptr);

    std::string client_error;
    auto client = connect(test.endpoint, client_error);
    INFO(client_error);
    REQUIRE(client != nullptr);

    std::unique_ptr<Connection> connection;
    for (int i = 0; i < 50 && !connection; ++i) {
        connection = server->accept(100, error);
    }
    REQUIRE(connection != nullptr);

    Message message;
    std::string receive_error;
    REQUIRE_FALSE(connection->receive(message, 200, receive_error));
    REQUIRE(receive_error == "timeout");
}
