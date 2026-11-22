// mie: week 0 command line. It can only talk to the service (ping, status, shutdown).
// Scanning is not built yet.
#include <cstdio>
#include <string>

#include "mie/channel/transport.hpp"
#include "mie/version.hpp"

namespace {

void usage() {
    std::fputs("usage: mie [--endpoint NAME] ping|status|shutdown\n"
               "       mie version\n"
               "exit codes: 0 ok, 1 the service answered with an error, 2 usage,\n"
               "            4 the service is not reachable, 5 no valid answer\n",
               stderr);
}

}  // namespace

int main(int argc, char** argv) {
    std::string endpoint_name;
    std::string op;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--endpoint" && i + 1 < argc) {
            endpoint_name = argv[++i];
        } else if (op.empty() && !arg.empty() && arg[0] != '-') {
            op = arg;
        } else {
            usage();
            return 2;
        }
    }
    if (op == "version") {
        std::printf("mie %s\n", mie::kEngineVersion);
        return 0;
    }
    if (op != "ping" && op != "status" && op != "shutdown") {
        usage();
        return 2;
    }

    std::string error;
    mie::channel::Endpoint endpoint{endpoint_name};
    if (endpoint.name.empty()) {
        endpoint = mie::channel::default_endpoint(error);
        if (endpoint.name.empty()) {
            std::fprintf(stderr, "mie: no endpoint: %s\n", error.c_str());
            return 4;
        }
    }
    const auto connection = mie::channel::connect(endpoint, error);
    if (!connection) {
        std::fprintf(stderr, "mie: the service is not reachable: %s\n", error.c_str());
        return 4;
    }

    mie::channel::Message request;
    request.id = 1;
    request.type = mie::channel::MessageType::Request;
    request.op = op;
    if (!connection->send(request, error)) {
        std::fprintf(stderr, "mie: send failed: %s\n", error.c_str());
        return 5;
    }
    mie::channel::Message response;
    if (!connection->receive(response, 5000, error)) {
        std::fprintf(stderr, "mie: no valid answer: %s\n", error.c_str());
        return 5;
    }
    if (response.type != mie::channel::MessageType::Response || response.id != request.id ||
        response.op != request.op) {
        std::fputs("mie: the answer does not match the request\n", stderr);
        return 5;
    }
    std::printf("%s\n", response.body.dump().c_str());
    const auto ok = response.body.find("ok");
    return (ok != response.body.end() && ok->is_boolean() && ok->get<bool>()) ? 0 : 1;
}
