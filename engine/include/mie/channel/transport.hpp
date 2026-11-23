// The local channel between the interface, the command line and the service.
// There is NO network listener: Windows uses a named pipe that only the current user
// may open and that rejects remote clients; Linux and macOS use a Unix-domain socket
// in a directory only the current user can enter, and the service checks the user id
// of every peer. See engine/docs/INTERFACES.md.
#pragma once

#include <memory>
#include <string>

#include "mie/channel/frame.hpp"

namespace mie::channel {

// POSIX: path of the socket file. Windows: full pipe name (\\.\pipe\...), UTF-8.
struct Endpoint {
    std::string name;
};

// The endpoint of the current user's service. Empty name and `error` set on failure.
Endpoint default_endpoint(std::string& error);

class Connection {
public:
    virtual ~Connection() = default;
    virtual bool send(const Message& message, std::string& error) = 0;
    // Waits up to timeout_ms for one whole message. Returns false with `error` set on
    // timeout ("timeout"), on a closed peer ("closed") or on a protocol error.
    virtual bool receive(Message& out, int timeout_ms, std::string& error) = 0;
};

class Server {
public:
    virtual ~Server() = default;
    // Waits up to timeout_ms for a client. Returns nullptr on timeout (error empty) or
    // on failure (error set). A peer that is not the current user is dropped.
    virtual std::unique_ptr<Connection> accept(int timeout_ms, std::string& error) = 0;
};

// HeldByOtherAccount: the endpoint's name (the pipe, or the socket directory) exists but
// belongs to another account of this computer. This user's service cannot run and
// nothing can be trusted behind that name. Programs must say so in plain words
// ("MIE is not running: ... not protected by MIE"), never treat it as "running".
enum class ListenStatus { Ok, AlreadyRunning, HeldByOtherAccount, Error };

// Starts listening. AlreadyRunning: another service of this user holds the endpoint.
std::unique_ptr<Server> listen(const Endpoint& endpoint, ListenStatus& status, std::string& error);

enum class ConnectStatus { Ok, NotRunning, HeldByOtherAccount, Error };

// Connects to the service. On failure returns nullptr and sets `status` and `error`.
std::unique_ptr<Connection> connect(const Endpoint& endpoint, ConnectStatus& status, std::string& error);

// Same, for callers that only need success or failure.
std::unique_ptr<Connection> connect(const Endpoint& endpoint, std::string& error);

// The sentence every program shows for HeldByOtherAccount (one wording, one place).
inline constexpr const char* kHeldByOtherAccountMessage =
    "Another account on this computer is holding MIE's channel name. MIE's background service "
    "cannot run, and this computer is not protected by MIE.";

}  // namespace mie::channel
