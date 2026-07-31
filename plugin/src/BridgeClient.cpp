#include "BridgeClient.h"
#include <stdexcept>
#include <string>

#ifdef _WIN32
#  pragma comment(lib, "ws2_32.lib")
namespace {
    // One-time Winsock init (thread-safe via function-local static).
    bool initWinsock() {
        WSADATA wd{};
        return WSAStartup(MAKEWORD(2, 2), &wd) == 0;
    }
    bool s_wsaInit = initWinsock();
}
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// Connect / disconnect
// ---------------------------------------------------------------------------

bool BridgeClient::connect(const std::string& host, int port, std::string& errorOut) {
    disconnect();

    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCK) {
        errorOut = "socket() failed";
        return false;
    }

    const char* h = host.empty() ? "127.0.0.1" : host.c_str();
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, h, &addr.sin_addr) != 1) {
        errorOut = std::string("Invalid bridge host address: ") + h;
        CLOSE_SOCK(s);
        return false;
    }

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        errorOut = "connect() to " + std::string(h) + ":" + std::to_string(port) + " failed";
        CLOSE_SOCK(s);
        return false;
    }

    m_sock    = s;
    m_running = true;
    m_recvThread = std::thread(&BridgeClient::receiveLoop, this);
    return true;
}

void BridgeClient::disconnect() {
    m_running = false;
    if (m_sock != INVALID_SOCK) {
        // Closing the socket wakes up the blocking recv() in receiveLoop.
        CLOSE_SOCK(m_sock);
        m_sock = INVALID_SOCK;
    }
    if (m_recvThread.joinable()) {
        m_recvThread.join();
    }
    // Fail all pending requests.
    std::map<int, ResponseCallback> pending;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        pending = std::move(m_pending);
    }
    for (auto& [id, cb] : pending) {
        cb(nlohmann::json{{"id", id}, {"ok", false},
                          {"error", "BridgeClient disconnected"}});
    }
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

bool BridgeClient::sendRaw(const std::string& line) {
    std::lock_guard<std::mutex> lk(m_sendMutex);
    if (m_sock == INVALID_SOCK) return false;
    const char* p   = line.c_str();
    int         rem = static_cast<int>(line.size());
    while (rem > 0) {
        int sent = ::send(m_sock, p, rem, 0);
        if (sent <= 0) return false;
        p   += sent;
        rem -= sent;
    }
    return true;
}

void BridgeClient::sendAsync(nlohmann::json request, ResponseCallback callback) {
    int id = m_nextId.fetch_add(1);
    request["id"] = id;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        m_pending[id] = std::move(callback);
    }
    std::string line = request.dump() + "\n";
    if (!sendRaw(line)) {
        // Socket gone — invoke callback with error immediately.
        ResponseCallback cb;
        {
            std::lock_guard<std::mutex> lk(m_pendingMutex);
            auto it = m_pending.find(id);
            if (it != m_pending.end()) { cb = it->second; m_pending.erase(it); }
        }
        if (cb) cb(nlohmann::json{{"id", id}, {"ok", false}, {"error", "send failed"}});
    }
}

nlohmann::json BridgeClient::sendSync(nlohmann::json request, int timeoutMs) {
    // Use a shared_ptr<promise> so the lambda is safe even if this function
    // returns (due to timeout) before the callback fires.
    auto prom = std::make_shared<std::promise<nlohmann::json>>();
    auto fut  = prom->get_future();

    sendAsync(std::move(request), [prom](nlohmann::json resp) {
        prom->set_value(std::move(resp));
    });

    if (fut.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::timeout) {
        throw std::runtime_error("Ghidra bridge request timed out after " +
                                 std::to_string(timeoutMs) + "ms");
    }
    return fut.get();
}

void BridgeClient::setEventCallback(EventCallback cb) {
    std::lock_guard<std::mutex> lk(m_eventMutex);
    m_eventCallback = std::move(cb);
}

// ---------------------------------------------------------------------------
// Receive loop (runs on m_recvThread)
// ---------------------------------------------------------------------------

void BridgeClient::receiveLoop() {
    char        buf[8192];
    std::string partial;

    while (m_running) {
        int n = ::recv(m_sock, buf, sizeof(buf), 0);
        if (n <= 0) break; // disconnected or error

        partial.append(buf, static_cast<size_t>(n));

        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string line = partial.substr(0, pos);
            partial.erase(0, pos + 1);
            // Strip CR for Windows line endings
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            try {
                dispatch(nlohmann::json::parse(line));
            } catch (const std::exception&) {
                // Malformed JSON — ignore and continue.
            }
        }
    }

    m_running = false;
}

void BridgeClient::dispatch(const nlohmann::json& msg) {
    if (msg.contains("event")) {
        // Async push event from the bridge.
        EventCallback cb;
        {
            std::lock_guard<std::mutex> lk(m_eventMutex);
            cb = m_eventCallback;
        }
        if (cb) cb(msg);
        return;
    }

    if (!msg.contains("id")) return;

    int id = msg["id"].get<int>();
    ResponseCallback cb;
    {
        std::lock_guard<std::mutex> lk(m_pendingMutex);
        auto it = m_pending.find(id);
        if (it != m_pending.end()) {
            cb = std::move(it->second);
            m_pending.erase(it);
        }
    }
    if (cb) cb(msg);
}
