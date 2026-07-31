#pragma once
#include <nlohmann/json.hpp>
#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using socket_t = SOCKET;
#  define INVALID_SOCK INVALID_SOCKET
#  define CLOSE_SOCK(s) ::closesocket(s)
#else
   using socket_t = int;
#  define INVALID_SOCK (-1)
#  define CLOSE_SOCK(s) ::close(s)
#endif

/**
 * Async JSON-over-TCP client for the ghidra-bridge process.
 *
 * Wire format: newline-delimited JSON in both directions.
 *
 * Requests carry an integer "id"; the bridge echoes it in the response.
 * Async events from the bridge carry an "event" key instead of "id".
 *
 * Thread model:
 *   - A dedicated receive thread reads and dispatches all incoming messages.
 *   - sendAsync() is safe to call from any thread.
 *   - sendSync() blocks the calling thread up to timeoutMs.
 *   - The event callback is invoked from the receive thread — callers that
 *     update Qt UI must queue the call (QMetaObject::invokeMethod with
 *     Qt::QueuedConnection).
 */
class BridgeClient {
public:
    using Json             = nlohmann::json;
    using ResponseCallback = std::function<void(Json)>;
    using EventCallback    = std::function<void(Json)>;

    BridgeClient() = default;
    ~BridgeClient() { disconnect(); }

    BridgeClient(const BridgeClient&) = delete;
    BridgeClient& operator=(const BridgeClient&) = delete;

    /** Connect to the bridge at <host>:<port> and start the receive thread. */
    bool connect(const std::string& host, int port, std::string& errorOut);

    /** Disconnect and stop the receive thread. */
    void disconnect();

    bool isConnected() const { return m_sock != INVALID_SOCK; }

    /**
     * Send a request and invoke callback when the response arrives.
     * Assigns the next request ID automatically — do not set "id" in request.
     */
    void sendAsync(Json request, ResponseCallback callback);

    /**
     * Send a request and block until the response arrives.
     * Throws std::runtime_error on timeout or disconnect.
     */
    Json sendSync(Json request, int timeoutMs = 15'000);

    /** Register a callback for asynchronous events pushed by the bridge. */
    void setEventCallback(EventCallback cb);

private:
    socket_t             m_sock = INVALID_SOCK;
    std::thread          m_recvThread;
    std::atomic<bool>    m_running{false};
    std::atomic<int>     m_nextId{1};

    std::mutex                     m_sendMutex;
    std::mutex                     m_pendingMutex;
    std::map<int, ResponseCallback> m_pending;

    std::mutex      m_eventMutex;
    EventCallback   m_eventCallback;

    void receiveLoop();
    void dispatch(const Json& msg);
    bool sendRaw(const std::string& line);
};
