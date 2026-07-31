// BridgeClientProtocolTest.cpp
// Tests for the BridgeClient JSON-over-TCP wire protocol.
//
// A MiniServer accepts a single connection per test, captures one
// newline-delimited JSON request, and returns a canned response — no real
// Ghidra bridge is needed.

#include <gtest/gtest.h>
#include "BridgeClient.h"
#include <nlohmann/json.hpp>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using socket_t  = SOCKET;
#  define CLOSE_SOCK(s) ::closesocket(s)
#  define INVALID_SOCK  INVALID_SOCKET
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
   using socket_t  = int;
#  define CLOSE_SOCK(s) ::close(s)
#  define INVALID_SOCK  (-1)
#endif

#include <atomic>
#include <thread>
#include <string>
#include <stdexcept>

using Json = nlohmann::json;

// ---------------------------------------------------------------------------
// MiniServer — ephemeral mock TCP server for one request/response exchange
// ---------------------------------------------------------------------------

class MiniServer {
public:
    int         port        = 0;
    std::string lastRequest;       ///< raw JSON line received (no newline)
    std::atomic<bool> accepted{false};

    explicit MiniServer() {
        m_listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_NE(m_listenFd, INVALID_SOCK) << "socket() failed";

        int opt = 1;
        ::setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&opt), sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = 0; // let the OS pick a free port
        EXPECT_EQ(::bind(m_listenFd,
                         reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        EXPECT_EQ(::listen(m_listenFd, 1), 0);

        socklen_t len = sizeof(addr);
        ::getsockname(m_listenFd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
    }

    ~MiniServer() {
        if (m_worker.joinable()) m_worker.join();
        if (m_listenFd != INVALID_SOCK) CLOSE_SOCK(m_listenFd);
    }

    // Start serving one connection.  The server reads one newline-terminated
    // JSON line, stores it in lastRequest, then writes cannedResponse + '\n'.
    // Call join() before inspecting lastRequest to ensure the exchange is done.
    void serveOne(const std::string& cannedResponse) {
        m_worker = std::thread([this, cannedResponse]() {
            socket_t client = ::accept(m_listenFd, nullptr, nullptr);
            if (client == INVALID_SOCK) return;
            accepted.store(true);

            std::string buf;
            char ch;
            while (::recv(client, &ch, 1, 0) > 0) {
                if (ch == '\n') break;
                buf += ch;
            }
            lastRequest = buf;

            std::string resp = cannedResponse + "\n";
            ::send(client, resp.c_str(), static_cast<int>(resp.size()), 0);
            CLOSE_SOCK(client);
        });
    }

    void join() {
        if (m_worker.joinable()) m_worker.join();
    }

private:
    socket_t    m_listenFd = INVALID_SOCK;
    std::thread m_worker;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void connectTo(BridgeClient& client, MiniServer& server) {
    std::string err;
    ASSERT_TRUE(client.connect("127.0.0.1", server.port, err)) << err;
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

TEST(BridgeClientProtocolTest, IsConnected_FalseBeforeConnect) {
    BridgeClient client;
    EXPECT_FALSE(client.isConnected());
}

TEST(BridgeClientProtocolTest, IsConnected_TrueAfterConnect) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true})");

    BridgeClient client; connectTo(client, server);
    EXPECT_TRUE(client.isConnected());

    client.sendSync({{"op", "noop"}}, 3000);
    server.join();
}

TEST(BridgeClientProtocolTest, IsConnected_FalseAfterDisconnect) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true})");

    BridgeClient client; connectTo(client, server);
    client.sendSync({{"op", "noop"}}, 3000);
    server.join();

    client.disconnect();
    EXPECT_FALSE(client.isConnected());
}

// ---------------------------------------------------------------------------
// Wire format — request serialisation
// ---------------------------------------------------------------------------

TEST(BridgeClientProtocolTest, SendSync_WritesNewlineDelimitedJson) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true})");

    BridgeClient client; connectTo(client, server);
    client.sendSync({{"op", "ping"}}, 3000);
    server.join();

    ASSERT_FALSE(server.lastRequest.empty());
    // Must parse as valid JSON (no newline embedded)
    Json wire;
    ASSERT_NO_THROW(wire = Json::parse(server.lastRequest));
    EXPECT_EQ(wire["op"], "ping");
}

TEST(BridgeClientProtocolTest, SendSync_AutoAssignsId_StartsAtOne) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true})");

    BridgeClient client; connectTo(client, server);
    client.sendSync({{"op", "test"}}, 3000);
    server.join();

    Json wire = Json::parse(server.lastRequest);
    ASSERT_TRUE(wire.contains("id")) << "request must carry an 'id' field";
    EXPECT_EQ(wire["id"].get<int>(), 1);
}

TEST(BridgeClientProtocolTest, SendSync_PayloadFieldsPreserved) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true})");

    BridgeClient client; connectTo(client, server);
    Json req = {
        {"op",   "openRepo"},
        {"repo", "test-repo"},
        {"flag", true},
        {"num",  42}
    };
    client.sendSync(req, 3000);
    server.join();

    Json wire = Json::parse(server.lastRequest);
    EXPECT_EQ(wire["op"],   "openRepo");
    EXPECT_EQ(wire["repo"], "test-repo");
    EXPECT_EQ(wire["flag"], true);
    EXPECT_EQ(wire["num"],  42);
}

// ---------------------------------------------------------------------------
// Checkin request — the most important wire format to get right
// ---------------------------------------------------------------------------

TEST(BridgeClientProtocolTest, CheckinRequest_HasAllRequiredFields) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true,"symbols_written":2,"comments_written":1})");

    BridgeClient client; connectTo(client, server);

    Json syms = Json::array();
    syms.push_back({{"key", 42},   {"name", "renamed_func"}});
    syms.push_back({{"key", 99},   {"name", "helper_func"}});

    Json comms = Json::array();
    comms.push_back({{"va", "0x401000"}, {"eol", "important note"},
                     {"key", "0x200000001000"}});

    Json req = {
        {"op",      "checkin"},
        {"repo",    "myrepo"},
        {"folder",  "/binaries"},
        {"item",    "ls"},
        {"comment", "BN sync"},
        {"symbols",  syms},
        {"comments", comms}
    };

    Json resp = client.sendSync(req, 3000);
    server.join();

    // Verify the response is parsed correctly
    EXPECT_TRUE(resp.value("ok", false));
    EXPECT_EQ(resp.value("symbols_written",  -1), 2);
    EXPECT_EQ(resp.value("comments_written", -1), 1);

    // Verify the wire JSON has correct structure
    Json wire = Json::parse(server.lastRequest);
    EXPECT_EQ(wire["op"],          "checkin");
    EXPECT_EQ(wire["repo"],        "myrepo");
    EXPECT_EQ(wire["folder"],      "/binaries");
    EXPECT_EQ(wire["item"],        "ls");
    EXPECT_EQ(wire["comment"],     "BN sync");

    ASSERT_EQ(wire["symbols"].size(), 2u);
    EXPECT_EQ(wire["symbols"][0]["key"],  42);
    EXPECT_EQ(wire["symbols"][0]["name"], "renamed_func");
    EXPECT_EQ(wire["symbols"][1]["key"],  99);
    EXPECT_EQ(wire["symbols"][1]["name"], "helper_func");

    ASSERT_EQ(wire["comments"].size(), 1u);
    EXPECT_EQ(wire["comments"][0]["va"],  "0x401000");
    EXPECT_EQ(wire["comments"][0]["eol"], "important note");
    EXPECT_EQ(wire["comments"][0]["key"], "0x200000001000");
}

TEST(BridgeClientProtocolTest, CheckinRequest_EmptyArraysAreValid) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true,"symbols_written":0,"comments_written":0})");

    BridgeClient client; connectTo(client, server);
    Json req = {
        {"op", "checkin"}, {"repo", "r"}, {"folder", "/"}, {"item", "i"},
        {"comment", ""}, {"symbols", Json::array()}, {"comments", Json::array()}
    };
    Json resp = client.sendSync(req, 3000);
    server.join();

    EXPECT_TRUE(resp.value("ok", false));

    Json wire = Json::parse(server.lastRequest);
    EXPECT_EQ(wire["symbols"].size(),  0u);
    EXPECT_EQ(wire["comments"].size(), 0u);
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

TEST(BridgeClientProtocolTest, SendSync_ReturnsParsedResponse) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":true,"data":"hello"})");

    BridgeClient client; connectTo(client, server);
    Json resp = client.sendSync({{"op","test"}}, 3000);
    server.join();

    EXPECT_TRUE(resp.value("ok", false));
    EXPECT_EQ(resp.value("data", std::string{}), "hello");
}

TEST(BridgeClientProtocolTest, SendSync_ErrorResponse_ReturnedAsIs) {
    MiniServer server;
    server.serveOne(R"({"id":1,"ok":false,"error":"item not found"})");

    BridgeClient client; connectTo(client, server);
    Json resp = client.sendSync({{"op","openRepo"},{"repo","missing"}}, 3000);
    server.join();

    EXPECT_FALSE(resp.value("ok", true));
    EXPECT_EQ(resp.value("error", std::string{}), "item not found");
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

TEST(BridgeClientProtocolTest, SendSync_ThrowsOnTimeout) {
    // Open a raw listening socket that accepts but never sends a response.
    socket_t listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(listenFd, INVALID_SOCK);
    int opt = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = 0;
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listenFd, 1), 0);

    socklen_t len = sizeof(addr);
    ::getsockname(listenFd, reinterpret_cast<sockaddr*>(&addr), &len);
    int silentPort = ntohs(addr.sin_port);

    // Accept thread: receives the request but never replies.
    std::thread silentServer([listenFd]() {
        socket_t client = ::accept(listenFd, nullptr, nullptr);
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        if (client != INVALID_SOCK) CLOSE_SOCK(client);
    });

    BridgeClient client;
    std::string err;
    ASSERT_TRUE(client.connect("127.0.0.1", silentPort, err));

    EXPECT_THROW(client.sendSync({{"op","noop"}}, 200 /*ms*/),
                 std::runtime_error);

    CLOSE_SOCK(listenFd);
    silentServer.join();
}
