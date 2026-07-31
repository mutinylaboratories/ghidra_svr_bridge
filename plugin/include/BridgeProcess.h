#pragma once
#include <string>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <sys/types.h>
#  include <thread>
#endif

/**
 * Spawns the ghidra-bridge.jar Java process and reads its startup handshake.
 *
 * Startup sequence:
 *   1. Build classpath from bridge JAR + Ghidra Framework JARs.
 *   2. Launch: java -cp <cp> com.ghidra_svr.bridge.BridgeMain --port 0 [--trust-all]
 *   3. Read bridge stdout line-by-line until "READY port=<N>" is received.
 *   4. Store the bound port; the C++ plugin then connects on localhost:<N>.
 *
 * Bridge stderr is captured and forwarded to BN's log on all platforms.
 */
class BridgeProcess {
public:
    BridgeProcess() = default;
    ~BridgeProcess() { stop(); }

    BridgeProcess(const BridgeProcess&) = delete;
    BridgeProcess& operator=(const BridgeProcess&) = delete;

    /**
     * Launch the bridge process.
     *
     * @param javaExe     Path to java executable (empty = search PATH).
     * @param bridgeJar   Path to ghidra-bridge-*.jar.
     * @param ghidraHome  Path to Ghidra installation (for Framework JARs).
     * @param trustAll    Pass --trust-all to the bridge (skips SSL cert check).
     * @param errorOut    Receives a human-readable error message on failure.
     * @return true on success (bridge is listening and port is known).
     */
    bool start(const std::string& javaExe,
               const std::string& bridgeJar,
               const std::string& ghidraHome,
               bool trustAll,
               std::string& errorOut);

    /** Terminate the bridge process and release all handles. */
    void stop();

    /** TCP port the bridge is listening on, or -1 if not started. */
    int port() const { return m_port; }

    bool isRunning() const;

private:
    int m_port = -1;

#ifdef _WIN32
    PROCESS_INFORMATION m_pi = {};
    HANDLE m_hStdoutRead     = INVALID_HANDLE_VALUE;
    HANDLE m_hStderrRead     = INVALID_HANDLE_VALUE;
    HANDLE m_hStderrThread   = INVALID_HANDLE_VALUE;

    bool readReadyLine(std::string& errorOut);
    void startStderrLogger();
    static DWORD WINAPI stderrLoggerThread(LPVOID param);
    static std::string buildClasspath(const std::string& bridgeJar,
                                      const std::string& ghidraHome);
#else
    pid_t       m_pid          = -1;
    int         m_pipeFd       = -1;
    int         m_stderrFd     = -1;
    std::thread m_stderrThread;

    bool readReadyLine(std::string& errorOut);
    void startStderrLogger();
    static std::string buildClasspath(const std::string& bridgeJar,
                                      const std::string& ghidraHome);
#endif
};
