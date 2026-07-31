package com.ghidra_svr.bridge;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Binds a TCP server socket and spawns a {@link BridgeConnection} thread for
 * each incoming client.
 *
 * When {@code bindAll} is false (default) the socket is bound to the loopback
 * address (127.0.0.1) — suitable for local testing.  When {@code bindAll} is
 * true the socket is bound to the wildcard address (0.0.0.0) so Binary Ninja
 * can connect from another machine on the network.
 *
 * Startup handshake:
 *   1. ServerSocket binds.
 *   2. Bridge prints "READY port=<N>" to stdout.
 *   3. Binary Ninja reads that line, connects on the reported port, and begins
 *      sending newline-delimited JSON requests.
 */
public class BridgeServer {

    private final int     requestedPort;
    private final String  ghidraHome;
    private final boolean bindAll;

    public BridgeServer(int requestedPort, String ghidraHome, boolean bindAll) {
        this.requestedPort = requestedPort;
        this.ghidraHome    = ghidraHome;
        this.bindAll       = bindAll;
    }

    public void serve() throws Exception {
        InetAddress bindAddr = bindAll
                ? InetAddress.getByName("0.0.0.0")
                : InetAddress.getLoopbackAddress();

        try (ServerSocket server = new ServerSocket(requestedPort, /*backlog*/ 8, bindAddr)) {
            server.setReuseAddress(true);
            int boundPort = server.getLocalPort();
            System.err.println("[ghidra-bridge] listening on " +
                               bindAddr.getHostAddress() + ":" + boundPort);

            // Signal startup complete.
            System.out.println("READY port=" + boundPort);
            System.out.flush();

            while (!Thread.currentThread().isInterrupted()) {
                Socket client = server.accept();
                client.setTcpNoDelay(true);
                System.err.println("[ghidra-bridge] client connected from " +
                                   client.getRemoteSocketAddress());
                Thread t = new Thread(new BridgeConnection(client, ghidraHome), "bridge-conn");
                t.setDaemon(true);
                t.start();
            }
        }
    }
}
