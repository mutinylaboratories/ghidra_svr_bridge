package com.ghidra_svr.bridge;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Entry point.  Runs on the Ghidra server machine as a persistent service:
 *
 *   java -cp "ghidra-bridge-0.1.0.jar:<ghidra-jars>/*"
 *        com.ghidra_svr.bridge.BridgeMain
 *        [--port <N>] [--bind-all] [--trust-all] [--ghidra-home <path>]
 *
 * By default binds to 127.0.0.1 only.  Pass --bind-all to listen on all
 * interfaces so Binary Ninja can connect from another machine.
 *
 * Writes "READY port=<N>" to stdout once the server socket is bound.
 */
public class BridgeMain {

    public static void main(String[] args) throws Exception {
        int     port       = 13200;
        boolean trustAll   = false;
        boolean bindAll    = false;
        String  ghidraHome = "";

        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--trust-all".equals(args[i])) {
                trustAll = true;
            } else if ("--bind-all".equals(args[i])) {
                bindAll = true;
            } else if ("--ghidra-home".equals(args[i]) && i + 1 < args.length) {
                ghidraHome = args[++i];
            }
        }

        if (trustAll) {
            installTrustAllContext();
            System.err.println("[ghidra-bridge] WARNING: SSL certificate validation disabled");
        }

        // Initialize Ghidra's UniversalIdGenerator so that DBHandle.initDatabaseId()
        // doesn't print "nextID called before UniversalIdGenerator initialized!" when
        // we create the empty change-set DBHandle during db.save().
        ghidra.util.UniversalIdGenerator.initialize();

        if (!ghidraHome.isEmpty())
            System.err.println("[ghidra-bridge] ghidraHome=" + ghidraHome);

        // Initialize Ghidra's Application framework so ProgramDB / DataTypeManager /
        // SymbolTable / FunctionManager are usable for checkin writes.  Without this
        // initialization, opening a buffer file as a ProgramDB throws because the
        // language services (processor specs, compiler specs) are not loaded.
        //
        // We pass the Ghidra installation directory via --ghidra-home so the
        // GhidraApplicationLayout can find the Processors/* modules at runtime.
        //
        // Initialization is best-effort: if it fails (e.g. ghidraHome is missing or
        // the install is incompatible), the bridge continues to work for read-only
        // operations.  Checkin will then throw at the ProgramDB construction step
        // with a clearer error than a NullPointerException deep inside Ghidra.
        if (!ghidraHome.isEmpty()) {
            try {
                long t0 = System.currentTimeMillis();
                ghidra.GhidraApplicationLayout layout =
                    new ghidra.GhidraApplicationLayout(new java.io.File(ghidraHome));
                ghidra.framework.HeadlessGhidraApplicationConfiguration config =
                    new ghidra.framework.HeadlessGhidraApplicationConfiguration();
                config.setInitializeLogging(false);
                ghidra.framework.Application.initializeApplication(layout, config);
                System.err.println("[ghidra-bridge] Ghidra Application initialized in "
                    + (System.currentTimeMillis() - t0) + " ms");
            } catch (Throwable t) {
                System.err.println("[ghidra-bridge] WARNING: Application init failed — "
                    + "checkin write operations will be unavailable. " + t.getMessage());
                t.printStackTrace(System.err);
            }
        } else {
            System.err.println("[ghidra-bridge] WARNING: no --ghidra-home; Application "
                + "framework not initialized — checkin writes will fail.");
        }

        System.err.println("[ghidra-bridge] starting on port " + port +
                           (bindAll ? " (all interfaces)" : " (loopback only)"));
        new BridgeServer(port, ghidraHome, bindAll).serve();
    }

    /** Installs a no-op TrustManager so the bridge accepts any server certificate.
     *  Use only on trusted internal networks or for development. */
    // Package-visible: LiveServerE2ETest reuses this against its self-signed test server.
    static void installTrustAllContext() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAll, new java.security.SecureRandom());
        SSLContext.setDefault(sc);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
}
