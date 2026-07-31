package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import db.buffers.ManagedBufferFileHandle;
import ghidra.framework.remote.RepositoryHandle;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tier-4: live Ghidra-server end-to-end test.
 *
 * Boots a real ghidraSvr (GhidraServer class launched directly from the
 * GHIDRA_HOME jars) against a temp repository root, seeds the parity fixture
 * binary via analyzeHeadless, then drives the production RMI path in-process:
 * GhidraSession.connect → checkout → DatabaseExporter.export(remote handle) →
 * DatabaseImporter.apply (the real opCheckin write path) → re-export the new
 * version and verify the data round-tripped through the server.
 *
 * Gated: only runs with GHIDRA_E2E=1 (test.bat --e2e). Environmental setup
 * failures abort via assumptions rather than failing the build.
 */
@Tag("e2e")
@EnabledIfEnvironmentVariable(named = "GHIDRA_E2E", matches = "1")
class LiveServerE2ETest extends ProgramTestBase {

    // analyzeHeadless authenticates as the OS user regardless of -connect, so
    // the test server provisions exactly that account.
    private static final String USER = System.getProperty("user.name");
    private static final String PASSWORD = "changeme"; // Ghidra server default
    private static final String REPO = "e2erepo";
    private static final String ITEM = "parity_x64.bin";
    private static final long   BASE = 0x400000L;

    private static Path serverRoot;
    private static Path headlessProjectDir;
    private static Process serverProcess;
    private static int basePort;
    private static GhidraSession session;

    @BeforeAll
    static void startServerAndSeed() throws Exception {
        String ghidraHome = System.getProperty("ghidra.home",
            System.getenv().getOrDefault("GHIDRA_HOME", ""));
        assumeTrue(!ghidraHome.isEmpty() && new File(ghidraHome).isDirectory(),
            "ghidra.home not set");

        serverRoot = Files.createTempDirectory("ghidra-e2e-repos");
        headlessProjectDir = Files.createTempDirectory("ghidra-e2e-proj");
        basePort = findFreePortTriple();

        // --- launch GhidraServer directly from the install's jars -----------
        String javaExe = System.getProperty("java.home") + File.separator + "bin"
            + File.separator + "java" + (isWindows() ? ".exe" : "");
        String classpath = buildServerClasspath(ghidraHome);
        List<String> cmd = new ArrayList<>(List.of(
            javaExe, "-cp", classpath,
            "ghidra.server.remote.GhidraServer",
            "-ip", "127.0.0.1",
            "-p" + basePort,
            "-a0",
            "-e0",
            serverRoot.toAbsolutePath().toString()));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        pb.redirectOutput(serverRoot.resolve("server.log").toFile());
        serverProcess = pb.start();

        assumeTrue(waitForPort("127.0.0.1", basePort, 90_000),
            "ghidraSvr did not open port " + basePort + " — see " +
            serverRoot.resolve("server.log"));

        // --- add a user via the server's admin command queue (svrAdmin path) --
        Path adminDir = serverRoot.resolve("~admin");
        for (int i = 0; i < 100 && !Files.isDirectory(adminDir); i++) Thread.sleep(200);
        assumeTrue(Files.isDirectory(adminDir), "server admin queue dir never appeared");
        Path tmpCmd = adminDir.resolve("e2e.tmp");
        Files.writeString(tmpCmd, "-add \"" + USER + "\"\n");
        Files.move(tmpCmd, adminDir.resolve("e2e.cmd"));
        // The server polls the queue; wait for the user to land in its users file.
        Path usersFile = serverRoot.resolve("users");
        boolean userAdded = false;
        for (int i = 0; i < 150 && !userAdded; i++) {
            Thread.sleep(200);
            userAdded = Files.exists(usersFile) &&
                        Files.readString(usersFile).contains(USER);
        }
        assumeTrue(userAdded, "user was not provisioned via admin command queue");

        // --- connect (self-signed cert) and create the repository -------------
        BridgeMain.installTrustAllContext();
        session = new GhidraSession();
        session.connect("127.0.0.1", basePort, USER, PASSWORD);
        session.serverHandle().createRepository(REPO);

        // --- seed the fixture binary via analyzeHeadless ------------------------
        Path fixtureBin = Path.of(System.getProperty("parity.fixtures"))
            .getParent().resolve("bin").resolve("parity_x64.bin");
        assumeTrue(Files.exists(fixtureBin), "fixture binary missing: " + fixtureBin);

        String headless = ghidraHome + File.separator + "support" + File.separator
            + (isWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
        List<String> seed = new ArrayList<>(List.of(
            headless,
            "ghidra://127.0.0.1:" + basePort + "/" + REPO,
            "-import", fixtureBin.toAbsolutePath().toString(),
            "-processor", "x86:LE:64:default",
            "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x" + Long.toHexString(BASE),
            "-noanalysis",
            "-commit", "e2e seed",
            "-p"));
        ProcessBuilder spb = new ProcessBuilder(seed);
        spb.redirectErrorStream(true);
        spb.redirectOutput(serverRoot.resolve("headless.log").toFile());
        Process sp = spb.start();
        sp.getOutputStream().write((PASSWORD + "\n").getBytes());
        sp.getOutputStream().flush();
        sp.getOutputStream().close();
        boolean done = sp.waitFor(5, TimeUnit.MINUTES);
        if (!done) sp.destroyForcibly();
        assumeTrue(done && sp.exitValue() == 0,
            "analyzeHeadless seed failed — see " + serverRoot.resolve("headless.log"));

        session.openRepo(REPO);
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (session != null) {
            try { session.disconnect(); } catch (Exception ignored) {}
        }
        if (serverProcess != null) {
            serverProcess.descendants().forEach(ProcessHandle::destroyForcibly);
            serverProcess.destroyForcibly();
            serverProcess.waitFor(30, TimeUnit.SECONDS);
        }
        for (Path dir : new Path[] {serverRoot, headlessProjectDir}) {
            if (dir == null) continue;
            try (Stream<Path> walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder())
                    .forEach(pth -> pth.toFile().delete());
            } catch (IOException ignored) {}
        }
    }

    // -----------------------------------------------------------------------

    @Test
    @DisplayName("e2e: checkout → export → checkin → re-export round-trips through a live server")
    void checkinRoundTrip_throughLiveServer() throws Exception {
        RepositoryHandle repo = session.getRepo(REPO);

        // --- export the seeded (empty-analysis) program -------------------------
        ManagedBufferFileHandle readHandle = repo.openDatabase("/", ITEM, -1, -1);
        JsonObject before = DatabaseExporter.export(readHandle);
        assertNotNull(before);
        assertTrue(before.has("image_base"), "export missing image_base");
        // The loader base hint is not reliably honored across Ghidra versions;
        // the parity check is base-agnostic, so work relative to whatever base
        // the seeded program actually got.
        long base = Long.parseUnsignedLong(
            before.get("image_base").getAsString().substring(2), 16);
        System.err.println("[e2e] seeded memory blocks: " + before.get("memory_blocks"));

        // --- build a checkin payload (fresh objects; the seed has none) -----------
        JsonObject payload = new JsonObject();
        JsonArray symbols = new JsonArray();
        JsonObject sym = new JsonObject();
        sym.addProperty("va", "0x" + Long.toHexString(base));
        sym.addProperty("name", "e2e_entry");
        sym.addProperty("sym_type", 0);
        symbols.add(sym);
        payload.add("symbols", symbols);

        JsonArray comments = new JsonArray();
        JsonObject cm = new JsonObject();
        cm.addProperty("va", "0x" + Long.toHexString(base + 0x10));
        cm.addProperty("eol", "e2e comment");
        comments.add(cm);
        payload.add("comments", comments);

        JsonArray typeChanges = new JsonArray();
        JsonObject st = new JsonObject();
        st.addProperty("op", "add");
        st.addProperty("kind", "struct");
        st.addProperty("name", "E2EPoint");
        st.addProperty("size", 8);
        JsonArray members = new JsonArray();
        members.add(member("x", 0));
        members.add(member("y", 4));
        st.add("members", members);
        typeChanges.add(st);
        payload.add("data_type_changes", typeChanges);

        JsonArray items = new JsonArray();
        JsonObject item = new JsonObject();
        item.addProperty("op", "add");
        item.addProperty("addr", "0x" + Long.toHexString(base + 0x100));
        item.addProperty("type_name", "E2EPoint");
        items.add(item);
        payload.add("data_item_changes", items);

        JsonArray bookmarks = new JsonArray();
        JsonObject bm = new JsonObject();
        bm.addProperty("op", "add");
        bm.addProperty("type", "Note");
        bm.addProperty("addr", "0x" + Long.toHexString(base + 0x120));
        bm.addProperty("category", "e2e");
        bm.addProperty("comment", "round trip");
        bookmarks.add(bm);
        payload.add("bookmark_changes", bookmarks);

        JsonArray empty = new JsonArray();

        // --- the real checkin write path (mirrors BridgeConnection.opCheckin) -----
        ItemCheckoutStatus co = repo.checkout("/", ITEM, CheckoutType.EXCLUSIVE,
            ItemCheckoutStatus.getProjectPath("binja-ghidra-e2e", false));
        assertNotNull(co, "exclusive checkout failed");
        long coId = co.getCheckoutId();
        try {
            ManagedBufferFileHandle writeHandle = repo.openDatabase("/", ITEM, coId);
            DatabaseImporter.apply(writeHandle, symbols, comments,
                empty, empty, bookmarks, empty,
                typeChanges, items, empty, "e2e checkin");
            Version[] versions = repo.getVersions("/", ITEM);
            assertTrue(versions.length >= 2, "checkin did not create a new version");
            repo.updateCheckoutVersion("/", ITEM, coId,
                versions[versions.length - 1].getVersion());
        } finally {
            try { repo.terminateCheckout("/", ITEM, coId, true); } catch (Exception ignored) {}
        }

        // --- re-export the new version and verify the data is stored ---------------
        ManagedBufferFileHandle afterHandle = repo.openDatabase("/", ITEM, -1, -1);
        JsonObject after = DatabaseExporter.export(afterHandle);

        JsonObject expected = new JsonObject();
        expected.add("symbols", jsonArrayOf(obj(o -> {
            o.addProperty("key", 0); // identity — resolved per document
            o.addProperty("name", "e2e_entry");
            o.addProperty("addr", "0x" + Long.toHexString(base));
            o.addProperty("type", 0);
        })));
        expected.add("comments", jsonArrayOf(obj(o -> {
            o.addProperty("addr", "0x" + Long.toHexString(base + 0x10));
            o.addProperty("eol", "e2e comment");
        })));
        expected.add("bookmarks", jsonArrayOf(obj(o -> {
            o.addProperty("type", "Note");
            o.addProperty("addr", "0x" + Long.toHexString(base + 0x120));
            o.addProperty("category", "e2e");
            o.addProperty("comment", "round trip");
        })));
        expected.add("data_types", jsonArrayOf(obj(o -> {
            o.addProperty("id", 0);
            o.addProperty("kind", "struct");
            o.addProperty("name", "E2EPoint");
            o.addProperty("size", 8);
            JsonArray ms = new JsonArray();
            ms.add(member("x", 0));
            ms.add(member("y", 4));
            o.add("members", ms);
        })));
        expected.add("data_items", jsonArrayOf(obj(o -> {
            o.addProperty("addr", "0x" + Long.toHexString(base + 0x100));
            o.addProperty("type_name", "E2EPoint");
        })));

        List<String> issues = CanonicalAssert.compare(expected, after);
        assertTrue(issues.isEmpty(),
            "live-server parity issues:\n  " + String.join("\n  ", issues));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static JsonObject member(String name, int offset) {
        JsonObject m = new JsonObject();
        m.addProperty("name", name);
        m.addProperty("offset", offset);
        m.addProperty("size", 4);
        m.addProperty("type_name", "int32_t");
        return m;
    }

    private static JsonObject obj(java.util.function.Consumer<JsonObject> fill) {
        JsonObject o = new JsonObject();
        fill.accept(o);
        return o;
    }

    private static JsonArray jsonArrayOf(JsonObject o) {
        JsonArray a = new JsonArray();
        a.add(o);
        return a;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static int findFreePortTriple() throws IOException {
        // Ghidra server uses basePort..basePort+2 (registry, RMI, block stream).
        for (int attempt = 0; attempt < 50; attempt++) {
            int candidate = 15_000 + (int) (Math.random() * 10_000);
            if (portsFree(candidate, candidate + 1, candidate + 2)) return candidate;
        }
        throw new IOException("no free port triple found");
    }

    private static boolean portsFree(int... ports) {
        for (int port : ports) {
            try (java.net.ServerSocket s = new java.net.ServerSocket(port)) {
                s.setReuseAddress(true);
            } catch (IOException e) {
                return false;
            }
        }
        return true;
    }

    private static boolean waitForPort(String host, int port, int timeoutMs)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (serverProcess != null && !serverProcess.isAlive()) return false;
            try (Socket s = new Socket(host, port)) {
                return true;
            } catch (IOException e) {
                Thread.sleep(500);
            }
        }
        return false;
    }

    private static String buildServerClasspath(String ghidraHome) throws IOException {
        List<String> jars = new ArrayList<>();
        for (String sub : new String[] {
                "Ghidra" + File.separator + "Framework",
                "Ghidra" + File.separator + "Features" + File.separator + "GhidraServer"}) {
            Path base = Path.of(ghidraHome, sub);
            if (!Files.isDirectory(base)) continue;
            try (Stream<Path> walk = Files.walk(base)) {
                walk.filter(p -> p.toString().endsWith(".jar")
                              && p.getParent().getFileName().toString().equals("lib"))
                    .forEach(p -> jars.add(p.toAbsolutePath().toString()));
            }
        }
        return String.join(File.pathSeparator, jars);
    }
}
