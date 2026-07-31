package com.ghidra_svr.bridge;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.util.UniversalIdGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;

import java.io.File;
import java.io.IOException;

/**
 * Base class for round-trip tests that exercise DatabaseExporter / ProgramApplier
 * against a real in-memory ProgramDB built by Ghidra's own ProgramBuilder.
 *
 * Why ProgramDB instead of a raw DBHandle: the bugs we kept hitting in production
 * (cloneAllComponentSettings ArrayIndexOutOfBoundsException, StackPurge corruption,
 * IsVariableAddress crash) were all invariants enforced by ProgramDB and below.
 * Tests against a raw DBHandle don't enforce those invariants, so they pass on
 * code that would crash Ghidra.  These tests build a real Program, mutate it
 * exactly the way production does (via ProgramApplier), then ask Ghidra to load
 * the result the same way it would after a checkin.
 *
 * Application init runs once per JVM (BeforeAll on a PER_CLASS lifecycle).
 * Without it, ProgramBuilder's language services would fail to load.
 *
 * Each test method creates a fresh program via newProgram(); the builder is
 * disposed automatically by tearDown() / @AfterEach.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class ProgramTestBase {

    private static boolean appInitialized = false;

    /** Architecture identifier for the test program.  Override to test on a different
     *  ISA (e.g. ProgramBuilder._X64, _ARM, _AARCH64).  Default is x86_64. */
    protected String architecture() {
        return ProgramBuilder._X64;
    }

    /** Default memory range for tests.  Subclasses can override if they need larger.
     *  0x00400000 was chosen to match a typical PIE-disabled ELF load address. */
    protected long memoryStart() { return 0x00400000L; }
    protected int  memorySize()  { return 0x10000;     }

    private ProgramBuilder currentBuilder;

    @BeforeAll
    public void initializeGhidra() throws IOException {
        if (appInitialized) return;
        UniversalIdGenerator.initialize();
        String ghidraHome = System.getProperty("ghidra.home",
            System.getenv().getOrDefault("GHIDRA_HOME", ""));
        if (ghidraHome.isEmpty()) {
            // Fall back to the path used by the bridge in this repo.
            ghidraHome = System.getProperty("user.dir")
                + "/../ghidra/ghidra_12.0.4_PUBLIC";
        }
        File home = new File(ghidraHome);
        if (!home.isDirectory()) {
            throw new IOException("Ghidra installation not found at " + ghidraHome
                + " — set the ghidra.home system property or GHIDRA_HOME env var.");
        }
        GhidraApplicationLayout layout = new GhidraApplicationLayout(home);
        HeadlessGhidraApplicationConfiguration cfg =
            new HeadlessGhidraApplicationConfiguration();
        cfg.setInitializeLogging(false);
        Application.initializeApplication(layout, cfg);
        appInitialized = true;
    }

    /**
     * Create a fresh test program with a single RW memory block.  The test owns
     * the returned ProgramDB and must NOT dispose it manually — tearDown() does
     * that after each test method.
     */
    protected ProgramDB newProgram() throws Exception {
        currentBuilder = new ProgramBuilder("test", architecture());
        currentBuilder.createMemory(".text",
            "0x" + Long.toHexString(memoryStart()),
            memorySize(),
            "test memory");
        return currentBuilder.getProgram();
    }

    /** Convenience: build a Ghidra Address from a virtual address. */
    protected Address addr(ProgramDB p, long va) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(va);
    }

    /** The ProgramBuilder owned by the current test — use its helpers to
     *  populate the program (createEmptyFunction, createLabel, etc.). */
    protected ProgramBuilder builder() {
        return currentBuilder;
    }

    @AfterEach
    public void tearDown() {
        if (currentBuilder != null) {
            try { currentBuilder.dispose(); }
            catch (Exception ignored) {}
            currentBuilder = null;
        }
    }

    /** Run a Runnable inside a Ghidra program transaction. */
    protected void withTx(ProgramDB p, String name, Runnable r) {
        int tx = p.startTransaction(name);
        boolean ok = false;
        try {
            r.run();
            p.endTransaction(tx, true);
            ok = true;
        } finally {
            if (!ok) p.endTransaction(tx, false);
        }
    }
}
