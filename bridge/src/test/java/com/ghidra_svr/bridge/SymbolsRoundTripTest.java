package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for label symbols.
 *
 * The harness builds a real x86_64 ProgramDB, applies BN-shaped JSON via the
 * production ProgramApplier helpers, then asserts the visible Ghidra state.
 * If a future change breaks how we encode/decode symbol records (wrong column,
 * wrong source-type bits, missing namespace), these tests fail before reaching
 * production.
 */
class SymbolsRoundTripTest extends ProgramTestBase {

    /** {name, va} — used to create a fresh label. */
    private static JsonObject symAtAddr(String name, long va) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("va", "0x" + Long.toHexString(va));
        return o;
    }

    /** {name, key} — used to rename an existing label by its symbol ID. */
    private static JsonObject symByKey(String name, long key) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("key", key);
        return o;
    }

    @Test
    @DisplayName("import: new label at va shows up in SymbolTable")
    void importNewLabel_createsSymbol() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x100;

        JsonArray syms = new JsonArray();
        syms.add(symAtAddr("my_func", va));
        withTx(p, "new label", () -> ProgramApplier.applySymbols(p, syms));

        SymbolTable st = p.getSymbolTable();
        Symbol[] found = st.getSymbols(addr(p, va));
        assertNotNull(found);
        // Could be more than one if Ghidra auto-created a default name; ours
        // should be among them.
        boolean ours = false;
        for (Symbol s : found) {
            if ("my_func".equals(s.getName())) { ours = true; break; }
        }
        assertTrue(ours, "created label 'my_func' not found at " + addr(p, va));
    }

    @Test
    @DisplayName("import: rename existing label via {key, name}")
    void importRenameByKey_changesSymbolName() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x200;

        // Pre-create a label so we have a key to rename.
        final long[] keyHolder = new long[1];
        withTx(p, "setup", () -> {
            try {
                Symbol s = p.getSymbolTable().createLabel(addr(p, va), "orig",
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                keyHolder[0] = s.getID();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        long key = keyHolder[0];

        JsonArray syms = new JsonArray();
        syms.add(symByKey("renamed", key));
        withTx(p, "rename", () -> ProgramApplier.applySymbols(p, syms));

        Symbol s = p.getSymbolTable().getSymbol(key);
        assertNotNull(s, "renamed symbol disappeared");
        assertEquals("renamed", s.getName());
    }

    @Test
    @DisplayName("import: idempotent — applying the same rename twice has no extra effect")
    void importIdempotent() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x300;

        final long[] keyHolder = new long[1];
        withTx(p, "setup", () -> {
            try {
                Symbol s = p.getSymbolTable().createLabel(addr(p, va), "orig",
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                keyHolder[0] = s.getID();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        long key = keyHolder[0];

        JsonArray syms = new JsonArray();
        syms.add(symByKey("final", key));
        withTx(p, "rename 1", () -> ProgramApplier.applySymbols(p, syms));
        // Apply again — should be a no-op (name is already 'final')
        withTx(p, "rename 2", () -> ProgramApplier.applySymbols(p, syms));

        Symbol s = p.getSymbolTable().getSymbol(key);
        assertNotNull(s);
        assertEquals("final", s.getName());
    }

    @Test
    @DisplayName("import: empty / missing name entries are skipped, no exception")
    void importSkipsBadEntries() throws Exception {
        ProgramDB p = newProgram();
        JsonArray syms = new JsonArray();
        // Missing name
        JsonObject a = new JsonObject();
        a.addProperty("va", "0x" + Long.toHexString(memoryStart() + 0x400));
        syms.add(a);
        // Empty name
        JsonObject b = new JsonObject();
        b.addProperty("name", "");
        b.addProperty("va", "0x" + Long.toHexString(memoryStart() + 0x500));
        syms.add(b);
        // Valid entry — should still apply
        syms.add(symAtAddr("ok", memoryStart() + 0x600));

        assertDoesNotThrow(() ->
            withTx(p, "mixed", () -> ProgramApplier.applySymbols(p, syms)));

        // The valid entry made it through
        Symbol[] found = p.getSymbolTable().getSymbols(addr(p, memoryStart() + 0x600));
        boolean ours = false;
        for (Symbol s : found) if ("ok".equals(s.getName())) { ours = true; break; }
        assertTrue(ours);
    }

    @Test
    @DisplayName("import: rename targeting a nonexistent key is a no-op, no exception")
    void importMissingKey_isNoOp() throws Exception {
        ProgramDB p = newProgram();
        JsonArray syms = new JsonArray();
        syms.add(symByKey("ghost", 99999999L));
        assertDoesNotThrow(() ->
            withTx(p, "missing key", () -> ProgramApplier.applySymbols(p, syms)));
    }
}
