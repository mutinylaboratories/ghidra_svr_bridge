package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for function signatures.  The flagship regression test in
 * this class is {@link #returnType_doesNotCorruptStackPurge()} — that is the
 * explicit check that we are NOT writing the return-type ID into the
 * StackPurge column.  The old raw-write code called
 * <code>rec.setLongValue(1, typeId)</code> on the Function Data table, and
 * because column 1 is an IntField, {@code IntField.setLongValue} silently
 * truncated the long to an int via {@code l2i} — corrupting StackPurge on
 * every modified function.
 */
class FunctionSignaturesRoundTripTest extends ProgramTestBase {

    private static JsonObject sigChange(long key, String retType, String cc) {
        JsonObject o = new JsonObject();
        o.addProperty("key", key);
        if (retType != null) o.addProperty("ret_type", retType);
        if (cc != null)      o.addProperty("cc", cc);
        return o;
    }

    /** Creates an empty function via ProgramBuilder and returns its key. */
    private long mkFunc(ProgramDB p, long va, String name) {
        final long[] keyHolder = new long[1];
        withTx(p, "mkfunc", () -> {
            try {
                Function fn = builder().createEmptyFunction(name,
                    "0x" + Long.toHexString(va), 1, IntegerDataType.dataType);
                keyHolder[0] = fn.getID();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        return keyHolder[0];
    }

    @Test
    @DisplayName("import: return type change updates Function.returnType")
    void returnType_isApplied() throws Exception {
        ProgramDB p = newProgram();
        long key = mkFunc(p, memoryStart() + 0x100, "f");

        JsonArray changes = new JsonArray();
        changes.add(sigChange(key, "int", null));
        withTx(p, "apply sig", () -> ProgramApplier.applyFuncSigs(p, changes));

        FunctionManager fm = p.getFunctionManager();
        Function fn = fm.getFunction(key);
        assertNotNull(fn);
        DataType rt = fn.getReturnType();
        assertNotNull(rt);
        assertEquals("int", rt.getName());
    }

    /**
     * REGRESSION: the raw-write code corrupted StackPurge by writing the
     * return-type ID into column 1 (IntField).  After a sig update, StackPurge
     * must equal whatever it was before — i.e. the function-default sentinel
     * (Integer.MAX_VALUE in V3 schema, "unknown purge").
     */
    @Test
    @DisplayName("regression: sig change must NOT corrupt StackPurge")
    void returnType_doesNotCorruptStackPurge() throws Exception {
        ProgramDB p = newProgram();
        long key = mkFunc(p, memoryStart() + 0x200, "g");

        Function fn = p.getFunctionManager().getFunction(key);
        int beforePurge = fn.getStackPurgeSize();

        JsonArray changes = new JsonArray();
        changes.add(sigChange(key, "int", null));
        withTx(p, "sig", () -> ProgramApplier.applyFuncSigs(p, changes));

        Function fn2 = p.getFunctionManager().getFunction(key);
        int afterPurge = fn2.getStackPurgeSize();

        // The key assertion: we did not accidentally write a data-type ID into
        // the StackPurge column.  Both values should equal the function-default
        // sentinel.  A corrupted value would be some random truncated typeId.
        assertEquals(beforePurge, afterPurge,
            "StackPurge changed across a return-type update — silent IntField truncation regression");
    }

    /**
     * REGRESSION: BN names calling conventions without the leading
     * double-underscore ("cdecl", "stdcall") while Ghidra's compiler specs
     * register "__cdecl"/"__stdcall".  setCallingConvention("cdecl") throws
     * and was silently swallowed, so the CC never landed in Ghidra and BN
     * re-queued the same change on every check-in.  The applier must retry
     * with the "__" prefix.
     */
    @Test
    @DisplayName("import: BN-style cc name without underscores maps to Ghidra's __-prefixed cc")
    void bnStyleCallingConvention_isPrefixMapped() throws Exception {
        ProgramDB p = newProgram();
        long key = mkFunc(p, memoryStart() + 0x400, "i");

        JsonArray changes = new JsonArray();
        changes.add(sigChange(key, null, "stdcall"));
        withTx(p, "cc", () -> ProgramApplier.applyFuncSigs(p, changes));

        Function fn = p.getFunctionManager().getFunction(key);
        assertNotNull(fn);
        assertEquals("__stdcall", fn.getCallingConventionName(),
            "BN's 'stdcall' should have been applied as Ghidra's '__stdcall'");
    }

    @Test
    @DisplayName("import: unknown calling convention is silently ignored, no exception")
    void unknownCallingConvention_isIgnored() throws Exception {
        ProgramDB p = newProgram();
        long key = mkFunc(p, memoryStart() + 0x300, "h");

        JsonArray changes = new JsonArray();
        changes.add(sigChange(key, null, "__totally_made_up"));
        assertDoesNotThrow(() ->
            withTx(p, "bad cc", () -> ProgramApplier.applyFuncSigs(p, changes)));

        // Ghidra 11+ would happily store the bogus name as a "custom"
        // convention; the applier must skip it instead.
        Function fn = p.getFunctionManager().getFunction(key);
        assertNotEquals("__totally_made_up", fn.getCallingConventionName(),
            "bogus CC name must not be stored as a custom convention");
    }
}
