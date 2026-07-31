package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import db.DBRecord;
import db.RecordIterator;
import db.Table;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for function parameters.  The headline regression here is
 * {@link #noParameterSymbol_endsUpAtRamAddress()} — we make sure no PARAMETER
 * (type=6) or LOCAL_VAR (type=7) symbol ever ends up with an address column
 * outside Ghidra's VARIABLE space.  That was the corruption mode that caused
 * "Address is not a VariableAddress: 100000960" when Ghidra later tried to
 * load the function's variables.
 */
class ParametersRoundTripTest extends ProgramTestBase {

    private long mkFunc(ProgramDB p, long va, String name) {
        final long[] holder = new long[1];
        withTx(p, "mkfunc", () -> {
            try {
                Function fn = builder().createEmptyFunction(name,
                    "0x" + Long.toHexString(va), 1, IntegerDataType.dataType);
                holder[0] = fn.getID();
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        return holder[0];
    }

    @Test
    @DisplayName("import: rename existing parameter by symbol key")
    @SuppressWarnings("deprecation") // Function.addParameter — see ProgramApplier.applyParameters
    void renameParam_byKey() throws Exception {
        ProgramDB p = newProgram();
        long fva = memoryStart() + 0x100;
        long fkey = mkFunc(p, fva, "myfunc");

        // Add a parameter via the high-level API
        final long[] paramKey = new long[1];
        withTx(p, "add param", () -> {
            try {
                Function fn = p.getFunctionManager().getFunction(fkey);
                Parameter param = new ParameterImpl("orig", IntegerDataType.dataType, p);
                Parameter added = fn.addParameter(param, SourceType.USER_DEFINED);
                paramKey[0] = added.getSymbol().getID();
            } catch (Exception e) { throw new RuntimeException(e); }
        });

        // Rename via JSON {key, name}
        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("key", paramKey[0]);
        c.addProperty("name", "renamed");
        arr.add(c);
        withTx(p, "rename param", () -> ProgramApplier.applyParameters(p, arr));

        Function fn = p.getFunctionManager().getFunction(fkey);
        Parameter[] params = fn.getParameters();
        assertEquals(1, params.length);
        assertEquals("renamed", params[0].getName());
    }

    @Test
    @DisplayName("import: add a new parameter by func_va+ordinal")
    void addParam_byFuncVaOrdinal() throws Exception {
        ProgramDB p = newProgram();
        long fva = memoryStart() + 0x200;
        mkFunc(p, fva, "anotherfunc");

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("name", "added");
        c.addProperty("func_va", "0x" + Long.toHexString(fva));
        c.addProperty("ordinal", 0);
        c.addProperty("type_name", "int");
        c.addProperty("is_local", false);
        arr.add(c);
        withTx(p, "add param", () -> ProgramApplier.applyParameters(p, arr));

        Function fn = p.getFunctionManager().getFunctionAt(addr(p, fva));
        assertNotNull(fn);
        Parameter[] params = fn.getParameters();
        assertTrue(params.length >= 1, "expected at least 1 parameter, got " + params.length);
        // Find a parameter named "added"
        boolean found = false;
        for (Parameter prm : params) if ("added".equals(prm.getName())) { found = true; break; }
        assertTrue(found, "newly-added parameter not found");
    }

    /**
     * REGRESSION: after applyParameters runs, no symbol of type=6 (PARAMETER) or
     * type=7 (LOCAL_VAR) in the raw Symbols table may have its address column
     * point outside Ghidra's VARIABLE address space.  That's what caused the
     * "Address is not a VariableAddress" crash in prior versions of the bridge.
     */
    @Test
    @DisplayName("regression: no PARAMETER/LOCAL_VAR symbol has RAM-space address")
    void noParameterSymbol_endsUpAtRamAddress() throws Exception {
        ProgramDB p = newProgram();
        long fva = memoryStart() + 0x300;
        mkFunc(p, fva, "f");

        JsonArray arr = new JsonArray();
        for (int i = 0; i < 3; i++) {
            JsonObject c = new JsonObject();
            c.addProperty("name", "arg" + i);
            c.addProperty("func_va", "0x" + Long.toHexString(fva));
            c.addProperty("ordinal", i);
            c.addProperty("type_name", "int");
            c.addProperty("is_local", false);
            arr.add(c);
        }
        withTx(p, "params", () -> ProgramApplier.applyParameters(p, arr));

        // Scan the raw Symbols table for any type=6/7 record whose address
        // decodes to a non-variable space.
        Table symTable = p.getDBHandle().getTable("Symbols");
        assertNotNull(symTable);
        RecordIterator it = symTable.iterator();
        int badCount = 0;
        while (it.hasNext()) {
            DBRecord r = it.next();
            byte type;
            try { type = r.getByteValue(3); }
            catch (Exception e) { continue; }
            if (type != 6 && type != 7) continue;
            long encAddr;
            try { encAddr = r.getLongValue(1); }
            catch (Exception e) { ++badCount; continue; }
            try {
                ghidra.program.model.address.Address a =
                    p.getAddressMap().decodeAddress(encAddr);
                if (a == null || !a.isVariableAddress()) {
                    ++badCount;
                    System.err.println("BAD: symbol type=" + type + " encAddr=0x"
                        + Long.toHexString(encAddr) + " decoded=" + a);
                }
            } catch (Exception e) {
                ++badCount;
            }
        }
        assertEquals(0, badCount,
            "found " + badCount + " PARAMETER/LOCAL_VAR symbols with non-variable addresses");
    }
}
