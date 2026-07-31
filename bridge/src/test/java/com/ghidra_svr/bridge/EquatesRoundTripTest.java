package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for equates.  The interesting case here is the rename path:
 * Ghidra has no in-place rename, so ProgramApplier removes the old equate and
 * creates a new one with the same value.  References must be re-attached or
 * they're lost — this test pins down that behavior.
 */
class EquatesRoundTripTest extends ProgramTestBase {

    @Test
    @DisplayName("import: equate rename preserves the underlying value and re-attaches refs")
    void renameEquate_preservesValueAndRefs() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x100;

        // Seed: create an equate FOO=42 with a reference at our test address
        final long[] keyHolder = new long[1];
        withTx(p, "seed", () -> {
            try {
                EquateTable et = p.getEquateTable();
                Equate eq = et.createEquate("FOO", 42);
                eq.addReference(addr(p, va), 0);
                // The raw DB key of the equate record is what we send from BN.
                // EquateManager doesn't expose it directly, so we look it up
                // via the underlying table.
                db.Table tbl = p.getDBHandle().getTable("Equates");
                db.RecordIterator it = tbl.iterator();
                while (it.hasNext()) {
                    db.DBRecord r = it.next();
                    if ("FOO".equals(r.getString(0))) {
                        keyHolder[0] = r.getKey();
                        break;
                    }
                }
            } catch (Exception e) { throw new RuntimeException(e); }
        });

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("id", keyHolder[0]);
        c.addProperty("name", "BAR");
        arr.add(c);
        withTx(p, "rename", () -> ProgramApplier.applyEquateRenames(p, arr));

        EquateTable et = p.getEquateTable();
        assertNull(et.getEquate("FOO"), "old equate name should be gone");
        Equate renamed = et.getEquate("BAR");
        assertNotNull(renamed, "new equate name should exist");
        assertEquals(42, renamed.getValue(), "value lost during rename");
        assertTrue(renamed.getReferenceCount() >= 1, "references lost during rename");
    }

    @Test
    @DisplayName("import: addReference attaches an existing equate to an instruction operand")
    void addEquateRef_attachesReference() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x200;

        final long[] keyHolder = new long[1];
        withTx(p, "seed", () -> {
            try {
                Equate eq = p.getEquateTable().createEquate("FLAG_ON", 1);
                db.Table tbl = p.getDBHandle().getTable("Equates");
                db.RecordIterator it = tbl.iterator();
                while (it.hasNext()) {
                    db.DBRecord r = it.next();
                    if ("FLAG_ON".equals(r.getString(0))) {
                        keyHolder[0] = r.getKey();
                        break;
                    }
                }
            } catch (Exception e) { throw new RuntimeException(e); }
        });

        JsonArray arr = new JsonArray();
        JsonObject ref = new JsonObject();
        ref.addProperty("id", keyHolder[0]);
        ref.addProperty("va", "0x" + Long.toHexString(va));
        ref.addProperty("op_index", 0);
        arr.add(ref);
        withTx(p, "addRef", () -> ProgramApplier.applyEquateRefAdds(p, arr));

        Equate eq = p.getEquateTable().getEquate("FLAG_ON");
        assertTrue(eq.getReferenceCount() >= 1,
            "reference was not attached to FLAG_ON");
    }
}
