package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for typed data items (defined data at a specific address).
 * The key invariant: after applyDataItems runs, Listing.getDataAt(addr) must
 * return a Data with the requested type.
 */
class DataItemsRoundTripTest extends ProgramTestBase {

    @Test
    @DisplayName("import add data item: creates Data of the requested type")
    void addDataItem_createsTypedData() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x100;

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("op", "add");
        c.addProperty("addr", "0x" + Long.toHexString(va));
        c.addProperty("type_name", "int");
        arr.add(c);
        withTx(p, "add data", () -> ProgramApplier.applyDataItems(p, arr));

        Data d = p.getListing().getDataAt(addr(p, va));
        assertNotNull(d, "no data item created");
        assertEquals("int", d.getDataType().getName());
    }

    @Test
    @DisplayName("import delete data item: clears Listing entry at addr")
    void deleteDataItem_clearsListing() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x200;

        withTx(p, "seed", () -> {
            Listing l = p.getListing();
            try { l.createData(addr(p, va), IntegerDataType.dataType); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        // Sanity-check seed worked
        assertNotNull(p.getListing().getDataAt(addr(p, va)));

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("op", "delete");
        c.addProperty("addr", "0x" + Long.toHexString(va));
        c.addProperty("type_name", "int");
        arr.add(c);
        withTx(p, "delete", () -> ProgramApplier.applyDataItems(p, arr));

        Data d = p.getListing().getDataAt(addr(p, va));
        // After delete, getDataAt returns Data with an undefined type (i.e.
        // listing is "cleared" — there is no defined data here).
        assertTrue(d == null || d.getDataType().getName().startsWith("undefined")
            || !d.isDefined(),
            "data item should be cleared, found: " + (d == null ? "null" : d.getDataType().getName()));
    }
}
