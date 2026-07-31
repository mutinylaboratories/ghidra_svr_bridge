package com.ghidra_svr.bridge;

import com.google.gson.*;
import db.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class EquatesTest {

    private static final Schema EQUATES_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE, LongField.INSTANCE},
        new String[]{"Name", "Value"});

    // For op_index: try ShortField first, fall back to IntField in the test body
    private static final Schema ADDRMAP_SCHEMA = new Schema(0, "RowKey",
        new Field[]{LongField.INSTANCE, LongField.INSTANCE},
        new String[]{"SpaceId", "BaseVA"});

    private DBHandle db;
    private static final long BASE_VA = 0x400000L;

    @BeforeEach void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Equates",           EQUATES_SCHEMA);
        db.createTable("ADDRESS MAP",       ADDRMAP_SCHEMA);
        // Equate References: col0=Long(eqId), col1=Long(addr), col2=Int(opIdx)
        Schema refSchema = new Schema(0, "Key",
            new Field[]{LongField.INSTANCE, LongField.INSTANCE, IntField.INSTANCE},
            new String[]{"EquateId","Address","OpIndex"});
        db.createTable("Equate References", refSchema);

        // ADDRESS MAP row 0: base VA = 0x400000
        Table am = db.getTable("ADDRESS MAP");
        DBRecord amRec = ADDRMAP_SCHEMA.createRecord(0L);
        amRec.setLongValue(1, BASE_VA);
        am.putRecord(amRec);

        db.endTransaction(tx, true);
    }

    @AfterEach void tearDown() { if (db != null) db.close(); }

    private void insertEquate(long id, String name, long value) throws IOException {
        long tx = db.startTransaction();
        DBRecord r = EQUATES_SCHEMA.createRecord(id);
        r.setString(0, name); r.setLongValue(1, value);
        db.getTable("Equates").putRecord(r);
        db.endTransaction(tx, true);
    }

    private void insertRef(long refId, long eqId, long encodedAddr, int opIdx) throws IOException {
        long tx = db.startTransaction();
        Schema s = db.getTable("Equate References").getSchema();
        DBRecord r = s.createRecord(refId);
        r.setLongValue(0, eqId); r.setLongValue(1, encodedAddr); r.setIntValue(2, opIdx);
        db.getTable("Equate References").putRecord(r);
        db.endTransaction(tx, true);
    }

    @Test void exportEquates_appearsWithCorrectFields() throws IOException {
        insertEquate(1L, "ENOENT", 2L);
        // encode VA 0x401000: segKey=0, offset=0x1000 → encoded=0x1000
        insertRef(10L, 1L, 0x1000L, 1);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray equates = out.getAsJsonArray("equates");
        assertEquals(1, equates.size());
        JsonObject eq = equates.get(0).getAsJsonObject();
        assertEquals("ENOENT", eq.get("name").getAsString());
        assertEquals(2L,       eq.get("value").getAsLong());
        assertEquals(1,        eq.getAsJsonArray("refs").size());
        assertEquals("0x401000", eq.getAsJsonArray("refs").get(0).getAsJsonObject().get("addr").getAsString());
        assertEquals(1,        eq.getAsJsonArray("refs").get(0).getAsJsonObject().get("op_index").getAsInt());
    }

    @Test void exportEquates_skipsEquatesWithNoDecodableRefs() throws IOException {
        insertEquate(1L, "GHOST", 99L);
        // No refs inserted → equate should not appear
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("equates").size());
    }

    @Test void renameEquate_appearsInExport() throws IOException {
        insertEquate(1L, "ENOENT", 2L);
        insertRef(10L, 1L, 0x1000L, 0);

        JsonArray renames = new JsonArray();
        JsonObject r = new JsonObject();
        r.addProperty("id", 1L); r.addProperty("name", "FILE_NOT_FOUND");
        renames.add(r);
        long tx = db.startTransaction();
        DatabaseImporter.applyEquateRenames(db, renames);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals("FILE_NOT_FOUND", out.getAsJsonArray("equates")
            .get(0).getAsJsonObject().get("name").getAsString());
    }

    @Test void renameEquate_skipsUnknownId() throws IOException {
        assertDoesNotThrow(() -> {
            JsonArray renames = new JsonArray();
            JsonObject r = new JsonObject(); r.addProperty("id", 999L); r.addProperty("name", "X");
            renames.add(r);
            long tx = db.startTransaction();
            DatabaseImporter.applyEquateRenames(db, renames);
            db.endTransaction(tx, true);
        });
    }

    @Test void emptyEquatesTable_returnsEmptyArray() throws IOException {
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("equates").size());
    }
}
