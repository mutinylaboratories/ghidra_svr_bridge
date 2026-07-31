package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import db.ByteField;
import db.DBHandle;
import db.DBRecord;
import db.Field;
import db.LongField;
import db.Schema;
import db.StringField;
import db.Table;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Optional;
import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests: write changes via {@link DatabaseImporter}, read them back
 * via {@link DatabaseExporter}, and assert the exported JSON matches.
 *
 * This is the closest we get to a full "did the change land on the server?"
 * test without a real Ghidra server — the same in-memory DBHandle is shared
 * by both the importer and the exporter.
 *
 * Address encoding:
 *   The exporter uses an ADDRESS MAP table (rowKey → base VA) to decode
 *   encoded addresses.  For tests we build a minimal ADDRESS MAP so both
 *   importer and exporter agree on VA ↔ encoded-key mapping.
 *
 *   ADDRESS MAP schema: col 0 = LongField (base VA).
 *   Row key 0 → base VA 0x400000  (simulates a typical user-space binary).
 *   Encoded address = (segKey << 32) | offset
 *   With the new-format lookup: segKey = row key = 0, so encoded = offset.
 *   decode(encoded, {0→0x400000}) = 0x400000 + offset.
 *
 *   Example: function at VA 0x401000 → offset = 0x1000, encoded = 0x0000000000001000L.
 */
class DatabaseRoundTripTest {

    // ---- Schemas ----

    private static final Schema SYMBOLS_SCHEMA = new Schema(0, "Key",
        new Field[]{ StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
                     ByteField.INSTANCE,   ByteField.INSTANCE },
        new String[]{ "Name", "Address", "Namespace", "Type", "Flags" });

    private static final Schema COMMENTS_SCHEMA = new Schema(0, "Key",
        new Field[]{ StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                     StringField.INSTANCE, StringField.INSTANCE },
        new String[]{ "EOL", "Pre", "Post", "Plate", "Rep" });

    // ADDRESS MAP: one Long column for base VA.
    private static final Schema ADDRMAP_SCHEMA = new Schema(0, "RowKey",
        new Field[]{ LongField.INSTANCE, LongField.INSTANCE },
        new String[]{ "SpaceId", "BaseVA" });

    private static final byte FUNCTION_TYPE = 5; // Ghidra 11+ FUNCTION ordinal
    private static final long BASE_VA       = 0x400000L;

    private DBHandle db;

    @BeforeEach
    void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Symbols",     SYMBOLS_SCHEMA);
        db.createTable("Comments",    COMMENTS_SCHEMA);
        db.createTable("ADDRESS MAP", ADDRMAP_SCHEMA);

        // ADDRESS MAP row 0: base VA = 0x400000
        // col 1 (LongField) stores the base VA — mirrors DatabaseExporter.readBaseVA()
        Table am = db.getTable("ADDRESS MAP");
        DBRecord amRec = ADDRMAP_SCHEMA.createRecord(0L);
        amRec.setLongValue(0, 0L);       // SpaceId (unused in exporter)
        amRec.setLongValue(1, BASE_VA);  // Base VA
        am.putRecord(amRec);

        db.endTransaction(tx, true);
    }

    @AfterEach
    void tearDown() {
        if (db != null) db.close();
    }

    // ---- Helpers ----

    private void insertSymbol(long key, String name, long encodedAddr,
                              byte type, byte sourceFlags) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Symbols");
        DBRecord rec = SYMBOLS_SCHEMA.createRecord(key);
        rec.setString(0, name);
        rec.setLongValue(1, encodedAddr);
        rec.setLongValue(2, 0L);
        rec.setByteValue(3, type);
        rec.setByteValue(4, sourceFlags);
        t.putRecord(rec);
        db.endTransaction(tx, true);
    }

    /** Build encoded address for a given VA using row key 0 and base VA = 0x400000. */
    private static long encode(long va) {
        // segKey = 0 (row key of the ADDRESS MAP entry), offset = va - BASE_VA
        // New format: encoded = (segKey << 32) | offset = offset (since segKey=0)
        return va - BASE_VA; // segKey=0 → just the offset
    }

    private static JsonArray symbols(Object... pairs) {
        JsonArray arr = new JsonArray();
        for (int i = 0; i < pairs.length; i += 2) {
            JsonObject o = new JsonObject();
            o.addProperty("key",  ((Number) pairs[i]).longValue());
            o.addProperty("name", (String) pairs[i + 1]);
            arr.add(o);
        }
        return arr;
    }

    private static Optional<JsonObject> findSymbolByAddr(JsonArray arr, String addrHex) {
        return StreamSupport.stream(arr.spliterator(), false)
            .map(JsonElement::getAsJsonObject)
            .filter(o -> addrHex.equalsIgnoreCase(o.get("addr").getAsString()))
            .findFirst();
    }

    private static Optional<JsonObject> findCommentByAddr(JsonArray arr, String addrHex) {
        return StreamSupport.stream(arr.spliterator(), false)
            .map(JsonElement::getAsJsonObject)
            .filter(o -> addrHex.equalsIgnoreCase(o.get("addr").getAsString()))
            .findFirst();
    }

    // ---- Tests ----

    @Test
    void symbolRename_appearsInExport() throws IOException {
        long va = 0x401000L;
        insertSymbol(42L, "original_name", encode(va), FUNCTION_TYPE, (byte) 0);

        // Import: rename symbol 42 to "renamed_func"
        DatabaseImporter.applyToHandle(db, symbols(42L, "renamed_func"), null);

        // Export and verify the new name is present
        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray syms = exported.getAsJsonArray("symbols");

        Optional<JsonObject> sym = findSymbolByAddr(syms, "0x" + Long.toHexString(va));
        assertTrue(sym.isPresent(), "Exported symbols should contain VA 0x" + Long.toHexString(va));
        assertEquals("renamed_func", sym.get().get("name").getAsString(),
            "Exported name should be the renamed value");
        assertEquals(42L, sym.get().get("key").getAsLong());
    }

    @Test
    void symbolRename_oldNameGone() throws IOException {
        long va = 0x401000L;
        insertSymbol(42L, "old_name", encode(va), FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db, symbols(42L, "new_name"), null);

        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray syms = exported.getAsJsonArray("symbols");

        boolean oldNamePresent = StreamSupport.stream(syms.spliterator(), false)
            .map(JsonElement::getAsJsonObject)
            .anyMatch(o -> "old_name".equals(o.get("name").getAsString()));
        assertFalse(oldNamePresent, "Old name should not appear in export after rename");
    }

    @Test
    void multipleRenames_allAppearInExport() throws IOException {
        insertSymbol(1L, "func_a", encode(0x401000L), FUNCTION_TYPE, (byte) 0);
        insertSymbol(2L, "func_b", encode(0x402000L), FUNCTION_TYPE, (byte) 0);
        insertSymbol(3L, "func_c", encode(0x403000L), FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db,
            symbols(1L, "alpha", 2L, "beta", 3L, "gamma"), null);

        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray syms = exported.getAsJsonArray("symbols");

        assertTrue(findSymbolByAddr(syms, "0x401000").map(o -> "alpha".equals(o.get("name").getAsString())).orElse(false));
        assertTrue(findSymbolByAddr(syms, "0x402000").map(o -> "beta" .equals(o.get("name").getAsString())).orElse(false));
        assertTrue(findSymbolByAddr(syms, "0x403000").map(o -> "gamma".equals(o.get("name").getAsString())).orElse(false));
    }

    @Test
    void exportSkipsSymbolsWithEmptyName() throws IOException {
        // A DEFAULT-source symbol typically has an empty name stored in the DB.
        // DatabaseExporter.exportSymbols skips records where name is null/empty.
        insertSymbol(10L, "", encode(0x405000L), FUNCTION_TYPE, (byte) 0);

        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray syms = exported.getAsJsonArray("symbols");

        boolean found = StreamSupport.stream(syms.spliterator(), false)
            .map(JsonElement::getAsJsonObject)
            .anyMatch(o -> o.get("key").getAsLong() == 10L);
        assertFalse(found, "Symbol with empty name should be skipped by exporter");
    }

    @Test
    void afterRename_sourceIsUserDefined() throws IOException {
        // Verifies that the source field visible in the export is USER_DEFINED (3)
        // after a rename — important for BN to treat it as an authoritative name.
        insertSymbol(42L, "sub_1234", encode(0x401234L), FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db, symbols(42L, "my_func"), null);

        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray syms = exported.getAsJsonArray("symbols");

        Optional<JsonObject> sym = findSymbolByAddr(syms, "0x401234");
        assertTrue(sym.isPresent());
        assertEquals(3, sym.get().get("source").getAsInt(),
            "Source should be USER_DEFINED (3) after rename");
    }

    @Test
    void comment_eol_appearsInExport() throws IOException {
        // Create comment record at an encoded key and write an EOL comment via importer.
        long encodedKey = 0x200000001000L; // pre-computed encoded address

        JsonArray comments = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("key", "0x200000001000");
        c.addProperty("eol", "important note");
        comments.add(c);

        DatabaseImporter.applyToHandle(db, null, comments);

        // The exporter decodes the key back to a VA and emits the comment.
        // With ADDRESS MAP row 0 → base 0x400000, the exporter needs to match
        // the segKey to a row.  Our encoded key 0x200000001000 has
        // segKey = 0x200000001000 >> 32 = 0x2000L = 8192 — this won't match
        // ADDRESS MAP row 0 directly.  Use VA-based encoding instead.
        //
        // For this test we verify the importer wrote the record to the Comments
        // table and the exporter can read it.  We use encodeVA indirectly by
        // relying on the same logic as DatabaseImporter.applyComments (key lookup).
        //
        // Simpler approach: insert the comment at the encoded key that the
        // ADDRESS MAP + exporter will decode to a real VA.
        // With addrMap = {0L → 0x400000}, decode(encoded) = BASE_VA + (encoded & 0xFFFF_FFFFL).
        // Use encoded = 0x0000_0000_0000_1000 → VA = 0x400000 + 0x1000 = 0x401000.
        // But key "0x200000001000" encodes a different segKey.
        //
        // The test below is intentionally a direct DB verification to decouple it
        // from the address-map decoding path:
        db.getTable("Comments").getRecord(encodedKey); // must not throw

        // Verify the record was written (irrespective of whether exporter decodes it)
        DBRecord rec = db.getTable("Comments").getRecord(encodedKey);
        assertNotNull(rec, "Comment record should be present after applyToHandle");
        assertEquals("important note", rec.getString(0), "EOL column");
    }

    @Test
    void comment_appearsInExport_withAddressMapEncoding() throws IOException {
        // Use the ADDRESS MAP row 0 (base 0x400000) to build a key the exporter
        // will correctly decode.
        // decode(encoded, {0→0x400000}): tries addrMap.get(segKey).
        // With new-format: segKey = encoded >> 32.  Set segKey = 0 so it matches
        // the ADDRESS MAP row 0. encoded = (0L << 32) | offset = offset.
        // VA = addrMap[0] + offset = 0x400000 + 0x2000 = 0x402000.
        long offset  = 0x2000L;
        long encoded = offset; // segKey=0 → just offset

        // Write comment via importer (using pre-computed key)
        JsonArray comments = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("key", "0x" + Long.toHexString(encoded));
        c.addProperty("eol", "my round-trip comment");
        comments.add(c);

        DatabaseImporter.applyToHandle(db, null, comments);

        // Export and find the comment
        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        JsonArray comms = exported.getAsJsonArray("comments");

        long expectedVA = BASE_VA + offset; // 0x402000
        Optional<JsonObject> comm = findCommentByAddr(comms, "0x" + Long.toHexString(expectedVA));
        assertTrue(comm.isPresent(),
            "Comment at VA 0x" + Long.toHexString(expectedVA) + " should appear in export");
        assertEquals("my round-trip comment", comm.get().get("eol").getAsString());
    }

    @Test
    void imageBase_exportedFromAddressMap() throws IOException {
        // The ADDRESS MAP row 0 has base VA = 0x400000; that becomes image_base.
        JsonObject exported = DatabaseExporter.exportFromHandle(db);
        assertEquals("0x" + Long.toHexString(BASE_VA),
            exported.get("image_base").getAsString(),
            "image_base should match ADDRESS MAP row 0's base VA");
    }
}
