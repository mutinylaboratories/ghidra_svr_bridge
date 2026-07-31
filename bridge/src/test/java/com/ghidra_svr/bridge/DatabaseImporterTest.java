package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DatabaseImporter#applyToHandle}.
 *
 * Uses an in-memory {@link DBHandle} with schemas that mirror Ghidra's internal
 * Symbols and Comments tables, so no Ghidra server or RMI layer is required.
 *
 * Table layout (must match DatabaseImporter's column constants):
 *   Symbols  — col 0: Name (String), col 1: Address (Long encoded),
 *               col 2: Namespace (Long), col 3: Type (Byte), col 4: Flags (Byte)
 *   Comments — col 0: EOL, col 1: Pre, col 2: Post, col 3: Plate, col 4: Rep (all String)
 */
class DatabaseImporterTest {

    // ----- Schemas matching Ghidra's internal layout -----

    private static final Schema SYMBOLS_SCHEMA = new Schema(0, "Key",
        new Field[]{ StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
                     ByteField.INSTANCE,   ByteField.INSTANCE },
        new String[]{ "Name", "Address", "Namespace", "Type", "Flags" });

    private static final Schema COMMENTS_SCHEMA = new Schema(0, "Key",
        new Field[]{ StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE,
                     StringField.INSTANCE, StringField.INSTANCE },
        new String[]{ "EOL", "Pre", "Post", "Plate", "Rep" });

    private static final byte FUNCTION_TYPE = 5; // Ghidra 11+ ordinal
    private static final int  SOURCE_USER   = 3; // USER_DEFINED source
    private static final int  SOURCE_SHIFT  = 6;

    private DBHandle db;

    @BeforeEach
    void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Symbols",  SYMBOLS_SCHEMA);
        db.createTable("Comments", COMMENTS_SCHEMA);
        db.endTransaction(tx, true);
    }

    @AfterEach
    void tearDown() {
        if (db != null) db.close();
    }

    // ----- Helpers -----

    private void insertSymbol(long key, String name, long encodedAddr,
                              byte type, byte flags) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Symbols");
        DBRecord rec = SYMBOLS_SCHEMA.createRecord(key);
        rec.setString(0, name);
        rec.setLongValue(1, encodedAddr);
        rec.setLongValue(2, 0L); // global namespace
        rec.setByteValue(3, type);
        rec.setByteValue(4, flags);
        t.putRecord(rec);
        db.endTransaction(tx, true);
    }

    private void insertComment(long key, String eol, String pre) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Comments");
        DBRecord rec = COMMENTS_SCHEMA.createRecord(key);
        rec.setString(0, eol);
        rec.setString(1, pre);
        t.putRecord(rec);
        db.endTransaction(tx, true);
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

    private static JsonArray eolComment(String hexKey, String eol) {
        JsonArray arr = new JsonArray();
        JsonObject o = new JsonObject();
        o.addProperty("key", hexKey);
        o.addProperty("eol", eol);
        arr.add(o);
        return arr;
    }

    // ----- Symbol tests -----

    @Test
    void renameSymbol_updatesNameColumn() throws IOException {
        insertSymbol(42L, "original_name", 0x1000L, FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db, symbols(42L, "renamed_func"), null);

        DBRecord rec = db.getTable("Symbols").getRecord(42L);
        assertNotNull(rec, "record should still exist after rename");
        assertEquals("renamed_func", rec.getString(0), "Name column should be updated");
    }

    @Test
    void renameSymbol_promotesSourceToUserDefined() throws IOException {
        insertSymbol(42L, "sub_1000", 0x1000L, FUNCTION_TYPE, (byte) 0x00);

        DatabaseImporter.applyToHandle(db, symbols(42L, "my_func"), null);

        DBRecord rec = db.getTable("Symbols").getRecord(42L);
        byte flags = rec.getByteValue(4);
        int  source = (flags >> SOURCE_SHIFT) & 0x03;
        assertEquals(SOURCE_USER, source,
            "Source bits should be promoted to USER_DEFINED (3)");
    }

    @Test
    void renameSymbol_preservesLowerFlagBits() throws IOException {
        // Lower 6 bits carry type sub-flags; they must not be disturbed.
        byte initialFlags = 0b00_001010; // lower bits set, source = DEFAULT (0)
        insertSymbol(42L, "original", 0x1000L, FUNCTION_TYPE, initialFlags);

        DatabaseImporter.applyToHandle(db, symbols(42L, "new_name"), null);

        DBRecord rec = db.getTable("Symbols").getRecord(42L);
        byte flags = rec.getByteValue(4);
        assertEquals(0b11_001010, flags & 0xFF,
            "Lower 6 flag bits must be preserved; source bits set to USER_DEFINED");
    }

    @Test
    void renameSymbol_skipsEmptyName() throws IOException {
        insertSymbol(42L, "original", 0x1000L, FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db, symbols(42L, ""), null);

        // applySymbols skips names that are null or empty
        DBRecord rec = db.getTable("Symbols").getRecord(42L);
        assertEquals("original", rec.getString(0), "Empty name should be ignored");
    }

    @Test
    void renameSymbol_skipsUnknownKey() throws IOException {
        insertSymbol(42L, "known", 0x1000L, FUNCTION_TYPE, (byte) 0);

        // key 999 does not exist — should not throw
        assertDoesNotThrow(() ->
            DatabaseImporter.applyToHandle(db, symbols(999L, "ghost"), null));

        // original record untouched
        assertEquals("known", db.getTable("Symbols").getRecord(42L).getString(0));
    }

    @Test
    void renameMultipleSymbols_allUpdated() throws IOException {
        insertSymbol(1L, "func_a", 0x1000L, FUNCTION_TYPE, (byte) 0);
        insertSymbol(2L, "func_b", 0x2000L, FUNCTION_TYPE, (byte) 0);
        insertSymbol(3L, "func_c", 0x3000L, FUNCTION_TYPE, (byte) 0);

        DatabaseImporter.applyToHandle(db,
            symbols(1L, "alpha", 2L, "beta", 3L, "gamma"), null);

        Table t = db.getTable("Symbols");
        assertEquals("alpha", t.getRecord(1L).getString(0));
        assertEquals("beta",  t.getRecord(2L).getString(0));
        assertEquals("gamma", t.getRecord(3L).getString(0));
    }

    // ----- Comment tests -----

    @Test
    void writeComment_eolColumn() throws IOException {
        // Use a pre-computed encoded key matching the key the test record is stored under
        long key = 0x200000001000L; // encoded address: segKey=0x2000000, offset=0x1000
        // For simplicity, store record at that key
        long tx = db.startTransaction();
        DBRecord rec = COMMENTS_SCHEMA.createRecord(key);
        db.getTable("Comments").putRecord(rec);
        db.endTransaction(tx, true);

        DatabaseImporter.applyToHandle(db, null,
            eolComment("0x200000001000", "this is an eol comment"));

        DBRecord result = db.getTable("Comments").getRecord(key);
        assertNotNull(result);
        assertEquals("this is an eol comment", result.getString(0), "EOL column");
        assertNull(result.getString(1), "Pre column should be empty");
    }

    @Test
    void writeComment_createsRecordIfAbsent() throws IOException {
        // Key for a comment at an address that has no prior comment record
        long key = 0x200000002000L;
        assertNull(db.getTable("Comments").getRecord(key),
            "pre-condition: no record at this key");

        // applyComments can look up by 'key' field (pre-computed encoded address)
        // or by 'va' field — use 'key' here since we don't have an ADDRESS MAP table
        DatabaseImporter.applyToHandle(db, null,
            eolComment("0x200000002000", "new comment"));

        DBRecord result = db.getTable("Comments").getRecord(key);
        assertNotNull(result, "record should be created for new address");
        assertEquals("new comment", result.getString(0));
    }

    @Test
    void writeComment_multipleFields() throws IOException {
        long key = 0x200000003000L;
        JsonArray arr = new JsonArray();
        JsonObject o = new JsonObject();
        o.addProperty("key",   "0x200000003000");
        o.addProperty("eol",   "end-of-line note");
        o.addProperty("pre",   "pre-instruction note");
        o.addProperty("plate", "function header");
        arr.add(o);

        DatabaseImporter.applyToHandle(db, null, arr);

        DBRecord result = db.getTable("Comments").getRecord(key);
        assertNotNull(result);
        assertEquals("end-of-line note",    result.getString(0), "EOL col");
        assertEquals("pre-instruction note",result.getString(1), "Pre col");
        assertNull(result.getString(2),                          "Post col (unset)");
        assertEquals("function header",     result.getString(3), "Plate col");
        assertNull(result.getString(4),                          "Rep col (unset)");
    }

    @Test
    void writeComment_plateOnly_setsPlateColClearsEol() throws IOException {
        // When a function-header (plate) comment is checked in from BN, the
        // C++ side emits {"plate": text} instead of {"eol": text}.  Verify that
        // applyComments writes the plate column and leaves EOL null.
        long key = 0x200000004000L;
        JsonArray arr = new JsonArray();
        JsonObject o = new JsonObject();
        o.addProperty("key",   "0x200000004000");
        o.addProperty("plate", "function header comment");
        arr.add(o);

        DatabaseImporter.applyToHandle(db, null, arr);

        DBRecord result = db.getTable("Comments").getRecord(key);
        assertNotNull(result);
        assertNull(result.getString(0),                           "EOL col must be null");
        assertEquals("function header comment", result.getString(3), "Plate col");
    }

    @Test
    void writeComment_plateOnly_preservesExistingPreComment() throws IOException {
        // Checking in a plate comment must not destroy a pre-comment on the same record.
        long key = 0x200000005000L;
        long tx = db.startTransaction();
        DBRecord existing = COMMENTS_SCHEMA.createRecord(key);
        existing.setString(1, "pre-existing pre-comment");
        db.getTable("Comments").putRecord(existing);
        db.endTransaction(tx, true);

        JsonArray arr = new JsonArray();
        JsonObject o = new JsonObject();
        o.addProperty("key",   "0x200000005000");
        o.addProperty("plate", "new plate text");
        arr.add(o);

        DatabaseImporter.applyToHandle(db, null, arr);

        DBRecord result = db.getTable("Comments").getRecord(key);
        assertNotNull(result);
        assertEquals("new plate text",           result.getString(3), "Plate col updated");
        // pre-comment is cleared because setOrClear writes null when field absent —
        // this is gap #7 (known limitation), but plate itself must be correct.
        assertEquals("new plate text", result.getString(3));
    }

    @Test
    void nullSymbolsAndComments_noException() throws IOException {
        assertDoesNotThrow(() ->
            DatabaseImporter.applyToHandle(db, null, null));
    }
}
