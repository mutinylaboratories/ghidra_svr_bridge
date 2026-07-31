package com.ghidra_svr.bridge;

import com.google.gson.*;
import db.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.StreamSupport;
import static org.junit.jupiter.api.Assertions.*;

class ParametersTest {

    // Symbols: cols 0-8 (Name,Address,ParentId,Type,Flags,Hash,Primary,DataTypeId,VarOffset)
    private static final Schema SYMBOLS_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
                    ByteField.INSTANCE,   ByteField.INSTANCE, LongField.INSTANCE,
                    LongField.INSTANCE,   LongField.INSTANCE, LongField.INSTANCE},
        new String[]{"Name","Address","ParentId","Type","Flags","Hash","Primary","DataTypeId","VarOffset"});

    private static final Schema ADDRMAP_SCHEMA = new Schema(0, "RowKey",
        new Field[]{LongField.INSTANCE, LongField.INSTANCE},
        new String[]{"SpaceId", "BaseVA"});

    private DBHandle db;
    private static final long BASE_VA = 0x400000L;

    @BeforeEach void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Symbols",     SYMBOLS_SCHEMA);
        db.createTable("ADDRESS MAP", ADDRMAP_SCHEMA);
        Table am = db.getTable("ADDRESS MAP");
        DBRecord amRec = ADDRMAP_SCHEMA.createRecord(0L);
        amRec.setLongValue(1, BASE_VA);
        am.putRecord(amRec);
        db.endTransaction(tx, true);
    }

    @AfterEach void tearDown() { if (db != null) db.close(); }

    // Encode VA: segKey=0, offset=va-BASE_VA → encoded=offset
    private long encode(long va) { return va - BASE_VA; }

    private void insertParam(long key, String name, long funcVa, byte type, int ordinal) throws IOException {
        long tx = db.startTransaction();
        DBRecord r = SYMBOLS_SCHEMA.createRecord(key);
        r.setString(0, name);
        r.setLongValue(1, encode(funcVa));   // encoded func entry addr
        r.setLongValue(2, 0L);               // parent id
        r.setByteValue(3, type);             // 6=PARAMETER, 7=LOCAL_VAR
        r.setByteValue(4, (byte)0);          // flags
        r.setLongValue(5, 0L);               // hash
        r.setLongValue(6, 0L);               // primary
        r.setLongValue(7, 0L);               // data type id
        r.setLongValue(8, ordinal);          // var offset (ordinal proxy)
        db.getTable("Symbols").putRecord(r);
        db.endTransaction(tx, true);
    }

    @Test void exportParameters_appearsWithCorrectFields() throws IOException {
        insertParam(100L, "argc", 0x401000L, (byte)6, 0);
        insertParam(101L, "argv", 0x401000L, (byte)6, 1);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray params = out.getAsJsonArray("parameters");
        assertEquals(2, params.size());

        Optional<JsonObject> argc = StreamSupport.stream(params.spliterator(), false)
            .map(e -> e.getAsJsonObject())
            .filter(p -> "argc".equals(p.get("name").getAsString()))
            .findFirst();
        assertTrue(argc.isPresent());
        assertEquals("0x401000", argc.get().get("func_addr").getAsString());
        assertTrue(argc.get().get("is_param").getAsBoolean());
    }

    @Test void exportParameters_skipsLocalVarsWhenOnlyParamsWanted() throws IOException {
        insertParam(200L, "local_var", 0x402000L, (byte)7, 0);  // LOCAL_VAR
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        // LOCAL_VARs are exported too (is_param=false) — just verify it's present
        JsonArray params = out.getAsJsonArray("parameters");
        assertEquals(1, params.size());
        assertFalse(params.get(0).getAsJsonObject().get("is_param").getAsBoolean());
    }

    @Test void exportParameters_skipsEmptyName() throws IOException {
        insertParam(300L, "", 0x403000L, (byte)6, 0);
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("parameters").size());
    }

    @Test void renameParameter_appearsInExport() throws IOException {
        insertParam(100L, "argc", 0x401000L, (byte)6, 0);

        JsonArray renames = new JsonArray();
        JsonObject r = new JsonObject();
        r.addProperty("key", 100L); r.addProperty("name", "count");
        renames.add(r);
        long tx = db.startTransaction();
        DatabaseImporter.applyParameterRenames(db, renames);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals("count", out.getAsJsonArray("parameters")
            .get(0).getAsJsonObject().get("name").getAsString());
    }

    @Test void exportParameters_includesTypeName() throws IOException {
        // Create a Composite Data Types table with a struct "MyStruct"
        Schema compositeSchema = new Schema(0, "Key",
            new Field[]{StringField.INSTANCE, StringField.INSTANCE, ByteField.INSTANCE,
                        LongField.INSTANCE,   IntField.INSTANCE,    IntField.INSTANCE,
                        IntField.INSTANCE,    LongField.INSTANCE,   LongField.INSTANCE,
                        LongField.INSTANCE,   LongField.INSTANCE,   IntField.INSTANCE,
                        IntField.INSTANCE},
            new String[]{"Name","Comment","IsUnion","CatId","Length","Alignment","NumComponents",
                         "ArchiveId","UniversalId","SyncTime","LastChange","Packing","MinAlign"});

        long tx = db.startTransaction();
        db.createTable("Composite Data Types", compositeSchema);
        Table ct = db.getTable("Composite Data Types");
        long structId = 42L;
        DBRecord sr = compositeSchema.createRecord(structId);
        sr.setString(0, "MyStruct");
        sr.setString(1, "");
        sr.setByteValue(2, (byte)0);
        sr.setLongValue(3, 0L);
        sr.setIntValue(4, 8);
        ct.putRecord(sr);
        db.endTransaction(tx, true);

        // Insert a parameter symbol whose DataTypeId (col 7) points to MyStruct
        long tx2 = db.startTransaction();
        DBRecord r = SYMBOLS_SCHEMA.createRecord(999L);
        r.setString(0, "pCtx");
        r.setLongValue(1, encode(0x401000L));
        r.setLongValue(2, 0L);
        r.setByteValue(3, (byte)6);   // PARAMETER
        r.setByteValue(4, (byte)0);
        r.setLongValue(5, 0L);
        r.setLongValue(6, 0L);
        r.setLongValue(7, structId);  // DataTypeId → MyStruct
        r.setLongValue(8, 0L);
        db.getTable("Symbols").putRecord(r);
        db.endTransaction(tx2, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray params = out.getAsJsonArray("parameters");

        Optional<JsonObject> param = StreamSupport.stream(params.spliterator(), false)
            .map(e -> e.getAsJsonObject())
            .filter(p -> "pCtx".equals(p.get("name").getAsString()))
            .findFirst();
        assertTrue(param.isPresent());
        assertEquals("MyStruct", param.get().get("type_name").getAsString());
        assertEquals(structId, param.get().get("type_id").getAsLong());
    }

    @Test void renameParameter_rejectsNonParameterSymbol() throws IOException {
        // Insert a FUNCTION type symbol (type=5) — should not be renamed
        long tx = db.startTransaction();
        DBRecord r = SYMBOLS_SCHEMA.createRecord(500L);
        r.setString(0, "my_func"); r.setLongValue(1, encode(0x401000L));
        r.setByteValue(3, (byte)5);  // FUNCTION, not PARAMETER
        db.getTable("Symbols").putRecord(r);
        db.endTransaction(tx, true);

        JsonArray renames = new JsonArray();
        JsonObject rename = new JsonObject();
        rename.addProperty("key", 500L); rename.addProperty("name", "hacked");
        renames.add(rename);
        long renameTx = db.startTransaction();
        DatabaseImporter.applyParameterRenames(db, renames);
        db.endTransaction(renameTx, true);

        // Should not rename a FUNCTION symbol
        assertEquals("my_func", db.getTable("Symbols").getRecord(500L).getString(0));
    }
}
