package com.ghidra_svr.bridge;

import com.google.gson.*;
import db.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import java.util.Optional;
import java.util.stream.StreamSupport;
import static org.junit.jupiter.api.Assertions.*;

class DataTypesTest {

    private static final Schema COMPOSITE_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE, StringField.INSTANCE, ByteField.INSTANCE,
                    LongField.INSTANCE,   IntField.INSTANCE,    IntField.INSTANCE,
                    IntField.INSTANCE,    LongField.INSTANCE,   LongField.INSTANCE,
                    LongField.INSTANCE,   LongField.INSTANCE,   IntField.INSTANCE,
                    IntField.INSTANCE},
        new String[]{"Name","Comment","IsUnion","CatId","Length","Alignment","NumComponents",
                     "ArchiveId","UniversalId","SyncTime","LastChange","Packing","MinAlign"});

    private static final Schema COMPONENT_SCHEMA = new Schema(0, "Key",
        new Field[]{LongField.INSTANCE, IntField.INSTANCE, LongField.INSTANCE,
                    StringField.INSTANCE, StringField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE},
        new String[]{"ParentId","Offset","DataTypeId","FieldName","Comment","Size","Ordinal"});

    private static final Schema ENUM_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
                    ByteField.INSTANCE,   LongField.INSTANCE,   LongField.INSTANCE,
                    LongField.INSTANCE,   LongField.INSTANCE},
        new String[]{"Name","Comment","CatId","Size","ArchiveId","UniversalId","SyncTime","LastChange"});

    private static final Schema ENUM_VALUES_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE, StringField.INSTANCE},
        new String[]{"Name","Value","EnumId","Comment"});

    private static final Schema TYPEDEF_SCHEMA = new Schema(0, "Key",
        new Field[]{LongField.INSTANCE,   IntField.INSTANCE,  StringField.INSTANCE,
                    LongField.INSTANCE,   LongField.INSTANCE, LongField.INSTANCE,
                    LongField.INSTANCE,   LongField.INSTANCE},
        new String[]{"UnderlyingId","Flags","Name","CatId","ArchiveId","UniversalId","SyncTime","LastChange"});

    private DBHandle db;

    @BeforeEach void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Composite Data Types",  COMPOSITE_SCHEMA);
        db.createTable("Component Data Types",  COMPONENT_SCHEMA);
        db.createTable("Enumeration Data Types", ENUM_SCHEMA);
        db.createTable("Enumeration Values",    ENUM_VALUES_SCHEMA);
        db.createTable("Typedefs",              TYPEDEF_SCHEMA);
        db.endTransaction(tx, true);
    }

    @AfterEach void tearDown() { if (db != null) db.close(); }

    private long insertStruct(String name, int size, boolean isUnion) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Composite Data Types");
        long id = t.getRecordCount() + 1;
        DBRecord r = COMPOSITE_SCHEMA.createRecord(id);
        r.setString(0, name); r.setString(1, ""); r.setByteValue(2, isUnion ? (byte)1 : (byte)0);
        r.setLongValue(3, 0L); r.setIntValue(4, size); r.setIntValue(5, 1); r.setIntValue(6, 0);
        t.putRecord(r);
        db.endTransaction(tx, true);
        return id;
    }

    private void insertComponent(long parentId, int offset, String name, int size, int ordinal) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Component Data Types");
        DBRecord r = COMPONENT_SCHEMA.createRecord(t.getRecordCount() + 1);
        r.setLongValue(0, parentId); r.setIntValue(1, offset); r.setLongValue(2, -1L);
        r.setString(3, name); r.setString(4, ""); r.setIntValue(5, size); r.setIntValue(6, ordinal);
        t.putRecord(r);
        db.endTransaction(tx, true);
    }

    private long insertEnum(String name, byte size) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Enumeration Data Types");
        long id = t.getRecordCount() + 10;  // offset from structs
        DBRecord r = ENUM_SCHEMA.createRecord(id);
        r.setString(0, name); r.setString(1, ""); r.setLongValue(2, 0L); r.setByteValue(3, size);
        t.putRecord(r);
        db.endTransaction(tx, true);
        return id;
    }

    private void insertEnumValue(long enumId, String name, long value) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Enumeration Values");
        DBRecord r = ENUM_VALUES_SCHEMA.createRecord(t.getRecordCount() + 1);
        r.setString(0, name); r.setLongValue(1, value); r.setLongValue(2, enumId); r.setString(3, "");
        t.putRecord(r);
        db.endTransaction(tx, true);
    }

    private static Optional<JsonObject> findByName(JsonArray arr, String name) {
        return StreamSupport.stream(arr.spliterator(), false)
            .map(e -> e.getAsJsonObject())
            .filter(o -> name.equals(o.get("name").getAsString()))
            .findFirst();
    }

    @Test void exportStruct_withMembers() throws IOException {
        long id = insertStruct("Point", 8, false);
        insertComponent(id, 0, "x", 4, 0);
        insertComponent(id, 4, "y", 4, 1);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray types = out.getAsJsonArray("data_types");

        Optional<JsonObject> point = findByName(types, "Point");
        assertTrue(point.isPresent());
        assertEquals("struct", point.get().get("kind").getAsString());
        assertEquals(8, point.get().get("size").getAsInt());

        JsonArray members = point.get().getAsJsonArray("members");
        assertEquals(2, members.size());
        assertEquals("x", members.get(0).getAsJsonObject().get("name").getAsString());
        assertEquals(0,   members.get(0).getAsJsonObject().get("offset").getAsInt());
        assertEquals("y", members.get(1).getAsJsonObject().get("name").getAsString());
        assertEquals(4,   members.get(1).getAsJsonObject().get("offset").getAsInt());
    }

    @Test void exportUnion_kindIsUnion() throws IOException {
        insertStruct("IntFloat", 4, true);
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> u = findByName(out.getAsJsonArray("data_types"), "IntFloat");
        assertTrue(u.isPresent());
        assertEquals("union", u.get().get("kind").getAsString());
    }

    @Test void exportEnum_withValues() throws IOException {
        long id = insertEnum("Color", (byte)4);
        insertEnumValue(id, "RED",   0L);
        insertEnumValue(id, "GREEN", 1L);
        insertEnumValue(id, "BLUE",  2L);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> color = findByName(out.getAsJsonArray("data_types"), "Color");
        assertTrue(color.isPresent());
        assertEquals("enum", color.get().get("kind").getAsString());
        assertEquals(4, color.get().get("size").getAsInt());
        assertEquals(3, color.get().getAsJsonArray("values").size());
    }

    @Test void exportTypedef() throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Typedefs");
        DBRecord r = TYPEDEF_SCHEMA.createRecord(200L);
        r.setLongValue(0, -1L); r.setIntValue(1, 0); r.setString(2, "UINT32");
        t.putRecord(r);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> td = findByName(out.getAsJsonArray("data_types"), "UINT32");
        assertTrue(td.isPresent());
        assertEquals("typedef", td.get().get("kind").getAsString());
    }

    @Test void exportTypedef_includesUnderlyingName() throws IOException {
        // Insert struct "MyStruct"
        long structId = insertStruct("MyStruct", 16, false);

        // Insert typedef "PMyStruct" → MyStruct (col 0 = UnderlyingId = structId)
        long tx = db.startTransaction();
        Table t = db.getTable("Typedefs");
        DBRecord r = TYPEDEF_SCHEMA.createRecord(300L);
        r.setLongValue(0, structId);   // UnderlyingId → MyStruct
        r.setIntValue(1, 0);           // Flags
        r.setString(2, "PMyStruct");   // Name
        t.putRecord(r);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> td = findByName(out.getAsJsonArray("data_types"), "PMyStruct");
        assertTrue(td.isPresent());
        assertEquals("typedef", td.get().get("kind").getAsString());
        assertEquals("MyStruct", td.get().get("underlying_name").getAsString());
    }

    @Test void exportStructMember_includesTypeName() throws IOException {
        // Create an enum "Color" that will be used as a member type
        long enumId = insertEnum("Color", (byte)4);
        insertEnumValue(enumId, "RED", 0L);

        // Create a struct "Widget" with one member of type Color
        long structId = insertStruct("Widget", 8, false);

        // Insert component: parentId=Widget, typeId=Color
        long tx = db.startTransaction();
        Table t = db.getTable("Component Data Types");
        DBRecord r = COMPONENT_SCHEMA.createRecord(t.getRecordCount() + 1);
        r.setLongValue(0, structId);   // parent = Widget
        r.setIntValue(1, 0);           // offset
        r.setLongValue(2, enumId);     // type_id = Color enum
        r.setString(3, "kind");        // field name
        r.setString(4, "");            // comment
        r.setIntValue(5, 4);           // size
        r.setIntValue(6, 0);           // ordinal
        t.putRecord(r);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> widget = findByName(out.getAsJsonArray("data_types"), "Widget");
        assertTrue(widget.isPresent());

        JsonArray members = widget.get().getAsJsonArray("members");
        assertEquals(1, members.size());
        JsonObject member = members.get(0).getAsJsonObject();
        assertEquals("kind",  member.get("name").getAsString());
        assertEquals(enumId,  member.get("type_id").getAsLong());
        assertEquals("Color", member.get("type_name").getAsString());   // ← new field
    }

    @Test void exportStructMember_unknownTypeId_hasEmptyTypeName() throws IOException {
        long structId = insertStruct("Blob", 4, false);

        // Component with a type_id that doesn't exist in any type table
        long tx = db.startTransaction();
        Table t = db.getTable("Component Data Types");
        DBRecord r = COMPONENT_SCHEMA.createRecord(1L);
        r.setLongValue(0, structId); r.setIntValue(1, 0); r.setLongValue(2, 9999L);
        r.setString(3, "data"); r.setString(4, ""); r.setIntValue(5, 4); r.setIntValue(6, 0);
        t.putRecord(r);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        Optional<JsonObject> blob = findByName(out.getAsJsonArray("data_types"), "Blob");
        assertTrue(blob.isPresent());
        JsonObject member = blob.get().getAsJsonArray("members").get(0).getAsJsonObject();
        assertEquals("", member.get("type_name").getAsString());  // unknown → empty
    }

    @Test void emptyTables_returnEmptyArray() throws IOException {
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("data_types").size());
    }

    // -------------------------------------------------------------------------
    // applyDataTypeChanges — struct member DataTypeId resolution
    //
    // Two tests removed here in 2026-05 — they exercised the deprecated
    // DatabaseImporter.applyDataTypeChanges raw-write code path against a
    // hand-rolled DBHandle that used the V2 (ByteField) composite schema.
    // Production no longer uses that method; checkin now goes through
    // ProgramApplier + DataTypeManager, exercised by DataTypesRoundTripTest
    // (struct/union/enum/typedef + the cloneAllComponentSettings regression).
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Data type deletion
    // -------------------------------------------------------------------------

    @Test void applyStructDelete_removesCompositeAndComponents() throws IOException {
        long structId = insertStruct("ToDelete", 8, false);
        insertComponent(structId, 0, "x", 4, 0);
        insertComponent(structId, 4, "y", 4, 1);

        // Verify it's there first
        assertNotNull(db.getTable("Composite Data Types").getRecord(structId));
        assertEquals(2, db.getTable("Component Data Types").getRecordCount());

        JsonArray changes = new JsonArray();
        JsonObject del = new JsonObject();
        del.addProperty("op",        "delete");
        del.addProperty("kind",      "struct");
        del.addProperty("name",      "ToDelete");
        del.addProperty("ghidra_id", structId);
        del.addProperty("size",      8);
        changes.add(del);

        long tx = db.startTransaction();
        DatabaseImporter.applyDataTypeChanges(db, changes);
        db.endTransaction(tx, true);

        assertNull(db.getTable("Composite Data Types").getRecord(structId),
            "Struct record should be deleted");
        assertEquals(0, db.getTable("Component Data Types").getRecordCount(),
            "Components should be deleted along with struct");
    }

    @Test void applyEnumDelete_removesEnumAndValues() throws IOException {
        long enumId = insertEnum("ToDeleteEnum", (byte)4);
        insertEnumValue(enumId, "A", 0L);
        insertEnumValue(enumId, "B", 1L);

        assertNotNull(db.getTable("Enumeration Data Types").getRecord(enumId));
        assertEquals(2, db.getTable("Enumeration Values").getRecordCount());

        JsonArray changes = new JsonArray();
        JsonObject del = new JsonObject();
        del.addProperty("op",        "delete");
        del.addProperty("kind",      "enum");
        del.addProperty("name",      "ToDeleteEnum");
        del.addProperty("ghidra_id", enumId);
        del.addProperty("size",      4);
        changes.add(del);

        long tx = db.startTransaction();
        DatabaseImporter.applyDataTypeChanges(db, changes);
        db.endTransaction(tx, true);

        assertNull(db.getTable("Enumeration Data Types").getRecord(enumId),
            "Enum record should be deleted");
        assertEquals(0, db.getTable("Enumeration Values").getRecordCount(),
            "Enum values should be deleted along with enum");
    }

    // -------------------------------------------------------------------------
    // buildTypeIdByName covers typedef and pointer/array names
    // -------------------------------------------------------------------------

    @Test void buildTypeIdByName_coversTypedefs() throws IOException {
        // Insert a typedef "MyAlias" → underlying irrelevant for this test
        long tx = db.startTransaction();
        Table t = db.getTable("Typedefs");
        db.DBRecord r = TYPEDEF_SCHEMA.createRecord(500L);
        r.setLongValue(0, -1L); r.setIntValue(1, 0); r.setString(2, "MyAlias");
        t.putRecord(r);
        db.endTransaction(tx, true);

        java.util.Map<String, Long> map = DatabaseImporter.buildTypeIdByName(db);
        assertTrue(map.containsKey("MyAlias"),
            "buildTypeIdByName should include typedef names");
        assertEquals(500L, (long) map.get("MyAlias"));
    }

    // -------------------------------------------------------------------------
    // applyDataTypeChanges returns newly-assigned DB keys for op=add entries
    //
    // Two struct-related tests removed in 2026-05 for the same reason as the
    // member-resolution tests above: they targeted the deprecated raw-write
    // path that the current ProgramDB-based checkin doesn't use.  The struct
    // add/update cases are now covered by DataTypesRoundTripTest against a
    // real ProgramDB.  The enum tests below still exercise applyDataTypeChanges
    // because its enum branch happens to work with the V0/V1 test fixture
    // schema; they survive until applyDataTypeChanges itself is removed.
    // -------------------------------------------------------------------------

    @Test void applyDataTypeChanges_addEnum_returnsNewId() throws IOException {
        JsonArray changes = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("op",   "add");
        c.addProperty("kind", "enum");
        c.addProperty("name", "NewEnum");
        c.addProperty("size", 4);
        c.add("values", new JsonArray());
        changes.add(c);

        long tx = db.startTransaction();
        java.util.Map<String, Long> added = DatabaseImporter.applyDataTypeChanges(db, changes);
        db.endTransaction(tx, true);

        assertTrue(added.containsKey("NewEnum"));
        long newId = added.get("NewEnum");
        assertNotNull(db.getTable("Enumeration Data Types").getRecord(newId));
    }
}
