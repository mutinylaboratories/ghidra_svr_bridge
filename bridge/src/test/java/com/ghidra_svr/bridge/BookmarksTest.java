package com.ghidra_svr.bridge;

import com.google.gson.*;
import db.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class BookmarksTest {

    private static final Schema BM_TYPES_SCHEMA = new Schema(0, "Key",
        new Field[]{StringField.INSTANCE},
        new String[]{"TypeName"});
    // V3 bookmark: col0=encoded addr(Long), col1=category(String), col2=comment(String), auto-key
    private static final Schema BOOKMARKS_SCHEMA = new Schema(0, "Key",
        new Field[]{LongField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE},
        new String[]{"Address", "Category", "Comment"});
    private static final Schema ADDRMAP_SCHEMA = new Schema(0, "RowKey",
        new Field[]{LongField.INSTANCE, LongField.INSTANCE},
        new String[]{"SpaceId", "BaseVA"});

    private DBHandle db;
    private static final long BASE_VA = 0x400000L;

    @BeforeEach void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Bookmark Types", BM_TYPES_SCHEMA);
        db.createTable("ADDRESS MAP",    ADDRMAP_SCHEMA);
        Table am = db.getTable("ADDRESS MAP");
        DBRecord amRec = ADDRMAP_SCHEMA.createRecord(0L);
        amRec.setLongValue(1, BASE_VA);
        am.putRecord(amRec);
        db.endTransaction(tx, true);
    }

    @AfterEach void tearDown() { if (db != null) db.close(); }

    private long insertType(String name) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Bookmark Types");
        long id = t.getRecordCount();
        DBRecord r = BM_TYPES_SCHEMA.createRecord(id);
        r.setString(0, name);
        t.putRecord(r);
        db.endTransaction(tx, true);
        return id;
    }

    private void createBmTable(long typeId) throws IOException {
        long tx = db.startTransaction();
        db.createTable("Bookmarks" + typeId, BOOKMARKS_SCHEMA);
        db.endTransaction(tx, true);
    }

    private void insertBookmark(long typeId, long encodedAddr, String cat, String comment) throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Bookmarks" + typeId);
        DBRecord r = BOOKMARKS_SCHEMA.createRecord(t.getRecordCount());
        r.setLongValue(0, encodedAddr);
        r.setString(1, cat);
        r.setString(2, comment);
        t.putRecord(r);
        db.endTransaction(tx, true);
    }

    @Test void exportBookmarks_appearsWithCorrectFields() throws IOException {
        long typeId = insertType("Note");
        createBmTable(typeId);
        insertBookmark(typeId, 0x1000L, "Review", "Check this function");  // VA = 0x401000

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray bms = out.getAsJsonArray("bookmarks");
        assertEquals(1, bms.size());
        JsonObject bm = bms.get(0).getAsJsonObject();
        assertEquals("Note",                  bm.get("type").getAsString());
        assertEquals("0x401000",              bm.get("addr").getAsString());
        assertEquals("Review",               bm.get("category").getAsString());
        assertEquals("Check this function",  bm.get("comment").getAsString());
    }

    @Test void exportBookmarks_multipleTypes() throws IOException {
        long noteId = insertType("Note");
        long warnId = insertType("Warning");
        createBmTable(noteId);
        createBmTable(warnId);
        insertBookmark(noteId, 0x1000L, "", "note");
        insertBookmark(warnId, 0x2000L, "", "warning");

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(2, out.getAsJsonArray("bookmarks").size());
    }

    @Test void exportBookmarks_missingTable_returnsEmpty() throws IOException {
        // Type exists but no Bookmarks0 table
        insertType("Note");
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("bookmarks").size());
    }

    @Test void addBookmark_appearsInExport() throws IOException {
        long typeId = insertType("Note");
        createBmTable(typeId);

        JsonArray changes = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("op",       "add");
        c.addProperty("type",     "Note");
        c.addProperty("addr",     "0x401000");
        c.addProperty("category", "Bug");
        c.addProperty("comment",  "Fix this");
        changes.add(c);

        long tx = db.startTransaction();
        DatabaseImporter.applyBookmarkChanges(db, changes, new java.util.HashMap<Long, Long>() {{
            put(0L, BASE_VA);
        }});
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray bms = out.getAsJsonArray("bookmarks");
        assertEquals(1, bms.size());
        assertEquals("Fix this", bms.get(0).getAsJsonObject().get("comment").getAsString());
    }
}
