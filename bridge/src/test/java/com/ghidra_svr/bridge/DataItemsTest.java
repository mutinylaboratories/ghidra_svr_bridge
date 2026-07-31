package com.ghidra_svr.bridge;

import com.google.gson.*;
import db.*;
import org.junit.jupiter.api.*;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class DataItemsTest {

    private static final Schema DATA_SCHEMA = new Schema(0, "Key",
        new Field[]{LongField.INSTANCE},
        new String[]{"DataTypeId"});

    private static final Schema ADDRMAP_SCHEMA = new Schema(0, "RowKey",
        new Field[]{LongField.INSTANCE, LongField.INSTANCE},
        new String[]{"SpaceId", "BaseVA"});

    private DBHandle db;
    private static final long BASE_VA = 0x400000L;

    @BeforeEach void setUp() throws IOException {
        db = new DBHandle();
        long tx = db.startTransaction();
        db.createTable("Data",        DATA_SCHEMA);
        db.createTable("ADDRESS MAP", ADDRMAP_SCHEMA);
        Table am = db.getTable("ADDRESS MAP");
        DBRecord r = ADDRMAP_SCHEMA.createRecord(0L);
        r.setLongValue(1, BASE_VA);
        am.putRecord(r);
        db.endTransaction(tx, true);
    }

    @AfterEach void tearDown() { if (db != null) db.close(); }

    // Encode VA to DB key: segKey=0, offset=va-BASE_VA → key=offset
    private long encode(long va) { return va - BASE_VA; }

    @Test void exportDataItem_appearsWithCorrectAddr() throws IOException {
        long tx = db.startTransaction();
        DBRecord r = DATA_SCHEMA.createRecord(encode(0x402000L));
        r.setLongValue(0, 100L);  // data type id = 100
        db.getTable("Data").putRecord(r);
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonArray items = out.getAsJsonArray("data_items");
        assertEquals(1, items.size());
        JsonObject item = items.get(0).getAsJsonObject();
        assertEquals("0x402000", item.get("addr").getAsString());
        assertEquals(100L,       item.get("type_id").getAsLong());
    }

    @Test void exportMultipleDataItems() throws IOException {
        long tx = db.startTransaction();
        Table t = db.getTable("Data");
        for (int i = 0; i < 3; i++) {
            DBRecord r = DATA_SCHEMA.createRecord(encode(0x401000L + i * 0x100L));
            r.setLongValue(0, (long)i);
            t.putRecord(r);
        }
        db.endTransaction(tx, true);

        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(3, out.getAsJsonArray("data_items").size());
    }

    @Test void emptyDataTable_returnsEmptyArray() throws IOException {
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        assertEquals(0, out.getAsJsonArray("data_items").size());
    }

    @Test void xrefStats_presentInExport() throws IOException {
        // No xref tables → counts should be 0
        JsonObject out = DatabaseExporter.exportFromHandle(db);
        JsonObject stats = out.getAsJsonObject("xref_stats");
        assertNotNull(stats);
        assertEquals(0, stats.get("from_count").getAsInt());
        assertEquals(0, stats.get("to_count").getAsInt());
    }
}
