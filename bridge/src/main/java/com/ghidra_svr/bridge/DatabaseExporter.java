package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import db.DBHandle;
import db.DBRecord;
import db.RecordIterator;
import db.Table;
import db.buffers.ManagedBufferFileAdapter;
import db.buffers.ManagedBufferFileHandle;

import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Reads a Ghidra program database (via an RMI buffer-file handle) and
 * extracts symbols, comments, and function flags for Binary Ninja.
 *
 * Address encoding (old "ADDRESS MAP" format)
 * -------------------------------------------
 * Encoded address = ((spacePrefix | rowKey) << 32) | offset
 *
 * The ADDRESS MAP table has row keys 0, 1, 2, ... (segment indices).
 * Each row's col-1 stores the base VA for that segment.
 * spacePrefix identifies the address space type:
 *   0x20000000 = main RAM space (code + data)
 *   0x50000000 = external import space  (not a real VA, skip)
 *   0x60000000 = stack / local-var space (not a real VA, skip)
 *
 * Decoding: rowKey = segKey & 0xFF  (only valid when upper 24 bits = 0x200000)
 *           VA     = addrMap[rowKey] + offset
 */
public class DatabaseExporter {

    // ---- Address Map table ---------------------------------------------------
    private static final String ADDR_MAP_TABLE = "ADDRESS MAP";
    // Upper 24 bits of the segment key for the main RAM address space.
    private static final long RAM_SPACE_PREFIX = 0x200000L;

    // ---- Symbols table -------------------------------------------------------
    private static final String SYMBOLS_TABLE   = "Symbols";
    private static final int SYM_NAME_COL       = 0;  // StringField
    private static final int SYM_ADDR_COL       = 1;  // LongField (encoded)
    private static final int SYM_NAMESPACE_COL  = 2;  // LongField
    private static final int SYM_TYPE_COL       = 3;  // ByteField
    private static final int SYM_FLAGS_COL      = 4;  // ByteField

    private static final byte SYM_TYPE_LABEL       = 0;
    // Ghidra < 11 uses ordinal 4 for FUNCTION; Ghidra 11+ uses ordinal 5.
    private static final byte SYM_TYPE_FUNCTION_OLD = 4;
    private static final byte SYM_TYPE_FUNCTION_NEW = 5;
    private static final byte SYM_TYPE_EXTERNAL     = 8;

    private static final int SOURCE_SHIFT = 6;
    private static final int SOURCE_MASK  = 0x03;

    // ---- Comments table ------------------------------------------------------
    private static final String COMMENTS_TABLE = "Comments";
    private static final int COMM_EOL_COL   = 0;
    private static final int COMM_PRE_COL   = 1;
    private static final int COMM_POST_COL  = 2;
    private static final int COMM_PLATE_COL = 3;
    private static final int COMM_REP_COL   = 4;

    // ---- Functions table -----------------------------------------------------
    private static final String FUNCTIONS_TABLE = "Function Data";
    private static final int FUNC_RET_TYPE_COL  = 1;
    private static final int FUNC_CC_COL         = 3;
    private static final int FUNC_FLAGS_COL      = 4;
    private static final int FUNC_FLAG_THUNK     = 0x01;
    private static final int FUNC_FLAG_NRET      = 0x02;
    private static final int FUNC_FLAG_INLINE    = 0x04;

    // =========================================================================

    public static JsonObject export(ManagedBufferFileHandle remoteHandle) throws IOException {
        ManagedBufferFileAdapter adapter = new ManagedBufferFileAdapter(remoteHandle);
        DBHandle db = new DBHandle(adapter);

        // Best-effort: open a high-level ProgramDB (read-only) over the same handle
        // so we can read the memory map via the stable Memory API instead of the
        // version-specific raw "Memory Blocks" tables.  If the open fails (e.g. the
        // program's language isn't installed locally) we fall back to raw-table
        // reads only — every other category works without ProgramDB, so a missing
        // language must not block the entire import.
        Object consumer = new Object();
        ProgramDB program = null;
        try {
            program = new ProgramDB(db, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, consumer);
        } catch (Throwable t) {
            System.err.println("[ghidra-bridge] ProgramDB open failed; memory map unavailable: "
                + t.getClass().getSimpleName() + ": " + t.getMessage());
        }

        try {
            Map<Long, Long> addrMap = buildAddressMap(db);
            System.err.println("[ghidra-bridge] address map loaded: " + addrMap.size() + " segments");

            long imageBase = addrMap.getOrDefault(0L, 0L);
            // For raw/BinaryLoader-imported programs the ADDRESS MAP's first row
            // is 0 even when all memory lives at a non-zero base — which would
            // make the BN plugin rebase every address by the full BN load base.
            // Fall back to the lowest memory block start in that case.
            if (imageBase == 0 && program != null) {
                ghidra.program.model.address.Address min = program.getMemory().getMinAddress();
                if (min != null) imageBase = min.getOffset();
            }
            System.err.println("[ghidra-bridge] image_base=0x" + Long.toHexString(imageBase));

            JsonObject out = new JsonObject();
            out.addProperty("image_base", addrHex(imageBase));
            out.add("symbols",    exportSymbols(db, addrMap));
            out.add("comments",   exportComments(db, addrMap));
            out.add("func_flags", exportFunctions(db, addrMap));
            out.add("equates",    exportEquates(db, addrMap));
            out.add("bookmarks",  exportBookmarks(db, addrMap));
            out.add("parameters", exportParameters(db, addrMap));
            out.add("data_types", exportDataTypes(db));
            out.add("data_items", exportDataItems(db, addrMap));
            out.add("memory_blocks", program != null ? exportMemoryBlocks(program) : new JsonArray());
            out.add("xref_stats", exportCrossRefStats(db));
            return out;
        } finally {
            // Releasing the program closes the underlying DBHandle; only close the
            // handle directly when we never opened a ProgramDB over it.
            if (program != null) {
                try { program.release(consumer); } catch (Exception ignored) {}
            } else {
                db.close();
            }
        }
    }

    // -------------------------------------------------------------------------
    // Test seam
    // -------------------------------------------------------------------------

    /**
     * Export from an already-open DBHandle (no RMI / server required).
     * Package-private so tests in the same package can call it directly.
     */
    static JsonObject exportFromHandle(DBHandle db) throws IOException {
        Map<Long, Long> addrMap = buildAddressMap(db);
        JsonObject out = new JsonObject();
        out.addProperty("image_base", addrHex(addrMap.getOrDefault(0L, 0L)));
        out.add("symbols",    exportSymbols(db, addrMap));
        out.add("comments",   exportComments(db, addrMap));
        out.add("func_flags", exportFunctions(db, addrMap));
        out.add("equates",    exportEquates(db, addrMap));
        out.add("bookmarks",  exportBookmarks(db, addrMap));
        out.add("parameters", exportParameters(db, addrMap));
        out.add("data_types", exportDataTypes(db));
        out.add("data_items", exportDataItems(db, addrMap));
        out.add("xref_stats", exportCrossRefStats(db));
        return out;
    }

    // -------------------------------------------------------------------------
    // Address map
    // -------------------------------------------------------------------------

    private static Map<Long, Long> buildAddressMap(DBHandle db) {
        Map<Long, Long> map = new HashMap<>();
        Table table = db.getTable(ADDR_MAP_TABLE);
        if (table == null) {
            System.err.println("[ghidra-bridge] ADDRESS MAP table not found");
            return map;
        }
        try {
            RecordIterator iter = table.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                long rowKey = rec.getKey();
                long baseVA = readBaseVA(rec);
                map.put(rowKey, baseVA);
                System.err.println("[ghidra-bridge] addrmap row=0x"
                    + Long.toHexString(rowKey) + " base=0x" + Long.toHexString(baseVA));
            }
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] error reading ADDRESS MAP: "
                + e.getClass().getName() + ": " + e.getMessage());
        }
        return map;
    }

    /** Try every possible accessor for the base VA stored in ADDRESS MAP col 1 (then col 0). */
    private static long readBaseVA(DBRecord rec) {
        try { return rec.getLongValue(1); } catch (Exception ignored) {}
        try { return rec.getIntValue(1) & 0xFFFFFFFFL; } catch (Exception ignored) {}
        try { return rec.getLongValue(0); } catch (Exception ignored) {}
        try { return rec.getIntValue(0) & 0xFFFFFFFFL; } catch (Exception ignored) {}
        for (int col : new int[]{1, 0}) {
            try {
                byte[] b = rec.getBinaryData(col);
                if (b != null && b.length >= 4) {
                    long v = 0;
                    for (int i = 0; i < Math.min(b.length, 8); i++)
                        v = (v << 8) | (b[i] & 0xFF);
                    return v;
                }
            } catch (Exception ignored) {}
        }
        return 0;
    }

    /**
     * Decode a Ghidra-encoded address to a real virtual address.
     *
     * Returns -1 for addresses in the external import space (0x50000000),
     * local-var space (0x60000000), or any other non-RAM space.
     * Callers must skip symbols/comments where decode returns -1.
     */
    private static long decode(long encoded, Map<Long, Long> addrMap) {
        long segKey = encoded >> 32;
        long offset = encoded & 0xFFFFFFFFL;

        // Direct lookup — works when the ADDRESS MAP row key IS the full segKey.
        if (!addrMap.isEmpty()) {
            Long base = addrMap.get(segKey);
            if (base != null) return base + offset;

            // Old format: row key = lower byte of segKey, valid only for RAM space
            // (upper 24 bits of segKey == RAM_SPACE_PREFIX = 0x200000).
            if ((segKey >> 8) == RAM_SPACE_PREFIX) {
                base = addrMap.get(segKey & 0xFFL);
                if (base != null) return base + offset;
            }

            // Non-RAM space (external imports, stack, etc.) — no valid VA.
            return -1L;
        }

        // No address map available — return raw offset as best effort.
        return offset;
    }

    // -------------------------------------------------------------------------
    // Table exporters
    // -------------------------------------------------------------------------

    private static JsonArray exportSymbols(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table table = db.getTable(SYMBOLS_TABLE);
        if (table == null) return arr;

        RecordIterator iter = table.iterator();
        while (iter.hasNext()) {
            DBRecord rec = iter.next();

            byte type = rec.getByteValue(SYM_TYPE_COL);
            if (!isExportedType(type)) continue;

            String name = rec.getString(SYM_NAME_COL);
            if (name == null || name.isEmpty()) continue;

            long va = decode(rec.getLongValue(SYM_ADDR_COL), addrMap);
            if (va < 0) continue; // external or non-RAM space

            byte flags  = rec.getByteValue(SYM_FLAGS_COL);
            int  source = (flags >> SOURCE_SHIFT) & SOURCE_MASK;

            JsonObject sym = new JsonObject();
            sym.addProperty("key",    rec.getKey());
            sym.addProperty("name",   name);
            sym.addProperty("addr",   addrHex(va));
            // Normalize: C++ expects 4=FUNCTION regardless of Ghidra version ordinal.
            sym.addProperty("type",   normalizeType(type));
            sym.addProperty("source", source);
            sym.addProperty("ns",     rec.getLongValue(SYM_NAMESPACE_COL));
            arr.add(sym);
        }
        return arr;
    }

    private static JsonArray exportComments(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table table = db.getTable(COMMENTS_TABLE);
        if (table == null) return arr;

        RecordIterator iter = table.iterator();
        while (iter.hasNext()) {
            DBRecord rec = iter.next();

            String eol   = emptyIfNull(rec.getString(COMM_EOL_COL));
            String pre   = emptyIfNull(rec.getString(COMM_PRE_COL));
            String post  = emptyIfNull(rec.getString(COMM_POST_COL));
            String plate = emptyIfNull(rec.getString(COMM_PLATE_COL));
            String rep   = emptyIfNull(rec.getString(COMM_REP_COL));

            if (eol.isEmpty() && pre.isEmpty() && post.isEmpty()
                    && plate.isEmpty() && rep.isEmpty()) continue;

            long va = decode(rec.getKey(), addrMap);
            if (va < 0) continue; // external or non-RAM space

            JsonObject comm = new JsonObject();
            comm.addProperty("addr", addrHex(va));
            comm.addProperty("key",  addrHex(rec.getKey())); // encoded addr for write-back
            if (!eol.isEmpty())   comm.addProperty("eol",   eol);
            if (!pre.isEmpty())   comm.addProperty("pre",   pre);
            if (!post.isEmpty())  comm.addProperty("post",  post);
            if (!plate.isEmpty()) comm.addProperty("plate", plate);
            if (!rep.isEmpty())   comm.addProperty("rep",   rep);
            arr.add(comm);
        }
        return arr;
    }

    private static JsonArray exportFunctions(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table table = db.getTable(FUNCTIONS_TABLE);
        if (table == null) return arr;

        // Build typeId → name map (composite + enum + typedef)
        Map<Long, String> typeNameById = new HashMap<>();
        buildTypeNameMap(db, typeNameById);

        // The Function Data schema moved between adapter versions:
        //   V2 (older DBs):     col 1 = return type id, col 3 = CC name (string)
        //   V3 (Ghidra 11/12+): col 0 = return type id, col 1 = stack purge,
        //                       CC stored as a byte id (no name string column)
        // Detect by col 3's field class — StringField only in V2.
        boolean v2Schema = false;
        try {
            v2Schema = table.getSchema().getFields()[FUNC_CC_COL] instanceof db.StringField;
        } catch (Exception ignored) {}
        final int retTypeCol = v2Schema ? FUNC_RET_TYPE_COL : 0;

        RecordIterator iter = table.iterator();
        while (iter.hasNext()) {
            DBRecord rec = iter.next();
            byte flags = rec.getByteValue(FUNC_FLAGS_COL);

            // --- signature fields ---
            String cc = "";
            if (v2Schema) {
                try { cc = emptyIfNull(rec.getString(FUNC_CC_COL)); } catch (Exception ignored) {}
            }

            long retTypeId = -1L;
            String retTypeName = "";
            try { retTypeId = rec.getLongValue(retTypeCol); } catch (Exception ignored) {}
            if (retTypeId >= 0) retTypeName = typeNameById.getOrDefault(retTypeId, "");

            // Skip records with no useful data (no flags, no CC, no return type)
            if (flags == 0 && cc.isEmpty() && retTypeName.isEmpty()) continue;

            JsonObject f = new JsonObject();
            f.addProperty("key",         rec.getKey());
            f.addProperty("thunk",       (flags & FUNC_FLAG_THUNK)  != 0);
            f.addProperty("no_ret",      (flags & FUNC_FLAG_NRET)   != 0);
            f.addProperty("inline",      (flags & FUNC_FLAG_INLINE) != 0);
            f.addProperty("cc",          cc);
            f.addProperty("ret_type",    retTypeName);
            f.addProperty("ret_type_id", retTypeId);
            arr.add(f);
        }
        return arr;
    }

    /** Populate typeId → name from Composite, Enumeration, Typedef, and Built-In tables. */
    private static void buildTypeNameMap(DBHandle db, Map<Long, String> out) {
        // Composite (structs/unions) and Enumeration: name is col 0
        for (String tableName : new String[]{"Composite Data Types", "Enumeration Data Types"}) {
            Table t = db.getTable(tableName);
            if (t == null) continue;
            try {
                RecordIterator it = t.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String name = r.getString(0);
                    if (name != null && !name.isEmpty()) out.put(r.getKey(), name);
                }
            } catch (Exception ignored) {}
        }
        // Typedefs: name is col 2
        Table t = db.getTable("Typedefs");
        if (t != null) {
            try {
                RecordIterator it = t.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String name = r.getString(2);
                    if (name != null && !name.isEmpty()) out.put(r.getKey(), name);
                }
            } catch (Exception ignored) {}
        }
        // Built-in primitive types (int, char, void, etc.): name is col 0
        // Ghidra 12 names this table "Built-in datatypes"; older variants kept
        // for robustness against upgraded databases.
        for (String tableName : new String[]{"Built-in datatypes", "Built-In Data Types", "BuiltInTypes", "Built In Data Types"}) {
            Table bt = db.getTable(tableName);
            if (bt == null) continue;
            try {
                RecordIterator it = bt.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    // Try col 0 (display name) first; fall back to col 1 (class/internal name)
                    String name = null;
                    try { name = r.getString(0); } catch (Exception ignored2) {}
                    if (name == null || name.isEmpty()) {
                        try { name = r.getString(1); } catch (Exception ignored2) {}
                    }
                    if (name != null && !name.isEmpty()) out.put(r.getKey(), name);
                }
            } catch (Exception ignored) {}
            break; // stop at first matching table name
        }

        // Pointer types: col 0 = DataTypeId of referenced type (-1 = void *)
        // Two passes handle double pointers (pointer-to-pointer).
        for (int pass = 0; pass < 2; pass++) {
            Table ptrTable = db.getTable("Pointer Data Types");
            if (ptrTable == null) break;
            try {
                RecordIterator it = ptrTable.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    if (out.containsKey(r.getKey())) continue; // already resolved
                    long innerTypeId = -1L;
                    try { innerTypeId = r.getLongValue(0); } catch (Exception ignored2) {}
                    String innerName = (innerTypeId < 0) ? "void" : out.get(innerTypeId);
                    if (innerName != null && !innerName.isEmpty())
                        out.put(r.getKey(), innerName + " *");
                }
            } catch (Exception ignored) {}
        }

        // Array types: col 0 = element DataTypeId, col 2 = element count
        Table arrayTable = db.getTable("Array Data Types");
        if (arrayTable != null) {
            try {
                RecordIterator it = arrayTable.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    long innerTypeId = -1L;
                    int  elemCount   = 0;
                    try { innerTypeId = r.getLongValue(0); } catch (Exception ignored2) {}
                    try { elemCount   = r.getIntValue(2);  } catch (Exception ignored2) {
                        try { elemCount = r.getIntValue(1); } catch (Exception ignored3) {}
                    }
                    String innerName = (innerTypeId < 0) ? "" : out.getOrDefault(innerTypeId, "");
                    if (!innerName.isEmpty() && elemCount > 0)
                        out.put(r.getKey(), innerName + "[" + elemCount + "]");
                }
            } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // New exporters: equates, bookmarks, parameters, data types, data items, xref stats
    // -------------------------------------------------------------------------

    private static JsonArray exportEquates(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table equatesTable = db.getTable("Equates");
        Table refsTable    = db.getTable("Equate References");
        if (equatesTable == null) return arr;

        // Build equate id → {name, value}
        Map<Long, JsonObject> equateMap = new java.util.LinkedHashMap<>();
        RecordIterator eqIter = equatesTable.iterator();
        while (eqIter.hasNext()) {
            DBRecord rec = eqIter.next();
            JsonObject eq = new JsonObject();
            eq.addProperty("id",    rec.getKey());
            eq.addProperty("name",  rec.getString(0));
            eq.addProperty("value", rec.getLongValue(1));
            eq.add("refs", new JsonArray());
            equateMap.put(rec.getKey(), eq);
        }

        // Add refs
        if (refsTable != null) {
            RecordIterator refIter = refsTable.iterator();
            while (refIter.hasNext()) {
                DBRecord rec = refIter.next();
                long eqId    = rec.getLongValue(0);
                long encoded = rec.getLongValue(1);
                int  opIdx;
                try { opIdx = rec.getShortValue(2); }
                catch (Exception e) { opIdx = rec.getIntValue(2); }
                long va = decode(encoded, addrMap);
                if (va < 0) continue;
                JsonObject eq = equateMap.get(eqId);
                if (eq == null) continue;
                JsonObject ref = new JsonObject();
                ref.addProperty("addr",     addrHex(va));
                ref.addProperty("op_index", opIdx);
                eq.getAsJsonArray("refs").add(ref);
            }
        }

        for (JsonObject eq : equateMap.values()) {
            if (eq.getAsJsonArray("refs").size() > 0)
                arr.add(eq);
        }
        return arr;
    }

    private static JsonArray exportBookmarks(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table typesTable = db.getTable("Bookmark Types");
        if (typesTable == null) return arr;

        RecordIterator typeIter = typesTable.iterator();
        while (typeIter.hasNext()) {
            DBRecord typeRec = typeIter.next();
            long   typeId   = typeRec.getKey();
            String typeName = typeRec.getString(0);
            Table  bmTable  = db.getTable("Bookmarks" + typeId);
            if (bmTable == null) continue;
            RecordIterator bmIter = bmTable.iterator();
            while (bmIter.hasNext()) {
                DBRecord bm = bmIter.next();
                long encoded = bm.getLongValue(0);
                long va      = decode(encoded, addrMap);
                if (va < 0) continue;
                JsonObject obj = new JsonObject();
                obj.addProperty("type",     typeName);
                obj.addProperty("addr",     addrHex(va));
                obj.addProperty("category", emptyIfNull(bm.getString(1)));
                obj.addProperty("comment",  emptyIfNull(bm.getString(2)));
                arr.add(obj);
            }
        }
        return arr;
    }

    private static JsonArray exportParameters(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table table = db.getTable("Symbols");
        if (table == null) return arr;

        // Build typeId → name map for resolving DataTypeId (col 7)
        Map<Long, String> typeNameById = new HashMap<>();
        buildTypeNameMap(db, typeNameById);

        RecordIterator iter = table.iterator();
        while (iter.hasNext()) {
            DBRecord rec = iter.next();
            byte type = rec.getByteValue(3);
            if (type != 6 && type != 7) continue;  // PARAMETER=6, LOCAL_VAR=7
            String name = rec.getString(0);
            if (name == null || name.isEmpty()) continue;
            long encodedFuncAddr = rec.getLongValue(1);
            long funcVa = decode(encodedFuncAddr, addrMap);
            if (funcVa < 0) continue;
            long varOffset = rec.getLongValue(8);

            long dataTypeId = -1L;
            String typeName = "";
            try { dataTypeId = rec.getLongValue(7); } catch (Exception ignored) {}
            if (dataTypeId >= 0) typeName = typeNameById.getOrDefault(dataTypeId, "");

            JsonObject p = new JsonObject();
            p.addProperty("key",       rec.getKey());
            p.addProperty("func_addr", addrHex(funcVa));
            p.addProperty("name",      name);
            p.addProperty("is_param",  type == 6);
            p.addProperty("ordinal",   (int)(varOffset & 0xFFFFFFFFL)); // use varoffset as ordinal proxy
            p.addProperty("type_name", typeName);
            p.addProperty("type_id",   dataTypeId);
            arr.add(p);
        }
        return arr;
    }

    private static JsonArray exportDataTypes(DBHandle db) throws IOException {
        JsonArray arr = new JsonArray();

        // Build typeId → name map for resolving underlying type names in typedefs
        Map<Long, String> typeNameById = new HashMap<>();
        buildTypeNameMap(db, typeNameById);

        // Build component map: parentId -> list of components
        Map<Long, java.util.List<JsonObject>> componentMap = new java.util.LinkedHashMap<>();
        // Build typeId→name map before scanning components so we can resolve member types
        Map<Long, String> typeNameById2 = new HashMap<>();
        buildTypeNameMap(db, typeNameById2);

        Table compTable = db.getTable("Component Data Types");
        if (compTable != null) {
            RecordIterator iter = compTable.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                long parentId  = rec.getLongValue(0);
                long memberTypeId = rec.getLongValue(2);
                String memberTypeName = typeNameById2.getOrDefault(memberTypeId, "");
                JsonObject m = new JsonObject();
                m.addProperty("offset",    rec.getIntValue(1));
                m.addProperty("type_id",   memberTypeId);
                m.addProperty("type_name", memberTypeName);
                m.addProperty("name",      emptyIfNull(rec.getString(3)));
                m.addProperty("comment",   emptyIfNull(rec.getString(4)));
                m.addProperty("size",      rec.getIntValue(5));
                m.addProperty("ordinal",   rec.getIntValue(6));
                componentMap.computeIfAbsent(parentId, k -> new ArrayList<>()).add(m);
            }
        }

        // Export structs/unions
        Table compositeTable = db.getTable("Composite Data Types");
        if (compositeTable != null) {
            RecordIterator iter = compositeTable.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                boolean isUnion;
                try { isUnion = rec.getBooleanValue(2); }
                catch (Exception e) { isUnion = rec.getByteValue(2) != 0; }
                JsonObject dt = new JsonObject();
                dt.addProperty("id",      rec.getKey());
                dt.addProperty("kind",    isUnion ? "union" : "struct");
                dt.addProperty("name",    emptyIfNull(rec.getString(0)));
                dt.addProperty("comment", emptyIfNull(rec.getString(1)));
                dt.addProperty("size",    rec.getIntValue(4));
                JsonArray members = new JsonArray();
                java.util.List<JsonObject> mList = componentMap.getOrDefault(rec.getKey(), Collections.emptyList());
                mList.sort((a, b) -> a.get("ordinal").getAsInt() - b.get("ordinal").getAsInt());
                for (JsonObject m : mList) members.add(m);
                dt.add("members", members);
                arr.add(dt);
            }
        }

        // Build enum values map: enumId -> list of values
        Map<Long, java.util.List<JsonObject>> enumValMap = new java.util.LinkedHashMap<>();
        Table enumValTable = db.getTable("Enumeration Values");
        if (enumValTable != null) {
            RecordIterator iter = enumValTable.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                long enumId = rec.getLongValue(2);
                JsonObject v = new JsonObject();
                v.addProperty("name",    emptyIfNull(rec.getString(0)));
                v.addProperty("value",   rec.getLongValue(1));
                v.addProperty("comment", emptyIfNull(rec.getString(3)));
                enumValMap.computeIfAbsent(enumId, k -> new ArrayList<>()).add(v);
            }
        }

        // Export enums
        Table enumTable = db.getTable("Enumeration Data Types");
        if (enumTable != null) {
            RecordIterator iter = enumTable.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                JsonObject dt = new JsonObject();
                dt.addProperty("id",      rec.getKey());
                dt.addProperty("kind",    "enum");
                dt.addProperty("name",    emptyIfNull(rec.getString(0)));
                dt.addProperty("comment", emptyIfNull(rec.getString(1)));
                dt.addProperty("size",    rec.getByteValue(3) & 0xFF);
                JsonArray values = new JsonArray();
                for (JsonObject v : enumValMap.getOrDefault(rec.getKey(), Collections.emptyList()))
                    values.add(v);
                dt.add("values", values);
                arr.add(dt);
            }
        }

        // Build typeId → size map for resolving typedef sizes (composites + enums)
        Map<Long, Integer> typeIdToSize = new HashMap<>();
        if (compositeTable != null) {
            try {
                RecordIterator it = compositeTable.iterator();
                while (it.hasNext()) { DBRecord r = it.next(); typeIdToSize.put(r.getKey(), r.getIntValue(4)); }
            } catch (Exception ignored) {}
        }
        if (enumTable != null) {
            try {
                RecordIterator it = enumTable.iterator();
                while (it.hasNext()) { DBRecord r = it.next(); typeIdToSize.put(r.getKey(), (int)(r.getByteValue(3) & 0xFF)); }
            } catch (Exception ignored) {}
        }

        // Export typedefs
        Table typedefTable = db.getTable("Typedefs");
        if (typedefTable != null) {
            RecordIterator iter = typedefTable.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                long underlyingId = -1L;
                String underlyingName = "";
                try { underlyingId = rec.getLongValue(0); } catch (Exception ignored) {}
                if (underlyingId >= 0) underlyingName = typeNameById.getOrDefault(underlyingId, "");
                // Resolve size from underlying composite/enum; 0 for pointer/built-in (BN infers it)
                int resolvedSize = typeIdToSize.getOrDefault(underlyingId, 0);

                JsonObject dt = new JsonObject();
                dt.addProperty("id",                  rec.getKey());
                dt.addProperty("kind",                "typedef");
                dt.addProperty("name",                emptyIfNull(rec.getString(2)));
                dt.addProperty("underlying_type_id",  underlyingId);
                dt.addProperty("underlying_name",     underlyingName);
                dt.addProperty("size",                resolvedSize);
                arr.add(dt);
            }
        }

        return arr;
    }

    private static JsonArray exportDataItems(DBHandle db, Map<Long, Long> addrMap) throws IOException {
        JsonArray arr = new JsonArray();
        Table table = db.getTable("Data");
        if (table == null) return arr;
        RecordIterator iter = table.iterator();
        while (iter.hasNext()) {
            DBRecord rec = iter.next();
            long encoded = rec.getKey();  // key IS the encoded address
            long va = decode(encoded, addrMap);
            if (va < 0) continue;
            JsonObject item = new JsonObject();
            item.addProperty("addr",    addrHex(va));
            item.addProperty("type_id", rec.getLongValue(0));
            arr.add(item);
        }
        return arr;
    }

    /**
     * Export Ghidra's memory map via the high-level Memory API.
     *
     * Read through ProgramDB rather than the raw "Memory Blocks" / "Sub Memory
     * Blocks" tables because that schema is version-specific and fragile (the
     * same class of trap the checkin write path avoids).  {@link MemoryBlock} is
     * a stable API across Ghidra versions.
     *
     * Overlay blocks and any block not in the default address space are flagged
     * so the BN side can skip them — the plugin assumes a single RAM space.
     *
     * Package-private so the round-trip test can call it with a ProgramBuilder
     * program directly.
     */
    static JsonArray exportMemoryBlocks(ProgramDB program) {
        JsonArray arr = new JsonArray();
        try {
            AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
            for (MemoryBlock b : program.getMemory().getBlocks()) {
                Address start = b.getStart();
                boolean overlay = b.isOverlay()
                    || !start.getAddressSpace().equals(defSpace);

                JsonObject o = new JsonObject();
                o.addProperty("name",        b.getName());
                o.addProperty("addr",        addrHex(start.getOffset()));
                o.addProperty("size",        addrHex(b.getSize()));
                o.addProperty("r",           b.isRead());
                o.addProperty("w",           b.isWrite());
                o.addProperty("x",           b.isExecute());
                o.addProperty("initialized", b.isInitialized());
                o.addProperty("overlay",     overlay);
                arr.add(o);
            }
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] memory block export error: " + e.getMessage());
        }
        System.err.println("[ghidra-bridge] memory blocks exported: " + arr.size());
        return arr;
    }

    private static JsonObject exportCrossRefStats(DBHandle db) {
        JsonObject stats = new JsonObject();
        Table fromTable = db.getTable("FROM REFS");
        Table toTable   = db.getTable("TO REFS");
        stats.addProperty("from_count", fromTable != null ? fromTable.getRecordCount() : 0);
        stats.addProperty("to_count",   toTable   != null ? toTable.getRecordCount()   : 0);
        return stats;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static boolean isExportedType(byte type) {
        return type == SYM_TYPE_LABEL
            || type == SYM_TYPE_FUNCTION_OLD
            || type == SYM_TYPE_FUNCTION_NEW
            || type == SYM_TYPE_EXTERNAL;
    }

    /**
     * Normalize the Ghidra symbol type for the C++ side.
     * C++ GhidraSymbolType enum expects: Label=0, Function=4, External=8.
     * Ghidra 11+ uses ordinal 5 for FUNCTION; map it back to 4.
     */
    private static int normalizeType(byte type) {
        if (type == SYM_TYPE_FUNCTION_NEW) return SYM_TYPE_FUNCTION_OLD;
        return type & 0xFF;
    }

    private static String addrHex(long addr) {
        return "0x" + Long.toUnsignedString(addr, 16);
    }

    private static String emptyIfNull(String s) {
        return s == null ? "" : s;
    }
}
