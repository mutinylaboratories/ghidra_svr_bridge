package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import db.DBHandle;
import db.DBRecord;
import db.Table;
import db.buffers.ManagedBufferFileAdapter;
import db.buffers.ManagedBufferFileHandle;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Applies symbol renames and comment updates from Binary Ninja to a
 * Ghidra program database, then checks in the new version.
 *
 * The caller must hold an exclusive checkout for the item before calling
 * apply(); the checkout is implicitly committed by db.save() and should
 * be terminated by the caller afterwards.
 */
public class DatabaseImporter {

    private static final String SYMBOLS_TABLE  = "Symbols";
    private static final int SYM_NAME_COL      = 0;
    private static final int SYM_ADDR_COL      = 1;  // LongField (encoded address key)
    private static final int SYM_NAMESPACE_COL = 2;  // LongField
    private static final int SYM_TYPE_COL      = 3;  // ByteField
    private static final int SYM_FLAGS_COL     = 4;
    private static final int SOURCE_SHIFT      = 6;

    private static final String COMMENTS_TABLE = "Comments";
    private static final int COMM_EOL_COL      = 0;
    private static final int COMM_PRE_COL      = 1;
    private static final int COMM_POST_COL     = 2;
    private static final int COMM_PLATE_COL    = 3;
    private static final int COMM_REP_COL      = 4;

    /**
     * Apply changes and create a new version on the server.
     *
     * @param handle           writable handle obtained from openDatabase(folder,item,checkoutId)
     * @param symbols          JSON array of {key, name} — renamed symbols only
     * @param comments         JSON array of {key, eol?, pre?, post?, plate?, rep?}
     * @param equateRenames    JSON array of {id, name} — equate renames (may be null/empty)
     * @param bookmarkChanges  JSON array of {op, type, addr, category, comment} (may be null/empty)
     * @param paramRenames     JSON array of {key, name} — parameter/local-var renames (may be null/empty)
     * @param dataTypeChanges  JSON array of data type add/update ops (may be null/empty)
     * @param dataItemChanges  JSON array of {op, addr, type_name} — data item add/delete ops (may be null/empty)
     * @param funcSigChanges   JSON array of {key, cc?, ret_type?} — function signature changes (may be null/empty)
     * @param versionComment   comment for the new version
     */
    public static JsonObject apply(ManagedBufferFileHandle handle,
                              JsonArray symbols,
                              JsonArray comments,
                              JsonArray equateRenames,
                              JsonArray equateRefAdds,
                              JsonArray bookmarkChanges,
                              JsonArray paramRenames,
                              JsonArray dataTypeChanges,
                              JsonArray dataItemChanges,
                              JsonArray funcSigChanges,
                              String versionComment) throws IOException {
        // Production checkin now goes through ProgramApplier, which uses the
        // high-level ProgramDB / DataTypeManager / SymbolTable / FunctionManager
        // APIs.  The raw-table-write helpers below (applySymbols, applyComments,
        // applyDataTypeChanges, etc.) are kept solely so the existing unit tests
        // continue to exercise them against an in-memory DBHandle — they are not
        // called from the live checkin path.
        handle.setVersionComment(versionComment != null ? versionComment : "");
        return ProgramApplier.apply(handle, symbols, comments, equateRenames,
            equateRefAdds, bookmarkChanges, paramRenames, dataTypeChanges,
            dataItemChanges, funcSigChanges, versionComment);
    }

    /**
     * Convenience overload that omits the new fields — used by older callers
     * that only send symbols and comments.
     */
    public static JsonObject apply(ManagedBufferFileHandle handle,
                              JsonArray symbols,
                              JsonArray comments,
                              String versionComment) throws IOException {
        return apply(handle, symbols, comments, null, null, null, null, null, null, null, versionComment);
    }

    // -------------------------------------------------------------------------
    // Test seam — lets unit tests apply changes to an in-memory DBHandle
    // without needing a real Ghidra server or ManagedBufferFileHandle.
    // -------------------------------------------------------------------------

    /**
     * Apply symbol renames and comment updates to an already-open DBHandle.
     * Manages the transaction internally; does NOT call db.save().
     * Package-private so tests in the same package can call it directly.
     */
    static void applyToHandle(DBHandle db,
                               JsonArray symbols,
                               JsonArray comments) throws IOException {
        long txId = db.startTransaction();
        try {
            if (symbols  != null && symbols.size()  > 0) applySymbols(db, symbols);
            if (comments != null && comments.size() > 0) applyComments(db, comments);
            db.endTransaction(txId, true);
        } catch (IOException | RuntimeException e) {
            db.endTransaction(txId, false);
            if (e instanceof IOException) throw (IOException) e;
            throw new IOException(e);
        }
    }

    // -------------------------------------------------------------------------

    static void applyEquateRefAdds(DBHandle db, JsonArray equateRefAdds) throws IOException {
        Table refsTable = db.getTable("Equate References");
        if (refsTable == null) {
            System.err.println("[ghidra-bridge] WARNING: 'Equate References' table not found — skipping equate ref adds");
            return;
        }

        Map<Long, Long> addrMap = buildAddrMap(db);

        // Build a set of existing (equateId, encodedAddr, opIdx) tuples to avoid duplicates.
        java.util.Set<String> existing = new java.util.HashSet<>();
        {
            db.RecordIterator scanIter = refsTable.iterator();
            while (scanIter.hasNext()) {
                DBRecord r = scanIter.next();
                long eqId   = r.getLongValue(0);
                long enc    = r.getLongValue(1);
                int  opIdx;
                try { opIdx = r.getShortValue(2); } catch (Exception e) { opIdx = r.getIntValue(2); }
                existing.add(eqId + ":" + enc + ":" + opIdx);
            }
        }

        int count = 0;
        for (JsonElement el : equateRefAdds) {
            JsonObject r = el.getAsJsonObject();
            long equateId = r.has("id")       ? r.get("id").getAsLong()       : -1L;
            long va       = r.has("va")       ? parseHexLong(r.get("va").getAsString()) : -1L;
            int  opIdx    = r.has("op_index") ? r.get("op_index").getAsInt()  : 0;

            if (equateId < 0 || va < 0) continue;

            long encodedAddr = encodeVA(va, addrMap);
            if (encodedAddr < 0) {
                System.err.println("[ghidra-bridge] equate ref add: cannot encode VA 0x"
                    + Long.toHexString(va) + " — skipping");
                continue;
            }

            String key = equateId + ":" + encodedAddr + ":" + opIdx;
            if (existing.contains(key)) continue; // already exists

            long newKey = refsTable.getMaxKey() + 1;
            DBRecord newRec = refsTable.getSchema().createRecord(newKey);
            newRec.setLongValue(0, equateId);
            newRec.setLongValue(1, encodedAddr);
            try { newRec.setShortValue(2, (short)opIdx); }
            catch (Exception e) { newRec.setIntValue(2, opIdx); }
            refsTable.putRecord(newRec);
            existing.add(key);
            ++count;
        }
        System.err.println("[ghidra-bridge] equate refs added: " + count);
    }

    static void applyEquateRenames(DBHandle db, JsonArray equateRenames) throws IOException {
        Table table = db.getTable("Equates");
        if (table == null) return;
        for (JsonElement el : equateRenames) {
            JsonObject r  = el.getAsJsonObject();
            long   key    = r.get("id").getAsLong();
            String name   = r.get("name").getAsString();
            if (name == null || name.isEmpty()) continue;
            DBRecord rec = table.getRecord(key);
            if (rec == null) continue;
            rec.setString(0, name);
            table.putRecord(rec);
        }
    }

    static void applyBookmarkChanges(DBHandle db, JsonArray bookmarkChanges,
                                      Map<Long, Long> addrMap) throws IOException {
        Table typesTable = db.getTable("Bookmark Types");
        if (typesTable == null) return;

        // Build name -> id map for existing types
        Map<String, Long> typeIdByName = new HashMap<>();
        db.RecordIterator typeIter = typesTable.iterator();
        while (typeIter.hasNext()) {
            DBRecord rec = typeIter.next();
            typeIdByName.put(rec.getString(0), rec.getKey());
        }

        for (JsonElement el : bookmarkChanges) {
            JsonObject c  = el.getAsJsonObject();
            String op       = c.has("op")       ? c.get("op").getAsString()       : "add";
            String typeName = c.has("type")     ? c.get("type").getAsString()     : "Note";
            String addrStr  = c.has("addr")     ? c.get("addr").getAsString()     : "0x0";
            String category = c.has("category") ? c.get("category").getAsString() : "";
            String comment  = c.has("comment")  ? c.get("comment").getAsString()  : "";
            long va = parseHexLong(addrStr);

            // Get or create type
            Long typeId = typeIdByName.get(typeName);
            if (typeId == null) {
                if (!"add".equals(op)) continue;
                DBRecord typeRec = typesTable.getSchema().createRecord(typesTable.getMaxKey() + 1);
                typeRec.setString(0, typeName);
                typesTable.putRecord(typeRec);
                typeId = typeRec.getKey();
                typeIdByName.put(typeName, typeId);
            }

            Table bmTable = db.getTable("Bookmarks" + typeId);
            if (bmTable == null) continue;

            // Encode VA to find/create record
            long encoded = encodeVA(va, addrMap);
            if (encoded < 0) continue;

            if ("delete".equals(op)) {
                db.RecordIterator iter = bmTable.iterator();
                while (iter.hasNext()) {
                    DBRecord rec = iter.next();
                    if (rec.getLongValue(0) == encoded) {
                        bmTable.deleteRecord(rec.getKey());
                        break;
                    }
                }
            } else {
                Long existingKey = null;
                db.RecordIterator iter = bmTable.iterator();
                while (iter.hasNext()) {
                    DBRecord rec = iter.next();
                    if (rec.getLongValue(0) == encoded) {
                        existingKey = rec.getKey();
                        break;
                    }
                }
                DBRecord rec = (existingKey != null)
                    ? bmTable.getRecord(existingKey)
                    : bmTable.getSchema().createRecord(bmTable.getMaxKey() + 1);
                rec.setLongValue(0, encoded);
                rec.setString(1, category);
                rec.setString(2, comment);
                bmTable.putRecord(rec);
            }
        }
    }

    static void applyParameterRenames(DBHandle db, JsonArray paramRenames) throws IOException {
        Table table = db.getTable("Symbols");
        if (table == null) return;

        // Full type-name → id map (composite + enum + typedef + built-ins)
        Map<String, Long> typeIdByName = buildTypeIdByName(db);

        // Lazily built only when we encounter a func_va-based (new) param entry.
        Map<Long, Long> addrMap = null;
        // encodedFuncAddr → function symbol key — needed as the namespace for new params.
        Map<Long, Long> funcEncodedAddrToSymKey = null;

        int count = 0;
        for (JsonElement el : paramRenames) {
            JsonObject c  = el.getAsJsonObject();
            String name = c.has("name") ? c.get("name").getAsString() : "";
            if (name == null || name.isEmpty()) continue;

            DBRecord rec = null;

            if (c.has("key")) {
                // ── Existing param: look up by DB key ─────────────────────────────────
                long key = c.get("key").getAsLong();
                rec = table.getRecord(key);
                if (rec == null) continue;
                byte type = rec.getByteValue(SYM_TYPE_COL);
                if (type != 6 && type != 7) continue;  // must be PARAMETER or LOCAL_VAR

            } else if (c.has("func_va") && c.has("ordinal")) {
                // ── New param (no Ghidra key): create a PARAMETER symbol record ────────
                if (addrMap == null) addrMap = buildAddrMap(db);

                long funcVa = parseHexLong(c.get("func_va").getAsString());
                long encodedFuncAddr = encodeVA(funcVa, addrMap);
                if (encodedFuncAddr < 0) {
                    System.err.println("[ghidra-bridge] new param: cannot encode func VA 0x"
                        + Long.toHexString(funcVa) + " — skipping");
                    continue;
                }

                // Build the func-addr → symbol-key map on first use.
                if (funcEncodedAddrToSymKey == null) {
                    funcEncodedAddrToSymKey = new HashMap<>();
                    db.RecordIterator scanIter = table.iterator();
                    while (scanIter.hasNext()) {
                        DBRecord r = scanIter.next();
                        byte t = r.getByteValue(SYM_TYPE_COL);
                        if (t != 4 && t != 5) continue;  // FUNCTION types only
                        long ea = r.getLongValue(SYM_ADDR_COL);
                        if (!funcEncodedAddrToSymKey.containsKey(ea))
                            funcEncodedAddrToSymKey.put(ea, r.getKey());
                    }
                }

                int ordinal = c.get("ordinal").getAsInt();
                Long funcSymKey = funcEncodedAddrToSymKey.get(encodedFuncAddr);
                long namespaceId = (funcSymKey != null) ? funcSymKey : 0L;

                // is_local=true → LOCAL_VAR (type=7, ordinal = BN register index)
                // is_local=false → PARAMETER (type=6, ordinal = 0-based param index)
                boolean isLocal = c.has("is_local") && c.get("is_local").getAsBoolean();
                byte symType = isLocal ? (byte)7 : (byte)6;

                long newKey = table.getMaxKey() + 1;
                DBRecord newRec = table.getSchema().createRecord(newKey);
                newRec.setString(SYM_NAME_COL, name);
                newRec.setLongValue(SYM_ADDR_COL, encodedFuncAddr);
                newRec.setLongValue(SYM_NAMESPACE_COL, namespaceId);
                newRec.setByteValue(SYM_TYPE_COL, symType);
                newRec.setByteValue(SYM_FLAGS_COL, (byte)(3 << SOURCE_SHIFT)); // USER_DEFINED
                // col 8 = varOffset: ordinal for params, BN register index for reg locals
                // (Ghidra register IDs differ from BN's, but this is a best-effort record)
                try { newRec.setLongValue(8, (long)ordinal); } catch (Exception ignored) {}

                if (c.has("type_name") && !c.get("type_name").getAsString().isEmpty()) {
                    String tn = c.get("type_name").getAsString().trim();
                    Long tid = typeIdByName.get(tn);
                    if (tid == null) tid = typeIdByName.get(tn.split("[\\s\\*\\[<]+")[0]);
                    if (tid != null) {
                        try { newRec.setLongValue(7, tid); } catch (Exception ignored) {}
                    }
                }

                table.putRecord(newRec);
                ++count;
                continue; // already fully written

            } else {
                continue;
            }

            // ── Common update path: rename + promote to USER_DEFINED ─────────────────
            rec.setString(SYM_NAME_COL, name);
            byte flags = rec.getByteValue(SYM_FLAGS_COL);
            flags = (byte)((flags & 0x3F) | (3 << SOURCE_SHIFT));
            rec.setByteValue(SYM_FLAGS_COL, flags);

            if (c.has("type_name") && !c.get("type_name").getAsString().isEmpty()) {
                String tn = c.get("type_name").getAsString().trim();
                Long tid = typeIdByName.get(tn);
                if (tid == null) tid = typeIdByName.get(tn.split("[\\s\\*\\[<]+")[0]);
                if (tid != null) {
                    try { rec.setLongValue(7, tid); } catch (Exception ignored) {}
                }
            }

            table.putRecord(rec);
            ++count;
        }
        System.err.println("[ghidra-bridge] param renames/additions applied: " + count);
    }

    static Map<String, Long> applyToHandle(DBHandle db,
                               JsonArray symbols,
                               JsonArray comments,
                               JsonArray equateRenames,
                               JsonArray equateRefAdds,
                               JsonArray bookmarkChanges,
                               JsonArray paramRenames,
                               JsonArray dataTypeChanges,
                               JsonArray dataItemChanges,
                               JsonArray funcSigChanges) throws IOException {
        Map<String, Long> addedTypeIds = new HashMap<>();
        long txId = db.startTransaction();
        try {
            if (symbols          != null && symbols.size()          > 0) applySymbols(db, symbols);
            if (comments         != null && comments.size()         > 0) applyComments(db, comments);
            if (equateRenames    != null && equateRenames.size()    > 0) applyEquateRenames(db, equateRenames);
            if (equateRefAdds    != null && equateRefAdds.size()    > 0) applyEquateRefAdds(db, equateRefAdds);
            if (bookmarkChanges != null && bookmarkChanges.size() > 0) {
                Map<Long, Long> addrMap = buildAddrMap(db);
                applyBookmarkChanges(db, bookmarkChanges, addrMap);
            }
            if (paramRenames     != null && paramRenames.size()     > 0) applyParameterRenames(db, paramRenames);
            if (dataTypeChanges  != null && dataTypeChanges.size()  > 0)
                addedTypeIds.putAll(applyDataTypeChanges(db, dataTypeChanges));
            if (dataItemChanges  != null && dataItemChanges.size()  > 0) applyDataItems(db, dataItemChanges);
            if (funcSigChanges   != null && funcSigChanges.size()   > 0) applyFuncSigChanges(db, funcSigChanges);
            db.endTransaction(txId, true);
        } catch (IOException | RuntimeException e) {
            db.endTransaction(txId, false);
            if (e instanceof IOException) throw (IOException) e;
            throw new IOException(e);
        }
        return addedTypeIds;
    }

    // -------------------------------------------------------------------------

    static Map<String, Long> applyDataTypeChanges(DBHandle db, JsonArray changes) throws IOException {
        Map<String, Long> addedIds = new HashMap<>(); // name → assigned DB key for op=add entries
        Table compositeTable = db.getTable("Composite Data Types");
        Table componentTable = db.getTable("Component Data Types");
        Table enumTable      = db.getTable("Enumeration Data Types");
        Table enumValTable   = db.getTable("Enumeration Values");

        // Full type-name → id map (composite + enum + typedef + built-ins)
        Map<String, Long> typeIdByName = buildTypeIdByName(db);

        for (JsonElement el : changes) {
            JsonObject c    = el.getAsJsonObject();
            String op       = c.has("op")       ? c.get("op").getAsString()       : "add";
            String kind     = c.has("kind")     ? c.get("kind").getAsString()     : "";
            String name     = c.has("name")     ? c.get("name").getAsString()     : "";
            long   ghidraId = c.has("ghidra_id") ? c.get("ghidra_id").getAsLong() : 0L;
            int    size     = c.has("size")     ? c.get("size").getAsInt()        : 0;
            if (name.isEmpty()) continue;

            if ("delete".equals(op)) {
                // Remove the type and its children from the appropriate table.
                if (("struct".equals(kind) || "union".equals(kind)) && compositeTable != null && ghidraId > 0) {
                    // Delete components first
                    if (componentTable != null) {
                        db.RecordIterator iter = componentTable.iterator();
                        List<Long> toDelete = new ArrayList<>();
                        while (iter.hasNext()) {
                            DBRecord r = iter.next();
                            if (r.getLongValue(0) == ghidraId) toDelete.add(r.getKey());
                        }
                        for (long k : toDelete) componentTable.deleteRecord(k);
                    }
                    compositeTable.deleteRecord(ghidraId);
                } else if ("enum".equals(kind) && enumTable != null && ghidraId > 0) {
                    // Delete enum values first
                    if (enumValTable != null) {
                        db.RecordIterator iter = enumValTable.iterator();
                        List<Long> toDelete = new ArrayList<>();
                        while (iter.hasNext()) {
                            DBRecord r = iter.next();
                            if (r.getLongValue(2) == ghidraId) toDelete.add(r.getKey());
                        }
                        for (long k : toDelete) enumValTable.deleteRecord(k);
                    }
                    enumTable.deleteRecord(ghidraId);
                } else if ("typedef".equals(kind)) {
                    Table typedefTable = db.getTable("Typedefs");
                    if (typedefTable != null && ghidraId > 0)
                        typedefTable.deleteRecord(ghidraId);
                }
                continue;
            }

            if ("struct".equals(kind) || "union".equals(kind)) {
                if (compositeTable == null) continue;
                boolean isUnion = "union".equals(kind);

                // Find or create the composite record
                long compositeId = ghidraId;
                DBRecord compRec = (compositeId > 0) ? compositeTable.getRecord(compositeId) : null;
                if (compRec == null) {
                    compositeId = compositeTable.getMaxKey() + 1;
                    compRec = compositeTable.getSchema().createRecord(compositeId);
                }
                JsonArray members = c.has("members") ? c.get("members").getAsJsonArray() : new JsonArray();
                // Preserve existing composite-level comment; only blank it for brand-new records
                String existingTypeComment = "";
                try { existingTypeComment = compRec.getString(1); } catch (Exception ignored) {}
                compRec.setString(0, name);
                compRec.setString(1, existingTypeComment != null ? existingTypeComment : "");
                compRec.setBooleanValue(2, isUnion);  // col 2 is BooleanField in Ghidra V5V6 schema
                compRec.setLongValue(3, 0L);
                compRec.setIntValue(4, size);
                compRec.setIntValue(5, 1);
                compRec.setIntValue(6, members.size());
                compositeTable.putRecord(compRec);
                if ("add".equals(op)) addedIds.put(name, compositeId);

                // Read existing member comments (keyed by "offset:name") before deleting them
                Map<String, String> savedMemberComments = new HashMap<>();
                // Delete old components if updating
                if ("update".equals(op) && componentTable != null) {
                    db.RecordIterator iter = componentTable.iterator();
                    List<Long> toDelete = new ArrayList<>();
                    while (iter.hasNext()) {
                        DBRecord r = iter.next();
                        if (r.getLongValue(0) == compositeId) {
                            toDelete.add(r.getKey());
                            String cmt = r.getString(4);
                            if (cmt != null && !cmt.isEmpty()) {
                                String n = r.getString(3);
                                savedMemberComments.put(r.getIntValue(1) + ":" + (n != null ? n : ""), cmt);
                            }
                        }
                    }
                    for (long key : toDelete) componentTable.deleteRecord(key);
                }

                // Insert components
                if (componentTable != null) {
                    int ordinal = 0;
                    for (JsonElement mel : members) {
                        JsonObject m = mel.getAsJsonObject();
                        // Resolve member DataTypeId from type_name; fall back to -1 (unknown)
                        long memberTypeId = -1L;
                        if (m.has("type_name") && !m.get("type_name").getAsString().isEmpty()) {
                            String tn = m.get("type_name").getAsString().trim();
                            // Try full name first ("MyStruct *"), then strip suffixes
                            Long tid = typeIdByName.get(tn);
                            if (tid == null) tid = typeIdByName.get(tn.split("[\\s\\*\\[<]+")[0]);
                            if (tid != null) memberTypeId = tid;
                        }
                        int    mOffset = m.has("offset") ? m.get("offset").getAsInt() : 0;
                        String mName   = m.has("name")   ? m.get("name").getAsString() : "";
                        // Preserve existing Ghidra member comment if BN sends none
                        String mComment = m.has("comment") ? m.get("comment").getAsString() : "";
                        if (mComment.isEmpty())
                            mComment = savedMemberComments.getOrDefault(mOffset + ":" + mName, "");
                        long compKey = componentTable.getMaxKey() + 1;
                        DBRecord compRec2 = componentTable.getSchema().createRecord(compKey);
                        compRec2.setLongValue(0, compositeId);
                        compRec2.setIntValue(1, mOffset);
                        compRec2.setLongValue(2, memberTypeId);
                        compRec2.setString(3, mName);
                        compRec2.setString(4, mComment);
                        compRec2.setIntValue(5, m.has("size") ? m.get("size").getAsInt() : 0);
                        compRec2.setIntValue(6, ordinal++);
                        componentTable.putRecord(compRec2);
                    }
                }

            } else if ("enum".equals(kind)) {
                if (enumTable == null) continue;

                long enumId = ghidraId;
                DBRecord enumRec = (enumId > 0) ? enumTable.getRecord(enumId) : null;
                if (enumRec == null) {
                    enumId = enumTable.getMaxKey() + 1;
                    enumRec = enumTable.getSchema().createRecord(enumId);
                }
                enumRec.setString(0, name);
                enumRec.setString(1, "");
                enumRec.setLongValue(2, 0L);
                enumRec.setByteValue(3, (byte)(size > 0 ? size : 4));
                enumTable.putRecord(enumRec);
                if ("add".equals(op)) addedIds.put(name, enumId);

                // Delete old values if updating
                if ("update".equals(op) && enumValTable != null) {
                    db.RecordIterator iter = enumValTable.iterator();
                    List<Long> toDelete = new ArrayList<>();
                    while (iter.hasNext()) {
                        DBRecord r = iter.next();
                        if (r.getLongValue(2) == enumId) toDelete.add(r.getKey());
                    }
                    for (long key : toDelete) enumValTable.deleteRecord(key);
                }

                // Insert values
                if (enumValTable != null) {
                    JsonArray values = c.has("values") ? c.get("values").getAsJsonArray() : new JsonArray();
                    for (JsonElement vel : values) {
                        JsonObject v = vel.getAsJsonObject();
                        long valKey = enumValTable.getMaxKey() + 1;
                        DBRecord valRec = enumValTable.getSchema().createRecord(valKey);
                        valRec.setString(0, v.has("name")    ? v.get("name").getAsString()    : "");
                        valRec.setLongValue(1, v.has("value") ? v.get("value").getAsLong()    : 0L);
                        valRec.setLongValue(2, enumId);
                        valRec.setString(3, v.has("comment") ? v.get("comment").getAsString() : "");
                        enumValTable.putRecord(valRec);
                    }
                }

            } else if ("typedef".equals(kind)) {
                Table typedefTable = db.getTable("Typedefs");
                if (typedefTable == null) continue;

                String underlyingName = c.has("underlying_type_name")
                    ? c.get("underlying_type_name").getAsString() : "";
                if (underlyingName.isEmpty()) continue;

                // Look up the underlying type id
                Long underlyingId = typeIdByName.get(underlyingName);
                if (underlyingId == null) continue;

                long typedefId = ghidraId;
                DBRecord rec = (typedefId > 0) ? typedefTable.getRecord(typedefId) : null;
                if (rec == null) {
                    typedefId = typedefTable.getMaxKey() + 1;
                    rec = typedefTable.getSchema().createRecord(typedefId);
                }
                // V2 typedef schema (Ghidra 12.x):
                //   col 0: LongField  (Data Type ID — the wrapped/underlying type)
                //   col 1: ShortField (Flags)      ← must use setShortValue, NOT setIntValue
                //   col 2: StringField (Name)
                //   col 3: LongField  (Category ID)
                //   col 4-7: LongField (source archive timestamps — leave as 0)
                rec.setLongValue(0, underlyingId);
                rec.setShortValue(1, (short)0);     // Flags (ShortField — setIntValue throws!)
                rec.setString(2, name);
                try { rec.setLongValue(3, 0L); } catch (Exception ignored) {}  // Category ID
                typedefTable.putRecord(rec);
                if ("add".equals(op)) addedIds.put(name, typedefId);
            }
        }
        System.err.println("[ghidra-bridge] data type changes applied: " + changes.size());
        return addedIds;
    }

    // -------------------------------------------------------------------------

    static void applyDataItems(DBHandle db, JsonArray dataItems) throws IOException {
        Table dataTable = db.getTable("Data");
        if (dataTable == null) return;

        // Full type-name → id map (composite + enum + typedef + built-ins)
        Map<String, Long> typeIdByName = buildTypeIdByName(db);

        Map<Long, Long> addrMap = buildAddrMap(db);
        int count = 0;

        for (JsonElement el : dataItems) {
            JsonObject di   = el.getAsJsonObject();
            String op       = di.has("op")        ? di.get("op").getAsString()        : "add";
            // addr is now sent as a hex Ghidra VA string (e.g. "0x401000")
            long   ghidraVa = di.has("addr")       ? parseHexLong(di.get("addr").getAsString()) : 0L;
            String typeName = di.has("type_name")  ? di.get("type_name").getAsString() : "";

            long encoded = encodeVA(ghidraVa, addrMap);
            if (encoded < 0) {
                System.err.println("[ghidra-bridge] data item: cannot encode addr 0x"
                    + Long.toHexString(ghidraVa) + " — skipping");
                continue;
            }

            if ("delete".equals(op)) {
                dataTable.deleteRecord(encoded);
                ++count;
                continue;
            }

            // Try full name first ("MyStruct *"), then strip pointer/array suffixes
            String trimmed = typeName.trim();
            Long typeId = typeIdByName.get(trimmed);
            if (typeId == null) typeId = typeIdByName.get(trimmed.split("[\\s\\*\\[]+")[0]);
            if (typeId == null) {
                System.err.println("[ghidra-bridge] data item: unknown type '" + typeName + "' — skipping");
                continue;
            }

            DBRecord rec = dataTable.getRecord(encoded);
            if (rec == null) rec = dataTable.getSchema().createRecord(encoded);
            rec.setLongValue(0, typeId);
            dataTable.putRecord(rec);
            ++count;
        }
        System.err.println("[ghidra-bridge] data items applied: " + count);
    }

    // -------------------------------------------------------------------------

    static void applyFuncSigChanges(DBHandle db, JsonArray changes) throws IOException {
        // Function Data table schema (FunctionAdapterV3 / FUNCTION_SCHEMA):
        //   col 0: LongField  "Return DataType ID"
        //   col 1: IntField   "StackPurge"          ← NOT the return type! setLongValue silently truncates
        //   col 2: IntField   "StackReturnOffset"
        //   col 3: IntField   "StackLocalSize"       ← NOT for calling convention name
        //   col 4: ByteField  "Flags"                (includes signature source bits)
        //   col 5: ByteField  "Calling Convention ID" (byte key into CallingConventions table)
        //   col 6: StringField "Return Storage"
        Table funcTable = db.getTable("Function Data");
        if (funcTable == null) return;

        // Full type-name → id map (composite + enum + typedef + built-ins)
        Map<String, Long> typeIdByName = buildTypeIdByName(db);

        // Build calling-convention name → byte-key map from the CallingConventions table.
        // The table uses a ByteField as the record key; col 0 is the name string.
        Map<String, Byte> ccNameToId = new HashMap<>();
        for (String ccTableName : new String[]{"Calling Conventions", "CallingConventions"}) {
            Table cct = db.getTable(ccTableName);
            if (cct == null) continue;
            try {
                db.RecordIterator it = cct.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String n = null;
                    try { n = r.getString(0); } catch (Exception ignored) {}
                    if (n != null && !n.isEmpty())
                        ccNameToId.put(n, (byte) r.getKey());
                }
            } catch (Exception ignored) {}
            break;
        }

        int count = 0;
        for (JsonElement el : changes) {
            JsonObject c   = el.getAsJsonObject();
            long key       = c.get("key").getAsLong();
            String cc      = c.has("cc")       ? c.get("cc").getAsString()       : "";
            String retType = c.has("ret_type") ? c.get("ret_type").getAsString() : "";

            DBRecord rec = funcTable.getRecord(key);
            if (rec == null) continue;

            boolean changed = false;

            // Return type → col 0 (LongField "Return DataType ID")
            if (!retType.isEmpty()) {
                Long typeId = typeIdByName.get(retType);
                if (typeId == null) typeId = typeIdByName.get(retType.split("[\\s\\*\\[<]+")[0]);
                if (typeId != null) {
                    rec.setLongValue(0, typeId);
                    changed = true;
                }
            }

            // Calling convention → col 5 (ByteField "Calling Convention ID")
            // Requires a name→ID lookup in the CallingConventions table.
            if (!cc.isEmpty() && ccNameToId.containsKey(cc)) {
                rec.setByteValue(5, ccNameToId.get(cc));
                changed = true;
            }

            if (changed) {
                funcTable.putRecord(rec);
                ++count;
            }
        }
        System.err.println("[ghidra-bridge] func sig changes applied: " + count);
    }

    // -------------------------------------------------------------------------

    private static void applySymbols(DBHandle db, JsonArray symbols) throws IOException {
        Table table = db.getTable(SYMBOLS_TABLE);
        if (table == null) {
            System.err.println("[ghidra-bridge] WARNING: Symbols table not found");
            return;
        }

        // Lazily built when we encounter a va-based (new) symbol entry.
        Map<Long, Long> addrMap = null;
        // encodedAddr → symbol DB key — reverse index for new-symbol address lookup.
        Map<Long, Long> encodedAddrToSymKey = null;

        int count = 0;
        for (JsonElement el : symbols) {
            JsonObject s = el.getAsJsonObject();
            String name = s.has("name") ? s.get("name").getAsString() : "";
            if (name == null || name.isEmpty()) continue;

            DBRecord rec = null;

            if (s.has("key")) {
                // ── Existing Ghidra symbol: look up by DB key ──────────────────────────
                long key = s.get("key").getAsLong();
                rec = table.getRecord(key);
                if (rec == null) continue;

            } else if (s.has("va")) {
                // ── New symbol (no Ghidra key): find or create by encoded address ──────
                if (addrMap == null) addrMap = buildAddrMap(db);
                long va = parseHexLong(s.get("va").getAsString());
                long encodedAddr = encodeVA(va, addrMap);
                if (encodedAddr < 0) {
                    System.err.println("[ghidra-bridge] new symbol: cannot encode VA 0x"
                        + Long.toHexString(va) + " — skipping");
                    continue;
                }

                // Build the reverse map on first use (one scan of the Symbols table).
                if (encodedAddrToSymKey == null) {
                    encodedAddrToSymKey = new HashMap<>();
                    db.RecordIterator scanIter = table.iterator();
                    while (scanIter.hasNext()) {
                        DBRecord r = scanIter.next();
                        long ea = r.getLongValue(SYM_ADDR_COL);
                        // Keep first (lowest-key) record per address.
                        if (!encodedAddrToSymKey.containsKey(ea))
                            encodedAddrToSymKey.put(ea, r.getKey());
                    }
                }

                Long existingKey = encodedAddrToSymKey.get(encodedAddr);
                if (existingKey != null) {
                    // There is already a Ghidra symbol here (e.g. auto-analysis label) — update it.
                    rec = table.getRecord(existingKey);
                    if (rec == null) continue;
                } else {
                    // No Ghidra symbol at this address — create a new Label record.
                    // Always insert as Label (type=0) to avoid requiring a Functions table entry.
                    // If the BN symbol was a function, it will look like a named label in Ghidra
                    // (safer than a dangling Function-type symbol with no Functions record).
                    long newKey = table.getMaxKey() + 1;
                    DBRecord newRec = table.getSchema().createRecord(newKey);
                    newRec.setString(SYM_NAME_COL, name);
                    newRec.setLongValue(SYM_ADDR_COL, encodedAddr);
                    newRec.setLongValue(SYM_NAMESPACE_COL, 0L); // global namespace
                    newRec.setByteValue(SYM_TYPE_COL, (byte)0); // Label
                    newRec.setByteValue(SYM_FLAGS_COL, (byte)(3 << SOURCE_SHIFT)); // USER_DEFINED
                    table.putRecord(newRec);
                    encodedAddrToSymKey.put(encodedAddr, newKey);
                    ++count;
                    continue; // already fully written
                }
            } else {
                continue;
            }

            // ── Common update path: rename + promote to USER_DEFINED ─────────────────
            rec.setString(SYM_NAME_COL, name);
            byte flags = rec.getByteValue(SYM_FLAGS_COL);
            flags = (byte)((flags & 0x3F) | (3 << SOURCE_SHIFT));
            rec.setByteValue(SYM_FLAGS_COL, flags);
            table.putRecord(rec);
            ++count;
        }
        System.err.println("[ghidra-bridge] symbols written: " + count);
    }

    private static void applyComments(DBHandle db, JsonArray comments) throws IOException {
        Table table = db.getTable(COMMENTS_TABLE);
        if (table == null) {
            System.err.println("[ghidra-bridge] WARNING: Comments table not found");
            return;
        }

        // Build VA→encodedKey map from the address table so we can encode
        // comments added in BN at addresses that had no Ghidra comment.
        Map<Long, Long> addrMap = buildAddrMap(db);

        int count = 0;
        for (JsonElement el : comments) {
            JsonObject c = el.getAsJsonObject();

            // Resolve the DB record key: prefer the pre-computed encoded key,
            // fall back to encoding the Ghidra VA via the address map.
            long key;
            String keyStr = c.has("key") ? c.get("key").getAsString() : "";
            if (!keyStr.isEmpty()) {
                key = parseHexLong(keyStr);
            } else if (c.has("va")) {
                long va = parseHexLong(c.get("va").getAsString());
                key = encodeVA(va, addrMap);
                if (key < 0) {
                    System.err.println("[ghidra-bridge] could not encode VA 0x"
                        + Long.toHexString(va) + " — skipping");
                    continue;
                }
            } else {
                continue;
            }

            DBRecord rec = table.getRecord(key);
            if (rec == null) rec = table.getSchema().createRecord(key);

            setOrClear(rec, COMM_EOL_COL,   c, "eol");
            setOrClear(rec, COMM_PRE_COL,   c, "pre");
            setOrClear(rec, COMM_POST_COL,  c, "post");
            setOrClear(rec, COMM_PLATE_COL, c, "plate");
            setOrClear(rec, COMM_REP_COL,   c, "rep");
            table.putRecord(rec);
            ++count;
        }
        System.err.println("[ghidra-bridge] comments written: " + count);
    }

    /**
     * Build a type-name → DB key map covering user-defined and built-in types:
     *   Composite Data Types (structs/unions)
     *   Enumeration Data Types
     *   Typedefs (name is col 2)
     *   Built-In Data Types (Ghidra primitives: int, char, void, …)
     *
     * Used by every importer method that needs to write a DataTypeId.
     */
    static Map<String, Long> buildTypeIdByName(DBHandle db) {
        Map<String, Long> map = new HashMap<>();
        // Composite and Enumeration: name is col 0
        for (String tbl : new String[]{"Composite Data Types", "Enumeration Data Types"}) {
            Table t = db.getTable(tbl);
            if (t == null) continue;
            try {
                db.RecordIterator it = t.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String n = r.getString(0);
                    if (n != null && !n.isEmpty()) map.put(n, r.getKey());
                }
            } catch (Exception ignored) {}
        }
        // Typedefs: name is col 2
        Table td = db.getTable("Typedefs");
        if (td != null) {
            try {
                db.RecordIterator it = td.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String n = r.getString(2);
                    if (n != null && !n.isEmpty()) map.put(n, r.getKey());
                }
            } catch (Exception ignored) {}
        }
        // Built-In primitives: name is col 0 (try several possible table names)
        for (String tbl : new String[]{"Built-In Data Types", "BuiltInTypes", "Built In Data Types"}) {
            Table bt = db.getTable(tbl);
            if (bt == null) continue;
            try {
                db.RecordIterator it = bt.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    String n = null;
                    try { n = r.getString(0); } catch (Exception ignored) {}
                    if (n == null || n.isEmpty()) {
                        try { n = r.getString(1); } catch (Exception ignored) {}
                    }
                    if (n != null && !n.isEmpty()) map.put(n, r.getKey());
                }
            } catch (Exception ignored) {}
            break;
        }

        // Pointer types — "InnerName *" → pointer type DB key.  Two passes for double-pointers.
        for (int pass = 0; pass < 2; pass++) {
            Table ptrTable = db.getTable("Pointer Data Types");
            if (ptrTable == null) break;
            try {
                db.RecordIterator it = ptrTable.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    long innerTypeId = -1L;
                    try { innerTypeId = r.getLongValue(0); } catch (Exception ignored) {}
                    String innerName = null;
                    if (innerTypeId < 0) {
                        innerName = "void";
                    } else {
                        for (Map.Entry<String, Long> e : map.entrySet())
                            if (e.getValue().equals(innerTypeId)) { innerName = e.getKey(); break; }
                    }
                    if (innerName != null && !innerName.isEmpty())
                        map.putIfAbsent(innerName + " *", r.getKey());
                }
            } catch (Exception ignored) {}
        }

        // Array types — "ElemName[count]" → array type DB key.
        Table arrayTable = db.getTable("Array Data Types");
        if (arrayTable != null) {
            try {
                db.RecordIterator it = arrayTable.iterator();
                while (it.hasNext()) {
                    DBRecord r = it.next();
                    long innerTypeId = -1L;
                    int  elemCount   = 0;
                    try { innerTypeId = r.getLongValue(0); } catch (Exception ignored) {}
                    try { elemCount   = r.getIntValue(2);  } catch (Exception ignored) {
                        try { elemCount = r.getIntValue(1); } catch (Exception ignored2) {}
                    }
                    String innerName = null;
                    for (Map.Entry<String, Long> e : map.entrySet())
                        if (e.getValue().equals(innerTypeId)) { innerName = e.getKey(); break; }
                    if (innerName != null && !innerName.isEmpty() && elemCount > 0)
                        map.putIfAbsent(innerName + "[" + elemCount + "]", r.getKey());
                }
            } catch (Exception ignored) {}
        }

        return map;
    }

    /** Build ADDRESS MAP: rowKey → base VA (mirrors DatabaseExporter.buildAddressMap). */
    private static Map<Long, Long> buildAddrMap(DBHandle db) {
        Map<Long, Long> map = new HashMap<>();
        Table t = db.getTable("ADDRESS MAP");
        if (t == null) return map;
        try {
            db.RecordIterator iter = t.iterator();
            while (iter.hasNext()) {
                DBRecord rec = iter.next();
                long base = 0;
                try { base = rec.getLongValue(1); } catch (Exception e) {
                    try { base = rec.getIntValue(1) & 0xFFFFFFFFL; } catch (Exception ignored) {}
                }
                map.put(rec.getKey(), base);
            }
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] addrMap load error: " + e.getMessage());
        }
        return map;
    }

    /**
     * Encode a Ghidra VA to a DB record key using the address map.
     * Tries direct (new-format) lookup first, then old-format (RAM_SPACE_PREFIX).
     * Returns -1 if the VA cannot be encoded.
     */
    private static long encodeVA(long va, Map<Long, Long> addrMap) {
        long bestKey = -1, bestBase = -1;
        // Find the segment with the largest base ≤ va.
        for (Map.Entry<Long, Long> e : addrMap.entrySet()) {
            long base = e.getValue();
            if (base <= va && base > bestBase) {
                bestBase = base;
                bestKey  = e.getKey();
            }
        }
        if (bestKey < 0) return -1;

        long offset = va - bestBase;
        // New format: row key IS the full segKey stored in encoded addresses.
        // Old format: segKey = 0x20000000L | rowKey (RAM_SPACE_PREFIX << 8 | rowKey).
        // We detect old format by checking if bestKey is a small sequential index (0–255).
        long segKey = (bestKey < 256) ? (0x20000000L | bestKey) : bestKey;
        return (segKey << 32) | offset;
    }

    private static void setOrClear(DBRecord rec, int col, JsonObject obj, String field) {
        String val = obj.has(field) ? obj.get(field).getAsString() : null;
        rec.setString(col, (val != null && !val.isEmpty()) ? val : null);
    }

    private static long parseHexLong(String s) {
        if (s == null || s.isEmpty()) return 0;
        String t = (s.startsWith("0x") || s.startsWith("0X")) ? s.substring(2) : s;
        return Long.parseUnsignedLong(t, 16);
    }
}
