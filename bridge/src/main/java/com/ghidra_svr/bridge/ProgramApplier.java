package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import db.DBHandle;
import db.buffers.ManagedBufferFileAdapter;
import db.buffers.ManagedBufferFileHandle;

import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Applies BN-side changes to a Ghidra Program using the high-level
 * ProgramDB / DataTypeManager / SymbolTable / FunctionManager APIs instead
 * of raw db.Table.putRecord() writes.
 *
 * Reasons we use the high-level APIs:
 *
 *  - Ghidra DB schemas have many interlocking tables (Composite Data Types,
 *    Component Data Types, Settings, Parent indexes, source archive IDs,
 *    Universal IDs, etc.).  Writing one without updating the others
 *    produces files that look valid but crash plugins on open
 *    (e.g. CompositeEditorModel.cloneAllComponentSettings: Index 0 out of
 *    bounds for length 0 — composite header says N components but settings
 *    table has 0 entries).
 *
 *  - Field type mismatches in raw writes silently corrupt data
 *    (IntField.setLongValue does l2i, doesn't throw).  We saw this corrupt
 *    StackPurge values on every function we touched in earlier raw-write
 *    versions of the checkin path.
 *
 *  - The high-level APIs maintain ProgramDBChangeSet automatically, so
 *    Ghidra's later checkout merge logic has the data it needs.
 *
 * Application.initializeApplication() must have been called before invoking
 * this class — done at bridge startup in BridgeMain.
 */
public final class ProgramApplier {

    private ProgramApplier() {}

    /**
     * Apply all BN-side change arrays to the managed buffer file.
     *
     * @return JSON result: {"added_type_ids": {name: dbKey, ...},
     *         "applied": {category: appliedCount, ...}} — applied counts let
     *         the BN side warn when the server accepted fewer items than were
     *         sent (the shortfall re-queues on every check-in otherwise
     *         invisibly).
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

        ManagedBufferFileAdapter adapter = new ManagedBufferFileAdapter(handle);
        DBHandle dbHandle = new DBHandle(adapter);

        Object consumer = new Object();
        ProgramDB program;
        try {
            program = new ProgramDB(dbHandle, OpenMode.UPDATE, TaskMonitor.DUMMY, consumer);
        } catch (VersionException | LanguageNotFoundException | CancelledException e) {
            try { dbHandle.close(); } catch (Exception ignored) {}
            throw new IOException("Failed to open ProgramDB: " + e.getMessage(), e);
        } catch (Exception e) {
            try { dbHandle.close(); } catch (Exception ignored) {}
            throw new IOException("Failed to open ProgramDB: " + e.getMessage(), e);
        }

        Map<String, Long> addedIds = new HashMap<>();
        JsonObject applied = new JsonObject();
        try {
            int tx = program.startTransaction("BN sync");
            boolean ok = false;
            try {
                // Defensive cleanup: previous raw-write checkin attempts may have
                // written PARAMETER / LOCAL_VAR symbols whose SYM_ADDR_COL is in
                // RAM space instead of Ghidra's VARIABLE address space.  Any later
                // attempt to load that function's variables crashes with
                // "Address is not a VariableAddress".  Even our high-level API
                // calls below (Function.getParameters / addLocalVariable) trigger
                // that load, so we must purge the corrupted records first.
                cleanupBadVariableSymbols(program);

                // Data types first so symbols/params/data items can reference them.
                if (dataTypeChanges != null && dataTypeChanges.size() > 0) {
                    int[] dtApplied = new int[1];
                    addedIds.putAll(applyDataTypes(program, dataTypeChanges, dtApplied));
                    applied.addProperty("data_types", dtApplied[0]);
                }
                if (symbols         != null && symbols.size()         > 0) applied.addProperty("symbols",         applySymbols(program, symbols));
                if (comments        != null && comments.size()        > 0) applied.addProperty("comments",        applyComments(program, comments));
                if (equateRenames   != null && equateRenames.size()   > 0) applied.addProperty("equate_renames",  applyEquateRenames(program, equateRenames));
                if (equateRefAdds   != null && equateRefAdds.size()   > 0) applied.addProperty("equate_ref_adds", applyEquateRefAdds(program, equateRefAdds));
                if (bookmarkChanges != null && bookmarkChanges.size() > 0) applied.addProperty("bookmarks",       applyBookmarks(program, bookmarkChanges));
                if (paramRenames    != null && paramRenames.size()    > 0) applied.addProperty("params",          applyParameters(program, paramRenames));
                if (dataItemChanges != null && dataItemChanges.size() > 0) applied.addProperty("data_items",      applyDataItems(program, dataItemChanges));
                if (funcSigChanges  != null && funcSigChanges.size()  > 0) applied.addProperty("func_sigs",       applyFuncSigs(program, funcSigChanges));
                program.endTransaction(tx, true);
                ok = true;
            } finally {
                if (!ok) program.endTransaction(tx, false);
            }
            try {
                program.save(versionComment != null ? versionComment : "BN sync", TaskMonitor.DUMMY);
            } catch (CancelledException e) {
                throw new IOException("save cancelled unexpectedly", e);
            }
        } finally {
            program.release(consumer);
        }
        JsonObject result = new JsonObject();
        JsonObject addedJson = new JsonObject();
        for (Map.Entry<String, Long> e : addedIds.entrySet())
            addedJson.addProperty(e.getKey(), e.getValue());
        result.add("added_type_ids", addedJson);
        result.add("applied", applied);
        return result;
    }

    // -------------------------------------------------------------------------
    // Defensive cleanup for corruption left by earlier raw-write versions
    // -------------------------------------------------------------------------

    /**
     * Scan the Symbols table for PARAMETER (type=6) and LOCAL_VAR (type=7)
     * records whose stored address doesn't decode to a Variable-space address
     * (typical leftover from older raw-write checkin attempts where we wrote
     * the function's RAM entry address into the parameter symbol).
     *
     * Ghidra's FunctionDB.loadSymbolBasedVariables throws on such records
     * because VariableStorageManagerDB.getMyVariableStorage rejects non-Variable
     * addresses up-front rather than returning a "bad" marker.  That throw
     * propagates all the way out of any operation that touches the function's
     * variables (including Function.getParameters), so we must purge these
     * records via raw DBHandle access before any high-level API is invoked.
     *
     * Must run inside an active program transaction.
     */
    static void cleanupBadVariableSymbols(ProgramDB program) {
        DBHandle dbh = program.getDBHandle();
        db.Table symTable = dbh.getTable("Symbols");
        if (symTable == null) return;
        ghidra.program.database.map.AddressMap addrMap = program.getAddressMap();
        java.util.List<Long> toDelete = new java.util.ArrayList<>();
        try {
            db.RecordIterator it = symTable.iterator();
            while (it.hasNext()) {
                db.DBRecord r = it.next();
                byte type;
                try { type = r.getByteValue(3); }      // SYM_TYPE_COL
                catch (Exception e) { continue; }
                if (type != 6 && type != 7) continue;  // PARAMETER, LOCAL_VAR

                long encAddr;
                try { encAddr = r.getLongValue(1); }   // SYM_ADDR_COL
                catch (Exception e) { toDelete.add(r.getKey()); continue; }

                boolean bad;
                try {
                    Address addr = addrMap.decodeAddress(encAddr);
                    bad = addr == null || !addr.isVariableAddress();
                } catch (Exception e) {
                    bad = true;
                }
                if (bad) toDelete.add(r.getKey());
            }
            for (long k : toDelete) symTable.deleteRecord(k);
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] cleanupBadVariableSymbols error: " + e.getMessage());
        }
        if (!toDelete.isEmpty()) {
            System.err.println("[ghidra-bridge] purged " + toDelete.size()
                + " corrupted param/local-var symbols from prior runs");
        }
    }

    // -------------------------------------------------------------------------
    // Data types
    // -------------------------------------------------------------------------

    static Map<String, Long> applyDataTypes(ProgramDB program, JsonArray changes) {
        return applyDataTypes(program, changes, new int[1]);
    }

    static Map<String, Long> applyDataTypes(ProgramDB program, JsonArray changes, int[] appliedOut) {
        DataTypeManager dtm = program.getDataTypeManager();
        Map<String, Long> added = new HashMap<>();
        int n = 0, errors = 0;

        // Two passes: first define empty composite stubs (so members can reference
        // sibling types by name), then populate members.  Without this, struct A
        // containing struct B fails if B isn't created yet.
        for (JsonElement el : changes) {
            JsonObject c = el.getAsJsonObject();
            String op   = getStr(c, "op",   "add");
            String kind = getStr(c, "kind", "");
            String name = getStr(c, "name", "");
            if (name.isEmpty() || "delete".equals(op)) continue;
            try {
                if ("struct".equals(kind)) {
                    int size = c.has("size") ? c.get("size").getAsInt() : 0;
                    if (dtm.getDataType(CategoryPath.ROOT, name) == null) {
                        StructureDataType stub = new StructureDataType(name, size, dtm);
                        dtm.addDataType(stub, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                } else if ("union".equals(kind)) {
                    if (dtm.getDataType(CategoryPath.ROOT, name) == null) {
                        UnionDataType stub = new UnionDataType(name);
                        dtm.addDataType(stub, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                } else if ("enum".equals(kind)) {
                    int size = c.has("size") ? c.get("size").getAsInt() : 4;
                    if (dtm.getDataType(CategoryPath.ROOT, name) == null) {
                        EnumDataType stub = new EnumDataType(name, size > 0 ? size : 4);
                        dtm.addDataType(stub, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                }
            } catch (Exception e) { ++errors; }
        }

        // Second pass: populate members, enum values, typedefs.
        for (JsonElement el : changes) {
            JsonObject c = el.getAsJsonObject();
            String op   = getStr(c, "op",   "add");
            String kind = getStr(c, "kind", "");
            String name = getStr(c, "name", "");
            if (name.isEmpty()) continue;

            try {
                if ("delete".equals(op)) {
                    DataType dt = dtm.getDataType(CategoryPath.ROOT, name);
                    if (dt != null) dtm.remove(dt);
                    ++n;
                    continue;
                }

                if ("struct".equals(kind)) {
                    int size = c.has("size") ? c.get("size").getAsInt() : 0;
                    // Start at length 0 and place members at their declared
                    // offsets. Constructing with the declared size pre-fills
                    // that many undefined bytes and add() appends AFTER them,
                    // displacing every member by `size` and doubling the
                    // struct (caught by the canonical parity tests).
                    StructureDataType s = new StructureDataType(name, 0, dtm);
                    JsonArray members = c.has("members") ? c.get("members").getAsJsonArray() : new JsonArray();
                    for (JsonElement mel : members) {
                        JsonObject m = mel.getAsJsonObject();
                        String mName = getStr(m, "name", "");
                        String mTyN  = getStr(m, "type_name", "");
                        String mCmt  = getStr(m, "comment", "");
                        int mSize    = m.has("size") ? m.get("size").getAsInt() : 0;
                        int mOffset  = m.has("offset") ? m.get("offset").getAsInt() : -1;
                        DataType mDt = resolveDataType(dtm, mTyN, mSize);
                        if (mDt == null) {
                            // Unknown type → use undefined of the given size so the offset is preserved.
                            mDt = (mSize > 0)
                                ? Undefined.getUndefinedDataType(mSize)
                                : Undefined1DataType.dataType;
                        }
                        try {
                            if (mOffset >= 0) {
                                s.insertAtOffset(mOffset, mDt,
                                                 mSize > 0 ? mSize : mDt.getLength(),
                                                 mName.isEmpty() ? null : mName,
                                                 mCmt.isEmpty() ? null : mCmt);
                            } else {
                                s.add(mDt, mSize > 0 ? mSize : mDt.getLength(),
                                      mName.isEmpty() ? null : mName,
                                      mCmt.isEmpty() ? null : mCmt);
                            }
                        } catch (Exception e) { /* skip bad member */ }
                    }
                    // Preserve trailing padding when the declared size exceeds
                    // the last member's end.
                    if (size > s.getLength())
                        s.growStructure(size - s.getLength());
                    DataType result = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
                    if ("add".equals(op) && result != null) added.put(name, dtm.getID(result));
                    ++n;

                } else if ("union".equals(kind)) {
                    UnionDataType u = new UnionDataType(name);
                    JsonArray members = c.has("members") ? c.get("members").getAsJsonArray() : new JsonArray();
                    for (JsonElement mel : members) {
                        JsonObject m = mel.getAsJsonObject();
                        String mName = getStr(m, "name", "");
                        String mTyN  = getStr(m, "type_name", "");
                        String mCmt  = getStr(m, "comment", "");
                        int mSize    = m.has("size") ? m.get("size").getAsInt() : 0;
                        DataType mDt = resolveDataType(dtm, mTyN, mSize);
                        if (mDt == null) {
                            mDt = (mSize > 0) ? Undefined.getUndefinedDataType(mSize)
                                              : Undefined1DataType.dataType;
                        }
                        try {
                            u.add(mDt, mSize > 0 ? mSize : mDt.getLength(),
                                  mName.isEmpty() ? null : mName,
                                  mCmt.isEmpty() ? null : mCmt);
                        } catch (Exception e) { /* skip bad member */ }
                    }
                    DataType result = dtm.addDataType(u, DataTypeConflictHandler.REPLACE_HANDLER);
                    if ("add".equals(op) && result != null) added.put(name, dtm.getID(result));
                    ++n;

                } else if ("enum".equals(kind)) {
                    int size = c.has("size") ? c.get("size").getAsInt() : 4;
                    EnumDataType e = new EnumDataType(name, size > 0 ? size : 4);
                    JsonArray values = c.has("values") ? c.get("values").getAsJsonArray() : new JsonArray();
                    for (JsonElement vel : values) {
                        JsonObject v = vel.getAsJsonObject();
                        String vName = getStr(v, "name", "");
                        long   vVal  = v.has("value") ? v.get("value").getAsLong() : 0;
                        String vCmt  = getStr(v, "comment", "");
                        if (vName.isEmpty()) continue;
                        try { e.add(vName, vVal, vCmt.isEmpty() ? null : vCmt); }
                        catch (Exception ex) { /* duplicate name/value */ }
                    }
                    DataType result = dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER);
                    if ("add".equals(op) && result != null) added.put(name, dtm.getID(result));
                    ++n;

                } else if ("typedef".equals(kind)) {
                    String under = getStr(c, "underlying_type_name", "");
                    DataType underDt = resolveDataType(dtm, under, 0);
                    if (underDt == null) {
                        System.err.println("[ghidra-bridge] typedef '" + name
                            + "' skipped: cannot resolve underlying type '" + under + "'");
                        ++errors; continue;
                    }
                    TypedefDataType t = new TypedefDataType(name, underDt);
                    DataType result = dtm.addDataType(t, DataTypeConflictHandler.REPLACE_HANDLER);
                    if ("add".equals(op) && result != null) added.put(name, dtm.getID(result));
                    ++n;
                }
            } catch (Exception e) { ++errors; }
        }
        System.err.println("[ghidra-bridge] data types applied: " + n
            + (errors > 0 ? " (" + errors + " errors)" : ""));
        appliedOut[0] = n;
        return added;
    }

    /**
     * Resolve a BN-supplied type name to a Ghidra DataType.  Tries:
     *  1. Direct lookup by name in the root category.
     *  2. DataTypeParser (handles "int *", "char[5]", "MyStruct **", etc.)
     *  3. Fallback to undefined data type of the right size.
     */
    // Binary Ninja uses the stdint.h spelling (int32_t, uint8_t, …) which Ghidra's
    // built-ins do NOT expose, so resolveDataType returns null for them and any
    // typedef / struct member / parameter typed that way is silently dropped.
    // Map them to the equivalent Ghidra built-in by width + signedness.  64-bit
    // assumed for the pointer-width names (size_t etc.) — correct for the common
    // x86-64 case.
    private static final Map<String, String> STDINT_TO_GHIDRA = Map.ofEntries(
        Map.entry("int8_t",    "sbyte"),    Map.entry("uint8_t",   "byte"),
        Map.entry("int16_t",   "short"),    Map.entry("uint16_t",  "ushort"),
        Map.entry("int32_t",   "int"),      Map.entry("uint32_t",  "uint"),
        Map.entry("int64_t",   "longlong"), Map.entry("uint64_t",  "ulonglong"),
        Map.entry("size_t",    "ulonglong"),Map.entry("ssize_t",   "longlong"),
        Map.entry("intptr_t",  "longlong"), Map.entry("uintptr_t", "ulonglong"));

    /** Replace a leading stdint base name (e.g. "uint32_t" in "uint32_t *") with
     *  its Ghidra equivalent, preserving any pointer/array suffix. */
    private static String normalizePrimitives(String type) {
        int i = 0;
        while (i < type.length()
                && (Character.isLetterOrDigit(type.charAt(i)) || type.charAt(i) == '_')) {
            i++;
        }
        String mapped = STDINT_TO_GHIDRA.get(type.substring(0, i));
        return mapped != null ? mapped + type.substring(i) : type;
    }

    static DataType resolveDataType(DataTypeManager dtm, String name, int size) {
        if (name == null || name.isEmpty()) return null;
        String trimmed = normalizePrimitives(name.trim());

        // Direct hit
        DataType dt = dtm.getDataType(CategoryPath.ROOT, trimmed);
        if (dt != null) return dt;

        // Try via parser (handles compound type strings like "MyStruct *", "int[5]")
        try {
            DataTypeParser parser = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
            DataType parsed = parser.parse(trimmed);
            if (parsed != null) return parsed;
        } catch (Exception ignored) {}

        // Last resort: strip suffixes like " *", "[N]" and retry
        String stripped = trimmed.split("[\\s\\*\\[<]+")[0];
        if (!stripped.equals(trimmed)) {
            dt = dtm.getDataType(CategoryPath.ROOT, stripped);
            if (dt != null) return dt;
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Symbols
    // -------------------------------------------------------------------------

    static int applySymbols(ProgramDB program, JsonArray symbols) {
        SymbolTable st = program.getSymbolTable();
        AddressFactory af = program.getAddressFactory();
        int count = 0;
        for (JsonElement el : symbols) {
            JsonObject s = el.getAsJsonObject();
            String name = getStr(s, "name", "");
            if (name.isEmpty()) continue;
            try {
                if (s.has("key")) {
                    Symbol sym = st.getSymbol(s.get("key").getAsLong());
                    if (sym != null) {
                        sym.setName(name, SourceType.USER_DEFINED);
                        ++count;
                    }
                } else if (s.has("va")) {
                    long va = parseHexLong(s.get("va").getAsString());
                    Address addr = af.getDefaultAddressSpace().getAddress(va);
                    st.createLabel(addr, name, SourceType.USER_DEFINED);
                    ++count;
                }
            } catch (DuplicateNameException | InvalidInputException ignored) {
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] symbols written: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    static int applyComments(ProgramDB program, JsonArray comments) {
        Listing listing = program.getListing();
        AddressFactory af = program.getAddressFactory();
        int count = 0;
        for (JsonElement el : comments) {
            JsonObject c = el.getAsJsonObject();
            long va;
            if (c.has("va")) {
                va = parseHexLong(c.get("va").getAsString());
            } else if (c.has("key")) {
                // Older path sent the raw encoded DB key; we no longer have a
                // decoder at this level, so skip these.
                continue;
            } else {
                continue;
            }
            Address addr;
            try { addr = af.getDefaultAddressSpace().getAddress(va); }
            catch (Exception e) { continue; }

            try {
                if (c.has("eol"))   listing.setComment(addr, CommentType.EOL,        nullIfEmpty(c.get("eol").getAsString()));
                if (c.has("pre"))   listing.setComment(addr, CommentType.PRE,        nullIfEmpty(c.get("pre").getAsString()));
                if (c.has("post"))  listing.setComment(addr, CommentType.POST,       nullIfEmpty(c.get("post").getAsString()));
                if (c.has("plate")) listing.setComment(addr, CommentType.PLATE,      nullIfEmpty(c.get("plate").getAsString()));
                if (c.has("rep"))   listing.setComment(addr, CommentType.REPEATABLE, nullIfEmpty(c.get("rep").getAsString()));
                ++count;
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] comments written: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Equates
    // -------------------------------------------------------------------------

    static int applyEquateRenames(ProgramDB program, JsonArray equateRenames) {
        // The BN side currently sends {id (long), name} where `id` is the raw DB
        // key of the equate record.  The EquateTable interface only exposes lookup
        // by name (String), so we resolve key→equate via the existing
        // EquateManager's iterator.  In practice equate renames are rare and
        // typically empty in our payloads, so the linear scan is fine.
        ghidra.program.model.symbol.EquateTable et = program.getEquateTable();
        // Build key → Equate map once.
        Map<Long, Equate> byKey = new HashMap<>();
        // EquateManager exposes getEquates(long value) but no key iterator.
        // We can iterate via getEquateAddresses and getEquates(addr), but that
        // misses equates with no references.  Easiest: use the DB handle to
        // iterate the Equates table directly for the key→name mapping.
        try {
            DBHandle dbh = program.getDBHandle();
            db.Table tbl = dbh.getTable("Equates");
            if (tbl != null) {
                db.RecordIterator it = tbl.iterator();
                while (it.hasNext()) {
                    db.DBRecord r = it.next();
                    String n = r.getString(0);
                    if (n != null) {
                        Equate eq = et.getEquate(n);
                        if (eq != null) byKey.put(r.getKey(), eq);
                    }
                }
            }
        } catch (Exception ignored) {}

        int count = 0;
        for (JsonElement el : equateRenames) {
            JsonObject e = el.getAsJsonObject();
            long id    = e.has("id")   ? e.get("id").getAsLong()   : -1;
            String nm  = getStr(e, "name", "");
            if (id < 0 || nm.isEmpty()) continue;
            Equate eq = byKey.get(id);
            if (eq == null) continue;
            try {
                // Ghidra has no direct rename — remove old, create with new name,
                // re-attach references.
                long val = eq.getValue();
                EquateReference[] refs = eq.getReferences();
                Address[] refAddrs = new Address[refs.length];
                int[] opIdxs = new int[refs.length];
                for (int i = 0; i < refs.length; i++) {
                    refAddrs[i] = refs[i].getAddress();
                    opIdxs[i]   = refs[i].getOpIndex();
                }
                et.removeEquate(eq.getName());
                Equate newEq = et.createEquate(nm, val);
                for (int i = 0; i < refAddrs.length; i++) {
                    try { newEq.addReference(refAddrs[i], opIdxs[i]); }
                    catch (Exception ignored) {}
                }
                ++count;
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] equate renames applied: " + count);
        return count;
    }

    static int applyEquateRefAdds(ProgramDB program, JsonArray equateRefAdds) {
        ghidra.program.model.symbol.EquateTable et = program.getEquateTable();
        AddressFactory af = program.getAddressFactory();
        // Same key → Equate map as applyEquateRenames.
        Map<Long, Equate> byKey = new HashMap<>();
        try {
            DBHandle dbh = program.getDBHandle();
            db.Table tbl = dbh.getTable("Equates");
            if (tbl != null) {
                db.RecordIterator it = tbl.iterator();
                while (it.hasNext()) {
                    db.DBRecord r = it.next();
                    String n = r.getString(0);
                    if (n != null) {
                        Equate eq = et.getEquate(n);
                        if (eq != null) byKey.put(r.getKey(), eq);
                    }
                }
            }
        } catch (Exception ignored) {}

        int count = 0;
        for (JsonElement el : equateRefAdds) {
            JsonObject r = el.getAsJsonObject();
            long eqId  = r.has("id")       ? r.get("id").getAsLong()      : -1;
            long va    = r.has("va")       ? parseHexLong(r.get("va").getAsString()) : -1;
            int  opIdx = r.has("op_index") ? r.get("op_index").getAsInt() : 0;
            if (eqId < 0 || va < 0) continue;
            Equate eq = byKey.get(eqId);
            if (eq == null) continue;
            try {
                eq.addReference(af.getDefaultAddressSpace().getAddress(va), opIdx);
                ++count;
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] equate refs added: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Bookmarks
    // -------------------------------------------------------------------------

    static int applyBookmarks(ProgramDB program, JsonArray bookmarkChanges) {
        ghidra.program.model.listing.BookmarkManager bm = program.getBookmarkManager();
        AddressFactory af = program.getAddressFactory();
        int count = 0;
        for (JsonElement el : bookmarkChanges) {
            JsonObject c = el.getAsJsonObject();
            String op    = getStr(c, "op", "add");
            String type  = getStr(c, "type", "Note");
            String cat   = getStr(c, "category", "");
            String cmt   = getStr(c, "comment", "");
            long va = c.has("addr") ? parseHexLong(c.get("addr").getAsString()) : -1;
            if (va < 0) continue;
            try {
                Address addr = af.getDefaultAddressSpace().getAddress(va);
                if ("delete".equals(op)) {
                    Bookmark[] existing = bm.getBookmarks(addr, type);
                    for (Bookmark b : existing) bm.removeBookmark(b);
                } else {
                    bm.setBookmark(addr, type, cat, cmt);
                }
                ++count;
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] bookmarks applied: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Function parameters
    // -------------------------------------------------------------------------

    // Function.addParameter(Variable, SourceType) is deprecated in favour of
    // updateFunction(), which rebuilds the entire signature and recomputes all
    // parameter storage.  For a simple append that is heavier and riskier than the
    // direct call, so we keep addParameter and suppress the single deprecation here.
    @SuppressWarnings("deprecation")
    static int applyParameters(ProgramDB program, JsonArray paramRenames) {
        SymbolTable st = program.getSymbolTable();
        FunctionManager fm = program.getFunctionManager();
        DataTypeManager dtm = program.getDataTypeManager();
        AddressFactory af = program.getAddressFactory();
        int count = 0, skippedLocals = 0;

        for (JsonElement el : paramRenames) {
            JsonObject c = el.getAsJsonObject();
            String name = getStr(c, "name", "");
            if (name.isEmpty()) continue;
            try {
                if (c.has("key")) {
                    // Existing param/local var symbol — rename via its symbol.
                    Symbol sym = st.getSymbol(c.get("key").getAsLong());
                    if (sym == null) continue;
                    sym.setName(name, SourceType.USER_DEFINED);
                    if (c.has("type_name") && sym.getObject() instanceof Variable) {
                        DataType dt = resolveDataType(dtm, c.get("type_name").getAsString(), 0);
                        if (dt != null) {
                            try { ((Variable) sym.getObject()).setDataType(dt, SourceType.USER_DEFINED); }
                            catch (Exception ignored) {}
                        }
                    }
                    ++count;
                } else if (c.has("func_va") && c.has("ordinal")) {
                    boolean isLocal = c.has("is_local") && c.get("is_local").getAsBoolean();
                    if (isLocal) {
                        // BN's "ordinal" for a register-based local var is a BN register
                        // index, NOT a Ghidra stack offset — passing it through
                        // LocalVariableImpl(name, dt, stackOffset, program) creates
                        // bogus stack variables.  Cross-decompiler register-to-storage
                        // mapping is non-trivial; skip locals until that's modelled.
                        ++skippedLocals;
                        continue;
                    }

                    long fva = parseHexLong(c.get("func_va").getAsString());
                    int ord  = c.get("ordinal").getAsInt();
                    Address fAddr = af.getDefaultAddressSpace().getAddress(fva);
                    Function f = fm.getFunctionAt(fAddr);
                    if (f == null) continue;

                    DataType dt = null;
                    if (c.has("type_name")) {
                        dt = resolveDataType(dtm, c.get("type_name").getAsString(), 0);
                    }
                    if (dt == null) dt = ghidra.program.model.data.DataType.DEFAULT;

                    // Update existing param at ordinal or append a new one.  Guarded
                    // because getParameters() can still throw if a function had bad
                    // variable records we didn't successfully clean up.
                    Parameter[] params;
                    try { params = f.getParameters(); }
                    catch (Exception e) { continue; }

                    if (ord >= 0 && ord < params.length) {
                        params[ord].setName(name, SourceType.USER_DEFINED);
                        if (dt != ghidra.program.model.data.DataType.DEFAULT) {
                            try { params[ord].setDataType(dt, SourceType.USER_DEFINED); }
                            catch (Exception ignored) {}
                        }
                    } else {
                        try {
                            f.addParameter(
                                new ghidra.program.model.listing.ParameterImpl(name, dt, program),
                                SourceType.USER_DEFINED);
                        } catch (Exception ignored) {}
                    }
                    ++count;
                }
            } catch (Exception ignored) {}
        }
        System.err.println("[ghidra-bridge] params applied: " + count
            + (skippedLocals > 0 ? " (skipped " + skippedLocals + " locals — storage mapping not implemented)" : ""));
        return count;
    }

    // -------------------------------------------------------------------------
    // Data items
    // -------------------------------------------------------------------------

    static int applyDataItems(ProgramDB program, JsonArray dataItems) {
        Listing listing = program.getListing();
        DataTypeManager dtm = program.getDataTypeManager();
        AddressFactory af = program.getAddressFactory();
        int count = 0;
        for (JsonElement el : dataItems) {
            JsonObject d = el.getAsJsonObject();
            String op = getStr(d, "op", "add");
            long va = d.has("addr") ? parseHexLong(d.get("addr").getAsString()) : -1;
            if (va < 0) continue;
            try {
                Address addr = af.getDefaultAddressSpace().getAddress(va);
                if ("delete".equals(op)) {
                    Data data = listing.getDataAt(addr);
                    if (data != null) listing.clearCodeUnits(addr, data.getMaxAddress(), false);
                    ++count;
                } else {
                    DataType dt = resolveDataType(dtm, getStr(d, "type_name", ""), 0);
                    if (dt == null) continue;
                    // Clear any existing code unit at the location first.
                    Data existing = listing.getDataAt(addr);
                    if (existing != null) {
                        listing.clearCodeUnits(addr, existing.getMaxAddress(), false);
                    }
                    listing.createData(addr, dt);
                    ++count;
                }
            } catch (Exception e) {
                System.err.println("[ghidra-bridge] data item " + getStr(d, "addr", "?")
                    + " failed: " + e);
            }
        }
        System.err.println("[ghidra-bridge] data items applied: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Function signatures
    // -------------------------------------------------------------------------

    static int applyFuncSigs(ProgramDB program, JsonArray changes) {
        FunctionManager fm = program.getFunctionManager();
        DataTypeManager dtm = program.getDataTypeManager();
        int count = 0;
        for (JsonElement el : changes) {
            JsonObject c = el.getAsJsonObject();
            long key = c.get("key").getAsLong();
            // FunctionManager.getFunction(key) takes the function's primary symbol ID
            Function f;
            try { f = fm.getFunction(key); } catch (Exception e) { continue; }
            if (f == null) continue;

            boolean changed = false;
            if (c.has("ret_type")) {
                String rt = c.get("ret_type").getAsString();
                DataType retDt = resolveDataType(dtm, rt, 0);
                if (retDt != null) {
                    try {
                        f.setReturnType(retDt, SourceType.USER_DEFINED);
                        changed = true;
                    } catch (Exception ignored) {}
                }
            }
            if (c.has("cc")) {
                String cc = c.get("cc").getAsString();
                if (!cc.isEmpty()) {
                    // BN names conventions "cdecl"/"stdcall"; Ghidra's compiler
                    // specs register them as "__cdecl"/"__stdcall". Since
                    // Ghidra 11 setCallingConvention() accepts ANY string
                    // (stored as an unusable custom convention), so we must
                    // resolve against the spec's known models ourselves —
                    // otherwise the CC silently never lands and BN re-queues
                    // the same change on every check-in.
                    try {
                        java.util.Set<String> known = new java.util.HashSet<>();
                        for (ghidra.program.model.lang.PrototypeModel m
                                : program.getCompilerSpec().getCallingConventions())
                            known.add(m.getName());
                        String resolved = known.contains(cc) ? cc
                            : known.contains("__" + cc) ? "__" + cc : null;
                        if (resolved != null) {
                            f.setCallingConvention(resolved);
                            changed = true;
                        } else {
                            System.err.println("[ghidra-bridge] unknown calling convention '"
                                + cc + "' for function at " + f.getEntryPoint() + " — skipped");
                        }
                    } catch (Exception ignored) {}
                }
            }
            if (changed) ++count;
        }
        System.err.println("[ghidra-bridge] func sig changes applied: " + count);
        return count;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String getStr(JsonObject obj, String key, String dflt) {
        return obj.has(key) ? obj.get(key).getAsString() : dflt;
    }

    private static String nullIfEmpty(String s) {
        return (s == null || s.isEmpty()) ? null : s;
    }

    private static long parseHexLong(String s) {
        if (s == null || s.isEmpty()) return 0;
        String t = (s.startsWith("0x") || s.startsWith("0X")) ? s.substring(2) : s;
        return Long.parseUnsignedLong(t, 16);
    }
}
