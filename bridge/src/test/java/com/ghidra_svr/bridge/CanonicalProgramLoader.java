package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.util.HashMap;
import java.util.Map;

/**
 * Populates a fresh ProgramDB from a golden canonical export
 * (testdata/parity/fixtures — the DatabaseExporter JSON shape).
 *
 * Wherever the shapes line up, the loader routes through the production
 * ProgramApplier helpers so the import direction also exercises the real write
 * path. Golden DB keys/ids are identity, not content — the loader records the
 * REAL ids the fresh database assigned so callers can remap keys in a checkin
 * preview (see {@link #remapPreview}).
 */
final class CanonicalProgramLoader {

    /** golden symbol key → real symbol id in the loaded program. */
    final Map<Long, Long> symbolKeyMap = new HashMap<>();
    /** golden equate id → real Equates-table key in the loaded program. */
    final Map<Long, Long> equateIdMap = new HashMap<>();

    /** Must be called inside a transaction. */
    void load(ProgramDB p, JsonObject golden) throws Exception {
        // --- data types first: items/signatures reference them ---------------
        if (golden.has("data_types")) {
            JsonArray changes = new JsonArray();
            Map<Long, String> idToName = new HashMap<>();
            for (JsonElement el : golden.getAsJsonArray("data_types")) {
                JsonObject dt = el.getAsJsonObject();
                idToName.put(dt.get("id").getAsLong(), dt.get("name").getAsString());
                JsonObject c = dt.deepCopy();
                c.addProperty("op", "add");
                // Golden typedefs use the exporter key; the applier expects the
                // checkin-preview key.
                if (c.has("underlying_name"))
                    c.addProperty("underlying_type_name", c.get("underlying_name").getAsString());
                changes.add(c);
            }
            ProgramApplier.applyDataTypes(p, changes);
        }

        // --- symbols (functions + labels) -------------------------------------
        if (golden.has("symbols")) {
            for (JsonElement el : golden.getAsJsonArray("symbols")) {
                JsonObject s = el.getAsJsonObject();
                long goldenKey = s.get("key").getAsLong();
                String name    = s.get("name").getAsString();
                long va        = parseHex(s.get("addr").getAsString());
                int type       = s.has("type") ? s.get("type").getAsInt() : 0;
                Address addr   = addr(p, va);

                Symbol created;
                if (type == 4) {
                    Function f = p.getFunctionManager().createFunction(
                        name, addr, new AddressSet(addr, addr), SourceType.USER_DEFINED);
                    created = f.getSymbol();
                } else {
                    created = p.getSymbolTable().createLabel(
                        addr, name, SourceType.USER_DEFINED);
                }
                symbolKeyMap.put(goldenKey, created.getID());
            }
        }

        // --- comments ---------------------------------------------------------
        if (golden.has("comments")) {
            JsonArray comments = new JsonArray();
            for (JsonElement el : golden.getAsJsonArray("comments")) {
                JsonObject c = el.getAsJsonObject().deepCopy();
                c.addProperty("va", c.get("addr").getAsString());
                c.remove("key"); // encoded keys are export-side identity
                comments.add(c);
            }
            ProgramApplier.applyComments(p, comments);
        }

        // --- equates ------------------------------------------------------------
        if (golden.has("equates")) {
            EquateTable et = p.getEquateTable();
            for (JsonElement el : golden.getAsJsonArray("equates")) {
                JsonObject e = el.getAsJsonObject();
                Equate eq = et.createEquate(e.get("name").getAsString(),
                                            e.get("value").getAsLong());
                if (e.has("refs")) {
                    for (JsonElement rel : e.getAsJsonArray("refs")) {
                        JsonObject r = rel.getAsJsonObject();
                        eq.addReference(addr(p, parseHex(r.get("addr").getAsString())),
                                        r.get("op_index").getAsInt());
                    }
                }
            }
            // Resolve real Equates-table keys for id remapping.
            Map<String, Long> keyByName = new HashMap<>();
            db.Table tbl = p.getDBHandle().getTable("Equates");
            if (tbl != null) {
                db.RecordIterator it = tbl.iterator();
                while (it.hasNext()) {
                    db.DBRecord r = it.next();
                    if (r.getString(0) != null) keyByName.put(r.getString(0), r.getKey());
                }
            }
            for (JsonElement el : golden.getAsJsonArray("equates")) {
                JsonObject e = el.getAsJsonObject();
                Long real = keyByName.get(e.get("name").getAsString());
                if (real != null) equateIdMap.put(e.get("id").getAsLong(), real);
            }
        }

        // --- bookmarks -----------------------------------------------------------
        if (golden.has("bookmarks")) {
            JsonArray changes = new JsonArray();
            for (JsonElement el : golden.getAsJsonArray("bookmarks")) {
                JsonObject b = el.getAsJsonObject().deepCopy();
                b.addProperty("op", "add");
                changes.add(b);
            }
            ProgramApplier.applyBookmarks(p, changes);
        }

        // --- data items ------------------------------------------------------------
        if (golden.has("data_items")) {
            Map<Long, String> idToName = new HashMap<>();
            for (JsonElement el : golden.getAsJsonArray("data_types")) {
                JsonObject dt = el.getAsJsonObject();
                idToName.put(dt.get("id").getAsLong(), dt.get("name").getAsString());
            }
            JsonArray items = new JsonArray();
            for (JsonElement el : golden.getAsJsonArray("data_items")) {
                JsonObject d = el.getAsJsonObject();
                String typeName = idToName.get(d.get("type_id").getAsLong());
                if (typeName == null) continue;
                JsonObject item = new JsonObject();
                item.addProperty("op", "add");
                item.addProperty("addr", d.get("addr").getAsString());
                item.addProperty("type_name", typeName);
                items.add(item);
            }
            ProgramApplier.applyDataItems(p, items);
        }

        // --- function signatures (cc / return type) ---------------------------------
        if (golden.has("func_flags")) {
            JsonArray sigChanges = new JsonArray();
            for (JsonElement el : golden.getAsJsonArray("func_flags")) {
                JsonObject f = el.getAsJsonObject();
                if (!f.has("cc") && !f.has("ret_type")) continue;
                Long realKey = symbolKeyMap.get(f.get("key").getAsLong());
                if (realKey == null) continue;
                JsonObject c = new JsonObject();
                c.addProperty("key", realKey);
                if (f.has("cc"))       c.addProperty("cc", f.get("cc").getAsString());
                if (f.has("ret_type")) c.addProperty("ret_type", f.get("ret_type").getAsString());
                sigChanges.add(c);
            }
            ProgramApplier.applyFuncSigs(p, sigChanges);
        }
    }

    /**
     * Rewrite golden DB keys/ids in a checkin preview to the ids the loaded
     * program actually assigned. Returns a deep copy; the input is untouched.
     */
    JsonObject remapPreview(JsonObject preview) {
        JsonObject out = preview.deepCopy();
        if (out.has("symbols")) {
            for (JsonElement el : out.getAsJsonArray("symbols")) {
                JsonObject s = el.getAsJsonObject();
                if (s.has("key")) {
                    Long real = symbolKeyMap.get(s.get("key").getAsLong());
                    if (real != null) s.addProperty("key", real);
                }
            }
        }
        if (out.has("func_sig_changes")) {
            for (JsonElement el : out.getAsJsonArray("func_sig_changes")) {
                JsonObject s = el.getAsJsonObject();
                Long real = symbolKeyMap.get(s.get("key").getAsLong());
                if (real != null) s.addProperty("key", real);
            }
        }
        for (String arrName : new String[] {"equate_renames", "equate_ref_adds"}) {
            if (!out.has(arrName)) continue;
            for (JsonElement el : out.getAsJsonArray(arrName)) {
                JsonObject e = el.getAsJsonObject();
                if (e.has("id")) {
                    Long real = equateIdMap.get(e.get("id").getAsLong());
                    if (real != null) e.addProperty("id", real);
                }
            }
        }
        return out;
    }

    private static Address addr(ProgramDB p, long va) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(va);
    }

    private static long parseHex(String s) {
        String t = (s.startsWith("0x") || s.startsWith("0X")) ? s.substring(2) : s;
        return Long.parseUnsignedLong(t, 16);
    }
}
