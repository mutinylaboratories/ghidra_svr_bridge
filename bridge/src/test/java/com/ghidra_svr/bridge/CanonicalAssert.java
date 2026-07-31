package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Java half of the canonical-parity comparator. Mirrors
 * plugin/test/support/CanonicalDiff.cpp — the per-category modes and the
 * type-name normalization table are specified once in
 * testdata/parity/RULES.md; change all three together.
 *
 * DB keys/ids are identity, not content: func_flags keys are resolved to
 * addresses through the SAME document's symbols, and data-item type ids
 * through the same document's data_types.
 */
final class CanonicalAssert {

    private static final Map<String, String> NORMALIZE = new HashMap<>();
    static {
        NORMALIZE.put("int", "int32_t");        NORMALIZE.put("long", "int32_t");
        NORMALIZE.put("uint", "uint32_t");      NORMALIZE.put("ulong", "uint32_t");
        NORMALIZE.put("dword", "uint32_t");
        NORMALIZE.put("byte", "uint8_t");       NORMALIZE.put("uchar", "uint8_t");
        NORMALIZE.put("sbyte", "int8_t");       NORMALIZE.put("char", "int8_t");
        NORMALIZE.put("short", "int16_t");
        NORMALIZE.put("ushort", "uint16_t");    NORMALIZE.put("word", "uint16_t");
        NORMALIZE.put("longlong", "int64_t");
        NORMALIZE.put("ulonglong", "uint64_t"); NORMALIZE.put("qword", "uint64_t");
        NORMALIZE.put("undefined1", "uint8_t"); NORMALIZE.put("undefined2", "uint16_t");
        NORMALIZE.put("undefined4", "uint32_t");NORMALIZE.put("undefined8", "uint64_t");
    }

    static String normalizeTypeName(String raw) {
        if (raw == null) return "";
        String name = raw.trim();
        if (name.isEmpty()) return name;
        if (name.endsWith("*"))
            return normalizeTypeName(name.substring(0, name.length() - 1)) + "*";
        if (name.endsWith("]")) {
            int ob = name.lastIndexOf('[');
            if (ob >= 0)
                return normalizeTypeName(name.substring(0, ob)) + name.substring(ob);
        }
        for (String prefix : new String[] {"struct ", "union ", "enum "}) {
            if (name.startsWith(prefix))
                return normalizeTypeName(name.substring(prefix.length()));
        }
        return NORMALIZE.getOrDefault(name, name);
    }

    /** Compare golden vs actual canonical exports; empty list = parity holds. */
    static List<String> compare(JsonObject golden, JsonObject actual) {
        List<String> issues = new ArrayList<>();
        compareSymbols(golden, actual, issues);
        compareComments(golden, actual, issues);
        compareFuncFlags(golden, actual, issues);
        compareEquates(golden, actual, issues);
        compareBookmarks(golden, actual, issues);
        compareParameters(golden, actual, issues);
        compareDataTypes(golden, actual, issues);
        compareDataItems(golden, actual, issues);
        return issues;
    }

    // ---- helpers -------------------------------------------------------------

    private static JsonArray arr(JsonObject o, String key) {
        return (o.has(key) && o.get(key).isJsonArray())
            ? o.getAsJsonArray(key) : new JsonArray();
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : "";
    }

    private static boolean isAutoGenName(String n) {
        java.util.function.BiPredicate<Integer, Integer> hexSuffix = (offset, minLen) -> {
            if (n.length() < offset + minLen) return false;
            for (int k = offset; k < n.length(); ++k) {
                char c = n.charAt(k);
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F'))) return false;
            }
            return true;
        };
        if (n.startsWith("sub_") && hexSuffix.test(4, 4)) return true;
        if (n.startsWith("FUN_") && hexSuffix.test(4, 4)) return true;
        if (n.startsWith("off_") && hexSuffix.test(4, 4)) return true;
        if (n.startsWith("unk_") && hexSuffix.test(4, 4)) return true;
        if (n.startsWith("j_")   && hexSuffix.test(2, 2)) return true;
        if (n.startsWith("j_")   && isAutoGenName(n.substring(2))) return true;
        return false;
    }

    // ---- symbols (EXACT, both directions, auto names excluded) -----------------

    private static void compareSymbols(JsonObject golden, JsonObject actual,
                                       List<String> out) {
        Set<String> g = new HashSet<>(), a = new HashSet<>();
        for (JsonElement el : arr(golden, "symbols")) {
            JsonObject s = el.getAsJsonObject();
            if (isAutoGenName(str(s, "name"))) continue;
            g.add(str(s, "addr") + "|" + str(s, "name") + "|" +
                  (s.has("type") ? s.get("type").getAsInt() : 0));
        }
        for (JsonElement el : arr(actual, "symbols")) {
            JsonObject s = el.getAsJsonObject();
            if (isAutoGenName(str(s, "name"))) continue;
            a.add(str(s, "addr") + "|" + str(s, "name") + "|" +
                  (s.has("type") ? s.get("type").getAsInt() : 0));
        }
        for (String k : g) if (!a.contains(k)) out.add("symbol missing in actual: " + k);
        for (String k : a) if (!g.contains(k)) out.add("symbol only in actual: " + k);
    }

    // ---- comments (EXACT per (addr, column)) ------------------------------------

    private static final String[] COMMENT_FIELDS = {"eol", "pre", "post", "rep", "plate"};

    private static Map<String, String> flattenComments(JsonArray comments) {
        Map<String, String> m = new TreeMap<>();
        for (JsonElement el : comments) {
            JsonObject c = el.getAsJsonObject();
            for (String f : COMMENT_FIELDS) {
                String text = str(c, f);
                if (!text.isEmpty()) m.put(str(c, "addr") + "|" + f, text);
            }
        }
        return m;
    }

    private static void compareComments(JsonObject golden, JsonObject actual,
                                        List<String> out) {
        Map<String, String> g = flattenComments(arr(golden, "comments"));
        Map<String, String> a = flattenComments(arr(actual, "comments"));
        for (Map.Entry<String, String> e : g.entrySet()) {
            String have = a.get(e.getKey());
            if (have == null)
                out.add("comment missing in actual: " + e.getKey());
            else if (!have.equals(e.getValue()))
                out.add("comment text mismatch at " + e.getKey() +
                        ": golden \"" + e.getValue() + "\" vs actual \"" + have + "\"");
        }
        for (String k : a.keySet())
            if (!g.containsKey(k)) out.add("comment only in actual: " + k);
    }

    // ---- func flags / signatures (IMPORT_ONLY on golden fields) -------------------

    private static Map<Long, String> keyToAddr(JsonObject doc) {
        Map<Long, String> m = new HashMap<>();
        for (JsonElement el : arr(doc, "symbols")) {
            JsonObject s = el.getAsJsonObject();
            if (s.has("key")) m.put(s.get("key").getAsLong(), str(s, "addr"));
        }
        return m;
    }

    private static void compareFuncFlags(JsonObject golden, JsonObject actual,
                                         List<String> out) {
        Map<Long, String> gKeys = keyToAddr(golden);
        Map<Long, String> aKeys = keyToAddr(actual);

        Map<String, JsonObject> aByAddr = new HashMap<>();
        for (JsonElement el : arr(actual, "func_flags")) {
            JsonObject f = el.getAsJsonObject();
            String addr = f.has("addr") ? str(f, "addr")
                        : f.has("key") ? aKeys.get(f.get("key").getAsLong()) : null;
            if (addr != null) aByAddr.put(addr, f);
        }

        for (JsonElement el : arr(golden, "func_flags")) {
            JsonObject g = el.getAsJsonObject();
            String addr = g.has("addr") ? str(g, "addr")
                        : g.has("key") ? gKeys.get(g.get("key").getAsLong()) : null;
            if (addr == null) { out.add("golden func_flags entry has no resolvable addr"); continue; }
            JsonObject a = aByAddr.get(addr);
            if (a == null) { out.add("no actual function entry at " + addr); continue; }
            for (String flag : new String[] {"thunk", "no_ret", "inline"}) {
                boolean gv = g.has(flag) && g.get(flag).getAsBoolean();
                boolean av = a.has(flag) && a.get(flag).getAsBoolean();
                if (gv && !av) out.add("flag " + flag + " missing on actual function at " + addr);
            }
            if (!str(g, "cc").isEmpty() && !str(g, "cc").equals(str(a, "cc")))
                out.add("calling convention mismatch at " + addr + ": golden " +
                        str(g, "cc") + " vs actual " + str(a, "cc"));
            if (!str(g, "ret_type").isEmpty() &&
                !normalizeTypeName(str(g, "ret_type")).equals(normalizeTypeName(str(a, "ret_type"))))
                out.add("return type mismatch at " + addr + ": golden " +
                        str(g, "ret_type") + " vs actual " + str(a, "ret_type"));
        }
    }

    // ---- equates (EXACT golden → actual by name) ------------------------------------

    private static void compareEquates(JsonObject golden, JsonObject actual,
                                       List<String> out) {
        Map<String, JsonObject> aByName = new HashMap<>();
        for (JsonElement el : arr(actual, "equates")) {
            JsonObject e = el.getAsJsonObject();
            aByName.put(str(e, "name"), e);
        }
        for (JsonElement el : arr(golden, "equates")) {
            JsonObject g = el.getAsJsonObject();
            JsonObject a = aByName.get(str(g, "name"));
            if (a == null) { out.add("equate missing in actual: " + str(g, "name")); continue; }
            if (g.get("value").getAsLong() != a.get("value").getAsLong())
                out.add("equate value mismatch for " + str(g, "name"));
            Set<String> gr = refSet(g), ar = refSet(a);
            for (String r : gr)
                if (!ar.contains(r))
                    out.add("equate ref missing in actual: " + str(g, "name") + " @ " + r);
        }
    }

    private static Set<String> refSet(JsonObject equate) {
        Set<String> s = new HashSet<>();
        for (JsonElement el : arr(equate, "refs")) {
            JsonObject r = el.getAsJsonObject();
            s.add(str(r, "addr") + "#" +
                  (r.has("op_index") ? r.get("op_index").getAsInt() : 0));
        }
        return s;
    }

    // ---- bookmarks (EXACT both directions) ---------------------------------------------

    private static void compareBookmarks(JsonObject golden, JsonObject actual,
                                         List<String> out) {
        Set<String> g = new HashSet<>(), a = new HashSet<>();
        for (JsonElement el : arr(golden, "bookmarks")) {
            JsonObject b = el.getAsJsonObject();
            g.add(str(b, "type") + "|" + str(b, "addr") + "|" +
                  str(b, "category") + "|" + str(b, "comment"));
        }
        for (JsonElement el : arr(actual, "bookmarks")) {
            JsonObject b = el.getAsJsonObject();
            a.add(str(b, "type") + "|" + str(b, "addr") + "|" +
                  str(b, "category") + "|" + str(b, "comment"));
        }
        for (String k : g) if (!a.contains(k)) out.add("bookmark missing in actual: " + k);
        for (String k : a) if (!g.contains(k)) out.add("bookmark only in actual: " + k);
    }

    // ---- parameters & stack locals (EXACT on golden slots) ------------------------------

    private static void compareParameters(JsonObject golden, JsonObject actual,
                                          List<String> out) {
        Map<String, JsonObject> aBySlot = new HashMap<>();
        for (JsonElement el : arr(actual, "parameters")) {
            JsonObject p = el.getAsJsonObject();
            aBySlot.put(paramSlot(p), p);
        }
        for (JsonElement el : arr(golden, "parameters")) {
            JsonObject g = el.getAsJsonObject();
            JsonObject a = aBySlot.get(paramSlot(g));
            if (a == null) {
                out.add("parameter/local missing in actual: " + paramSlot(g) +
                        " (" + str(g, "name") + ")");
                continue;
            }
            if (!str(g, "name").equals(str(a, "name")))
                out.add("parameter name mismatch at " + paramSlot(g) + ": golden " +
                        str(g, "name") + " vs actual " + str(a, "name"));
            if (!str(g, "type_name").isEmpty() &&
                !normalizeTypeName(str(g, "type_name")).equals(normalizeTypeName(str(a, "type_name"))))
                out.add("parameter type mismatch at " + paramSlot(g));
        }
    }

    private static String paramSlot(JsonObject p) {
        boolean isParam = !p.has("is_param") || p.get("is_param").getAsBoolean();
        return str(p, "func_addr") + "|" + (isParam ? "p" : "l") + "|" +
               (p.has("ordinal") ? p.get("ordinal").getAsInt() : 0);
    }

    // ---- data types (golden → actual by name) ---------------------------------------------

    private static void compareDataTypes(JsonObject golden, JsonObject actual,
                                         List<String> out) {
        Map<String, JsonObject> aByName = new HashMap<>();
        for (JsonElement el : arr(actual, "data_types")) {
            JsonObject t = el.getAsJsonObject();
            aByName.put(str(t, "name"), t);
        }
        for (JsonElement el : arr(golden, "data_types")) {
            JsonObject g = el.getAsJsonObject();
            String name = str(g, "name");
            JsonObject a = aByName.get(name);
            if (a == null) { out.add("data type missing in actual: " + name); continue; }
            String kind = str(g, "kind");
            if (!kind.equals(str(a, "kind"))) {
                out.add("data type kind mismatch for " + name + ": golden " + kind +
                        " vs actual " + str(a, "kind"));
                continue;
            }
            switch (kind) {
                case "struct":
                case "union": {
                    if (g.has("size") && a.has("size") &&
                        g.get("size").getAsInt() != a.get("size").getAsInt())
                        out.add("struct size mismatch for " + name + ": golden " +
                                g.get("size").getAsInt() + " vs actual " +
                                a.get("size").getAsInt());
                    Map<Integer, JsonObject> gm = membersByOffset(g);
                    Map<Integer, JsonObject> am = membersByOffset(a);
                    for (Map.Entry<Integer, JsonObject> e : gm.entrySet()) {
                        JsonObject m = e.getValue();
                        JsonObject am2 = am.get(e.getKey());
                        if (am2 == null) {
                            out.add("member missing in actual " + name + " at offset " +
                                    e.getKey() + " (" + str(m, "name") + ")");
                            continue;
                        }
                        if (!str(m, "name").equals(str(am2, "name")))
                            out.add("member name mismatch in " + name + " at offset " +
                                    e.getKey() + ": golden " + str(m, "name") +
                                    " vs actual " + str(am2, "name"));
                        if (!str(m, "type_name").isEmpty() &&
                            !normalizeTypeName(str(m, "type_name"))
                                .equals(normalizeTypeName(str(am2, "type_name"))))
                            out.add("member type mismatch in " + name + " at offset " +
                                    e.getKey() + ": golden " + str(m, "type_name") +
                                    " vs actual " + str(am2, "type_name"));
                    }
                    for (Integer off : am.keySet())
                        if (!gm.containsKey(off))
                            out.add("extra member in actual " + name + " at offset " + off);
                    break;
                }
                case "enum": {
                    Map<String, Long> gv = enumValues(g), av = enumValues(a);
                    if (!gv.equals(av)) out.add("enum values mismatch for " + name);
                    if (g.has("size") && a.has("size") && g.get("size").getAsInt() != 0 &&
                        g.get("size").getAsInt() != a.get("size").getAsInt())
                        out.add("enum width mismatch for " + name);
                    break;
                }
                case "typedef": {
                    if (!normalizeTypeName(str(g, "underlying_name"))
                            .equals(normalizeTypeName(str(a, "underlying_name"))))
                        out.add("typedef target mismatch for " + name + ": golden " +
                                str(g, "underlying_name") + " vs actual " +
                                str(a, "underlying_name"));
                    break;
                }
                default:
                    break;
            }
        }
    }

    private static Map<Integer, JsonObject> membersByOffset(JsonObject type) {
        Map<Integer, JsonObject> m = new TreeMap<>();
        for (JsonElement el : arr(type, "members")) {
            JsonObject mm = el.getAsJsonObject();
            m.put(mm.has("offset") ? mm.get("offset").getAsInt() : 0, mm);
        }
        return m;
    }

    private static Map<String, Long> enumValues(JsonObject type) {
        Map<String, Long> m = new TreeMap<>();
        for (JsonElement el : arr(type, "values")) {
            JsonObject v = el.getAsJsonObject();
            m.put(str(v, "name"), v.has("value") ? v.get("value").getAsLong() : 0L);
        }
        return m;
    }

    // ---- data items (golden → actual; type via same-document data_types) ----------------

    private static void compareDataItems(JsonObject golden, JsonObject actual,
                                         List<String> out) {
        Map<Long, String> gTypes = typeIdToName(golden);
        Map<Long, String> aTypes = typeIdToName(actual);

        Map<String, String> aByAddr = new HashMap<>();
        for (JsonElement el : arr(actual, "data_items")) {
            JsonObject d = el.getAsJsonObject();
            String typeName = !str(d, "type_name").isEmpty()
                ? str(d, "type_name")
                : (d.has("type_id") ? aTypes.get(d.get("type_id").getAsLong()) : null);
            aByAddr.put(str(d, "addr"), typeName == null ? "" : typeName);
        }

        for (JsonElement el : arr(golden, "data_items")) {
            JsonObject d = el.getAsJsonObject();
            String addr = str(d, "addr");
            String typeName = !str(d, "type_name").isEmpty()
                ? str(d, "type_name")
                : (d.has("type_id") ? gTypes.get(d.get("type_id").getAsLong()) : null);
            String have = aByAddr.get(addr);
            if (have == null) { out.add("data item missing in actual at " + addr); continue; }
            if (typeName != null && !typeName.isEmpty() &&
                !Objects.equals(normalizeTypeName(typeName), normalizeTypeName(have)))
                out.add("data item type mismatch at " + addr + ": golden " + typeName +
                        " vs actual " + have);
        }
    }

    private static Map<Long, String> typeIdToName(JsonObject doc) {
        Map<Long, String> m = new HashMap<>();
        for (JsonElement el : arr(doc, "data_types")) {
            JsonObject t = el.getAsJsonObject();
            if (t.has("id")) m.put(t.get("id").getAsLong(), str(t, "name"));
        }
        return m;
    }

    private CanonicalAssert() {}
}
