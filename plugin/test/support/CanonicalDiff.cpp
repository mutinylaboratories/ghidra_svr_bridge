#include "CanonicalDiff.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

using nlohmann::json;

namespace parity {

namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    size_t e = s.find_last_not_of(" \t");
    if (b == std::string::npos) return {};
    return s.substr(b, e - b + 1);
}

// Base-token mapping into the stdint family. One table, mirrored in Java by
// CanonicalAssert.NORMALIZE — update RULES.md when touching either.
const std::unordered_map<std::string, std::string>& baseMap() {
    static const std::unordered_map<std::string, std::string> m = {
        {"int", "int32_t"},       {"long", "int32_t"},
        {"uint", "uint32_t"},     {"ulong", "uint32_t"},
        {"dword", "uint32_t"},
        {"byte", "uint8_t"},      {"uchar", "uint8_t"},
        {"sbyte", "int8_t"},      {"char", "int8_t"},
        {"short", "int16_t"},
        {"ushort", "uint16_t"},   {"word", "uint16_t"},
        {"longlong", "int64_t"},
        {"ulonglong", "uint64_t"},{"qword", "uint64_t"},
        {"undefined1", "uint8_t"},{"undefined2", "uint16_t"},
        {"undefined4", "uint32_t"},{"undefined8", "uint64_t"},
    };
    return m;
}

} // namespace

std::string normalizeTypeName(const std::string& raw) {
    std::string name = trim(raw);
    if (name.empty()) return name;

    // Pointer: normalize "T *" / "T*" recursively.
    if (name.back() == '*') {
        std::string base = trim(name.substr(0, name.size() - 1));
        return normalizeTypeName(base) + "*";
    }
    // Array: "T [N]" / "T[N]".
    if (name.back() == ']') {
        size_t ob = name.rfind('[');
        if (ob != std::string::npos) {
            std::string base  = trim(name.substr(0, ob));
            std::string count = name.substr(ob);
            return normalizeTypeName(base) + count;
        }
    }
    // Strip BN's elaborated "struct Foo" / "enum Foo" / "union Foo" spelling.
    for (const char* prefix : {"struct ", "union ", "enum "}) {
        if (name.rfind(prefix, 0) == 0)
            return normalizeTypeName(name.substr(strlen(prefix)));
    }
    auto it = baseMap().find(name);
    return (it != baseMap().end()) ? it->second : name;
}

namespace {

struct Issues {
    std::vector<std::string> list;
    template <typename... Parts>
    void add(Parts&&... parts) {
        std::ostringstream os;
        (os << ... << parts);
        list.push_back(os.str());
    }
};

json arr(const json& j, const char* key) {
    return (j.contains(key) && j[key].is_array()) ? j[key] : json::array();
}

std::string str(const json& j, const char* key) {
    return j.value(key, std::string{});
}

// ---- symbols ---------------------------------------------------------------

void compareSymbols(const json& golden, const json& bn, Issues& out) {
    auto keyOf = [](const json& s) {
        return str(s, "addr") + "|" + str(s, "name") + "|" +
               std::to_string(s.value("type", 0));
    };
    std::set<std::string> g, b;
    for (const auto& s : arr(golden, "symbols")) g.insert(keyOf(s));
    for (const auto& s : arr(bn, "symbols"))     b.insert(keyOf(s));
    for (const auto& k : g)
        if (!b.count(k)) out.add("symbol missing on BN side: ", k);
    for (const auto& k : b)
        if (!g.count(k)) out.add("symbol only on BN side: ", k);
}

// ---- comments ---------------------------------------------------------------

void compareComments(const json& golden, const json& bn, Issues& out) {
    static const char* kFields[] = {"eol", "pre", "post", "rep", "plate"};
    auto flatten = [](const json& arr_) {
        // (addr, field) → text
        std::map<std::pair<std::string, std::string>, std::string> m;
        for (const auto& c : arr_) {
            for (const char* f : kFields)
                if (c.contains(f) && !c[f].get<std::string>().empty())
                    m[{str(c, "addr"), f}] = c[f].get<std::string>();
        }
        return m;
    };
    auto g = flatten(arr(golden, "comments"));
    auto b = flatten(arr(bn, "comments"));
    for (const auto& [k, text] : g) {
        auto it = b.find(k);
        if (it == b.end())
            out.add("comment missing on BN side: ", k.first, " [", k.second, "]");
        else if (it->second != text)
            out.add("comment text mismatch at ", k.first, " [", k.second,
                    "]: golden \"", text, "\" vs BN \"", it->second, "\"");
    }
    for (const auto& [k, text] : b)
        if (!g.count(k))
            out.add("comment only on BN side: ", k.first, " [", k.second,
                    "] \"", text, "\"");
}

// ---- func flags / signatures (IMPORT_ONLY, keyed via golden symbols) --------

void compareFuncFlags(const json& golden, const json& bn, Issues& out) {
    // Golden func_flags are keyed by DB key; resolve to addr via golden symbols.
    std::unordered_map<int64_t, std::string> keyToAddr;
    for (const auto& s : arr(golden, "symbols"))
        if (s.contains("key")) keyToAddr[s["key"].get<int64_t>()] = str(s, "addr");

    std::unordered_map<std::string, json> bnByAddr;
    for (const auto& f : arr(bn, "func_flags")) bnByAddr[str(f, "addr")] = f;

    for (const auto& g : arr(golden, "func_flags")) {
        std::string addr = g.contains("addr") ? str(g, "addr")
                          : g.contains("key") ? keyToAddr[g["key"].get<int64_t>()]
                                              : std::string{};
        if (addr.empty()) { out.add("golden func_flags entry has no resolvable addr"); continue; }
        auto it = bnByAddr.find(addr);
        if (it == bnByAddr.end()) { out.add("no BN function at ", addr, " for func_flags"); continue; }
        const json& b = it->second;
        for (const char* flag : {"thunk", "no_ret", "inline"}) {
            if (g.value(flag, false) && !b.value(flag, false))
                out.add("flag ", flag, " missing on BN function at ", addr);
        }
        if (!str(g, "cc").empty() && str(g, "cc") != str(b, "cc"))
            out.add("calling convention mismatch at ", addr, ": golden ",
                    str(g, "cc"), " vs BN ", str(b, "cc"));
        if (!str(g, "ret_type").empty() &&
            normalizeTypeName(str(g, "ret_type")) != normalizeTypeName(str(b, "ret_type")))
            out.add("return type mismatch at ", addr, ": golden ",
                    str(g, "ret_type"), " vs BN ", str(b, "ret_type"));
    }
}

// ---- equates -----------------------------------------------------------------

void compareEquates(const json& golden, const json& bn, Issues& out) {
    std::unordered_map<std::string, json> bnByName;
    for (const auto& e : arr(bn, "equates")) bnByName[str(e, "name")] = e;

    for (const auto& g : arr(golden, "equates")) {
        auto it = bnByName.find(str(g, "name"));
        if (it == bnByName.end()) {
            out.add("equate missing on BN side: ", str(g, "name"));
            continue;
        }
        const json& b = it->second;
        if (g.value("value", int64_t{0}) != b.value("value", int64_t{0}))
            out.add("equate value mismatch for ", str(g, "name"));
        std::set<std::string> gr, br;
        for (const auto& r : arr(g, "refs"))
            gr.insert(str(r, "addr") + "#" + std::to_string(r.value("op_index", 0)));
        for (const auto& r : arr(b, "refs"))
            br.insert(str(r, "addr") + "#" + std::to_string(r.value("op_index", 0)));
        for (const auto& r : gr)
            if (!br.count(r))
                out.add("equate ref missing on BN side: ", str(g, "name"), " @ ", r);
    }
}

// ---- bookmarks -----------------------------------------------------------------

void compareBookmarks(const json& golden, const json& bn, Issues& out) {
    auto keyOf = [](const json& b) {
        return str(b, "type") + "|" + str(b, "addr") + "|" + str(b, "category") +
               "|" + str(b, "comment");
    };
    std::set<std::string> g, b;
    for (const auto& x : arr(golden, "bookmarks")) g.insert(keyOf(x));
    for (const auto& x : arr(bn, "bookmarks"))     b.insert(keyOf(x));
    for (const auto& k : g)
        if (!b.count(k)) out.add("bookmark missing on BN side: ", k);
    for (const auto& k : b)
        if (!g.count(k)) out.add("bookmark only on BN side: ", k);
}

// ---- parameters & stack locals --------------------------------------------------

void compareParameters(const json& golden, const json& bn, Issues& out) {
    auto slot = [](const json& p) {
        return str(p, "func_addr") + "|" + (p.value("is_param", true) ? "p" : "l") +
               "|" + std::to_string(p.value("ordinal", 0));
    };
    std::unordered_map<std::string, json> bnBySlot;
    for (const auto& p : arr(bn, "parameters")) bnBySlot[slot(p)] = p;

    for (const auto& g : arr(golden, "parameters")) {
        auto it = bnBySlot.find(slot(g));
        if (it == bnBySlot.end()) {
            out.add("parameter/local missing on BN side: ", slot(g),
                    " (", str(g, "name"), ")");
            continue;
        }
        if (str(g, "name") != str(it->second, "name"))
            out.add("parameter name mismatch at ", slot(g), ": golden ",
                    str(g, "name"), " vs BN ", str(it->second, "name"));
        if (!str(g, "type_name").empty() &&
            normalizeTypeName(str(g, "type_name")) !=
                normalizeTypeName(str(it->second, "type_name")))
            out.add("parameter type mismatch at ", slot(g), ": golden ",
                    str(g, "type_name"), " vs BN ", str(it->second, "type_name"));
    }
}

// ---- data types (golden → BN) -----------------------------------------------------

void compareDataTypes(const json& golden, const json& bn, Issues& out) {
    std::unordered_map<std::string, json> bnByName;
    for (const auto& t : arr(bn, "data_types")) bnByName[str(t, "name")] = t;

    for (const auto& g : arr(golden, "data_types")) {
        const std::string name = str(g, "name");
        auto it = bnByName.find(name);
        if (it == bnByName.end()) {
            out.add("data type missing on BN side: ", name);
            continue;
        }
        const json& b = it->second;
        if (str(g, "kind") != str(b, "kind")) {
            out.add("data type kind mismatch for ", name, ": golden ",
                    str(g, "kind"), " vs BN ", str(b, "kind"));
            continue;
        }
        const std::string kind = str(g, "kind");
        if (kind == "struct" || kind == "union") {
            if (g.value("size", 0) != b.value("size", 0))
                out.add("struct size mismatch for ", name, ": golden ",
                        g.value("size", 0), " vs BN ", b.value("size", 0));
            // Compare members by offset.
            std::map<int, json> gm, bm;
            for (const auto& m : arr(g, "members")) gm[m.value("offset", 0)] = m;
            for (const auto& m : arr(b, "members")) bm[m.value("offset", 0)] = m;
            for (const auto& [off, m] : gm) {
                auto bit = bm.find(off);
                if (bit == bm.end()) {
                    out.add("member missing in BN ", name, " at offset ", off,
                            " (", str(m, "name"), ")");
                    continue;
                }
                if (str(m, "name") != str(bit->second, "name"))
                    out.add("member name mismatch in ", name, " at offset ", off,
                            ": golden ", str(m, "name"), " vs BN ",
                            str(bit->second, "name"));
                if (!str(m, "type_name").empty() &&
                    normalizeTypeName(str(m, "type_name")) !=
                        normalizeTypeName(str(bit->second, "type_name")))
                    out.add("member type mismatch in ", name, " at offset ", off,
                            ": golden ", str(m, "type_name"), " vs BN ",
                            str(bit->second, "type_name"));
            }
            for (const auto& [off, m] : bm)
                if (!gm.count(off))
                    out.add("extra member in BN ", name, " at offset ", off,
                            " (", str(m, "name"), ")");
        } else if (kind == "enum") {
            std::map<std::string, int64_t> gv, bv;
            for (const auto& v : arr(g, "values"))
                gv[str(v, "name")] = v.value("value", int64_t{0});
            for (const auto& v : arr(b, "values"))
                bv[str(v, "name")] = v.value("value", int64_t{0});
            if (gv != bv) out.add("enum values mismatch for ", name);
            if (g.value("size", 0) != 0 && g.value("size", 0) != b.value("size", 0))
                out.add("enum width mismatch for ", name, ": golden ",
                        g.value("size", 0), " vs BN ", b.value("size", 0));
        } else if (kind == "typedef") {
            if (normalizeTypeName(str(g, "underlying_name")) !=
                normalizeTypeName(str(b, "underlying_name")))
                out.add("typedef target mismatch for ", name, ": golden ",
                        str(g, "underlying_name"), " vs BN ",
                        str(b, "underlying_name"));
        }
    }
}

// ---- data items --------------------------------------------------------------------

void compareDataItems(const json& golden, const json& bn, Issues& out) {
    // Golden items reference types by id; resolve via golden data_types.
    std::unordered_map<int64_t, std::string> idToName;
    for (const auto& t : arr(golden, "data_types"))
        if (t.contains("id")) idToName[t["id"].get<int64_t>()] = str(t, "name");

    std::unordered_map<std::string, std::string> bnByAddr;
    for (const auto& d : arr(bn, "data_items"))
        bnByAddr[str(d, "addr")] = str(d, "type_name");

    for (const auto& g : arr(golden, "data_items")) {
        const std::string addr = str(g, "addr");
        std::string typeName = str(g, "type_name");
        if (typeName.empty() && g.contains("type_id"))
            typeName = idToName[g["type_id"].get<int64_t>()];
        auto it = bnByAddr.find(addr);
        if (it == bnByAddr.end()) {
            out.add("data item missing on BN side at ", addr);
            continue;
        }
        if (!typeName.empty() &&
            normalizeTypeName(typeName) != normalizeTypeName(it->second))
            out.add("data item type mismatch at ", addr, ": golden ", typeName,
                    " vs BN ", it->second);
    }
}

// ---- memory blocks (presence only) ----------------------------------------------------

void compareMemoryBlocks(const json& golden, const json& bn, Issues& out) {
    std::set<std::pair<std::string, std::string>> bnSecs;
    for (const auto& s : arr(bn, "memory_blocks"))
        bnSecs.insert({str(s, "name"), str(s, "addr")});
    for (const auto& g : arr(golden, "memory_blocks")) {
        if (g.value("overlay", false)) continue;
        if (!bnSecs.count({str(g, "name"), str(g, "addr")}))
            out.add("memory block missing as BN section: ", str(g, "name"),
                    " @ ", str(g, "addr"));
    }
}

} // namespace

std::vector<std::string> compareCanonical(const json& golden, const json& bnExport) {
    Issues out;
    compareSymbols(golden, bnExport, out);
    compareComments(golden, bnExport, out);
    compareFuncFlags(golden, bnExport, out);
    compareEquates(golden, bnExport, out);
    compareBookmarks(golden, bnExport, out);
    compareParameters(golden, bnExport, out);
    compareDataTypes(golden, bnExport, out);
    compareDataItems(golden, bnExport, out);
    compareMemoryBlocks(golden, bnExport, out);
    return out.list;
}

} // namespace parity
