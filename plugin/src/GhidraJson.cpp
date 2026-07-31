#include "GhidraJson.h"
#include <cstdio>
#include <cstdlib>

namespace ghidra_json {

std::string toHex(uint64_t v) {
    char buf[20];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

uint64_t parseHexAddr(const std::string& s) {
    if (s.size() < 2) return 0;
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    return std::strtoull(p, nullptr, 16);
}

GhidraDbExport parseDbExportJson(const nlohmann::json& resp) {
    GhidraDbExport out;
    out.imageBase = parseHexAddr(resp.value("image_base", std::string{"0x0"}));

    if (resp.contains("diag")) {
        for (auto& d : resp["diag"])
            out.diag.push_back(d.get<std::string>());
    }

    if (resp.contains("symbols")) {
        for (auto& j : resp["symbols"]) {
            GhidraSymbol s;
            s.key         = j.value("key",  int64_t{0});
            s.name        = j.value("name", std::string{});
            s.addr        = parseHexAddr(j.value("addr", std::string{"0x0"}));
            s.type        = static_cast<GhidraSymbolType>(j.value("type",   0));
            s.source      = static_cast<GhidraSymbolSource>(j.value("source", 0));
            s.namespaceId = j.value("ns",   int64_t{0});
            out.symbols.push_back(std::move(s));
        }
    }

    if (resp.contains("comments")) {
        for (auto& j : resp["comments"]) {
            GhidraComment c;
            c.addr       = parseHexAddr(j.value("addr", std::string{"0x0"}));
            c.encodedKey = j.value("key",  std::string{});
            c.eol        = j.value("eol",   std::string{});
            c.pre   = j.value("pre",   std::string{});
            c.post  = j.value("post",  std::string{});
            c.plate = j.value("plate", std::string{});
            c.rep   = j.value("rep",   std::string{});
            out.comments.push_back(std::move(c));
        }
    }

    if (resp.contains("func_flags")) {
        for (auto& j : resp["func_flags"]) {
            GhidraFuncFlags f;
            f.key      = j.value("key",    int64_t{0});
            f.thunk    = j.value("thunk",  false);
            f.noReturn = j.value("no_ret", false);
            f.isInline = j.value("inline", false);
            out.funcFlags.push_back(f);

            std::string cc      = j.value("cc",          std::string{});
            std::string retType = j.value("ret_type",    std::string{});
            int64_t retTypeId   = j.value("ret_type_id", int64_t{-1});
            if (!cc.empty() || !retType.empty()) {
                GhidraFuncSig sig;
                sig.key               = f.key;
                sig.callingConvention = cc;
                sig.returnTypeName    = retType;
                sig.returnTypeId      = retTypeId;
                out.funcSigs.push_back(std::move(sig));
            }
        }
    }

    if (resp.contains("equates")) {
        for (auto& j : resp["equates"]) {
            GhidraEquate eq;
            eq.id    = j.value("id",    int64_t{0});
            eq.name  = j.value("name",  std::string{});
            eq.value = j.value("value", int64_t{0});
            if (j.contains("refs")) {
                for (auto& r : j["refs"]) {
                    GhidraEquateRef ref;
                    ref.addr    = parseHexAddr(r.value("addr",     std::string{"0x0"}));
                    ref.opIndex = r.value("op_index", 0);
                    eq.refs.push_back(std::move(ref));
                }
            }
            out.equates.push_back(std::move(eq));
        }
    }

    if (resp.contains("bookmarks")) {
        for (auto& j : resp["bookmarks"]) {
            GhidraBookmark bm;
            bm.type     = j.value("type",     std::string{});
            bm.addr     = parseHexAddr(j.value("addr",     std::string{"0x0"}));
            bm.category = j.value("category", std::string{});
            bm.comment  = j.value("comment",  std::string{});
            out.bookmarks.push_back(std::move(bm));
        }
    }

    if (resp.contains("parameters")) {
        for (auto& j : resp["parameters"]) {
            GhidraParameter p;
            p.key      = j.value("key",       int64_t{0});
            p.funcAddr = parseHexAddr(j.value("func_addr", std::string{"0x0"}));
            p.name     = j.value("name",      std::string{});
            p.isParam  = j.value("is_param",  true);
            p.ordinal  = j.value("ordinal",   0);
            p.typeName = j.value("type_name", std::string{});
            p.typeId   = j.value("type_id",   int64_t{-1});
            out.parameters.push_back(std::move(p));
        }
    }

    if (resp.contains("data_types")) {
        for (auto& j : resp["data_types"]) {
            GhidraDataType dt;
            dt.id      = j.value("id",      int64_t{0});
            dt.kind    = j.value("kind",    std::string{});
            dt.name    = j.value("name",    std::string{});
            dt.comment = j.value("comment", std::string{});
            dt.size    = j.value("size",    0);
            dt.underlyingTypeId = j.value("underlying_type_id", int64_t{0});
            if (dt.kind == "typedef")
                dt.underlyingTypeName = j.value("underlying_name", std::string{});
            if (j.contains("members")) {
                for (auto& m : j["members"]) {
                    GhidraDataTypeMember mem;
                    mem.offset   = m.value("offset",    0);
                    mem.typeId   = m.value("type_id",  int64_t{0});
                    mem.name     = m.value("name",     std::string{});
                    mem.comment  = m.value("comment",  std::string{});
                    mem.size     = m.value("size",     0);
                    mem.ordinal  = m.value("ordinal",  0);
                    mem.typeName = m.value("type_name",std::string{});
                    dt.members.push_back(std::move(mem));
                }
            }
            if (j.contains("values")) {
                for (auto& v : j["values"]) {
                    GhidraEnumValue ev;
                    ev.name    = v.value("name",    std::string{});
                    ev.value   = v.value("value",   int64_t{0});
                    ev.comment = v.value("comment", std::string{});
                    dt.values.push_back(std::move(ev));
                }
            }
            out.dataTypes.push_back(std::move(dt));
        }
    }

    if (resp.contains("data_items")) {
        for (auto& j : resp["data_items"]) {
            GhidraDataItem item;
            item.addr   = parseHexAddr(j.value("addr",    std::string{"0x0"}));
            item.typeId = j.value("type_id", int64_t{0});
            out.dataItems.push_back(std::move(item));
        }
    }

    if (resp.contains("memory_blocks")) {
        for (auto& j : resp["memory_blocks"]) {
            GhidraMemoryBlock mb;
            mb.name        = j.value("name", std::string{});
            mb.addr        = parseHexAddr(j.value("addr", std::string{"0x0"}));
            mb.size        = parseHexAddr(j.value("size", std::string{"0x0"}));
            mb.read        = j.value("r", true);
            mb.write       = j.value("w", false);
            mb.execute     = j.value("x", false);
            mb.initialized = j.value("initialized", true);
            mb.overlay     = j.value("overlay", false);
            out.memoryBlocks.push_back(std::move(mb));
        }
    }

    if (resp.contains("xref_stats")) {
        auto& xs = resp["xref_stats"];
        out.xrefStats.fromCount = xs.value("from_count", 0);
        out.xrefStats.toCount   = xs.value("to_count",   0);
    }

    return out;
}

nlohmann::json buildCheckinJson(
    const GhidraCheckinPreview& preview,
    int64_t rebase,
    const std::unordered_map<uint64_t, std::string>& addrToOriginalFuncComment,
    const std::unordered_map<uint64_t, std::string>& addrToCommentField)
{
    nlohmann::json symbols = nlohmann::json::array();
    for (const auto& r : preview.renames)
        symbols.push_back({{"key", r.key}, {"name", r.newName}});
    // New symbols: no Ghidra key — send VA so the bridge can find/create a record.
    for (const auto& s : preview.newSymbols) {
        uint64_t ghidraVa = (uint64_t)((int64_t)s.addr - rebase);
        symbols.push_back({
            {"va",       toHex(ghidraVa)},
            {"name",     s.name},
            {"sym_type", s.isFunction ? 5 : 0}  // 5=FUNCTION (new), 0=LABEL
        });
    }

    nlohmann::json comments = nlohmann::json::array();
    for (const auto& c : preview.comments) {
        // Ghidra VA = BN addr − rebase.
        uint64_t ghidraVa = (uint64_t)((int64_t)c.addr - rebase);
        // Route to the correct Ghidra comment column:
        //   • plate  — originated as a function-header comment (imported via func->SetComment)
        //   • eol/pre/post/rep — whichever single column held the text originally;
        //                        merged multi-column text defaults back to "eol"
        nlohmann::json entry = {{"va", toHex(ghidraVa)}};
        std::string field;
        if (addrToOriginalFuncComment.count(c.addr)) {
            field = "plate";
        } else {
            auto fIt = addrToCommentField.find(c.addr);
            field = (fIt != addrToCommentField.end()) ? fIt->second : "eol";
        }
        entry[field] = c.text;
        if (!c.encodedKey.empty())
            entry["key"] = c.encodedKey;
        comments.push_back(std::move(entry));
    }

    nlohmann::json equateRenames = nlohmann::json::array();
    for (const auto& r : preview.equateRenames)
        equateRenames.push_back({{"id", r.id}, {"name", r.name}});

    nlohmann::json equateRefAdds = nlohmann::json::array();
    for (const auto& r : preview.newEquateRefs) {
        uint64_t ghidraVa = (uint64_t)((int64_t)r.addr - rebase);
        equateRefAdds.push_back({
            {"id",       r.equateId},
            {"va",       toHex(ghidraVa)},
            {"op_index", r.opIndex}
        });
    }

    nlohmann::json bookmarkChanges = nlohmann::json::array();
    for (const auto& b : preview.bookmarkChanges) {
        uint64_t ghidraVa = (uint64_t)((int64_t)b.addr - rebase);
        bookmarkChanges.push_back({
            {"op",       b.op},
            {"type",     b.type},
            {"addr",     toHex(ghidraVa)},
            {"category", b.category},
            {"comment",  b.comment}
        });
    }

    nlohmann::json paramRenames = nlohmann::json::array();
    for (const auto& r : preview.paramRenames) {
        nlohmann::json j = {{"key", r.key}, {"name", r.name}};
        if (!r.typeName.empty()) j["type_name"] = r.typeName;
        paramRenames.push_back(j);
    }
    // New params/reg-locals: no Ghidra key — send func_va + ordinal so the bridge can create a record.
    for (const auto& p : preview.newParams) {
        uint64_t ghidraVa = (uint64_t)((int64_t)p.funcAddr - rebase);
        nlohmann::json j = {
            {"func_va",  toHex(ghidraVa)},
            {"ordinal",  p.ordinal},
            {"name",     p.name},
            {"is_local", p.isLocal}   // true → LOCAL_VAR (type=7), false → PARAMETER (type=6)
        };
        if (!p.typeName.empty()) j["type_name"] = p.typeName;
        paramRenames.push_back(j);
    }

    nlohmann::json dataTypeChanges = nlohmann::json::array();
    for (const auto& dt : preview.dataTypeChanges) {
        nlohmann::json j;
        j["op"]        = dt.op;
        j["kind"]      = dt.kind;
        j["name"]      = dt.name;
        j["ghidra_id"] = dt.ghidraId;
        j["size"]      = dt.size;
        if (!dt.members.empty()) {
            nlohmann::json members = nlohmann::json::array();
            for (const auto& m : dt.members) {
                members.push_back({{"name", m.name}, {"offset", m.offset},
                                   {"size", m.size}, {"type_name", m.typeName}});
            }
            j["members"] = members;
        }
        if (!dt.values.empty()) {
            nlohmann::json values = nlohmann::json::array();
            for (const auto& v : dt.values) {
                values.push_back({{"name", v.name}, {"value", v.value}});
            }
            j["values"] = values;
        }
        if (!dt.underlyingTypeName.empty())
            j["underlying_type_name"] = dt.underlyingTypeName;
        dataTypeChanges.push_back(j);
    }

    nlohmann::json dataItemChanges = nlohmann::json::array();
    for (const auto& di : preview.dataItemChanges) {
        // Convert BN VA → Ghidra VA before sending (same convention as bookmarks/comments).
        uint64_t ghidraItemVa = (uint64_t)((int64_t)di.addr - rebase);
        dataItemChanges.push_back({
            {"op",        di.op},
            {"addr",      toHex(ghidraItemVa)},
            {"type_name", di.typeName}
        });
    }

    nlohmann::json funcSigChanges = nlohmann::json::array();
    for (const auto& fs : preview.funcSigChanges) {
        nlohmann::json j;
        j["key"] = fs.key;
        if (!fs.callingConvention.empty()) j["cc"]       = fs.callingConvention;
        if (!fs.returnTypeName.empty())     j["ret_type"] = fs.returnTypeName;
        funcSigChanges.push_back(j);
    }

    return {
        {"symbols",           symbols},
        {"comments",          comments},
        {"equate_renames",    equateRenames},
        {"equate_ref_adds",   equateRefAdds},
        {"bookmark_changes",  bookmarkChanges},
        {"param_renames",     paramRenames},
        {"data_type_changes", dataTypeChanges},
        {"data_item_changes", dataItemChanges},
        {"func_sig_changes",  funcSigChanges}
    };
}

} // namespace ghidra_json
