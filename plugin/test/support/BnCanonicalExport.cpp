#include "BnCanonicalExport.h"
#include "GhidraJson.h"
#include <algorithm>
#include <map>
#include <unordered_map>
#include <unordered_set>

using namespace BinaryNinja;
using nlohmann::json;
using ghidra_json::toHex;

namespace parity {

namespace {

// Mirror of SyncEngine's auto-generated-name filter (kept in sync by the
// SyncEngineImportTest user-name-preservation cases).
bool isAutoGenName(const std::string& n) {
    auto hexSuffix = [&](size_t offset, size_t minLen = 4) -> bool {
        if (n.size() < offset + minLen) return false;
        for (size_t k = offset; k < n.size(); ++k) {
            char c = n[k];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    };
    if (n.rfind("sub_", 0) == 0 && hexSuffix(4)) return true;
    if (n.rfind("FUN_", 0) == 0 && hexSuffix(4)) return true;
    if (n.rfind("off_", 0) == 0 && hexSuffix(4)) return true;
    if (n.rfind("unk_", 0) == 0 && hexSuffix(4)) return true;
    if (n.rfind("j_",   0) == 0 && hexSuffix(2)) return true;
    if (n.rfind("data_", 0) == 0 && hexSuffix(5)) return true;
    // Thunks are named after their target; "j_<auto-name>" is auto too.
    if (n.rfind("j_", 0) == 0 && isAutoGenName(n.substr(2))) return true;
    return false;
}

bool isAutoParamName(const std::string& n) {
    return n.empty() || n.rfind("arg", 0) == 0 || n.rfind("param_", 0) == 0;
}

bool isAutoLocalName(const std::string& n) {
    return n.empty() || n.rfind("var_", 0) == 0 || n.rfind("local_", 0) == 0 ||
           n.rfind("temp", 0) == 0;
}

std::string typeToName(const Ref<Type>& type) {
    if (!type) return {};
    if (type->IsNamedTypeRefer())
        return type->GetNamedTypeReference()->GetName().GetString();
    return type->GetString();
}

} // namespace

json bnCanonicalExport(Ref<BinaryView> view, const GhidraDbExport& reference) {
    json out = json::object();
    if (!view) return out;

    const int64_t rebase =
        (int64_t)view->GetStart() - (int64_t)reference.imageBase;
    auto toGhidra = [&](uint64_t bnAddr) -> uint64_t {
        return (uint64_t)((int64_t)bnAddr - rebase);
    };
    auto toBn = [&](uint64_t ghidraAddr) -> uint64_t {
        return (uint64_t)((int64_t)ghidraAddr + rebase);
    };

    out["image_base"] = toHex(reference.imageBase);

    // -- symbols ------------------------------------------------------------
    json symbols = json::array();
    for (auto& sym : view->GetSymbols()) {
        const std::string name = sym->GetFullName();
        if (name.empty() || isAutoGenName(name)) continue;
        int type;
        switch (sym->GetType()) {
        case FunctionSymbol:         type = 4; break;
        case ImportedFunctionSymbol: type = 8; break;
        case DataSymbol:             type = 0; break;
        default:                     continue; // not part of the sync model
        }
        symbols.push_back({{"name", name},
                           {"addr", toHex(toGhidra(sym->GetAddress()))},
                           {"type", type}});
    }
    out["symbols"] = symbols;

    // -- comments -----------------------------------------------------------
    // One canonical entry per address; the column comes from the reference
    // comment at the same Ghidra address (same reconstruction SyncEngine used
    // at import: sole non-empty column, else "eol").
    std::unordered_map<uint64_t, std::string> refField; // ghidra addr → column
    for (const auto& c : reference.comments) {
        int count = 0;
        std::string solo;
        const std::pair<const std::string*, const char*> parts[] = {
            {&c.eol, "eol"}, {&c.rep, "rep"}, {&c.pre, "pre"}, {&c.post, "post"}};
        for (const auto& [part, fieldName] : parts) {
            if (part->empty()) continue;
            ++count;
            if (count == 1) solo = fieldName;
        }
        if (count > 0) refField[c.addr] = (count == 1) ? solo : "eol";
    }

    std::map<uint64_t, json> commentByAddr; // ordered for stable output
    for (uint64_t bnAddr : view->GetCommentedAddresses()) {
        std::string text = view->GetCommentForAddress(bnAddr);
        if (text.empty()) continue;
        uint64_t ga = toGhidra(bnAddr);
        auto it = refField.find(ga);
        std::string field = (it != refField.end()) ? it->second : "eol";
        json& entry = commentByAddr[ga];
        entry["addr"] = toHex(ga);
        entry[field]  = text;
    }
    for (auto& func : view->GetAnalysisFunctionList()) {
        std::string plate = func->GetComment();
        if (plate.empty()) continue;
        uint64_t ga = toGhidra(func->GetStart());
        json& entry = commentByAddr[ga];
        entry["addr"]  = toHex(ga);
        entry["plate"] = plate;
    }
    json comments = json::array();
    for (auto& [ga, entry] : commentByAddr) comments.push_back(entry);
    out["comments"] = comments;

    // -- func_flags (flags from "Ghidra: *" tags; cc / ret_type read live) ---
    json funcFlags = json::array();
    for (auto& func : view->GetAnalysisFunctionList()) {
        bool thunk = false, noRet = false, isInline = false;
        for (auto& tag : func->GetFunctionTags()) {
            const std::string tn = tag->GetType()->GetName();
            if (tn == "Ghidra: Thunk")    thunk = true;
            else if (tn == "Ghidra: NoReturn") noRet = true;
            else if (tn == "Ghidra: Inline")   isInline = true;
        }
        json entry = {{"addr",   toHex(toGhidra(func->GetStart()))},
                      {"thunk",  thunk},
                      {"no_ret", noRet},
                      {"inline", isInline}};
        auto cc = func->GetCallingConvention();
        if (cc.GetValue())
            entry["cc"] = cc.GetValue()->GetName();
        auto ret = func->GetReturnType();
        if (ret.GetValue())
            entry["ret_type"] = typeToName(ret.GetValue());
        funcFlags.push_back(entry);
    }
    out["func_flags"] = funcFlags;

    // -- equates (probed at the reference ref sites) -------------------------
    json equates = json::array();
    for (const auto& eq : reference.equates) {
        Ref<Type> eqType = view->GetTypeById("ghidra_eq_" + std::to_string(eq.id));
        if (!eqType || !eqType->IsEnumeration()) continue;
        std::string name;
        int64_t value = 0;
        {
            auto members = eqType->GetEnumeration()->GetMembers();
            if (members.size() != 1) continue;
            name  = members[0].name;
            value = (int64_t)members[0].value;
        }
        json refs = json::array();
        for (const auto& r : eq.refs) {
            uint64_t bnAddr = toBn(r.addr);
            for (auto& func : view->GetAnalysisFunctionsContainingAddress(bnAddr)) {
                auto [disp, dispType] = func->GetIntegerConstantDisplayTypeAndEnumType(
                    func->GetArchitecture(), bnAddr, (uint64_t)eq.value,
                    (size_t)r.opIndex);
                (void)dispType;
                if (disp == EnumerationDisplayType) {
                    refs.push_back({{"addr", toHex(r.addr)},
                                    {"op_index", r.opIndex}});
                    break;
                }
            }
        }
        equates.push_back({{"id", eq.id}, {"name", name},
                           {"value", value}, {"refs", refs}});
    }
    out["equates"] = equates;

    // -- bookmarks (data tags with a "Ghidra: " tag type) ---------------------
    json bookmarks = json::array();
    for (auto& ref : view->GetDataTagReferences()) {
        if (!ref.tag) continue;
        const std::string tn = ref.tag->GetType()->GetName();
        if (tn.rfind("Ghidra: ", 0) != 0) continue;
        std::string data = ref.tag->GetData();
        std::string category, comment = data;
        if (!data.empty() && data[0] == '[') {
            size_t close = data.find("] ");
            if (close != std::string::npos) {
                category = data.substr(1, close - 1);
                comment  = data.substr(close + 2);
            }
        }
        bookmarks.push_back({{"type", tn.substr(8)},
                             {"addr", toHex(toGhidra(ref.addr))},
                             {"category", category},
                             {"comment", comment}});
    }
    out["bookmarks"] = bookmarks;

    // -- parameters & stack locals -------------------------------------------
    json parameters = json::array();
    for (auto& func : view->GetAnalysisFunctionList()) {
        const std::string fa = toHex(toGhidra(func->GetStart()));
        auto params = func->GetParameterVariables().GetValue();
        for (size_t i = 0; i < params.size(); ++i) {
            std::string name = func->GetVariableName(params[i]);
            if (isAutoParamName(name)) continue;
            json entry = {{"func_addr", fa}, {"name", name},
                          {"is_param", true}, {"ordinal", (int)i}};
            auto vt = func->GetVariableType(params[i]);
            if (vt.GetValue()) entry["type_name"] = typeToName(vt.GetValue());
            parameters.push_back(entry);
        }
        for (const auto& [var, nat] : func->GetVariables()) {
            if (var.type != StackVariableSourceType) continue;
            if (isAutoLocalName(nat.name)) continue;
            // Skip vars already emitted as parameters (stack-passed params).
            bool isParam = false;
            for (const auto& p : params)
                if (p == var) { isParam = true; break; }
            if (isParam) continue;
            json entry = {{"func_addr", fa}, {"name", nat.name},
                          {"is_param", false}, {"ordinal", (int)var.storage}};
            if (nat.type.GetValue())
                entry["type_name"] = typeToName(nat.type.GetValue());
            parameters.push_back(entry);
        }
    }
    out["parameters"] = parameters;

    // -- data types ------------------------------------------------------------
    // Equate enums use the same DefineType machinery; exclude them by name.
    // Platform type libraries (10k+ types on windows platforms) also show up
    // in GetTypes(); only user-created types and types named in the reference
    // are part of the sync model.
    std::unordered_set<std::string> equateNames;
    for (const auto& eq : reference.equates) equateNames.insert(eq.name);
    std::unordered_set<std::string> allowedNames;
    for (const auto& dt : reference.dataTypes) allowedNames.insert(dt.name);
    {
        auto userTypes = view->GetUserTypeContainer().GetTypes();
        if (userTypes)
            for (auto& [typeId, namedType] : *userTypes)
                allowedNames.insert(namedType.first.GetString());
    }

    json dataTypes = json::array();
    for (auto& [qname, type] : view->GetTypes()) {
        const std::string name = qname.GetString();
        if (equateNames.count(name) || !allowedNames.count(name)) continue;
        if (type->IsStructure()) {
            auto s = type->GetStructure();
            json members = json::array();
            int ordinal = 0;
            for (const auto& m : s->GetMembers()) {
                Ref<Type> mt = m.type.GetValue();
                members.push_back({{"name", m.name},
                                   {"offset", (int)m.offset},
                                   {"size", (int)(mt ? mt->GetWidth() : 0)},
                                   {"ordinal", ordinal++},
                                   {"type_name", typeToName(mt)}});
            }
            dataTypes.push_back({
                {"kind", s->GetStructureType() == UnionStructureType ? "union" : "struct"},
                {"name", name},
                {"size", (int)s->GetWidth()},
                {"members", members}});
        } else if (type->IsEnumeration()) {
            json values = json::array();
            for (const auto& v : type->GetEnumeration()->GetMembers())
                values.push_back({{"name", v.name}, {"value", (int64_t)v.value}});
            dataTypes.push_back({{"kind", "enum"},
                                 {"name", name},
                                 {"size", (int)type->GetWidth()},
                                 {"values", values}});
        } else if (type->IsNamedTypeRefer()) {
            dataTypes.push_back({
                {"kind", "typedef"},
                {"name", name},
                {"size", (int)type->GetWidth()},
                {"underlying_name",
                 type->GetNamedTypeReference()->GetName().GetString()}});
        }
    }
    out["data_types"] = dataTypes;

    // -- data items -----------------------------------------------------------
    json dataItems = json::array();
    for (auto& [addr, dv] : view->GetDataVariables()) {
        if (dv.autoDiscovered) continue;
        Ref<Type> t = dv.type.GetValue();
        if (!t) continue;
        dataItems.push_back({{"addr", toHex(toGhidra(addr))},
                             {"type_name", typeToName(t)}});
    }
    out["data_items"] = dataItems;

    // -- memory blocks (BN sections; presence-checked only) --------------------
    json blocks = json::array();
    for (auto& sec : view->GetSections()) {
        blocks.push_back({{"name", sec->GetName()},
                          {"addr", toHex(toGhidra(sec->GetStart()))},
                          {"size", toHex(sec->GetLength())}});
    }
    out["memory_blocks"] = blocks;

    return out;
}

} // namespace parity
