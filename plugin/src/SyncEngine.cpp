#include "SyncEngine.h"
#include <binaryninjaapi.h>
#include <unordered_map>

using namespace BinaryNinja;

// ---------------------------------------------------------------------------
// resolveTypeName — look up a type by name in BN, with fallback for Ghidra
// primitive type names that BN doesn't register as named types.
//
// Priority:
//   1. User-defined type already in BN (struct, enum, typedef)
//   2. Ghidra built-in primitive → equivalent BN type construct
//   3. hintSize > 0 → generic integer of that width
//   4. nullptr (caller should fall back to VoidType or leave unchanged)
// ---------------------------------------------------------------------------
static BinaryNinja::Ref<BinaryNinja::Type> resolveTypeName(
    BinaryNinja::Ref<BinaryNinja::BinaryView> view,
    const std::string& typeName,
    int hintSize = 0)
{
    if (typeName.empty()) return nullptr;

    // Helper: trim trailing whitespace (no std::string_view needed).
    auto rtrim = [](const std::string& s) -> std::string {
        size_t n = s.size();
        while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t')) --n;
        return s.substr(0, n);
    };

    // 0a. Pointer type: ends with '*' after trimming.
    {
        std::string trimmed = rtrim(typeName);
        if (!trimmed.empty() && trimmed.back() == '*') {
            std::string base = rtrim(trimmed.substr(0, trimmed.size() - 1));
            // Recurse to resolve the pointee (void * if base is empty or unresolvable).
            auto inner = base.empty() ? BinaryNinja::Type::VoidType()
                                      : resolveTypeName(view, base, 0);
            if (!inner) inner = BinaryNinja::Type::VoidType();
            size_t ptrWidth = view ? view->GetAddressSize() : 8;
            return BinaryNinja::Type::PointerType(ptrWidth, {inner, 255});
        }
    }

    // 0b. Array type: "ElementType[count]" — bracket before trailing ']'.
    {
        auto ob = typeName.rfind('[');
        if (ob != std::string::npos && typeName.back() == ']') {
            std::string elemName = rtrim(typeName.substr(0, ob));
            std::string countStr = typeName.substr(ob + 1, typeName.size() - ob - 2);
            uint64_t count = 0;
            try { count = std::stoull(countStr); } catch (...) {}
            if (count > 0 && !elemName.empty()) {
                auto inner = resolveTypeName(view, elemName, 0);
                if (inner) return BinaryNinja::Type::ArrayType({inner, 255}, count);
            }
        }
    }

    // 1. Try user-defined / imported type by name first.
    if (view) {
        auto t = view->GetTypeByName(BinaryNinja::QualifiedName(typeName));
        if (t) return t;
    }

    // 2. Map common Ghidra primitive names to BN type constructors.
    //    Ghidra names are case-sensitive; we match as-is.
    struct PrimEntry { const char* name; size_t width; bool isSigned; bool isFloat; };
    static const PrimEntry prims[] = {
        {"void",           0, false, false},
        {"bool",           1, false, false},
        {"char",           1, true,  false},
        {"uchar",          1, false, false},
        {"byte",           1, false, false},
        {"sbyte",          1, true,  false},
        {"short",          2, true,  false},
        {"ushort",         2, false, false},
        {"word",           2, false, false},
        {"int",            4, true,  false},
        {"uint",           4, false, false},
        {"dword",          4, false, false},
        {"long",           4, true,  false},
        {"ulong",          4, false, false},
        {"longlong",       8, true,  false},
        {"ulonglong",      8, false, false},
        {"qword",          8, false, false},
        {"int8_t",         1, true,  false},
        {"uint8_t",        1, false, false},
        {"int16_t",        2, true,  false},
        {"uint16_t",       2, false, false},
        {"int32_t",        4, true,  false},
        {"uint32_t",       4, false, false},
        {"int64_t",        8, true,  false},
        {"uint64_t",       8, false, false},
        {"float",          4, false, true},
        {"double",         8, false, true},
        {"long double",   10, false, true},
        {"float16",        2, false, true},
    };
    for (const auto& p : prims) {
        if (typeName == p.name) {
            if (p.width == 0) return BinaryNinja::Type::VoidType();
            if (p.isFloat)    return BinaryNinja::Type::FloatType(p.width);
            if (p.name[0] == 'b' && typeName == "bool")
                return BinaryNinja::Type::BoolType();
            return BinaryNinja::Type::IntegerType(p.width, p.isSigned);
        }
    }

    // 3. Fall back to an integer of hintSize if the name is unrecognised.
    if (hintSize > 0 && hintSize <= 16)
        return BinaryNinja::Type::IntegerType((size_t)hintSize, false);

    return nullptr;
}

// ---------------------------------------------------------------------------
// Tag-type helper — creates a new TagType if it doesn't exist yet
// ---------------------------------------------------------------------------

Ref<TagType> SyncEngine::getOrCreateTagType(Ref<BinaryView> view,
                                             const std::string& name) {
    auto tt = view->GetTagType(name);
    if (!tt) {
        tt = new TagType(view.GetPtr(), name, "G");
        view->AddTagType(tt);
    }
    return tt;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

SyncResult SyncEngine::applyToView(Ref<BinaryView> view, const GhidraDbExport& data) {
    SyncResult result;
    if (!view) return result;

    result.imageBase = data.imageBase;

    // Compute address rebase: Ghidra may have analyzed the binary at a different
    // image base than BN.  The bridge exports the Ghidra base for the main
    // ("ram") segment (row 0 of the ADDRESS MAP).
    uint64_t bnBase     = view->GetStart();
    uint64_t ghidraBase = data.imageBase;
    int64_t  rebase     = (int64_t)bnBase - (int64_t)ghidraBase;
    BinaryNinja::LogInfo("ghidra-bridge: imageBase=0x%llx bnBase=0x%llx rebase=0x%llx",
                         (unsigned long long)ghidraBase, (unsigned long long)bnBase,
                         (unsigned long long)(uint64_t)rebase);

    auto applyRebase = [&](uint64_t addr) -> uint64_t {
        return (uint64_t)((int64_t)addr + rebase);
    };

    // Needed for funcFlags: symbol key → virtual address mapping.
    std::unordered_map<int64_t, uint64_t> keyToAddr;
    keyToAddr.reserve(data.symbols.size());

    // Default platform — used to create functions Ghidra found that BN missed.
    // Held as a Ref so it stays alive while we use it across the symbol loop.
    Ref<Platform> defaultPlat = view->GetDefaultPlatform();

    // -----------------------------------------------------------------------
    // Memory map — import Ghidra's blocks as named BN sections, adding segments
    // only for ranges BN's own loader didn't already map (e.g. Ghidra's EXTERNAL
    // block, uninitialized regions).  Existing segments are never modified, so
    // the loaded view's layout can't be corrupted.  Runs before symbols so any
    // functions / data created in Ghidra-only regions have backing memory —
    // and because AddUserSection requires the range to already be mapped.
    // -----------------------------------------------------------------------
    for (const auto& mb : data.memoryBlocks) {
        if (mb.size == 0 || mb.overlay) continue; // skip empty / overlay spaces
        uint64_t start = applyRebase(mb.addr);

        // Add a segment only when BN doesn't already map this range.  We don't
        // transfer block bytes here, so the segment is zero-filled (dataLength=0)
        // — the real cases for an unmapped Ghidra block are its EXTERNAL and
        // uninitialized regions, which are zero-filled anyway.
        if (!view->GetSegmentAt(start)) {
            uint32_t flags = 0;
            if (mb.read)    flags |= SegmentReadable;
            if (mb.write)   flags |= SegmentWritable;
            if (mb.execute) flags |= SegmentExecutable;
            flags |= mb.execute ? SegmentContainsCode : SegmentContainsData;
            view->AddUserSegment(start, mb.size, /*dataOffset=*/0, /*dataLength=*/0, flags);
            ++result.segmentsAdded;
        }

        BNSectionSemantics sem = mb.execute ? ReadOnlyCodeSectionSemantics
                               : mb.write   ? ReadWriteDataSectionSemantics
                                            : ReadOnlyDataSectionSemantics;
        std::string name = mb.name.empty()
            ? ("ghidra_" + std::to_string(start)) : mb.name;
        view->AddUserSection(name, start, mb.size, sem);
        ++result.sectionsAdded;
    }

    // -----------------------------------------------------------------------
    // Symbols
    // -----------------------------------------------------------------------
    for (const auto& sym : data.symbols) {
        BNSymbolType bnType;
        if (sym.type == GhidraSymbolType::Function)
            bnType = FunctionSymbol;
        else if (sym.type == GhidraSymbolType::External)
            bnType = ImportedFunctionSymbol;
        else
            bnType = DataSymbol;

        uint64_t addr = applyRebase(sym.addr);

        // Only overwrite BN's name if it looks auto-generated.  If the user
        // (or a previous import) already set a real name at this address,
        // preserve it — and still record Ghidra's name as the write-back
        // baseline so collectCheckinChanges() can detect the rename and push
        // it back to the server on the next check-in.
        //
        // Auto-generated names have the form PREFIX_HEXADDR, where the suffix
        // is a run of pure hex digits (the address).  Names like "sub_test123"
        // are user-chosen and must NOT be treated as auto-generated.
        //
        // Known auto-generated patterns (prefix + ≥4 hex digits):
        //   sub_XXXXXXXX  — BN auto-analysis
        //   FUN_XXXXXXXX  — Ghidra auto-analysis / previous import
        //   off_XXXXXXXX  — data offset labels
        //   unk_XXXXXXXX  — unknown data labels
        //   j_XXXXXXXX    — compiler thunk stubs (hex-address form)
        auto isAutoGenName = [](const std::string& n) -> bool {
            // Returns true iff every char from `offset` onward is a hex digit
            // and there are at least `minLen` such chars.
            auto hexSuffix = [&](size_t offset, size_t minLen = 4) -> bool {
                if (n.size() < offset + minLen) return false;
                for (size_t k = offset; k < n.size(); ++k) {
                    char c = n[k];
                    if (!((c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F'))) return false;
                }
                return true;
            };
            if (n.rfind("sub_", 0) == 0 && hexSuffix(4)) return true;
            if (n.rfind("FUN_", 0) == 0 && hexSuffix(4)) return true;
            if (n.rfind("off_", 0) == 0 && hexSuffix(4)) return true;
            if (n.rfind("unk_", 0) == 0 && hexSuffix(4)) return true;
            if (n.rfind("j_",   0) == 0 && hexSuffix(2)) return true;
            return false;
        };

        bool applyName = true;
        {
            auto existing = view->GetSymbolByAddress(addr);
            if (existing) {
                const std::string en = existing->GetFullName();
                if (!en.empty() && en != sym.name && !isAutoGenName(en))
                    applyName = false;
            }
        }

        if (applyName)
            view->DefineUserSymbol(new Symbol(bnType, sym.name, addr));

        // Ghidra frequently identifies functions BN's linear sweep / auto-analysis
        // misses.  Without this, such an address gets a function-typed *label* but
        // no actual BN function — and the func-flags / signature passes below
        // (keyed on functions that exist) would silently no-op for it.  Create the
        // function only when BN has none starting here, mirroring what BN's own
        // native Ghidra import does.
        if (sym.type == GhidraSymbolType::Function && defaultPlat) {
            bool hasFunc = false;
            auto existing = view->GetAnalysisFunctionsForAddress(addr);
            for (auto& f : existing)
                if (f->GetStart() == addr) { hasFunc = true; break; }
            if (!hasFunc) {
                view->CreateUserFunction(defaultPlat.GetPtr(), addr);
                ++result.functionsCreated;
            }
        }

        ++result.symbolsApplied;

        if (addr < result.addrMin) result.addrMin = addr;
        if (addr > result.addrMax) result.addrMax = addr;
        if (result.sampleSymbol.empty() && sym.type == GhidraSymbolType::Function)
            result.sampleSymbol = sym.name;

        // Ghidra's name is always the write-back baseline, regardless of
        // whether we applied it to the view.
        result.addrToKey[addr]          = sym.key;
        result.addrToOriginalName[addr] = sym.name;
        if (sym.type == GhidraSymbolType::Function)
            keyToAddr[sym.key] = addr;
    }

    // -----------------------------------------------------------------------
    // Comments
    // -----------------------------------------------------------------------
    for (const auto& comm : data.comments) {
        uint64_t caddr = applyRebase(comm.addr);
        if (!comm.encodedKey.empty())
            result.addrToCommentKey[caddr] = comm.encodedKey;

        // Track originating column so check-in writes back to the right one.
        const std::pair<const std::string*, const char*> commParts[] = {
            {&comm.eol, "eol"}, {&comm.rep, "rep"}, {&comm.pre, "pre"}, {&comm.post, "post"}
        };
        std::string text;
        int fieldCount = 0;
        std::string soloField;
        for (const auto& [part, fieldName] : commParts) {
            if (part->empty()) continue;
            ++fieldCount;
            if (fieldCount == 1) soloField = fieldName;
            if (!text.empty()) text += '\n';
            text += *part;
        }
        if (!text.empty()) {
            // Sole non-empty column → write back to it; merged text → default to "eol".
            result.addrToCommentField[caddr] = (fieldCount == 1) ? soloField : "eol";
            // Preserve any comment the user has already written at this address.
            // If BN has a comment that differs from Ghidra's, keep the BN one
            // and record Ghidra's as the baseline so a future check-in picks it up.
            std::string existing = view->GetCommentForAddress(caddr);
            result.addrToOriginalComment[caddr] = text;
            if (existing.empty() || existing == text) {
                view->SetCommentForAddress(caddr, text);
                ++result.commentsApplied;
            }
            // else: user has a different comment — leave it, check-in will sync it
        }

        // Plate comment → BN function-level comment (same preserve logic).
        if (!comm.plate.empty()) {
            auto funcs = view->GetAnalysisFunctionsForAddress(caddr);
            for (auto& func : funcs) {
                if (func->GetStart() == caddr) {
                    result.addrToOriginalFuncComment[caddr] = comm.plate;
                    if (func->GetComment().empty() || func->GetComment() == comm.plate) {
                        func->SetComment(comm.plate);
                    }
                    break;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Function flags  (thunk / noReturn / inline → BN user tags)
    // -----------------------------------------------------------------------
    Ref<TagType> ttThunk, ttNoRet, ttInline;

    for (const auto& ff : data.funcFlags) {
        auto it = keyToAddr.find(ff.key);
        if (it == keyToAddr.end()) continue;

        // Use GetAnalysisFunctionsForAddress instead of GetAnalysisFunction(platform, addr).
        // GetAnalysisFunction takes a raw Platform* that can become a dangling pointer when
        // BN's own analysis runs concurrently with this worker — using the address-only
        // lookup avoids touching the platform pointer entirely and eliminates the data race.
        Ref<Function> func;
        {
            auto candidates = view->GetAnalysisFunctionsForAddress(it->second);
            for (auto& f : candidates)
                if (f->GetStart() == it->second) { func = f; break; }
        }
        if (!func) continue;

        if (ff.thunk) {
            if (!ttThunk) ttThunk = getOrCreateTagType(view, "Ghidra: Thunk");
            func->CreateUserFunctionTag(ttThunk, "");
        }
        if (ff.noReturn) {
            if (!ttNoRet) ttNoRet = getOrCreateTagType(view, "Ghidra: NoReturn");
            func->CreateUserFunctionTag(ttNoRet, "");
        }
        if (ff.isInline) {
            if (!ttInline) ttInline = getOrCreateTagType(view, "Ghidra: Inline");
            func->CreateUserFunctionTag(ttInline, "");
        }
        ++result.flagsApplied;
    }

    // -----------------------------------------------------------------------
    // Equates → BN enum types + integer display overrides
    // -----------------------------------------------------------------------
    for (const auto& eq : data.equates) {
        if (eq.name.empty() || eq.refs.empty()) continue;

        // Create a single-member enum type for this equate.
        // The member name is the display label; the value is the equate value.
        BinaryNinja::QualifiedName qualName(eq.name);
        BinaryNinja::EnumerationBuilder eb;
        eb.AddMemberWithValue(eq.name, (uint64_t)eq.value);
        auto enumType = BinaryNinja::Type::EnumerationType(eb.Finalize(), 4, false);

        // Use a stable type ID so we can find it back at check-in time.
        std::string typeId = "ghidra_eq_" + std::to_string(eq.id);
        view->DefineType(typeId, qualName, enumType);

        // Retrieve the registered type (DefineType may deduplicate).
        Ref<BinaryNinja::Type> bnType = view->GetTypeById(typeId);
        if (!bnType) continue;

        // Apply integer display override at each reference site.
        for (const auto& ref : eq.refs) {
            uint64_t refAddr = applyRebase(ref.addr);

            // SetIntegerConstantDisplayType is on Function, so find containing functions.
            auto funcs = view->GetAnalysisFunctionsContainingAddress(refAddr);
            for (auto& func : funcs) {
                func->SetIntegerConstantDisplayType(
                    func->GetArchitecture(),
                    refAddr,
                    (uint64_t)eq.value,
                    (size_t)ref.opIndex,
                    BNIntegerDisplayType::EnumerationDisplayType,
                    bnType);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bookmarks → BN user data tags
    // -----------------------------------------------------------------------
    for (const auto& bm : data.bookmarks) {
        uint64_t bmAddr = applyRebase(bm.addr);
        std::string tagTypeName = "Ghidra: " + bm.type;
        Ref<TagType> tt = getOrCreateTagType(view, tagTypeName);

        // Build tag data: category + comment
        std::string tagData;
        if (!bm.category.empty()) tagData += "[" + bm.category + "] ";
        tagData += bm.comment;

        view->CreateUserDataTag(bmAddr, tt, tagData, false);
    }

    // -----------------------------------------------------------------------
    // Parameters & local variables — apply names / types from Ghidra
    // -----------------------------------------------------------------------
    for (const auto& param : data.parameters) {
        uint64_t funcBnAddr = applyRebase(param.funcAddr);
        Ref<Function> func;
        {
            auto candidates = view->GetAnalysisFunctionsForAddress(funcBnAddr);
            for (auto& f : candidates)
                if (f->GetStart() == funcBnAddr) { func = f; break; }
        }
        if (!func) continue;

        if (param.isParam) {
            // --- Parameters: look up by ordinal ---
            auto vars = func->GetParameterVariables().GetValue();
            if (param.ordinal >= 0 && (size_t)param.ordinal < vars.size()) {
                const BinaryNinja::Variable var = vars[param.ordinal];
                std::string curName = func->GetVariableName(var);
                bool autoGen = curName.empty() ||
                               curName.rfind("arg",    0) == 0 ||
                               curName.rfind("param_", 0) == 0;
                if (autoGen) {
                    Confidence<Ref<Type>> varType(func->GetVariableType(var).GetValue(), 0);
                    auto resolved = resolveTypeName(view, param.typeName);
                    if (resolved) varType = {resolved, 128};
                    func->CreateUserVariable(var, varType, param.name);
                }
            }
        } else {
            // --- Local variables: match by stack storage offset ---
            // Ghidra exports the stack offset as `ordinal` for locals.
            // BN stores it in Variable::storage for StackVariableSourceType.
            auto allVars = func->GetVariables();
            for (const auto& [var, nat] : allVars) {
                if (var.type != StackVariableSourceType) continue;
                if ((int)var.storage != param.ordinal) continue;

                bool autoGen = nat.name.empty() ||
                               nat.name.rfind("var_",   0) == 0 ||
                               nat.name.rfind("local_", 0) == 0;
                if (autoGen) {
                    Confidence<Ref<Type>> varType(nat.type.GetValue(), 0);
                    auto resolved = resolveTypeName(view, param.typeName);
                    if (resolved) varType = {resolved, 128};
                    func->CreateUserVariable(var, varType, param.name);
                }
                break; // one match per (funcAddr, offset)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Data types — register structs, unions, enums, typedefs in BN
    // -----------------------------------------------------------------------
    for (const auto& dt : data.dataTypes) {
        if (dt.name.empty()) continue;

        BinaryNinja::QualifiedName qualName(dt.name);

        if (dt.kind == "struct" || dt.kind == "union") {
            bool isUnion = (dt.kind == "union");
            BinaryNinja::StructureBuilder sb;
            sb.SetPacked(false);
            if (isUnion) sb.SetStructureType(UnionStructureType);
            for (const auto& m : dt.members) {
                if (m.name.empty()) continue;
                // Resolve member type; fall back to an integer of the right width, then void.
                auto memberType = resolveTypeName(view, m.typeName, m.size);
                if (!memberType) {
                    memberType = (m.size > 0)
                        ? BinaryNinja::Type::IntegerType((size_t)m.size, false)
                        : BinaryNinja::Type::VoidType();
                }
                sb.AddMemberAtOffset(memberType, m.name, m.offset);
            }
            auto structType = BinaryNinja::Type::StructureType(sb.Finalize());
            std::string typeId = BinaryNinja::Type::GenerateAutoTypeId("ghidra", qualName);
            view->DefineType(typeId, qualName, structType);

        } else if (dt.kind == "enum") {
            BinaryNinja::EnumerationBuilder eb;
            for (const auto& v : dt.values)
                eb.AddMemberWithValue(v.name, (uint64_t)v.value);
            auto enumType = BinaryNinja::Type::EnumerationType(
                eb.Finalize(), dt.size > 0 ? dt.size : 4, false);
            std::string typeId = BinaryNinja::Type::GenerateAutoTypeId("ghidra", qualName);
            view->DefineType(typeId, qualName, enumType);

        } else if (dt.kind == "typedef" && !dt.underlyingTypeName.empty()) {
            // Create a BN typedef pointing to the underlying type by name.
            BinaryNinja::NamedTypeReference ntr(
                BNNamedTypeReferenceClass::TypedefNamedTypeClass,
                "",   // no stable type-reference ID needed
                BinaryNinja::QualifiedName(dt.underlyingTypeName));
            auto typedefType = BinaryNinja::Type::NamedType(&ntr,
                dt.size > 0 ? (size_t)dt.size : 0);
            std::string typeId = BinaryNinja::Type::GenerateAutoTypeId("ghidra", qualName);
            view->DefineType(typeId, qualName, typedefType);
        }
    }

    // -----------------------------------------------------------------------
    // Data items — define typed variables at their addresses
    // -----------------------------------------------------------------------
    // Build a type-id-to-BN-type map from the types we just registered
    std::unordered_map<std::string, BinaryNinja::Ref<BinaryNinja::Type>> typeById;
    for (const auto& dt : data.dataTypes) {
        if (dt.name.empty()) continue;
        BinaryNinja::QualifiedName qualName(dt.name);
        auto type = view->GetTypeByName(qualName);
        if (type)
            typeById[dt.name] = type;
    }

    for (const auto& item : data.dataItems) {
        uint64_t itemAddr = applyRebase(item.addr);
        // Find which data type this item references by matching id to name
        for (const auto& dt : data.dataTypes) {
            if (dt.id == item.typeId && !dt.name.empty()) {
                auto it = typeById.find(dt.name);
                if (it != typeById.end()) {
                    view->DefineUserDataVariable(itemAddr,
                        BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>(it->second, 128));
                }
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Function signatures — calling convention + return type
    // -----------------------------------------------------------------------
    for (const auto& sig : data.funcSigs) {
        auto it = keyToAddr.find(sig.key);
        if (it == keyToAddr.end()) continue;
        uint64_t bnAddr = it->second;

        Ref<Function> func;
        {
            auto candidates = view->GetAnalysisFunctionsForAddress(bnAddr);
            for (auto& f : candidates)
                if (f->GetStart() == bnAddr) { func = f; break; }
        }
        if (!func) continue;

        // Calling convention — look up by name on the architecture
        if (!sig.callingConvention.empty()) {
            auto arch = func->GetArchitecture();
            if (arch) {
                auto cc = arch->GetCallingConventionByName(sig.callingConvention);
                if (cc)
                    func->SetCallingConvention({cc, 128});  // 128 = "imported" confidence
            }
        }

        // Return type — resolve by name (handles primitives + user types)
        if (!sig.returnTypeName.empty()) {
            auto retType = resolveTypeName(view, sig.returnTypeName);
            if (retType)
                func->SetReturnType({retType, 128});
        }
    }

    result.ghidraDataTypes = data.dataTypes;
    result.parameters      = data.parameters;
    result.bookmarks       = data.bookmarks;
    result.dataItems       = data.dataItems;
    result.equates         = data.equates;
    result.funcSigs        = data.funcSigs;

    view->UpdateAnalysis();
    return result;
}

// ---------------------------------------------------------------------------
// Map-only build — no view modifications
// ---------------------------------------------------------------------------

SyncResult SyncEngine::buildWritebackMaps(Ref<BinaryView> view,
                                           const GhidraDbExport& data) {
    SyncResult result;
    if (!view) return result;

    result.imageBase = data.imageBase;

    uint64_t bnBase     = view->GetStart();
    uint64_t ghidraBase = data.imageBase;
    int64_t  rebase     = (int64_t)bnBase - (int64_t)ghidraBase;

    auto applyRebase = [&](uint64_t addr) -> uint64_t {
        return (uint64_t)((int64_t)addr + rebase);
    };

    for (const auto& sym : data.symbols) {
        uint64_t addr = applyRebase(sym.addr);
        result.addrToKey[addr]          = sym.key;
        result.addrToOriginalName[addr] = sym.name;
        if (addr < result.addrMin) result.addrMin = addr;
        if (addr > result.addrMax) result.addrMax = addr;
    }

    for (const auto& comm : data.comments) {
        uint64_t caddr = applyRebase(comm.addr);
        if (!comm.encodedKey.empty())
            result.addrToCommentKey[caddr] = comm.encodedKey;

        const std::pair<const std::string*, const char*> commParts[] = {
            {&comm.eol, "eol"}, {&comm.rep, "rep"}, {&comm.pre, "pre"}, {&comm.post, "post"}
        };
        std::string text;
        int fieldCount = 0;
        std::string soloField;
        for (const auto& [part, fieldName] : commParts) {
            if (part->empty()) continue;
            ++fieldCount;
            if (fieldCount == 1) soloField = fieldName;
            if (!text.empty()) text += '\n';
            text += *part;
        }
        if (!text.empty()) {
            result.addrToCommentField[caddr] = (fieldCount == 1) ? soloField : "eol";
            result.addrToOriginalComment[caddr] = text;
        }

        if (!comm.plate.empty())
            result.addrToOriginalFuncComment[caddr] = comm.plate;
    }

    result.ghidraDataTypes = data.dataTypes;
    result.parameters      = data.parameters;
    result.bookmarks       = data.bookmarks;
    result.dataItems       = data.dataItems;
    result.equates         = data.equates;
    result.funcSigs        = data.funcSigs;

    return result;
}
