// GhidraJsonTest.cpp
// Tests for ghidra_json::parseDbExportJson / buildCheckinJson — the JSON <->
// data-model mapping shared by the production import (open_db) and check-in
// paths.  The sample JSON here mirrors the keys DatabaseExporter.java emits.

#include <gtest/gtest.h>
#include "GhidraJson.h"

using nlohmann::json;
using namespace ghidra_json;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

TEST(GhidraJsonHexTest, ToHex_FormatsWithPrefix) {
    EXPECT_EQ(toHex(0x401000), "0x401000");
    EXPECT_EQ(toHex(0), "0x0");
}

TEST(GhidraJsonHexTest, ParseHexAddr_RoundTripsToHex) {
    EXPECT_EQ(parseHexAddr(toHex(0x140001000ull)), 0x140001000ull);
}

TEST(GhidraJsonHexTest, ParseHexAddr_AcceptsUpperCasePrefix) {
    EXPECT_EQ(parseHexAddr("0X401000"), 0x401000u);
}

TEST(GhidraJsonHexTest, ParseHexAddr_HighBitAddress) {
    // Addresses above 2^63 must survive the unsigned round trip.
    EXPECT_EQ(parseHexAddr("0xffffffff80001000"), 0xffffffff80001000ull);
    EXPECT_EQ(toHex(0xffffffff80001000ull), "0xffffffff80001000");
}

TEST(GhidraJsonHexTest, ParseHexAddr_TooShortIsZero) {
    EXPECT_EQ(parseHexAddr(""), 0u);
    EXPECT_EQ(parseHexAddr("5"), 0u);
}

// ---------------------------------------------------------------------------
// parseDbExportJson
// ---------------------------------------------------------------------------

TEST(ParseDbExportTest, EmptyObject_YieldsEmptyExport) {
    GhidraDbExport out = parseDbExportJson(json::object());
    EXPECT_EQ(out.imageBase, 0u);
    EXPECT_TRUE(out.symbols.empty());
    EXPECT_TRUE(out.comments.empty());
    EXPECT_TRUE(out.funcFlags.empty());
    EXPECT_TRUE(out.funcSigs.empty());
    EXPECT_TRUE(out.equates.empty());
    EXPECT_TRUE(out.bookmarks.empty());
    EXPECT_TRUE(out.parameters.empty());
    EXPECT_TRUE(out.dataTypes.empty());
    EXPECT_TRUE(out.dataItems.empty());
    EXPECT_TRUE(out.memoryBlocks.empty());
}

TEST(ParseDbExportTest, ImageBase_Parsed) {
    GhidraDbExport out = parseDbExportJson({{"image_base", "0x400000"}});
    EXPECT_EQ(out.imageBase, 0x400000u);
}

TEST(ParseDbExportTest, Symbols_AllFields) {
    json resp = {{"symbols", json::array({
        {{"key", 42}, {"name", "main"}, {"addr", "0x401000"},
         {"type", 4}, {"source", 3}, {"ns", 7}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.symbols.size(), 1u);
    const auto& s = out.symbols[0];
    EXPECT_EQ(s.key, 42);
    EXPECT_EQ(s.name, "main");
    EXPECT_EQ(s.addr, 0x401000u);
    EXPECT_EQ(s.type, GhidraSymbolType::Function);
    EXPECT_EQ(s.source, GhidraSymbolSource::User);
    EXPECT_EQ(s.namespaceId, 7);
}

TEST(ParseDbExportTest, Comments_AllColumns) {
    json resp = {{"comments", json::array({
        {{"addr", "0x401010"}, {"key", "0x200000001010"},
         {"eol", "e"}, {"pre", "p"}, {"post", "o"}, {"plate", "l"}, {"rep", "r"}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.comments.size(), 1u);
    const auto& c = out.comments[0];
    EXPECT_EQ(c.addr, 0x401010u);
    EXPECT_EQ(c.encodedKey, "0x200000001010");
    EXPECT_EQ(c.eol, "e");
    EXPECT_EQ(c.pre, "p");
    EXPECT_EQ(c.post, "o");
    EXPECT_EQ(c.plate, "l");
    EXPECT_EQ(c.rep, "r");
}

TEST(ParseDbExportTest, FuncFlags_WithoutSignature_NoFuncSig) {
    json resp = {{"func_flags", json::array({
        {{"key", 5}, {"thunk", true}, {"no_ret", false}, {"inline", true}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.funcFlags.size(), 1u);
    EXPECT_TRUE(out.funcFlags[0].thunk);
    EXPECT_FALSE(out.funcFlags[0].noReturn);
    EXPECT_TRUE(out.funcFlags[0].isInline);
    EXPECT_TRUE(out.funcSigs.empty());
}

TEST(ParseDbExportTest, FuncFlags_WithSignature_SplitsIntoFuncSig) {
    json resp = {{"func_flags", json::array({
        {{"key", 5}, {"thunk", false}, {"no_ret", false}, {"inline", false},
         {"cc", "__fastcall"}, {"ret_type", "int32_t"}, {"ret_type_id", 99}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.funcSigs.size(), 1u);
    EXPECT_EQ(out.funcSigs[0].key, 5);
    EXPECT_EQ(out.funcSigs[0].callingConvention, "__fastcall");
    EXPECT_EQ(out.funcSigs[0].returnTypeName, "int32_t");
    EXPECT_EQ(out.funcSigs[0].returnTypeId, 99);
}

TEST(ParseDbExportTest, Equates_WithRefs) {
    json resp = {{"equates", json::array({
        {{"id", 3}, {"name", "MAX_SIZE"}, {"value", 500},
         {"refs", json::array({
            {{"addr", "0x401005"}, {"op_index", 1}},
            {{"addr", "0x401020"}, {"op_index", 0}}
         })}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.equates.size(), 1u);
    EXPECT_EQ(out.equates[0].name, "MAX_SIZE");
    EXPECT_EQ(out.equates[0].value, 500);
    ASSERT_EQ(out.equates[0].refs.size(), 2u);
    EXPECT_EQ(out.equates[0].refs[0].addr, 0x401005u);
    EXPECT_EQ(out.equates[0].refs[0].opIndex, 1);
}

TEST(ParseDbExportTest, Bookmarks_AllFields) {
    json resp = {{"bookmarks", json::array({
        {{"type", "Note"}, {"addr", "0x401030"},
         {"category", "review"}, {"comment", "look here"}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.bookmarks.size(), 1u);
    EXPECT_EQ(out.bookmarks[0].type, "Note");
    EXPECT_EQ(out.bookmarks[0].addr, 0x401030u);
    EXPECT_EQ(out.bookmarks[0].category, "review");
    EXPECT_EQ(out.bookmarks[0].comment, "look here");
}

TEST(ParseDbExportTest, Parameters_ParamAndLocal) {
    json resp = {{"parameters", json::array({
        {{"key", 10}, {"func_addr", "0x401000"}, {"name", "count"},
         {"is_param", true}, {"ordinal", 0}, {"type_name", "int32_t"}, {"type_id", 4}},
        {{"key", 11}, {"func_addr", "0x401000"}, {"name", "local_8"},
         {"is_param", false}, {"ordinal", -8}, {"type_name", "uint64_t"}, {"type_id", 9}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.parameters.size(), 2u);
    EXPECT_TRUE(out.parameters[0].isParam);
    EXPECT_EQ(out.parameters[0].ordinal, 0);
    EXPECT_FALSE(out.parameters[1].isParam);
    EXPECT_EQ(out.parameters[1].ordinal, -8);
    EXPECT_EQ(out.parameters[1].typeName, "uint64_t");
}

TEST(ParseDbExportTest, DataTypes_StructWithMembers) {
    json resp = {{"data_types", json::array({
        {{"id", 100}, {"kind", "struct"}, {"name", "Point"}, {"comment", ""},
         {"size", 8},
         {"members", json::array({
            {{"offset", 0}, {"type_id", 4}, {"name", "x"}, {"comment", ""},
             {"size", 4}, {"ordinal", 0}, {"type_name", "int32_t"}},
            {{"offset", 4}, {"type_id", 4}, {"name", "y"}, {"comment", ""},
             {"size", 4}, {"ordinal", 1}, {"type_name", "int32_t"}}
         })}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.dataTypes.size(), 1u);
    const auto& dt = out.dataTypes[0];
    EXPECT_EQ(dt.kind, "struct");
    EXPECT_EQ(dt.name, "Point");
    EXPECT_EQ(dt.size, 8);
    ASSERT_EQ(dt.members.size(), 2u);
    EXPECT_EQ(dt.members[1].offset, 4);
    EXPECT_EQ(dt.members[1].name, "y");
    EXPECT_EQ(dt.members[1].typeName, "int32_t");
}

TEST(ParseDbExportTest, DataTypes_EnumWithValues) {
    json resp = {{"data_types", json::array({
        {{"id", 101}, {"kind", "enum"}, {"name", "Color"}, {"size", 4},
         {"values", json::array({
            {{"name", "RED"}, {"value", 0}, {"comment", ""}},
            {{"name", "NEG"}, {"value", -1}, {"comment", ""}}
         })}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.dataTypes.size(), 1u);
    ASSERT_EQ(out.dataTypes[0].values.size(), 2u);
    EXPECT_EQ(out.dataTypes[0].values[1].name, "NEG");
    EXPECT_EQ(out.dataTypes[0].values[1].value, -1);
}

TEST(ParseDbExportTest, DataTypes_TypedefUnderlyingName) {
    json resp = {{"data_types", json::array({
        {{"id", 102}, {"kind", "typedef"}, {"name", "handle_t"},
         {"underlying_type_id", 100}, {"underlying_name", "Point"}, {"size", 8}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.dataTypes.size(), 1u);
    EXPECT_EQ(out.dataTypes[0].underlyingTypeId, 100);
    EXPECT_EQ(out.dataTypes[0].underlyingTypeName, "Point");
}

TEST(ParseDbExportTest, DataTypes_NonTypedefIgnoresUnderlyingName) {
    json resp = {{"data_types", json::array({
        {{"id", 103}, {"kind", "struct"}, {"name", "S"},
         {"underlying_name", "ShouldBeIgnored"}, {"size", 4}}
    })}};
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.dataTypes.size(), 1u);
    EXPECT_TRUE(out.dataTypes[0].underlyingTypeName.empty());
}

TEST(ParseDbExportTest, DataItems_MemoryBlocks_XrefStats_Diag) {
    json resp = {
        {"data_items", json::array({{{"addr", "0x402000"}, {"type_id", 100}}})},
        {"memory_blocks", json::array({
            {{"name", ".text"}, {"addr", "0x401000"}, {"size", "0x1000"},
             {"r", true}, {"w", false}, {"x", true},
             {"initialized", true}, {"overlay", false}}
        })},
        {"xref_stats", {{"from_count", 12}, {"to_count", 34}}},
        {"diag", json::array({"note one", "note two"})}
    };
    GhidraDbExport out = parseDbExportJson(resp);
    ASSERT_EQ(out.dataItems.size(), 1u);
    EXPECT_EQ(out.dataItems[0].addr, 0x402000u);
    EXPECT_EQ(out.dataItems[0].typeId, 100);
    ASSERT_EQ(out.memoryBlocks.size(), 1u);
    EXPECT_EQ(out.memoryBlocks[0].name, ".text");
    EXPECT_EQ(out.memoryBlocks[0].size, 0x1000u);
    EXPECT_TRUE(out.memoryBlocks[0].execute);
    EXPECT_FALSE(out.memoryBlocks[0].write);
    EXPECT_EQ(out.xrefStats.fromCount, 12);
    EXPECT_EQ(out.xrefStats.toCount, 34);
    ASSERT_EQ(out.diag.size(), 2u);
    EXPECT_EQ(out.diag[0], "note one");
}

// ---------------------------------------------------------------------------
// buildCheckinJson
// ---------------------------------------------------------------------------

namespace {
const std::unordered_map<uint64_t, std::string> kNoFuncComments;
const std::unordered_map<uint64_t, std::string> kNoCommentFields;
}

TEST(BuildCheckinTest, EmptyPreview_AllNineArraysPresentAndEmpty) {
    GhidraCheckinPreview preview;
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    for (const char* key : {"symbols", "comments", "equate_renames",
                            "equate_ref_adds", "bookmark_changes", "param_renames",
                            "data_type_changes", "data_item_changes",
                            "func_sig_changes"}) {
        ASSERT_TRUE(body.contains(key)) << key;
        EXPECT_TRUE(body[key].is_array()) << key;
        EXPECT_TRUE(body[key].empty()) << key;
    }
}

TEST(BuildCheckinTest, Rename_SendsKeyAndNewName) {
    GhidraCheckinPreview preview;
    preview.renames.push_back({42, 0x401000, "old", "new_name"});
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["symbols"].size(), 1u);
    EXPECT_EQ(body["symbols"][0]["key"], 42);
    EXPECT_EQ(body["symbols"][0]["name"], "new_name");
    EXPECT_FALSE(body["symbols"][0].contains("va"));
}

TEST(BuildCheckinTest, NewSymbol_RebasedVaAndSymType) {
    GhidraCheckinPreview preview;
    preview.newSymbols.push_back({0x140001000, "my_func", true});
    preview.newSymbols.push_back({0x140002000, "my_label", false});
    // BN base 0x140000000, Ghidra base 0x400000.
    int64_t rebase = (int64_t)0x140000000 - (int64_t)0x400000;
    json body = buildCheckinJson(preview, rebase, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["symbols"].size(), 2u);
    EXPECT_EQ(body["symbols"][0]["va"], "0x401000");
    EXPECT_EQ(body["symbols"][0]["sym_type"], 5);
    EXPECT_EQ(body["symbols"][1]["va"], "0x402000");
    EXPECT_EQ(body["symbols"][1]["sym_type"], 0);
}

TEST(BuildCheckinTest, NegativeRebase_NewSymbolVa) {
    // BN loaded below the Ghidra image base.
    GhidraCheckinPreview preview;
    preview.newSymbols.push_back({0x101000, "f", false});
    int64_t rebase = (int64_t)0x100000 - (int64_t)0x400000; // negative
    json body = buildCheckinJson(preview, rebase, kNoFuncComments, kNoCommentFields);
    EXPECT_EQ(body["symbols"][0]["va"], "0x401000");
}

TEST(BuildCheckinTest, Comment_DefaultsToEolColumn) {
    GhidraCheckinPreview preview;
    preview.comments.push_back({0x401010, "new comment", ""});
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["comments"].size(), 1u);
    EXPECT_EQ(body["comments"][0]["va"], "0x401010");
    EXPECT_EQ(body["comments"][0]["eol"], "new comment");
    EXPECT_FALSE(body["comments"][0].contains("key"));
}

TEST(BuildCheckinTest, Comment_RoutedToOriginalColumn) {
    GhidraCheckinPreview preview;
    preview.comments.push_back({0x401010, "edited", "0x200000001010"});
    std::unordered_map<uint64_t, std::string> fields{{0x401010, "pre"}};
    json body = buildCheckinJson(preview, 0, kNoFuncComments, fields);
    EXPECT_EQ(body["comments"][0]["pre"], "edited");
    EXPECT_FALSE(body["comments"][0].contains("eol"));
    EXPECT_EQ(body["comments"][0]["key"], "0x200000001010");
}

TEST(BuildCheckinTest, Comment_FunctionCommentRoutedToPlate) {
    GhidraCheckinPreview preview;
    preview.comments.push_back({0x401000, "header text", ""});
    std::unordered_map<uint64_t, std::string> funcComments{{0x401000, "orig"}};
    // Even with a conflicting field entry, plate wins for function comments.
    std::unordered_map<uint64_t, std::string> fields{{0x401000, "eol"}};
    json body = buildCheckinJson(preview, 0, funcComments, fields);
    EXPECT_EQ(body["comments"][0]["plate"], "header text");
    EXPECT_FALSE(body["comments"][0].contains("eol"));
}

TEST(BuildCheckinTest, EquateRenameAndNewRef) {
    GhidraCheckinPreview preview;
    preview.equateRenames.push_back({7, "NEW_NAME"});
    preview.newEquateRefs.push_back({7, 0x401005, 1});
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["equate_renames"].size(), 1u);
    EXPECT_EQ(body["equate_renames"][0]["id"], 7);
    EXPECT_EQ(body["equate_renames"][0]["name"], "NEW_NAME");
    ASSERT_EQ(body["equate_ref_adds"].size(), 1u);
    EXPECT_EQ(body["equate_ref_adds"][0]["va"], "0x401005");
    EXPECT_EQ(body["equate_ref_adds"][0]["op_index"], 1);
}

TEST(BuildCheckinTest, BookmarkChange_RebasedAddr) {
    GhidraCheckinPreview preview;
    preview.bookmarkChanges.push_back({"add", "Note", 0x140001030, "cat", "cm"});
    int64_t rebase = (int64_t)0x140000000 - (int64_t)0x400000;
    json body = buildCheckinJson(preview, rebase, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["bookmark_changes"].size(), 1u);
    EXPECT_EQ(body["bookmark_changes"][0]["op"], "add");
    EXPECT_EQ(body["bookmark_changes"][0]["addr"], "0x401030");
    EXPECT_EQ(body["bookmark_changes"][0]["category"], "cat");
}

TEST(BuildCheckinTest, ParamRename_TypeNameOnlyWhenSet) {
    GhidraCheckinPreview preview;
    preview.paramRenames.push_back({10, "count", ""});
    preview.paramRenames.push_back({11, "size", "uint64_t"});
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["param_renames"].size(), 2u);
    EXPECT_FALSE(body["param_renames"][0].contains("type_name"));
    EXPECT_EQ(body["param_renames"][1]["type_name"], "uint64_t");
}

TEST(BuildCheckinTest, NewParam_FuncVaOrdinalIsLocal) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::NewParam p;
    p.funcAddr = 0x401000;
    p.ordinal  = 2;
    p.name     = "arg3";
    p.isLocal  = false;
    p.typeName = "int32_t";
    preview.newParams.push_back(p);
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["param_renames"].size(), 1u);
    const auto& j = body["param_renames"][0];
    EXPECT_EQ(j["func_va"], "0x401000");
    EXPECT_EQ(j["ordinal"], 2);
    EXPECT_EQ(j["is_local"], false);
    EXPECT_EQ(j["type_name"], "int32_t");
    EXPECT_FALSE(j.contains("key"));
}

TEST(BuildCheckinTest, DataTypeChange_StructMembersSerialized) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::DataTypeChange dt;
    dt.op   = "add";
    dt.kind = "struct";
    dt.name = "Point";
    dt.size = 8;
    dt.members.push_back({"x", 0, 4, "int32_t"});
    dt.members.push_back({"y", 4, 4, "int32_t"});
    preview.dataTypeChanges.push_back(dt);
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["data_type_changes"].size(), 1u);
    const auto& j = body["data_type_changes"][0];
    EXPECT_EQ(j["op"], "add");
    EXPECT_EQ(j["ghidra_id"], 0);
    ASSERT_EQ(j["members"].size(), 2u);
    EXPECT_EQ(j["members"][1]["offset"], 4);
    EXPECT_EQ(j["members"][1]["type_name"], "int32_t");
    EXPECT_FALSE(j.contains("values"));
    EXPECT_FALSE(j.contains("underlying_type_name"));
}

TEST(BuildCheckinTest, DataTypeChange_EnumAndTypedef) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::DataTypeChange en;
    en.op = "update"; en.kind = "enum"; en.name = "Color";
    en.ghidraId = 101; en.size = 4;
    en.values.push_back({"RED", 0});
    preview.dataTypeChanges.push_back(en);
    GhidraCheckinPreview::DataTypeChange td;
    td.op = "add"; td.kind = "typedef"; td.name = "handle_t";
    td.size = 8; td.underlyingTypeName = "Point";
    preview.dataTypeChanges.push_back(td);
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["data_type_changes"].size(), 2u);
    EXPECT_EQ(body["data_type_changes"][0]["ghidra_id"], 101);
    EXPECT_EQ(body["data_type_changes"][0]["values"][0]["name"], "RED");
    EXPECT_EQ(body["data_type_changes"][1]["underlying_type_name"], "Point");
}

TEST(BuildCheckinTest, DataItemChange_RebasedAddr) {
    GhidraCheckinPreview preview;
    preview.dataItemChanges.push_back({"add", 0x140002000, "Point"});
    preview.dataItemChanges.push_back({"delete", 0x140002010, ""});
    int64_t rebase = (int64_t)0x140000000 - (int64_t)0x400000;
    json body = buildCheckinJson(preview, rebase, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["data_item_changes"].size(), 2u);
    EXPECT_EQ(body["data_item_changes"][0]["addr"], "0x402000");
    EXPECT_EQ(body["data_item_changes"][0]["type_name"], "Point");
    EXPECT_EQ(body["data_item_changes"][1]["op"], "delete");
}

TEST(BuildCheckinTest, FuncSigChange_OptionalFields) {
    GhidraCheckinPreview preview;
    preview.funcSigChanges.push_back({5, "__fastcall", ""});
    preview.funcSigChanges.push_back({6, "", "uint64_t"});
    json body = buildCheckinJson(preview, 0, kNoFuncComments, kNoCommentFields);
    ASSERT_EQ(body["func_sig_changes"].size(), 2u);
    EXPECT_EQ(body["func_sig_changes"][0]["cc"], "__fastcall");
    EXPECT_FALSE(body["func_sig_changes"][0].contains("ret_type"));
    EXPECT_EQ(body["func_sig_changes"][1]["ret_type"], "uint64_t");
    EXPECT_FALSE(body["func_sig_changes"][1].contains("cc"));
}

// ---------------------------------------------------------------------------
// Import/export symmetry: a parsed export re-encoded as checkin changes keeps
// addresses stable when rebase = 0 (sanity pin for the parity suite).
// ---------------------------------------------------------------------------

TEST(GhidraJsonSymmetryTest, ParsedAddressesSurviveCheckinEncoding) {
    json resp = {
        {"image_base", "0x400000"},
        {"symbols", json::array({
            {{"key", 1}, {"name", "f"}, {"addr", "0x401000"}, {"type", 4},
             {"source", 3}, {"ns", 0}}
        })}
    };
    GhidraDbExport parsed = parseDbExportJson(resp);
    ASSERT_EQ(parsed.symbols.size(), 1u);

    GhidraCheckinPreview preview;
    preview.newSymbols.push_back({parsed.symbols[0].addr, "f2", true});
    json body = buildCheckinJson(preview, /*rebase=*/0,
                                 kNoFuncComments, kNoCommentFields);
    EXPECT_EQ(body["symbols"][0]["va"], "0x401000");
}
