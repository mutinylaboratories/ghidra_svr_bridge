// CanonicalParityTest.cpp — tier-3 cross-database parity, C++ side.
//
// Consumes the shared golden fixtures in testdata/parity/fixtures/ (the same
// files the Java CanonicalParityTest uses). Import direction: golden →
// SyncEngine → BnCanonicalExport must equal the golden. Checkin direction:
// golden baseline + scripted edits → buildCheckinJson must equal
// expected-preview.json. If both sides match the goldens, the .bndb and the
// Ghidra DB are field-equal by transitivity (testdata/parity/RULES.md).

#include "BnViewFixture.h"
#include "GhidraConnection.h"
#include "GhidraJson.h"
#include "SyncEngine.h"
#include "support/BnCanonicalExport.h"
#include "support/CanonicalDiff.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdio>
#include <fstream>

using namespace BinaryNinja;
using namespace bn_fixture;
using nlohmann::json;

namespace {

json loadGolden(const std::string& relPath) {
    std::ifstream in(testDataDir() + "/parity/" + relPath);
    EXPECT_TRUE(in.good()) << "cannot open golden " << relPath;
    json j = json::parse(in, nullptr, /*allow_exceptions=*/false);
    EXPECT_FALSE(j.is_discarded()) << "golden is not valid JSON: " << relPath;
    j.erase("_comment");
    return j;
}

// Normalize type-bearing fields, then serialize each array element and sort —
// array order is not part of the checkin contract.
json normalizeElement(json e) {
    if (e.is_object()) {
        for (const char* f : {"type_name", "ret_type"})
            if (e.contains(f))
                e[f] = parity::normalizeTypeName(e[f].get<std::string>());
        if (e.contains("members"))
            for (auto& m : e["members"]) m = normalizeElement(m);
    }
    return e;
}

std::vector<std::string> sortedElements(const json& array) {
    std::vector<std::string> out;
    for (const auto& e : array) out.push_back(normalizeElement(e).dump());
    std::sort(out.begin(), out.end());
    return out;
}

void expectPreviewMatches(const json& expected, const json& actual) {
    for (const char* key : {"symbols", "comments", "equate_renames",
                            "equate_ref_adds", "bookmark_changes",
                            "param_renames", "data_type_changes",
                            "data_item_changes", "func_sig_changes"}) {
        ASSERT_TRUE(actual.contains(key)) << key;
        EXPECT_EQ(sortedElements(expected.value(key, json::array())),
                  sortedElements(actual[key]))
            << "checkin preview array mismatch: " << key;
    }
}

class CanonicalParityTest : public ::testing::Test {
protected:
    void SetUp() override {
        BN_REQUIRE_CORE();
    }
    void TearDown() override {
        GhidraConnection::instance().clearCheckinState();
        if (view) closeView(view);
    }

    // Create BN functions for every golden Function symbol before the import
    // runs, mirroring a real session where BN analyzed the binary first (and
    // required for equate display overrides + plate comments to land).
    void prepareFunctions(const GhidraDbExport& data, uint64_t bnBase) {
        for (const auto& s : data.symbols) {
            if (s.type != GhidraSymbolType::Function) continue;
            uint64_t va = s.addr - kDefaultBase + bnBase;
            view->CreateUserFunction(view->GetDefaultPlatform(), va);
        }
        view->UpdateAnalysisAndWait();
    }

    SyncResult importGolden(const json& golden, uint64_t bnBase) {
        view = makeViewAt(bnBase);
        EXPECT_TRUE(view);
        if (!view) return {};
        GhidraDbExport data = ghidra_json::parseDbExportJson(golden);
        prepareFunctions(data, bnBase);
        SyncResult r = SyncEngine::applyToView(view, data);
        view->UpdateAnalysisAndWait();
        return r;
    }

    void storeBaseline(const SyncResult& r) {
        GhidraConnection::instance().storeCheckinState(
            r.addrToKey, r.addrToOriginalName, r.addrToCommentKey,
            r.addrToOriginalComment, r.addrToOriginalFuncComment,
            r.addrToCommentField, r.ghidraDataTypes, r.parameters, r.bookmarks,
            r.dataItems, r.equates, r.funcSigs, r.imageBase,
            "testrepo", "/", "testitem");
    }

    // The BN-side user edits documented in fixtures/checkin/basic/edits.json.
    // Shared by the preview-match test and the convergence test.
    void applyScriptedEdits() {
        const uint64_t base = kDefaultBase;
        view->DefineUserSymbol(new Symbol(FunctionSymbol, "main_entry", base + kOffFuncRet));
        view->DefineUserSymbol(new Symbol(DataSymbol, "new_label", base + kOffDataInt));
        view->SetCommentForAddress(base + kOffFuncEquate, "updated size note");
        view->SetCommentForAddress(base + kOffFuncFrame, "fresh note");
        {   // GPoint: rename member y → height
            StructureBuilder sb;
            sb.AddMemberAtOffset(Type::IntegerType(4, true), "x", 0);
            sb.AddMemberAtOffset(Type::IntegerType(4, true), "height", 4);
            view->DefineUserType(QualifiedName("GPoint"),
                                 Type::StructureType(sb.Finalize()));
        }
        {   // new struct BnStruct
            StructureBuilder sb;
            sb.AddMemberAtOffset(Type::IntegerType(4, true), "a", 0);
            sb.AddMemberAtOffset(Type::IntegerType(4, true), "b", 4);
            view->DefineUserType(QualifiedName("BnStruct"),
                                 Type::StructureType(sb.Finalize()));
        }
        {   // bookmark add + delete
            Ref<TagType> tt = view->GetTagType("Ghidra: Note");
            ASSERT_TRUE(tt);
            view->CreateUserDataTag(base + kOffDataPoint, tt, "[new] added", false);
            for (auto& tag : view->GetUserDataTags(base + kOffDataStr))
                view->RemoveUserDataTag(base + kOffDataStr, tag);
        }
        {   // data item add + delete
            Ref<Type> bnStruct = view->GetTypeByName(QualifiedName("BnStruct"));
            ASSERT_TRUE(bnStruct);
            view->DefineUserDataVariable(base + kOffDataInt,
                                         Confidence<Ref<Type>>(bnStruct, 255));
            view->UndefineUserDataVariable(base + kOffDataPoint);
        }
        {   // equate rename
            EnumerationBuilder eb;
            eb.AddMemberWithValue("BUFFER_MAX", 500);
            view->DefineType("ghidra_eq_42", QualifiedName("MAX_SIZE"),
                             Type::EnumerationType(eb.Finalize(), 4, false));
        }
        {   // return type change on main_entry
            for (auto& f : view->GetAnalysisFunctionsForAddress(base + kOffFuncRet))
                if (f->GetStart() == base + kOffFuncRet)
                    f->SetReturnType(Confidence<Ref<Type>>(Type::IntegerType(8, false), 255));
        }
        view->UpdateAnalysisAndWait();
    }

    Ref<BinaryView> view;
};

// ---------------------------------------------------------------------------
// Import direction
// ---------------------------------------------------------------------------

TEST_F(CanonicalParityTest, Import_FullDb_MatchesGolden) {
    json golden = loadGolden("fixtures/import/full_db.json");
    importGolden(golden, kDefaultBase);

    GhidraDbExport ref = ghidra_json::parseDbExportJson(golden);
    json bnExport = parity::bnCanonicalExport(view, ref);
    auto issues = parity::compareCanonical(golden, bnExport);
    EXPECT_TRUE(issues.empty())
        << "parity issues:\n  " << [&] {
               std::string s;
               for (const auto& i : issues) s += i + "\n  ";
               return s;
           }();
}

TEST_F(CanonicalParityTest, Import_FullDb_RebasedViewStillMatchesGolden) {
    json golden = loadGolden("fixtures/import/full_db.json");
    importGolden(golden, 0x140000000);

    GhidraDbExport ref = ghidra_json::parseDbExportJson(golden);
    json bnExport = parity::bnCanonicalExport(view, ref);
    auto issues = parity::compareCanonical(golden, bnExport);
    EXPECT_TRUE(issues.empty())
        << "parity issues (rebased):\n  " << [&] {
               std::string s;
               for (const auto& i : issues) s += i + "\n  ";
               return s;
           }();
}

TEST_F(CanonicalParityTest, Import_FullDb_SurvivesBndbSaveReopen) {
    json golden = loadGolden("fixtures/import/full_db.json");
    importGolden(golden, kDefaultBase);

    std::string bndb = testDataDir() + "/tmp_parity.bndb";
    Ref<BinaryView> reopened = saveAndReopen(view, bndb);
    view = nullptr;
    ASSERT_TRUE(reopened);
    reopened->UpdateAnalysisAndWait();

    GhidraDbExport ref = ghidra_json::parseDbExportJson(golden);
    json bnExport = parity::bnCanonicalExport(reopened, ref);
    auto issues = parity::compareCanonical(golden, bnExport);
    EXPECT_TRUE(issues.empty())
        << "parity issues after .bndb round trip:\n  " << [&] {
               std::string s;
               for (const auto& i : issues) s += i + "\n  ";
               return s;
           }();

    closeView(reopened);
    std::remove(bndb.c_str());
}

// The oracle must bite: a corrupted golden may not compare clean.
TEST_F(CanonicalParityTest, Import_MutatedGolden_IsDetected) {
    json golden = loadGolden("fixtures/import/full_db.json");
    importGolden(golden, kDefaultBase);

    json mutated = golden;
    mutated["symbols"][0]["name"] = "wrong_name";

    GhidraDbExport ref = ghidra_json::parseDbExportJson(golden);
    json bnExport = parity::bnCanonicalExport(view, ref);
    auto issues = parity::compareCanonical(mutated, bnExport);
    EXPECT_FALSE(issues.empty())
        << "comparator failed to flag a mutated golden symbol name";
}

// ---------------------------------------------------------------------------
// Checkin direction
// ---------------------------------------------------------------------------

TEST_F(CanonicalParityTest, Checkin_Basic_PreviewMatchesGolden) {
    json baseline = loadGolden("fixtures/checkin/basic/baseline.json");
    json expectedPreview = loadGolden("fixtures/checkin/basic/expected-preview.json");

    SyncResult r = importGolden(baseline, kDefaultBase);
    storeBaseline(r);
    applyScriptedEdits();

    GhidraCheckinPreview preview =
        GhidraConnection::instance().collectCheckinChanges(view);
    int64_t rebase = (int64_t)view->GetStart() - (int64_t)r.imageBase;
    json body = ghidra_json::buildCheckinJson(
        preview, rebase, r.addrToOriginalFuncComment, r.addrToCommentField);

    expectPreviewMatches(expectedPreview, body);
}

// A fresh checkout with ZERO user edits must produce an empty preview — the
// baseline came from the very export the view was just synced from, so any
// entry here is a BN↔Ghidra representation mismatch that re-prompts forever.
TEST_F(CanonicalParityTest, Checkin_NoEdits_EmptyPreview) {
    json golden = loadGolden("fixtures/import/full_db.json");

    SyncResult r = importGolden(golden, kDefaultBase);
    storeBaseline(r);

    GhidraCheckinPreview p =
        GhidraConnection::instance().collectCheckinChanges(view);
    int64_t rebase = (int64_t)view->GetStart() - (int64_t)r.imageBase;
    json body = ghidra_json::buildCheckinJson(
        p, rebase, r.addrToOriginalFuncComment, r.addrToCommentField);

    expectPreviewMatches(json::object(), body);
}

// Same, but with the BN view at a different base than the Ghidra program —
// every category is address-keyed, so a rebase bug here re-prompts everything.
TEST_F(CanonicalParityTest, Checkin_NoEditsRebased_EmptyPreview) {
    json golden = loadGolden("fixtures/import/full_db.json");

    SyncResult r = importGolden(golden, 0x140000000);
    storeBaseline(r);

    GhidraCheckinPreview p =
        GhidraConnection::instance().collectCheckinChanges(view);
    int64_t rebase = (int64_t)view->GetStart() - (int64_t)r.imageBase;
    json body = ghidra_json::buildCheckinJson(
        p, rebase, r.addrToOriginalFuncComment, r.addrToCommentField);

    expectPreviewMatches(json::object(), body);
}

// REGRESSION for the "same items prompted on every check-in" bug: after a
// check-in lands on the server and the user checks the item out again, the
// re-imported server state IS the new baseline, so the next check-in preview
// must be empty. Models the full cycle: edit → check in (server now holds
// expected-after per the Java CanonicalParityTest) → check out again
// (re-import expected-after over the SAME view) → collect → nothing queued.
TEST_F(CanonicalParityTest, Checkin_Convergence_SecondPreviewIsEmpty) {
    json baseline = loadGolden("fixtures/checkin/basic/baseline.json");
    json after    = loadGolden("fixtures/checkin/basic/expected-after.json");

    SyncResult r = importGolden(baseline, kDefaultBase);
    storeBaseline(r);
    applyScriptedEdits();

    // Sanity: the first preview has work to send.
    {
        GhidraCheckinPreview p1 =
            GhidraConnection::instance().collectCheckinChanges(view);
        ASSERT_FALSE(p1.renames.empty() && p1.newSymbols.empty() &&
                     p1.comments.empty() && p1.dataTypeChanges.empty());
    }

    // Fresh checkout of the post-check-in server state into the same view.
    GhidraDbExport afterData = ghidra_json::parseDbExportJson(after);
    SyncResult r2 = SyncEngine::applyToView(view, afterData);
    view->UpdateAnalysisAndWait();
    storeBaseline(r2);

    GhidraCheckinPreview p2 =
        GhidraConnection::instance().collectCheckinChanges(view);
    int64_t rebase = (int64_t)view->GetStart() - (int64_t)r2.imageBase;
    json body = ghidra_json::buildCheckinJson(
        p2, rebase, r2.addrToOriginalFuncComment, r2.addrToCommentField);

    // Every category must be empty — anything left here re-prompts forever.
    expectPreviewMatches(json::object(), body);
}

} // namespace
