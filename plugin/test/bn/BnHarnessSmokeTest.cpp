// BnHarnessSmokeTest.cpp — validates the headless harness itself before any
// parity test builds on it: fixture loads, image base is honored, bytes are
// readable, rebase loads work, and a .bndb save/reopen round-trips.

#include "BnViewFixture.h"
#include <gtest/gtest.h>
#include <cstdio>

using namespace BinaryNinja;
using namespace bn_fixture;

TEST(BnHarnessSmokeTest, FixtureLoads_AtRequestedBase) {
    BN_REQUIRE_CORE();
    Ref<BinaryView> view = makeView();
    ASSERT_TRUE(view) << "Mapped load of " << fixtureBinPath() << " failed";
    EXPECT_EQ(view->GetStart(), kDefaultBase);
    // BN may pad the mapped region slightly; require the fixture range only.
    EXPECT_GE(view->GetEnd(), kDefaultBase + 0x200);
    ASSERT_TRUE(view->GetDefaultPlatform());
    EXPECT_EQ(view->GetDefaultPlatform()->GetName(), "windows-x86_64");
    closeView(view);
}

TEST(BnHarnessSmokeTest, FixtureBytes_MatchLayout) {
    BN_REQUIRE_CORE();
    Ref<BinaryView> view = makeView();
    ASSERT_TRUE(view);
    uint8_t b = 0;
    // func_ret: c3
    ASSERT_EQ(view->Read(&b, kDefaultBase + kOffFuncRet, 1), 1u);
    EXPECT_EQ(b, 0xc3);
    // func_equate: b8 (mov eax, imm32)
    ASSERT_EQ(view->Read(&b, kDefaultBase + kOffFuncEquate, 1), 1u);
    EXPECT_EQ(b, 0xb8);
    // data_int: 500 little-endian
    uint32_t v = 0;
    ASSERT_EQ(view->Read(&v, kDefaultBase + kOffDataInt, 4), 4u);
    EXPECT_EQ(v, 500u);
    closeView(view);
}

TEST(BnHarnessSmokeTest, RebasedLoad_ShiftsAddresses) {
    BN_REQUIRE_CORE();
    Ref<BinaryView> view = makeViewAt(0x140000000);
    ASSERT_TRUE(view);
    EXPECT_EQ(view->GetStart(), 0x140000000u);
    uint8_t b = 0;
    ASSERT_EQ(view->Read(&b, 0x140000000u + kOffFuncRet, 1), 1u);
    EXPECT_EQ(b, 0xc3);
    closeView(view);
}

TEST(BnHarnessSmokeTest, CreateFunction_Works) {
    BN_REQUIRE_CORE();
    Ref<BinaryView> view = makeView();
    ASSERT_TRUE(view);
    view->CreateUserFunction(view->GetDefaultPlatform(),
                             kDefaultBase + kOffFuncRet);
    view->UpdateAnalysisAndWait();
    Ref<Function> func =
        view->GetAnalysisFunction(view->GetDefaultPlatform(),
                                  kDefaultBase + kOffFuncRet);
    ASSERT_TRUE(func);
    EXPECT_EQ(func->GetStart(), kDefaultBase + kOffFuncRet);
    closeView(view);
}

TEST(BnHarnessSmokeTest, BndbSaveReopen_PreservesSymbol) {
    BN_REQUIRE_CORE();
    Ref<BinaryView> view = makeView();
    ASSERT_TRUE(view);
    const uint64_t va = kDefaultBase + kOffFuncRet;
    view->DefineUserSymbol(new Symbol(FunctionSymbol, "smoke_func", va));

    std::string bndb = testDataDir() + "/tmp_smoke.bndb";
    Ref<BinaryView> reopened = saveAndReopen(view, bndb);
    ASSERT_TRUE(reopened) << "CreateDatabase/Load round trip failed";

    Ref<Symbol> sym = reopened->GetSymbolByAddress(va);
    ASSERT_TRUE(sym);
    EXPECT_EQ(sym->GetShortName(), "smoke_func");
    EXPECT_EQ(reopened->GetStart(), kDefaultBase);
    closeView(reopened);
    std::remove(bndb.c_str());
}
