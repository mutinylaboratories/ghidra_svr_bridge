// GhidraConnectionStateTest.cpp
// Tests for the GhidraConnection check-in state machine:
//   storeCheckinState / hasCheckinState / isCheckinItem / clearCheckinState
//
// These methods are pure in-memory (no network, no BN API calls) and form
// the backbone of the "does the UI know a checkout is active?" logic.

#include <gtest/gtest.h>
#include "GhidraConnection.h"

// ---------------------------------------------------------------------------
// Fixture: always clear state before and after each test so the singleton
// doesn't carry leftover data between test cases.
// ---------------------------------------------------------------------------

class GhidraConnectionStateTest : public ::testing::Test {
protected:
    void SetUp()    override { GhidraConnection::instance().clearCheckinState(); }
    void TearDown() override { GhidraConnection::instance().clearCheckinState(); }

    // Shorthand: store state for a single item with a single tracked address.
    void storeSimple(const std::string& repo,
                     const std::string& folder,
                     const std::string& item,
                     uint64_t addr = 0x1000,
                     int64_t  key  = 42) {
        GhidraConnection::instance().storeCheckinState(
            {{addr, key}},             // addrToKey
            {{addr, "original_name"}}, // addrToOriginalName
            {},                        // addrToCommentKey
            {},                        // addrToOriginalComment
            {},                        // addrToOriginalFuncComment
            {},                        // addrToCommentField
            {},                        // ghidraDataTypes
            {},                        // parameters
            {},                        // bookmarks
            {},                        // dataItems
            {},                        // equates
            {},                        // funcSigs
            0x400000,                  // imageBase
            repo, folder, item);
    }
};

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, InitiallyNoCheckinState) {
    EXPECT_FALSE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, InitiallyEmptyCoordinates) {
    EXPECT_EQ(GhidraConnection::instance().checkinRepo(),   "");
    EXPECT_EQ(GhidraConnection::instance().checkinFolder(), "");
    EXPECT_EQ(GhidraConnection::instance().checkinItem(),   "");
}

// ---------------------------------------------------------------------------
// storeCheckinState → hasCheckinState / checkinRepo/Folder/Item
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, Store_SetsHasState) {
    storeSimple("myrepo", "/binaries", "ls");
    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, Store_SetsCoordinates) {
    storeSimple("repo1", "/folder1", "item1");
    EXPECT_EQ(GhidraConnection::instance().checkinRepo(),   "repo1");
    EXPECT_EQ(GhidraConnection::instance().checkinFolder(), "/folder1");
    EXPECT_EQ(GhidraConnection::instance().checkinItem(),   "item1");
}

TEST_F(GhidraConnectionStateTest, Store_EmptyMaps_StillSetsState) {
    // Storing with empty maps is valid (e.g. a DB with no user-renamed symbols).
    GhidraConnection::instance().storeCheckinState(
        {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 0, "r", "/", "i");
    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, Store_OverwritesPreviousState) {
    storeSimple("repo1", "/", "itemA");
    storeSimple("repo2", "/sub", "itemB");

    EXPECT_EQ(GhidraConnection::instance().checkinRepo(),   "repo2");
    EXPECT_EQ(GhidraConnection::instance().checkinFolder(), "/sub");
    EXPECT_EQ(GhidraConnection::instance().checkinItem(),   "itemB");
}

TEST_F(GhidraConnectionStateTest, Store_MultipleAddresses) {
    GhidraConnection::instance().storeCheckinState(
        {{0x1000, 1}, {0x2000, 2}, {0x3000, 3}},
        {{0x1000, "fn1"}, {0x2000, "fn2"}, {0x3000, "fn3"}},
        {}, {}, {}, {}, {}, {}, {}, {}, {}, {},
        0x400000, "r", "/", "i");
    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
}

// ---------------------------------------------------------------------------
// isCheckinItem
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, IsCheckinItem_MatchesExact) {
    storeSimple("myrepo", "/dir", "mybinary");
    EXPECT_TRUE(
        GhidraConnection::instance().isCheckinItem("myrepo", "/dir", "mybinary"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_WrongRepo) {
    storeSimple("repo1", "/", "item");
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo2", "/", "item"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_WrongFolder) {
    storeSimple("repo", "/a", "item");
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo", "/b", "item"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_WrongItem) {
    storeSimple("repo", "/", "item1");
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo", "/", "item2"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_AllWrong) {
    storeSimple("repo1", "/dir1", "item1");
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo2", "/dir2", "item2"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_CaseSensitive) {
    storeSimple("Repo", "/Folder", "Item");
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo", "/folder", "item"));
}

TEST_F(GhidraConnectionStateTest, IsCheckinItem_WhenNoStateStored) {
    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("any", "/", "item"));
}

// ---------------------------------------------------------------------------
// clearCheckinState
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, Clear_RemovesHasState) {
    storeSimple("r", "/", "i");
    ASSERT_TRUE(GhidraConnection::instance().hasCheckinState());

    GhidraConnection::instance().clearCheckinState();
    EXPECT_FALSE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, Clear_ResetsCoordinates) {
    storeSimple("repo", "/folder", "item");
    GhidraConnection::instance().clearCheckinState();

    EXPECT_EQ(GhidraConnection::instance().checkinRepo(),   "");
    EXPECT_EQ(GhidraConnection::instance().checkinFolder(), "");
    EXPECT_EQ(GhidraConnection::instance().checkinItem(),   "");
}

TEST_F(GhidraConnectionStateTest, Clear_ThenStoreAgain_Works) {
    storeSimple("repo1", "/", "item1");
    GhidraConnection::instance().clearCheckinState();
    storeSimple("repo2", "/sub", "item2");

    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
    EXPECT_EQ(GhidraConnection::instance().checkinItem(), "item2");
}

TEST_F(GhidraConnectionStateTest, Clear_WhenNoState_IsNoOp) {
    EXPECT_NO_THROW(GhidraConnection::instance().clearCheckinState());
    EXPECT_FALSE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, Clear_MakesIsCheckinItemFalse) {
    storeSimple("repo", "/", "item");
    GhidraConnection::instance().clearCheckinState();

    EXPECT_FALSE(
        GhidraConnection::instance().isCheckinItem("repo", "/", "item"));
}

// ---------------------------------------------------------------------------
// Local variable entries (isParam=false) are stored in the parameter baseline
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, LocalVar_StoredInBaseline_HasState) {
    // Locals are stored the same way as params; storeCheckinState still sets m_checkinItem.
    GhidraParameter local;
    local.key      = 77;
    local.funcAddr = 0x401000;
    local.name     = "local_buf";
    local.isParam  = false;
    local.ordinal  = -8;  // stack offset -8 (stored as int)
    local.typeName = "char";
    local.typeId   = -1;

    GhidraConnection::instance().storeCheckinState(
        {{0x401000, 77}},
        {{0x401000, "func"}},
        {}, {}, {}, {},
        {},             // ghidraDataTypes
        {local},        // parameters (contains our local)
        {}, {}, {}, {},
        0x400000,
        "repo", "/", "item");

    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
}

TEST_F(GhidraConnectionStateTest, LocalVar_ClearedByRestore) {
    GhidraParameter local;
    local.key = 77; local.funcAddr = 0x401000;
    local.name = "buf"; local.isParam = false; local.ordinal = -8;

    GhidraConnection::instance().storeCheckinState(
        {}, {}, {}, {}, {}, {},
        {}, {local}, {}, {}, {}, {},
        0x400000, "r", "/", "i");

    ASSERT_TRUE(GhidraConnection::instance().hasCheckinState());
    GhidraConnection::instance().clearCheckinState();
    EXPECT_FALSE(GhidraConnection::instance().hasCheckinState());
}

// ---------------------------------------------------------------------------
// Image base is stored separately from item coordinates
// ---------------------------------------------------------------------------

TEST_F(GhidraConnectionStateTest, Store_WithDifferentImageBases) {
    // Verify that different image bases don't interfere with state lookup.
    GhidraConnection::instance().storeCheckinState(
        {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 0x00400000, "r", "/", "i");
    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());

    GhidraConnection::instance().clearCheckinState();
    GhidraConnection::instance().storeCheckinState(
        {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, 0x100000000ULL, "r", "/", "i");
    EXPECT_TRUE(GhidraConnection::instance().hasCheckinState());
}
