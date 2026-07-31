// CheckinPreviewTest.cpp
// Tests for GhidraCheckinPreview — the struct that carries pending check-in
// changes (symbol renames + comment edits) before they are sent to the server.

#include <gtest/gtest.h>
#include "GhidraConnection.h"

// ---------------------------------------------------------------------------
// GhidraCheckinPreview::empty()
// ---------------------------------------------------------------------------

TEST(CheckinPreviewTest, DefaultConstructed_IsEmpty) {
    GhidraCheckinPreview preview;
    EXPECT_TRUE(preview.empty());
}

TEST(CheckinPreviewTest, AddRename_NotEmpty) {
    GhidraCheckinPreview preview;
    preview.renames.push_back({42, 0x1000, "original_name", "new_name"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, AddComment_NotEmpty) {
    GhidraCheckinPreview preview;
    preview.comments.push_back({0x1000, "my comment text", "0x200000001000"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, AddBoth_NotEmpty) {
    GhidraCheckinPreview preview;
    preview.renames.push_back({42, 0x1000, "old", "new"});
    preview.comments.push_back({0x2000, "note", "0x200000002000"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, ClearRenames_EmptyAgain) {
    GhidraCheckinPreview preview;
    preview.renames.push_back({1, 0x100, "a", "b"});
    ASSERT_FALSE(preview.empty());
    preview.renames.clear();
    EXPECT_TRUE(preview.empty());
}

TEST(CheckinPreviewTest, ClearComments_EmptyAgain) {
    GhidraCheckinPreview preview;
    preview.comments.push_back({0x200, "x", "0x0"});
    ASSERT_FALSE(preview.empty());
    preview.comments.clear();
    EXPECT_TRUE(preview.empty());
}

TEST(CheckinPreviewTest, MultipleRenames_CountCorrect) {
    GhidraCheckinPreview preview;
    for (int i = 0; i < 10; ++i)
        preview.renames.push_back({(int64_t)i, (uint64_t)(i * 0x1000),
                                    "old_" + std::to_string(i),
                                    "new_" + std::to_string(i)});
    EXPECT_EQ(preview.renames.size(), 10u);
    EXPECT_FALSE(preview.empty());
}

// ---------------------------------------------------------------------------
// Struct field sanity
// ---------------------------------------------------------------------------

TEST(CheckinPreviewTest, SymbolRename_FieldsStoredCorrectly) {
    GhidraCheckinPreview::SymbolRename r{42, 0xDEADBEEF, "original", "renamed"};
    EXPECT_EQ(r.key,          42);
    EXPECT_EQ(r.addr,         0xDEADBEEFu);
    EXPECT_EQ(r.originalName, "original");
    EXPECT_EQ(r.newName,      "renamed");
}

TEST(CheckinPreviewTest, CommentChange_FieldsStoredCorrectly) {
    GhidraCheckinPreview::CommentChange c{0x1234, "hello world", "0xABCD"};
    EXPECT_EQ(c.addr,       0x1234u);
    EXPECT_EQ(c.text,       "hello world");
    EXPECT_EQ(c.encodedKey, "0xABCD");
}

TEST(CheckinPreviewTest, EquateRename_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.equateRenames.push_back({42, "NEW_NAME"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, BookmarkChange_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.bookmarkChanges.push_back({"add", "Note", 0x1000, "Review", "Check this"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, ParamRename_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.paramRenames.push_back({100, "new_param"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, AllNewFields_StillEmptyWhenOnlyOldFieldsCleared) {
    GhidraCheckinPreview preview;
    preview.renames.push_back({1, 0x1000, "a", "b"});
    preview.renames.clear();
    // equateRenames etc. are also empty → should be empty
    EXPECT_TRUE(preview.empty());
}

TEST(CheckinPreviewTest, DataTypeChange_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::DataTypeChange::Member m{"field1", 0, 4, "int"};
    GhidraCheckinPreview::DataTypeChange dt{"add", "struct", "MyStruct", 0, 8, "", {m}, {}};
    preview.dataTypeChanges.push_back(dt);
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, DataItemChange_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.dataItemChanges.push_back({"add", 0x1000, "MyStruct"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, FuncSigChange_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.funcSigChanges.push_back({42, "__stdcall", "int"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, ParamRename_WithType_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.paramRenames.push_back({100, "new_param", "MyStruct *"});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, TypedefChange_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::DataTypeChange dt;
    dt.op = "add"; dt.kind = "typedef"; dt.name = "HANDLE"; dt.underlyingTypeName = "void *";
    preview.dataTypeChanges.push_back(dt);
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, DataItemDelete_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    preview.dataItemChanges.push_back({"delete", 0x2000, ""});
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, DataItemDelete_OpFieldCorrect) {
    GhidraCheckinPreview::DataItemChange del{"delete", 0x4000, ""};
    EXPECT_EQ(del.op,   "delete");
    EXPECT_EQ(del.addr, 0x4000u);
    EXPECT_TRUE(del.typeName.empty());
}

TEST(CheckinPreviewTest, DataTypeDelete_MakesPreviewNotEmpty) {
    GhidraCheckinPreview preview;
    GhidraCheckinPreview::DataTypeChange del;
    del.op = "delete"; del.kind = "struct"; del.name = "OldStruct"; del.ghidraId = 7;
    preview.dataTypeChanges.push_back(del);
    EXPECT_FALSE(preview.empty());
}

TEST(CheckinPreviewTest, DataTypeDelete_OpFieldCorrect) {
    GhidraCheckinPreview::DataTypeChange del;
    del.op = "delete"; del.kind = "enum"; del.name = "OldEnum"; del.ghidraId = 42;
    EXPECT_EQ(del.op,       "delete");
    EXPECT_EQ(del.kind,     "enum");
    EXPECT_EQ(del.name,     "OldEnum");
    EXPECT_EQ(del.ghidraId, int64_t{42});
}
