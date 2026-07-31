package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for bookmarks.  Verifies add/update/delete and that the
 * category and comment strings survive the round trip.
 */
class BookmarksRoundTripTest extends ProgramTestBase {

    private static JsonObject bmk(String op, String type, long va,
                                  String category, String comment) {
        JsonObject o = new JsonObject();
        o.addProperty("op", op);
        o.addProperty("type", type);
        o.addProperty("addr", "0x" + Long.toHexString(va));
        o.addProperty("category", category);
        o.addProperty("comment", comment);
        return o;
    }

    @Test
    @DisplayName("import add bookmark: shows up via BookmarkManager.getBookmarks")
    void addBookmark_isVisible() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x100;

        JsonArray arr = new JsonArray();
        arr.add(bmk("add", "Note", va, "Important", "needs review"));
        withTx(p, "add bookmark", () -> ProgramApplier.applyBookmarks(p, arr));

        BookmarkManager bm = p.getBookmarkManager();
        Bookmark[] found = bm.getBookmarks(addr(p, va), "Note");
        assertEquals(1, found.length, "exactly one bookmark expected");
        assertEquals("Important",     found[0].getCategory());
        assertEquals("needs review",  found[0].getComment());
    }

    @Test
    @DisplayName("import delete bookmark: removes it from the same address")
    void deleteBookmark_removes() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x200;

        // Seed
        withTx(p, "seed", () ->
            p.getBookmarkManager().setBookmark(addr(p, va), "Note", "cat", "comment"));

        JsonArray arr = new JsonArray();
        arr.add(bmk("delete", "Note", va, "", ""));
        withTx(p, "delete", () -> ProgramApplier.applyBookmarks(p, arr));

        Bookmark[] found = p.getBookmarkManager().getBookmarks(addr(p, va), "Note");
        assertEquals(0, found.length, "bookmark should be deleted");
    }

    @Test
    @DisplayName("import: setBookmark on existing addr+type replaces comment in place")
    void resetBookmark_updatesCommentInPlace() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x300;

        withTx(p, "seed", () ->
            p.getBookmarkManager().setBookmark(addr(p, va), "Note", "cat", "old"));

        JsonArray arr = new JsonArray();
        arr.add(bmk("add", "Note", va, "cat", "new"));
        withTx(p, "update", () -> ProgramApplier.applyBookmarks(p, arr));

        Bookmark[] found = p.getBookmarkManager().getBookmarks(addr(p, va), "Note");
        assertEquals(1, found.length, "still expected exactly one bookmark");
        assertEquals("new", found[0].getComment());
    }
}
