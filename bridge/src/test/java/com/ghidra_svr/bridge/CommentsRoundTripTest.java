package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the five Ghidra comment kinds: EOL, PRE, POST, PLATE,
 * REPEATABLE.  Validates that ProgramApplier.applyComments maps each JSON field
 * to the correct CommentType constant.
 */
class CommentsRoundTripTest extends ProgramTestBase {

    @Test
    @DisplayName("import: each comment field maps to the right CommentType constant")
    void eachCommentFieldRoutedCorrectly() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x100;

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("va",    "0x" + Long.toHexString(va));
        c.addProperty("eol",   "eol text");
        c.addProperty("pre",   "pre text");
        c.addProperty("post",  "post text");
        c.addProperty("plate", "plate text");
        c.addProperty("rep",   "rep text");
        arr.add(c);

        withTx(p, "comments", () -> ProgramApplier.applyComments(p, arr));

        Listing l = p.getListing();
        assertEquals("eol text",   l.getComment(CommentType.EOL,        addr(p, va)));
        assertEquals("pre text",   l.getComment(CommentType.PRE,        addr(p, va)));
        assertEquals("post text",  l.getComment(CommentType.POST,       addr(p, va)));
        assertEquals("plate text", l.getComment(CommentType.PLATE,      addr(p, va)));
        assertEquals("rep text",   l.getComment(CommentType.REPEATABLE, addr(p, va)));
    }

    @Test
    @DisplayName("import: omitting a field leaves the existing comment untouched")
    void omittedFieldIsNotCleared() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x200;

        // Seed both an EOL and a PRE
        withTx(p, "seed", () -> {
            Listing l = p.getListing();
            l.setComment(addr(p, va), CommentType.EOL, "original eol");
            l.setComment(addr(p, va), CommentType.PRE, "original pre");
        });

        // Send a JSON that only updates EOL — PRE should remain
        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("va",  "0x" + Long.toHexString(va));
        c.addProperty("eol", "new eol");
        arr.add(c);
        withTx(p, "partial update", () -> ProgramApplier.applyComments(p, arr));

        assertEquals("new eol",      p.getListing().getComment(CommentType.EOL, addr(p, va)));
        assertEquals("original pre", p.getListing().getComment(CommentType.PRE, addr(p, va)));
    }

    @Test
    @DisplayName("import: empty string clears the comment")
    void emptyStringClears() throws Exception {
        ProgramDB p = newProgram();
        long va = memoryStart() + 0x300;
        withTx(p, "seed", () ->
            p.getListing().setComment(addr(p, va), CommentType.EOL, "will be cleared"));

        JsonArray arr = new JsonArray();
        JsonObject c = new JsonObject();
        c.addProperty("va",  "0x" + Long.toHexString(va));
        c.addProperty("eol", "");
        arr.add(c);
        withTx(p, "clear", () -> ProgramApplier.applyComments(p, arr));

        assertNull(p.getListing().getComment(CommentType.EOL, addr(p, va)));
    }
}
