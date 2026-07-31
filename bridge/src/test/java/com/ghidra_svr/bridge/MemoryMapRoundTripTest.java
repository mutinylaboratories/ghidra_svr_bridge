package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.database.ProgramDB;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for the memory-map read path: build a real ProgramDB with
 * memory blocks via ProgramBuilder, export them through
 * {@link DatabaseExporter#exportMemoryBlocks(ProgramDB)}, and assert the JSON
 * carries the bounds / permissions / initialized flags the BN side needs to
 * recreate sections (and segments for unmapped ranges).
 *
 * Reads go through the high-level {@code Memory} API rather than raw tables —
 * see DatabaseExporter.exportMemoryBlocks for the rationale.
 */
class MemoryMapRoundTripTest extends ProgramTestBase {

    @Test
    void textBlock_exportedWithBoundsAndPermissions() throws Exception {
        // newProgram() creates an initialized ".text" block at 0x00400000, size 0x10000.
        ProgramDB p = newProgram();

        JsonArray blocks = DatabaseExporter.exportMemoryBlocks(p);
        assertTrue(blocks.size() >= 1, "should export at least the .text block");

        JsonObject text = findBlock(blocks, ".text");
        assertNotNull(text, ".text block should be present in export");
        assertEquals("0x400000", text.get("addr").getAsString(), "block base VA");
        assertEquals("0x10000",  text.get("size").getAsString(), "block size");
        assertTrue(text.get("r").getAsBoolean(), "block should be readable");
        assertTrue(text.get("initialized").getAsBoolean(), "createMemory makes an initialized block");
        assertFalse(text.get("overlay").getAsBoolean(), "default-space block is not an overlay");
    }

    @Test
    void additionalInitializedBlock_appearsInExport() throws Exception {
        ProgramDB p = newProgram();
        builder().createMemory(".data", "0x500000", 0x1000, "data");

        JsonArray blocks = DatabaseExporter.exportMemoryBlocks(p);

        JsonObject data = findBlock(blocks, ".data");
        assertNotNull(data, ".data block should be present");
        assertEquals("0x500000", data.get("addr").getAsString());
        assertEquals("0x1000",   data.get("size").getAsString());
    }

    @Test
    void uninitializedBlock_flaggedUninitialized() throws Exception {
        // Mirrors a Ghidra .bss / EXTERNAL region BN's loader may not have mapped:
        // the BN side adds a zero-filled segment for these before sectioning.
        ProgramDB p = newProgram();
        builder().createUninitializedMemory(".bss", "0x600000", 0x800);

        JsonArray blocks = DatabaseExporter.exportMemoryBlocks(p);

        JsonObject bss = findBlock(blocks, ".bss");
        assertNotNull(bss, ".bss block should be present");
        assertEquals("0x600000", bss.get("addr").getAsString());
        assertFalse(bss.get("initialized").getAsBoolean(),
            "an uninitialized block must be flagged so BN maps it zero-filled");
    }

    private static JsonObject findBlock(JsonArray arr, String name) {
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            if (name.equals(o.get("name").getAsString())) return o;
        }
        return null;
    }
}
