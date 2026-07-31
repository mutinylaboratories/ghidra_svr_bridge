package com.ghidra_svr.bridge;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.database.ProgramDB;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tier-3 cross-database parity, Ghidra side.
 *
 * Consumes the same golden fixtures as the C++ CanonicalParityTest
 * (testdata/parity/fixtures). Import direction: golden →
 * CanonicalProgramLoader → DatabaseExporter re-export must equal the golden.
 * Checkin direction: baseline → ProgramApplier applies expected-preview.json →
 * re-export must equal expected-after.json. Together with the C++ side this
 * proves .bndb and Ghidra DB store the same compatible data (RULES.md).
 */
@Tag("parity")
class CanonicalParityTest extends ProgramTestBase {

    private static Path fixtures() {
        String dir = System.getProperty("parity.fixtures");
        assertNotNull(dir, "parity.fixtures system property not set (build.gradle passes it)");
        return Paths.get(dir, "fixtures");
    }

    private static JsonObject loadGolden(String relPath) throws Exception {
        String text = Files.readString(fixtures().resolve(relPath));
        JsonObject o = JsonParser.parseString(text).getAsJsonObject();
        o.remove("_comment");
        return o;
    }

    private static void assertNoIssues(List<String> issues, String context) {
        assertTrue(issues.isEmpty(),
            context + " parity issues:\n  " + String.join("\n  ", issues));
    }

    // -----------------------------------------------------------------------
    // Import direction
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("import: golden full_db loads and re-exports identically")
    void importGolden_reexportMatchesGolden() throws Exception {
        JsonObject golden = loadGolden("import/full_db.json");
        ProgramDB p = newProgram();
        CanonicalProgramLoader loader = new CanonicalProgramLoader();
        withTx(p, "load golden", () -> {
            try { loader.load(p, golden); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        JsonObject export = DatabaseExporter.exportFromHandle(p.getDBHandle());
        assertNoIssues(CanonicalAssert.compare(golden, export), "import full_db");
    }

    @Test
    @DisplayName("oracle: a mutated golden is detected (comparator bites)")
    void mutatedGolden_isDetected() throws Exception {
        JsonObject golden = loadGolden("import/full_db.json");
        ProgramDB p = newProgram();
        CanonicalProgramLoader loader = new CanonicalProgramLoader();
        withTx(p, "load golden", () -> {
            try { loader.load(p, golden); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        JsonObject mutated = golden.deepCopy();
        mutated.getAsJsonArray("symbols").get(0).getAsJsonObject()
               .addProperty("name", "wrong_name");

        JsonObject export = DatabaseExporter.exportFromHandle(p.getDBHandle());
        assertFalse(CanonicalAssert.compare(mutated, export).isEmpty(),
            "comparator failed to flag a mutated golden symbol name");
    }

    // -----------------------------------------------------------------------
    // Checkin direction
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("checkin: applying expected-preview yields expected-after")
    void checkinBasic_applyPreview_matchesExpectedAfter() throws Exception {
        JsonObject baseline = loadGolden("checkin/basic/baseline.json");
        JsonObject previewGolden = loadGolden("checkin/basic/expected-preview.json");
        JsonObject expectedAfter = loadGolden("checkin/basic/expected-after.json");

        ProgramDB p = newProgram();
        CanonicalProgramLoader loader = new CanonicalProgramLoader();
        withTx(p, "load baseline", () -> {
            try { loader.load(p, baseline); }
            catch (Exception e) { throw new RuntimeException(e); }
        });

        // Golden keys/ids are the baseline document's identity — rewrite them
        // to the ids this fresh database actually assigned, exactly like a
        // real checkout/checkin cycle where the preview keys come from the
        // exported DB itself.
        JsonObject preview = loader.remapPreview(previewGolden);

        withTx(p, "apply preview", () -> {
            ProgramApplier.applyDataTypes(p, preview.getAsJsonArray("data_type_changes"));
            ProgramApplier.applySymbols(p, preview.getAsJsonArray("symbols"));
            ProgramApplier.applyComments(p, preview.getAsJsonArray("comments"));
            ProgramApplier.applyEquateRenames(p, preview.getAsJsonArray("equate_renames"));
            ProgramApplier.applyEquateRefAdds(p, preview.getAsJsonArray("equate_ref_adds"));
            ProgramApplier.applyBookmarks(p, preview.getAsJsonArray("bookmark_changes"));
            ProgramApplier.applyParameters(p, preview.getAsJsonArray("param_renames"));
            ProgramApplier.applyDataItems(p, preview.getAsJsonArray("data_item_changes"));
            ProgramApplier.applyFuncSigs(p, preview.getAsJsonArray("func_sig_changes"));
        });

        JsonObject export = DatabaseExporter.exportFromHandle(p.getDBHandle());
        assertNoIssues(CanonicalAssert.compare(expectedAfter, export), "checkin basic");
    }
}
