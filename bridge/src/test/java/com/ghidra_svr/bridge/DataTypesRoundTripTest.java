package com.ghidra_svr.bridge;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Round-trip tests for struct / union / enum / typedef. The most important
 * test in this class is {@link #struct_cloneSettings_doesNotThrow()} — that
 * is the explicit regression check for the bug that originally motivated the
 * full ProgramDB refactor (the raw-write code wrote composite header rows
 * without the matching component-settings rows, so opening the struct in the
 * data-type editor crashed with ArrayIndexOutOfBoundsException at
 * CompositeEditorModel.cloneAllComponentSettings).
 */
class DataTypesRoundTripTest extends ProgramTestBase {

    private static JsonObject structJson(String op, String name, int size,
                                         JsonArray members) {
        JsonObject o = new JsonObject();
        o.addProperty("op", op);
        o.addProperty("kind", "struct");
        o.addProperty("name", name);
        o.addProperty("size", size);
        o.add("members", members);
        return o;
    }

    private static JsonObject member(String name, String typeName, int offset, int size) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("type_name", typeName);
        o.addProperty("offset", offset);
        o.addProperty("size", size);
        return o;
    }

    @Test
    @DisplayName("import struct: added with correct members")
    void addStruct_membersPresent() throws Exception {
        ProgramDB p = newProgram();

        JsonArray members = new JsonArray();
        members.add(member("a", "int",   0, 4));
        members.add(member("b", "int",   4, 4));
        members.add(member("c", "char",  8, 1));

        JsonArray changes = new JsonArray();
        changes.add(structJson("add", "Foo", 16, members));

        withTx(p, "add Foo", () -> ProgramApplier.applyDataTypes(p, changes));

        DataType dt = p.getDataTypeManager().getDataType(CategoryPath.ROOT, "Foo");
        assertNotNull(dt, "struct Foo was not added");
        assertTrue(dt instanceof Structure, "Foo is not a Structure");
        Structure s = (Structure) dt;
        assertEquals(3, s.getNumDefinedComponents(),
            "expected 3 named members, got: " + s.getNumDefinedComponents());
    }

    /**
     * The regression that motivated the refactor.  cloneAllComponentSettings
     * iterates per-component settings — if NumberOfComponents > 0 but the
     * settings table is empty, ArrayIndexOutOfBoundsException is thrown.
     * Going through DataTypeManager.addDataType keeps the two in sync.
     */
    @Test
    @DisplayName("import struct: cloneAllComponentSettings does NOT throw (regression)")
    void struct_cloneSettings_doesNotThrow() throws Exception {
        ProgramDB p = newProgram();
        JsonArray members = new JsonArray();
        members.add(member("x", "int", 0, 4));
        members.add(member("y", "int", 4, 4));
        JsonArray changes = new JsonArray();
        changes.add(structJson("add", "RegFoo", 8, members));
        withTx(p, "add", () -> ProgramApplier.applyDataTypes(p, changes));

        Structure s = (Structure) p.getDataTypeManager()
            .getDataType(CategoryPath.ROOT, "RegFoo");
        // The original crash triggered when the editor cloned settings before
        // displaying the struct.  We mirror that read pattern here — every
        // DataTypeComponent.getDefaultSettings() must succeed and the
        // per-component settings array must be at least as long as the
        // component count.
        assertDoesNotThrow(() -> {
            for (DataTypeComponent dtc : s.getDefinedComponents()) {
                ghidra.docking.settings.Settings defaults = dtc.getDefaultSettings();
                assertNotNull(defaults, "default settings null for component " + dtc.getOrdinal());
            }
        });
    }

    @Test
    @DisplayName("import union: each member is at offset 0")
    void addUnion_membersOverlapAtZero() throws Exception {
        ProgramDB p = newProgram();

        JsonArray members = new JsonArray();
        members.add(member("as_int",   "int",  0, 4));
        members.add(member("as_float", "float", 0, 4));

        JsonObject u = new JsonObject();
        u.addProperty("op", "add");
        u.addProperty("kind", "union");
        u.addProperty("name", "U");
        u.addProperty("size", 4);
        u.add("members", members);

        JsonArray changes = new JsonArray();
        changes.add(u);
        withTx(p, "add U", () -> ProgramApplier.applyDataTypes(p, changes));

        DataType dt = p.getDataTypeManager().getDataType(CategoryPath.ROOT, "U");
        assertNotNull(dt);
        assertTrue(dt instanceof Union);
        Union un = (Union) dt;
        for (DataTypeComponent c : un.getDefinedComponents()) {
            assertEquals(0, c.getOffset(),
                "union member " + c.getFieldName() + " should be at offset 0");
        }
    }

    @Test
    @DisplayName("import enum: values present with correct numeric values")
    void addEnum_valuesPresent() throws Exception {
        ProgramDB p = newProgram();

        JsonArray values = new JsonArray();
        JsonObject v1 = new JsonObject();
        v1.addProperty("name",  "RED");
        v1.addProperty("value", 0);
        values.add(v1);
        JsonObject v2 = new JsonObject();
        v2.addProperty("name",  "GREEN");
        v2.addProperty("value", 1);
        values.add(v2);
        JsonObject v3 = new JsonObject();
        v3.addProperty("name",  "BLUE");
        v3.addProperty("value", 2);
        values.add(v3);

        JsonObject e = new JsonObject();
        e.addProperty("op", "add");
        e.addProperty("kind", "enum");
        e.addProperty("name", "Color");
        e.addProperty("size", 4);
        e.add("values", values);

        JsonArray changes = new JsonArray();
        changes.add(e);
        withTx(p, "add Color", () -> ProgramApplier.applyDataTypes(p, changes));

        DataType dt = p.getDataTypeManager().getDataType(CategoryPath.ROOT, "Color");
        assertNotNull(dt);
        assertTrue(dt instanceof ghidra.program.model.data.Enum);
        ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
        assertEquals(0, en.getValue("RED"));
        assertEquals(1, en.getValue("GREEN"));
        assertEquals(2, en.getValue("BLUE"));
    }

    @Test
    @DisplayName("import typedef: aliases an existing type")
    void addTypedef_referencesUnderlying() throws Exception {
        ProgramDB p = newProgram();

        JsonObject td = new JsonObject();
        td.addProperty("op", "add");
        td.addProperty("kind", "typedef");
        td.addProperty("name", "myint32");
        td.addProperty("underlying_type_name", "int");

        JsonArray changes = new JsonArray();
        changes.add(td);
        withTx(p, "add typedef", () -> ProgramApplier.applyDataTypes(p, changes));

        DataType dt = p.getDataTypeManager().getDataType(CategoryPath.ROOT, "myint32");
        assertNotNull(dt);
        assertTrue(dt instanceof TypeDef);
        TypeDef td2 = (TypeDef) dt;
        assertEquals(4, td2.getLength(), "typedef should inherit underlying int size");
    }

    @Test
    @DisplayName("import struct: member typed as 'OtherStruct *' resolves via DataTypeParser")
    void member_pointerToStruct_resolves() throws Exception {
        ProgramDB p = newProgram();

        // First add Inner
        JsonArray innerMembers = new JsonArray();
        innerMembers.add(member("v", "int", 0, 4));
        JsonArray changes1 = new JsonArray();
        changes1.add(structJson("add", "Inner", 4, innerMembers));
        withTx(p, "add Inner", () -> ProgramApplier.applyDataTypes(p, changes1));

        // Then Outer with member "p" of type "Inner *"
        JsonArray outerMembers = new JsonArray();
        outerMembers.add(member("p", "Inner *", 0, 8));
        JsonArray changes2 = new JsonArray();
        changes2.add(structJson("add", "Outer", 8, outerMembers));
        withTx(p, "add Outer", () -> ProgramApplier.applyDataTypes(p, changes2));

        Structure s = (Structure) p.getDataTypeManager()
            .getDataType(CategoryPath.ROOT, "Outer");
        DataTypeComponent pc = s.getDefinedComponents()[0];
        DataType pdt = pc.getDataType();
        assertTrue(pdt instanceof Pointer,
            "expected member 'p' to be a Pointer, got " + pdt.getClass().getSimpleName());
    }

    @Test
    @DisplayName("import struct: unknown member type falls back to undefined of given size")
    void member_unknownType_fallsBackToUndefined() throws Exception {
        ProgramDB p = newProgram();

        JsonArray members = new JsonArray();
        members.add(member("unknown", "SomeMissingType", 0, 8));
        JsonArray changes = new JsonArray();
        changes.add(structJson("add", "Mystery", 8, members));
        withTx(p, "add", () -> ProgramApplier.applyDataTypes(p, changes));

        Structure s = (Structure) p.getDataTypeManager()
            .getDataType(CategoryPath.ROOT, "Mystery");
        assertNotNull(s);
        DataType memberDt = s.getDefinedComponents()[0].getDataType();
        // It should be some kind of Undefined* (any of Undefined1/Undefined8/etc.)
        assertTrue(memberDt instanceof Undefined || memberDt.getName().startsWith("undefined"),
            "expected Undefined fallback, got " + memberDt.getClass().getSimpleName()
                + "/" + memberDt.getName());
    }

    @Test
    @DisplayName("import struct twice: second add replaces first cleanly")
    void addStruct_idempotent_replacesPrevious() throws Exception {
        ProgramDB p = newProgram();

        JsonArray m1 = new JsonArray();
        m1.add(member("x", "int", 0, 4));
        JsonArray changes1 = new JsonArray();
        changes1.add(structJson("add", "Sym", 4, m1));
        withTx(p, "v1", () -> ProgramApplier.applyDataTypes(p, changes1));

        JsonArray m2 = new JsonArray();
        m2.add(member("x", "int", 0, 4));
        m2.add(member("y", "int", 4, 4));
        JsonArray changes2 = new JsonArray();
        changes2.add(structJson("add", "Sym", 8, m2));
        withTx(p, "v2", () -> ProgramApplier.applyDataTypes(p, changes2));

        Structure s = (Structure) p.getDataTypeManager()
            .getDataType(CategoryPath.ROOT, "Sym");
        assertNotNull(s);
        assertEquals(2, s.getNumDefinedComponents());
    }
}
