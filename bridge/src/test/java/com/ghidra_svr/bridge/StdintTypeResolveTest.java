package com.ghidra_svr.bridge;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression: Binary Ninja types use the stdint.h spelling (int32_t, uint8_t, …)
 * which Ghidra's built-ins do not expose.  Without normalization,
 * {@link ProgramApplier#resolveDataType} returns null for them, so any typedef /
 * struct member / parameter typed that way was silently dropped on check-in.
 */
class StdintTypeResolveTest extends ProgramTestBase {

    @Test
    void stdintNames_resolveToGhidraBuiltins() throws Exception {
        ProgramDB p = newProgram();
        DataTypeManager dtm = p.getDataTypeManager();

        // name -> expected (Ghidra built-in name, length)
        Object[][] cases = {
            {"int8_t",   "sbyte",     1}, {"uint8_t",  "byte",      1},
            {"int16_t",  "short",     2}, {"uint16_t", "ushort",    2},
            {"int32_t",  "int",       4}, {"uint32_t", "uint",      4},
            {"int64_t",  "longlong",  8}, {"uint64_t", "ulonglong", 8},
        };
        for (Object[] c : cases) {
            String in = (String) c[0];
            DataType dt = ProgramApplier.resolveDataType(dtm, in, 0);
            assertNotNull(dt, in + " should resolve");
            assertEquals(c[1], dt.getName(), in + " maps to the wrong type");
            assertEquals((int) (Integer) c[2], dt.getLength(), in + " has the wrong width");
        }
    }

    @Test
    void stdintPointer_resolves() throws Exception {
        ProgramDB p = newProgram();
        DataType dt = ProgramApplier.resolveDataType(p.getDataTypeManager(), "uint32_t *", 0);
        assertNotNull(dt, "pointer to a stdint type should resolve");
        assertEquals(p.getDefaultPointerSize(), dt.getLength());
    }

    @Test
    void plainGhidraNames_stillResolve() throws Exception {
        ProgramDB p = newProgram();
        DataTypeManager dtm = p.getDataTypeManager();
        assertNotNull(ProgramApplier.resolveDataType(dtm, "int", 0));
        assertNotNull(ProgramApplier.resolveDataType(dtm, "char", 0));
    }
}
