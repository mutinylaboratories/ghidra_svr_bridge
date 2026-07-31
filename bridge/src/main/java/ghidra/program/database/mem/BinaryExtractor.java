package ghidra.program.database.mem;

import db.DBHandle;

import java.util.ArrayList;
import java.util.List;

/**
 * Extracts the original file bytes from a Ghidra program database.
 *
 * Placed in package {@code ghidra.program.database.mem} for package-private
 * access to {@code FileBytesAdapterV0}, avoiding the need for OpenMode which
 * is not on the Ghidra server runtime classpath.
 */
public class BinaryExtractor {

    private static final long MAX_BYTES = 512L * 1024 * 1024; // 512 MB hard cap

    public static class ExtractedFile {
        public final String filename;
        public final byte[] bytes;

        public ExtractedFile(String filename, byte[] bytes) {
            this.filename = filename;
            this.bytes    = bytes;
        }
    }

    public static List<ExtractedFile> extract(DBHandle db) throws Exception {
        // Use the V0 concrete adapter directly — no OpenMode dependency.
        FileBytesAdapterV0 adapter = new FileBytesAdapterV0(db, /*create=*/false);
        List<FileBytes> all = adapter.getAllFileBytes();
        List<ExtractedFile> result = new ArrayList<>(all.size());

        for (FileBytes fb : all) {
            long size = fb.getSize();
            String name = fb.getFilename();
            if (size <= 0) {
                System.err.println("[ghidra-bridge] skip empty FileBytes: " + name);
                continue;
            }
            if (size > MAX_BYTES) {
                System.err.println("[ghidra-bridge] skip FileBytes too large (" + size + "): " + name);
                continue;
            }
            byte[] bytes = new byte[(int) size];
            int read = fb.getOriginalBytes(0, bytes);
            System.err.println("[ghidra-bridge] extracted " + read + "/" + size + " bytes: " + name);
            result.add(new ExtractedFile(name, bytes));
        }
        return result;
    }
}
