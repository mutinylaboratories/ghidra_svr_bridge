package com.ghidra_svr.bridge;

import com.google.gson.*;
import ghidra.framework.remote.RepositoryChangeEvent;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Handles one TCP client (the Binary Ninja C++ plugin).
 *
 * Protocol: newline-delimited JSON in both directions.
 *
 * Every request carries an integer "id" and a string "op".  The bridge
 * always sends a response with the same "id".  Asynchronous events (pushed
 * by EventStreamers) carry an "event" key instead of "id".
 *
 * Request ops
 * -----------
 *  ping
 *  connect         host, port, user, password
 *  disconnect
 *  status
 *  list_repos
 *  open_repo       repo
 *  close_repo      repo
 *  list_items      repo, [folder="/"]
 *  get_subfolders  repo, [folder="/"]
 *  checkout        repo, [folder="/"], item, [type="NORMAL"], [project_path]
 *  terminate_checkout  repo, [folder="/"], item, checkout_id
 *  get_versions    repo, [folder="/"], item
 *  get_checkouts   repo, [folder="/"], item
 *  open_db         repo, [folder="/"], item, [version=-1]
 *  checkin         repo, [folder="/"], item, [comment], [symbols=[]], [comments=[]],
 *                  [equate_renames=[]], [bookmark_changes=[]], [param_renames=[]], [data_item_changes=[]]
 *  upload_binary   repo, [folder="/"], item, data(base64), [comment], [keep_checkout=false],
 *                  host, port, user, [password]
 *
 * Successful response shape
 * -------------------------
 *  { "id": <N>, "ok": true, ...extra fields... }
 *
 * Error response shape
 * --------------------
 *  { "id": <N>, "ok": false, "error": "<message>" }
 *
 * Async event shape
 * -----------------
 *  { "event": "repo_changed", "repo": "<name>",
 *    "type":  "<REP_*>",
 *    "parent_path": "...", "name": "...",
 *    "new_parent_path": "...", "new_name": "..." }
 */
public class BridgeConnection implements Runnable {

    private final Socket socket;
    private final String ghidraHome;
    private final GhidraSession session = new GhidraSession();
    private final Gson gson = new Gson();

    // Guarded by 'this' — both the request-handler thread and EventStreamer threads write here.
    private PrintWriter out;

    // EventStreamer per open repo.  Accessed only from the request-handler thread.
    private final Map<String, EventStreamer> streamers = new HashMap<>();

    public BridgeConnection(Socket socket, String ghidraHome) {
        this.socket     = socket;
        this.ghidraHome = ghidraHome != null ? ghidraHome : "";
    }

    // -------------------------------------------------------------------------
    // Main loop
    // -------------------------------------------------------------------------

    @Override
    public void run() {
        try (socket;
             var br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             var pw = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true)) {

            synchronized (this) { out = pw; }

            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) handleRequest(trimmed);
            }
        } catch (IOException e) {
            System.err.println("[ghidra-bridge] connection closed: " + e.getMessage());
        } finally {
            synchronized (this) { out = null; }
            stopAllStreamers();
            session.disconnect();
            System.err.println("[ghidra-bridge] connection handler exiting");
        }
    }

    // -------------------------------------------------------------------------
    // Thread-safe output
    // -------------------------------------------------------------------------

    private synchronized void writeLine(String json) {
        if (out != null) {
            out.println(json);
        }
    }

    // -------------------------------------------------------------------------
    // Dispatch
    // -------------------------------------------------------------------------

    private void handleRequest(String line) {
        JsonObject req;
        int id = -1;
        try {
            req = gson.fromJson(line, JsonObject.class);
            id  = req.has("id") ? req.get("id").getAsInt() : -1;
            String op = req.get("op").getAsString();

            switch (op) {
                case "ping":               respondOk(id); break;
                case "connect":            opConnect(id, req); break;
                case "disconnect":         opDisconnect(id); break;
                case "status":             opStatus(id); break;
                case "list_repos":         opListRepos(id); break;
                case "open_repo":          opOpenRepo(id, req); break;
                case "close_repo":         opCloseRepo(id, req); break;
                case "list_items":         opListItems(id, req); break;
                case "get_subfolders":     opGetSubfolders(id, req); break;
                case "checkout":           opCheckout(id, req); break;
                case "terminate_checkout": opTerminateCheckout(id, req); break;
                case "get_versions":       opGetVersions(id, req); break;
                case "get_checkouts":      opGetCheckouts(id, req); break;
                case "open_db":            opOpenDb(id, req); break;
                case "checkin":            opCheckin(id, req); break;
                case "download_binary":    opDownloadBinary(id, req); break;
                case "upload_binary":      opUploadBinary(id, req); break;
                case "delete_item":        opDeleteItem(id, req); break;
                default:                   respondError(id, "unknown op: " + op); break;
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            respondError(id, msg != null ? msg : e.getClass().getName());
        }
    }

    // -------------------------------------------------------------------------
    // Operation handlers
    // -------------------------------------------------------------------------

    private void opConnect(int id, JsonObject req) throws Exception {
        String host     = req.get("host").getAsString();
        int    port     = req.get("port").getAsInt();
        String user     = req.get("user").getAsString();
        String password = req.has("password") ? req.get("password").getAsString() : "";
        session.connect(host, port, user, password);
        JsonObject data = new JsonObject();
        data.addProperty("user", session.getConnectedUser());
        respondOk(id, data);
    }

    private void opDisconnect(int id) {
        stopAllStreamers();
        session.disconnect();
        respondOk(id);
    }

    private void opStatus(int id) {
        JsonObject data = new JsonObject();
        data.addProperty("connected", session.isConnected());
        data.addProperty("user", session.getConnectedUser());
        JsonArray repos = new JsonArray();
        session.getOpenRepos().forEach(repos::add);
        data.add("open_repos", repos);
        respondOk(id, data);
    }

    private void opListRepos(int id) throws Exception {
        String[] repos = session.listRepos();
        JsonObject data = new JsonObject();
        JsonArray arr = new JsonArray();
        for (String r : repos) arr.add(r);
        data.add("repos", arr);
        respondOk(id, data);
    }

    private void opOpenRepo(int id, JsonObject req) throws Exception {
        String name = req.get("repo").getAsString();
        session.openRepo(name);
        startStreamer(name);
        respondOk(id);
    }

    private void opCloseRepo(int id, JsonObject req) throws Exception {
        String name = req.get("repo").getAsString();
        stopStreamer(name);
        session.closeRepo(name);
        respondOk(id);
    }

    private void opListItems(int id, JsonObject req) throws Exception {
        String repo   = req.get("repo").getAsString();
        String folder = strOrDefault(req, "folder", "/");
        RepositoryItem[] items = session.listItems(repo, folder);
        JsonArray arr = new JsonArray();
        if (items != null) {
            for (RepositoryItem item : items) arr.add(itemToJson(item));
        }
        JsonObject data = new JsonObject();
        data.add("items", arr);
        data.addProperty("count", arr.size());
        System.err.println("[ghidra-bridge] list_items repo=" + repo + " folder=" + folder + " count=" + arr.size());
        respondOk(id, data);
    }

    private void opGetSubfolders(int id, JsonObject req) throws Exception {
        String repo   = req.get("repo").getAsString();
        String folder = strOrDefault(req, "folder", "/");
        String[] subs = session.getSubfolders(repo, folder);
        JsonArray arr = new JsonArray();
        if (subs != null) {
            for (String s : subs) arr.add(s);
        }
        JsonObject data = new JsonObject();
        data.add("subfolders", arr);
        data.addProperty("count", arr.size());
        System.err.println("[ghidra-bridge] get_subfolders repo=" + repo + " folder=" + folder + " count=" + arr.size());
        respondOk(id, data);
    }

    private void opCheckout(int id, JsonObject req) throws Exception {
        String repo        = req.get("repo").getAsString();
        String folder      = strOrDefault(req, "folder", "/");
        String item        = req.get("item").getAsString();
        String type        = strOrDefault(req, "type", "NORMAL");
        String projectPath = strOrDefault(req, "project_path",
                ItemCheckoutStatus.getProjectPath("binja-ghidra", false));
        ItemCheckoutStatus co = session.checkout(repo, folder, item, type, projectPath);
        JsonObject data = new JsonObject();
        data.add("checkout", checkoutToJson(co));
        respondOk(id, data);
    }

    private void opTerminateCheckout(int id, JsonObject req) throws Exception {
        String repo     = req.get("repo").getAsString();
        String folder   = strOrDefault(req, "folder", "/");
        String item     = req.get("item").getAsString();
        long   coId     = req.get("checkout_id").getAsLong();
        session.terminateCheckout(repo, folder, item, coId);
        respondOk(id);
    }

    private void opGetVersions(int id, JsonObject req) throws Exception {
        String repo   = req.get("repo").getAsString();
        String folder = strOrDefault(req, "folder", "/");
        String item   = req.get("item").getAsString();
        Version[] versions = session.getVersions(repo, folder, item);
        JsonArray arr = new JsonArray();
        for (Version v : versions) {
            JsonObject obj = new JsonObject();
            obj.addProperty("version", v.getVersion());
            obj.addProperty("time",    v.getCreateTime());
            obj.addProperty("user",    v.getUser());
            obj.addProperty("comment", v.getComment());
            arr.add(obj);
        }
        JsonObject data = new JsonObject();
        data.add("versions", arr);
        respondOk(id, data);
    }

    private void opGetCheckouts(int id, JsonObject req) throws Exception {
        String repo   = req.get("repo").getAsString();
        String folder = strOrDefault(req, "folder", "/");
        String item   = req.get("item").getAsString();
        ItemCheckoutStatus[] checkouts = session.getCheckouts(repo, folder, item);
        JsonArray arr = new JsonArray();
        for (ItemCheckoutStatus co : checkouts) arr.add(checkoutToJson(co));
        JsonObject data = new JsonObject();
        data.add("checkouts", arr);
        respondOk(id, data);
    }

    private void opOpenDb(int id, JsonObject req) throws Exception {
        String repo    = req.get("repo").getAsString();
        String folder  = strOrDefault(req, "folder", "/");
        String item    = req.get("item").getAsString();
        int    version = req.has("version") ? req.get("version").getAsInt() : -1;

        // Auto-open the repo if it hasn't been opened yet (e.g. auto-import fires
        // before the user has expanded the repo tree in the sidebar).
        session.openRepo(repo);

        // Open the database buffer file read-only from the server.
        // minChangeDataVer = -1 means we only want the latest change data.
        ghidra.framework.remote.RepositoryHandle repoHandle = session.getRepo(repo);
        db.buffers.ManagedBufferFileHandle bufHandle =
            repoHandle.openDatabase(folder, item, version, -1);

        // Export tables → JSON (runs synchronously; blocks until done).
        com.google.gson.JsonObject dbData = DatabaseExporter.export(bufHandle);

        JsonObject data = new JsonObject();
        if (dbData.has("image_base")) data.add("image_base", dbData.get("image_base"));
        data.add("symbols",    dbData.get("symbols"));
        data.add("comments",   dbData.get("comments"));
        data.add("func_flags", dbData.get("func_flags"));
        if (dbData.has("equates"))    data.add("equates",    dbData.get("equates"));
        if (dbData.has("bookmarks"))  data.add("bookmarks",  dbData.get("bookmarks"));
        if (dbData.has("parameters")) data.add("parameters", dbData.get("parameters"));
        if (dbData.has("data_types")) data.add("data_types", dbData.get("data_types"));
        if (dbData.has("data_items")) data.add("data_items", dbData.get("data_items"));
        if (dbData.has("xref_stats")) data.add("xref_stats", dbData.get("xref_stats"));
        respondOk(id, data);
    }

    private void opCheckin(int id, JsonObject req) throws Exception {
        String repo    = req.get("repo").getAsString();
        String folder  = strOrDefault(req, "folder", "/");
        String item    = req.get("item").getAsString();
        String comment = strOrDefault(req, "comment", "BN sync");
        JsonArray symbols         = req.has("symbols")            ? req.get("symbols").getAsJsonArray()            : new JsonArray();
        JsonArray comments        = req.has("comments")           ? req.get("comments").getAsJsonArray()           : new JsonArray();
        JsonArray equateRenames   = req.has("equate_renames")     ? req.get("equate_renames").getAsJsonArray()     : new JsonArray();
        JsonArray equateRefAdds   = req.has("equate_ref_adds")    ? req.get("equate_ref_adds").getAsJsonArray()    : new JsonArray();
        JsonArray bookmarkChanges = req.has("bookmark_changes")   ? req.get("bookmark_changes").getAsJsonArray()   : new JsonArray();
        JsonArray paramRenames    = req.has("param_renames")      ? req.get("param_renames").getAsJsonArray()      : new JsonArray();
        JsonArray dataTypeChanges = req.has("data_type_changes")  ? req.get("data_type_changes").getAsJsonArray()  : new JsonArray();
        JsonArray dataItemChanges = req.has("data_item_changes")  ? req.get("data_item_changes").getAsJsonArray()  : new JsonArray();
        JsonArray funcSigChanges  = req.has("func_sig_changes")   ? req.get("func_sig_changes").getAsJsonArray()   : new JsonArray();

        ghidra.framework.remote.RepositoryHandle repoHandle = session.getRepo(repo);

        // Reuse a *bridge-owned* checkout if one is already active (e.g. a leftover
        // from a previous failed terminate), otherwise acquire a new one.
        //
        // CRITICAL: only ever reuse — and therefore later terminate — checkouts that
        // THIS bridge created.  A bridge checkout is tagged with the project path
        // "<host>::binja-ghidra".  Earlier this matched on user alone, which would
        // grab the user's own interactive Ghidra checkout (same user) and terminate
        // it on check-in — leaving the user's local Ghidra copy with a dangling
        // checkout, which Ghidra reports as "hijacked".
        String bridgeProjectPath = ghidra.framework.store.ItemCheckoutStatus
                .getProjectPath("binja-ghidra", false);
        long coId = -1;
        String currentUser = session.getConnectedUser();
        ghidra.framework.store.ItemCheckoutStatus[] existing =
                repoHandle.getCheckouts(folder, item);
        if (existing != null) {
            for (ghidra.framework.store.ItemCheckoutStatus s : existing) {
                if (currentUser != null && currentUser.equals(s.getUser())
                        && bridgeProjectPath.equals(s.getProjectPath())) {
                    coId = s.getCheckoutId();
                    System.err.println("[ghidra-bridge] reusing bridge checkout_id=" + coId);
                    break;
                }
            }
        }
        boolean ownedCheckout = false;
        if (coId == -1) {
            ghidra.framework.store.ItemCheckoutStatus co =
                    repoHandle.checkout(folder, item,
                            ghidra.framework.store.CheckoutType.EXCLUSIVE, bridgeProjectPath);
            if (co == null) {
                throw new java.io.IOException(
                    "Checkout failed — the item is already checked out (this may be your "
                    + "own Ghidra session). Check it in or undo the checkout in Ghidra, then retry.");
            }
            coId = co.getCheckoutId();
            ownedCheckout = true;
            System.err.println("[ghidra-bridge] new checkout_id=" + coId);
        }
        System.err.println("[ghidra-bridge] checkin checkout_id=" + coId
                + " symbols=" + symbols.size() + " comments=" + comments.size()
                + " equates=" + equateRenames.size()
                + " equate_ref_adds=" + equateRefAdds.size()
                + " bookmarks=" + bookmarkChanges.size()
                + " params=" + paramRenames.size()
                + " data_types=" + dataTypeChanges.size()
                + " data_items=" + dataItemChanges.size()
                + " func_sigs=" + funcSigChanges.size());

        JsonObject applyResult = new JsonObject();
        try {
            // 3-arg openDatabase opens in write mode for the given checkout.
            db.buffers.ManagedBufferFileHandle handle =
                    repoHandle.openDatabase(folder, item, coId);
            applyResult = DatabaseImporter.apply(handle, symbols, comments,
                                   equateRenames, equateRefAdds, bookmarkChanges, paramRenames,
                                   dataTypeChanges, dataItemChanges, funcSigChanges, comment);
        } catch (Exception e) {
            // Only release a checkout we created; if we reused an existing one and the
            // write failed partway through we leave it for the user to sort out manually.
            if (ownedCheckout) terminateQuietly(repoHandle, folder, item, coId);
            throw e;
        }

        // Always release the checkout after a successful write — whether we created it
        // or reused a leftover from a previous failed attempt.  The bridge never keeps
        // checkouts alive between operations, so there is no legitimate "caller" that
        // would expect the checkout to remain after checkin completes.
        try {
            ghidra.framework.store.Version[] versions = repoHandle.getVersions(folder, item);
            if (versions != null && versions.length > 0) {
                int newVersion = versions[versions.length - 1].getVersion();
                repoHandle.updateCheckoutVersion(folder, item, coId, newVersion);
                System.err.println("[ghidra-bridge] updateCheckoutVersion → v" + newVersion);
            }
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] updateCheckoutVersion failed: " + e.getMessage());
        }
        terminateQuietly(repoHandle, folder, item, coId);

        System.err.println("[ghidra-bridge] checkin complete");
        JsonObject data = new JsonObject();
        data.addProperty("symbols_written",     symbols.size());
        data.addProperty("comments_written",    comments.size());
        data.addProperty("equates_written",     equateRenames.size());
        data.addProperty("equate_ref_adds_written", equateRefAdds.size());
        data.addProperty("bookmarks_written",   bookmarkChanges.size());
        data.addProperty("params_written",      paramRenames.size());
        data.addProperty("data_items_written",  dataItemChanges.size());
        data.addProperty("func_sigs_written",   funcSigChanges.size());
        // Return the DB keys assigned to newly-added types so C++ can update its baseline.
        data.add("added_type_ids", applyResult.has("added_type_ids")
            ? applyResult.get("added_type_ids") : new JsonObject());
        // Per-category applied counts — lets the BN side warn when the server
        // accepted fewer items than were sent (the shortfall would otherwise
        // re-queue invisibly on every check-in).
        if (applyResult.has("applied"))
            data.add("applied", applyResult.get("applied"));
        respondOk(id, data);
    }

    private void opDownloadBinary(int id, JsonObject req) throws Exception {
        String repo    = req.get("repo").getAsString();
        String folder  = strOrDefault(req, "folder", "/");
        String item    = req.get("item").getAsString();
        int    version = req.has("version") ? req.get("version").getAsInt() : -1;

        ghidra.framework.remote.RepositoryHandle repoHandle = session.getRepo(repo);
        db.buffers.ManagedBufferFileHandle bufHandle =
            repoHandle.openDatabase(folder, item, version, -1);

        db.buffers.ManagedBufferFileAdapter adapter =
            new db.buffers.ManagedBufferFileAdapter(bufHandle);
        db.DBHandle dbHandle = new db.DBHandle(adapter);
        try {
            List<ghidra.program.database.mem.BinaryExtractor.ExtractedFile> files =
                ghidra.program.database.mem.BinaryExtractor.extract(dbHandle);

            JsonArray arr = new JsonArray();
            for (ghidra.program.database.mem.BinaryExtractor.ExtractedFile ef : files) {
                JsonObject obj = new JsonObject();
                obj.addProperty("filename", ef.filename);
                obj.addProperty("size",     ef.bytes.length);
                obj.addProperty("data",     Base64.getEncoder().encodeToString(ef.bytes));
                arr.add(obj);
            }

            JsonObject data = new JsonObject();
            data.add("files", arr);
            respondOk(id, data);
        } finally {
            dbHandle.close();
            // Explicitly dispose the RMI stub so the server releases the buffer
            // file handle immediately.  Without this the server-side handle leaks
            // until GC finalises it, and some Ghidra server versions respond by
            // forcibly closing the connection (manifests as an immediate disconnect
            // after a successful download).
            try { bufHandle.dispose(); } catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // Ghidra post-import script — runs inside analyzeHeadless after the binary
    // is imported but before -commit, with no Ghidra auto-analysis running.
    // Creates functions at BN-known addresses, applies BN names and comments.
    // -------------------------------------------------------------------------
    /**
     * Java GhidraScript applied as analyzeHeadless -postScript.
     *
     * Ghidra 11+ dropped Jython; .java scripts are compiled on the fly by Ghidra's
     * own Java compiler, so this works with no external Python installation.
     *
     * Data file format (tab-separated lines):
     *   F  <hexaddr>  <name>  <plate>   — function; name/plate may be empty
     *   C  <hexaddr>  <text>            — EOL comment
     * Newlines inside text fields are encoded as the two-char sequence \n.
     * Backslashes are escaped as \\.
     */
    private static final String BINJA_SYNC_SCRIPT =
        "import ghidra.app.script.GhidraScript;\n"
      + "import ghidra.app.cmd.disassemble.DisassembleCommand;\n"
      + "import ghidra.app.cmd.function.CreateFunctionCmd;\n"
      + "import ghidra.program.model.address.Address;\n"
      + "import ghidra.program.model.listing.CodeUnit;\n"
      + "import ghidra.program.model.listing.Function;\n"
      + "import ghidra.program.model.listing.FunctionManager;\n"
      + "import ghidra.program.model.listing.Listing;\n"
      + "import ghidra.program.model.symbol.SourceType;\n"
      + "import java.io.BufferedReader;\n"
      + "import java.io.FileReader;\n"
      + "\n"
      + "public class BinjaSyncScript extends GhidraScript {\n"
      + "    @Override\n"
      + "    public void run() throws Exception {\n"
      + "        String[] args = getScriptArgs();\n"
      + "        if (args.length == 0) {\n"
      + "            printerr(\"[BN->Ghidra] No data file argument provided\");\n"
      + "            return;\n"
      + "        }\n"
      + "        FunctionManager fm      = currentProgram.getFunctionManager();\n"
      + "        Listing         listing = currentProgram.getListing();\n"
      + "        int             nFuncs  = 0;\n"
      + "        int             nComms  = 0;\n"
      + "        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {\n"
      + "            String line;\n"
      + "            while ((line = br.readLine()) != null) {\n"
      + "                if (line.isEmpty()) continue;\n"
      + "                String[] p = line.split(\"\\t\", -1);\n"
      + "                if (p.length < 2) continue;\n"
      + "                Address addr;\n"
      + "                try {\n"
      + "                    addr = toAddr(Long.parseUnsignedLong(\n"
      + "                        p[1].startsWith(\"0x\") ? p[1].substring(2) : p[1], 16));\n"
      + "                } catch (Exception e) {\n"
      + "                    printerr(\"[BN->Ghidra] Bad address: \" + p[1]);\n"
      + "                    continue;\n"
      + "                }\n"
      + "                if (\"F\".equals(p[0]) && p.length >= 4) {\n"
      + "                    String name  = unescape(p[2]);\n"
      + "                    String plate = unescape(p[3]);\n"
      + "                    try {\n"
      + "                        // Ensure bytes are disassembled before creating the function.\n"
      + "                        // With -noanalysis the bytes are present but not yet decoded.\n"
      + "                        if (listing.getCodeUnitAt(addr) == null) {\n"
      + "                            runCommand(new DisassembleCommand(addr, null, true));\n"
      + "                        }\n"
      + "                        Function func = fm.getFunctionAt(addr);\n"
      + "                        if (func == null) {\n"
      + "                            runCommand(new CreateFunctionCmd(addr));\n"
      + "                            func = fm.getFunctionAt(addr);\n"
      + "                        }\n"
      + "                        if (func == null) {\n"
      + "                            printerr(\"[BN->Ghidra] Could not create function at \" + addr);\n"
      + "                            continue;\n"
      + "                        }\n"
      + "                        if (!name.isEmpty()) {\n"
      + "                            func.setName(name, SourceType.USER_DEFINED);\n"
      + "                        } else {\n"
      + "                            // Without an explicit setName() call Ghidra uses\n"
      + "                            // DEFAULT source type, which stores an empty string\n"
      + "                            // in SYM_NAME_COL (the name is computed on the fly).\n"
      + "                            // The bridge exporter skips empty-name rows, so the\n"
      + "                            // symbol is invisible to collectCheckinChanges().\n"
      + "                            // Re-set the auto-name with ANALYSIS source so it is\n"
      + "                            // written to the DB and visible to the exporter.\n"
      + "                            func.setName(func.getName(), SourceType.ANALYSIS);\n"
      + "                        }\n"
      + "                        nFuncs++;\n"
      + "                        if (!plate.isEmpty()) func.setComment(plate);\n"
      + "                    } catch (Exception e) {\n"
      + "                        printerr(\"[BN->Ghidra] Function error at \" + addr\n"
      + "                            + \": \" + e.getMessage());\n"
      + "                    }\n"
      + "                } else if (\"C\".equals(p[0]) && p.length >= 3) {\n"
      + "                    String text = unescape(p[2]);\n"
      + "                    if (!text.isEmpty()) {\n"
      + "                        try {\n"
      + "                            listing.setComment(addr, CodeUnit.EOL_COMMENT, text);\n"
      + "                            nComms++;\n"
      + "                        } catch (Exception e) {\n"
      + "                            printerr(\"[BN->Ghidra] Comment error at \" + addr\n"
      + "                                + \": \" + e.getMessage());\n"
      + "                        }\n"
      + "                    }\n"
      + "                }\n"
      + "            }\n"
      + "        }\n"
      + "        println(\"[BN->Ghidra] sync complete: \" + nFuncs + \" functions, \"\n"
      + "            + nComms + \" comments\");\n"
      + "    }\n"
      + "\n"
      + "    /** Unescape \\\\, \\n and \\t escape sequences written by the C++ side. */\n"
      + "    private static String unescape(String s) {\n"
      + "        return s.replace(\"\\\\\\\\\", \"\\u0000\")\n"
      + "                .replace(\"\\\\n\",  \"\\n\")\n"
      + "                .replace(\"\\\\t\",  \"\\t\")\n"
      + "                .replace(\"\\u0000\", \"\\\\\");\n"
      + "    }\n"
      + "}\n";

    private void opDeleteItem(int id, JsonObject req) throws Exception {
        String repo   = req.get("repo").getAsString();
        String folder = strOrDefault(req, "folder", "/");
        String item   = req.get("item").getAsString();
        // version -1 deletes all versions of the item from the repository.
        session.openRepo(repo);
        session.getRepo(repo).deleteItem(folder, item, -1);
        respondOk(id);
    }

    private void opUploadBinary(int id, JsonObject req) throws Exception {
        String  repo         = req.get("repo").getAsString();
        String  folder       = strOrDefault(req, "folder", "/");
        String  item         = req.get("item").getAsString();
        String  b64Data      = req.get("data").getAsString();
        String  comment      = strOrDefault(req, "comment", "Uploaded from Binary Ninja");
        boolean keepCheckout = req.has("keep_checkout") && req.get("keep_checkout").getAsBoolean();
        String  host         = req.get("host").getAsString();
        int     port         = req.get("port").getAsInt();
        String  user         = req.get("user").getAsString();
        String  password     = strOrDefault(req, "password", "");
        String  analysisJson = strOrDefault(req, "analysis_json", "");

        if (ghidraHome.isEmpty())
            throw new IOException(
                "Ghidra home directory is not known to the bridge — "
                + "restart Binary Ninja so the bridge picks up the path.");

        // Locate the analyzeHeadless launcher script.
        boolean isWin  = System.getProperty("os.name", "").toLowerCase().contains("win");
        String  script = ghidraHome + File.separator + "support"
                       + File.separator + (isWin ? "analyzeHeadless.bat" : "analyzeHeadless");
        if (!new File(script).exists())
            throw new IOException("analyzeHeadless not found: " + script);

        // Decode binary bytes and write to a temp file.
        // getMimeDecoder() tolerates the line breaks that BN's DataBuffer::ToBase64() inserts.
        byte[] bytes      = Base64.getMimeDecoder().decode(b64Data);
        // The file must be named exactly <item> — analyzeHeadless uses the filename (not the path)
        // as the repository item name.  Place it in its own temp directory so the name is clean.
        File   tempBinDir = Files.createTempDirectory("binja_bin_").toFile();
        File   tempBin    = new File(tempBinDir, sanitize(item));
        // Declared here so they are visible in the finally block.
        File   scriptDir  = null;
        File   dataFile   = null;
        try {
            Files.write(tempBin.toPath(), bytes);

            // Server URL used as the project location (the correct analyzeHeadless invocation for
            // Ghidra Server repositories).  The analyzeHeadless help states:
            //   analyzeHeadless <project_location> <project_name>
            //                 | ghidra://<host>[:<port>]/<repository>[/<folder>]
            // Passing the server URL as the sole positional argument (no local project dir, no
            // project name, no -connect flag) makes analyzeHeadless commit the imported program
            // directly to the Ghidra Server repository rather than to a local project on disk.
            String serverUrl = String.format("ghidra://%s@%s:%d/%s", user, host, port, repo);

            // Build the command line.
            List<String> cmd = new ArrayList<>();
            if (!isWin) { cmd.add("/bin/sh"); cmd.add("-c"); }
            // On POSIX we build a single shell string so spaces in paths are handled correctly.
            StringBuilder sh = new StringBuilder();
            sh.append('"').append(script).append('"');
            sh.append(" \"").append(serverUrl).append('"');  // server URL = project location
            // No second positional arg (project name) — server URL mode takes only one.
            // -connect installs HeadlessClientAuthenticator so the server URL connection can auth.
            // -p tells analyzeHeadless to read a password; we pipe it to stdin below.
            sh.append(" -connect ").append(user);
            if (!password.isEmpty()) sh.append(" -p");
            sh.append(" -import \"").append(tempBin.getAbsolutePath()).append('"');
            sh.append(" -noanalysis");  // BN has already analysed the binary; skip redundant Ghidra pass

            // If BN analysis data was provided, write the sync script and data file to temp dirs,
            // then pass them to analyzeHeadless as a postScript so BN's names/comments are applied
            // to the Ghidra database before the first -commit.
            if (!analysisJson.isEmpty()) {
                scriptDir = Files.createTempDirectory("binja_script_").toFile();
                dataFile  = File.createTempFile("binja_data_", ".tsv");
                Files.write(dataFile.toPath(),
                    analysisJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                // Script filename must match the public class name so Ghidra's compiler is happy.
                File scriptFile = new File(scriptDir, "BinjaSyncScript.java");
                Files.write(scriptFile.toPath(),
                    BINJA_SYNC_SCRIPT.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                sh.append(" -scriptPath \"").append(scriptDir.getAbsolutePath()).append('"');
                sh.append(" -postScript BinjaSyncScript.java \"")
                  .append(dataFile.getAbsolutePath()).append('"');
            }

            sh.append(" -commit \"").append(comment.replace("\"", "'")).append('"');
            if (!folder.equals("/"))
                sh.append(" -folder ").append(folder);

            if (isWin) {
                // On Windows, pass args directly to cmd.exe.
                cmd.add("cmd.exe"); cmd.add("/c");
            }
            cmd.add(sh.toString());

            System.err.println("[ghidra-bridge] upload_binary: " + sh);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            // Let analyzeHeadless inherit the same JAVA_HOME so it uses a compatible JVM.
            pb.environment().put("JAVA_HOME", System.getProperty("java.home", ""));

            Process proc = pb.start();

            // Pipe password to stdin — analyzeHeadless prompts for it when no keystore entry
            // exists.  This is harmless if credentials are already cached (prompt never appears).
            final String pw = password;
            Thread pwWriter = new Thread(() -> {
                try (OutputStream os = proc.getOutputStream()) {
                    if (!pw.isEmpty()) {
                        os.write((pw + "\n")
                            .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        os.flush();
                    }
                } catch (IOException ignored) {}
            }, "pw-writer");
            pwWriter.setDaemon(true);
            pwWriter.start();

            // Drain stdout/stderr into the bridge log.
            StringBuilder output = new StringBuilder();
            Thread logger = new Thread(() -> {
                try (BufferedReader br =
                        new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        System.err.println("[analyzeHeadless] " + line);
                        synchronized (output) { output.append(line).append('\n'); }
                    }
                } catch (IOException ignored) {}
            }, "headless-log");
            logger.setDaemon(true);
            logger.start();

            // Wait up to 10 minutes (Ghidra auto-analysis can be slow for large binaries).
            boolean done = proc.waitFor(10, TimeUnit.MINUTES);
            if (!done) {
                proc.destroyForcibly();
                throw new IOException("analyzeHeadless timed out after 10 minutes");
            }
            int exit = proc.exitValue();
            if (exit != 0) {
                String tail = output.toString().trim();
                // Surface just the last ~500 chars so the error isn't overwhelming.
                if (tail.length() > 500) tail = "…" + tail.substring(tail.length() - 500);
                throw new IOException(
                    "analyzeHeadless failed (exit " + exit + ")"
                    + (tail.isEmpty() ? "" : ":\n" + tail));
            }

            System.err.println("[ghidra-bridge] upload_binary: succeeded for " + item);

            // Optionally leave the item checked out so BN can push changes back later.
            long checkoutId = -1;
            if (keepCheckout) {
                // Make sure this session has the repo open before checkout.
                session.openRepo(repo);
                ghidra.framework.remote.RepositoryHandle rh = session.getRepo(repo);
                String projectPath =
                    ItemCheckoutStatus.getProjectPath("binja-ghidra", false);
                ItemCheckoutStatus co =
                    rh.checkout(folder, item, CheckoutType.NORMAL, projectPath);
                if (co != null) {
                    checkoutId = co.getCheckoutId();
                    System.err.println("[ghidra-bridge] checkout_id=" + checkoutId);
                }
            }

            JsonObject data = new JsonObject();
            data.addProperty("checkout_id", checkoutId);
            respondOk(id, data);

        } finally {
            deleteRecursively(tempBinDir);
            if (dataFile  != null) dataFile.delete();
            if (scriptDir != null) deleteRecursively(scriptDir);
        }
    }

    /** Remove characters that are unsafe in temp filenames. */
    private static String sanitize(String name) {
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /** Recursively delete a directory tree. */
    private static void deleteRecursively(File dir) {
        if (!dir.exists()) return;
        File[] children = dir.listFiles();
        if (children != null) for (File c : children) deleteRecursively(c);
        dir.delete();
    }

    // -------------------------------------------------------------------------
    // Checkout helpers
    // -------------------------------------------------------------------------

    private static void terminateQuietly(
            ghidra.framework.remote.RepositoryHandle repo,
            String folder, String item, long coId) {
        try {
            repo.terminateCheckout(folder, item, coId, true);
            System.err.println("[ghidra-bridge] checkout terminated OK coId=" + coId);
        } catch (Exception e) {
            System.err.println("[ghidra-bridge] terminateCheckout failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Event streaming
    // -------------------------------------------------------------------------

    private void startStreamer(String repoName) throws Exception {
        if (streamers.containsKey(repoName)) return;
        var repo     = session.getRepo(repoName);
        var streamer = new EventStreamer(repoName, repo, this::pushEvent);
        streamers.put(repoName, streamer);
        streamer.start();
    }

    private void stopStreamer(String repoName) {
        EventStreamer s = streamers.remove(repoName);
        if (s != null) s.stop();
    }

    private void stopAllStreamers() {
        streamers.values().forEach(EventStreamer::stop);
        streamers.clear();
    }

    private void pushEvent(String repoName, RepositoryChangeEvent evt) {
        JsonObject msg = new JsonObject();
        msg.addProperty("event", "repo_changed");
        msg.addProperty("repo",  repoName);
        msg.addProperty("type",  eventTypeName(evt.type));
        if (evt.parentPath    != null) msg.addProperty("parent_path",     evt.parentPath);
        if (evt.name          != null) msg.addProperty("name",            evt.name);
        if (evt.newParentPath != null) msg.addProperty("new_parent_path", evt.newParentPath);
        if (evt.newName       != null) msg.addProperty("new_name",        evt.newName);
        writeLine(gson.toJson(msg));
    }

    // -------------------------------------------------------------------------
    // Response helpers
    // -------------------------------------------------------------------------

    private void respondOk(int id) {
        respondOk(id, null);
    }

    private void respondOk(int id, JsonObject extra) {
        JsonObject resp = new JsonObject();
        resp.addProperty("id", id);
        resp.addProperty("ok", true);
        if (extra != null) {
            for (Map.Entry<String, JsonElement> e : extra.entrySet()) {
                resp.add(e.getKey(), e.getValue());
            }
        }
        writeLine(gson.toJson(resp));
    }

    private void respondError(int id, String error) {
        JsonObject resp = new JsonObject();
        resp.addProperty("id",    id);
        resp.addProperty("ok",    false);
        resp.addProperty("error", error);
        writeLine(gson.toJson(resp));
    }

    // -------------------------------------------------------------------------
    // Serialisation helpers
    // -------------------------------------------------------------------------

    private static JsonObject itemToJson(RepositoryItem item) {
        JsonObject o = new JsonObject();
        o.addProperty("name",         item.getName());
        o.addProperty("parent_path",  item.getParentPath());
        o.addProperty("path",         item.getPathName());
        o.addProperty("file_id",      item.getFileID());
        o.addProperty("item_type",    item.getItemType());
        o.addProperty("content_type", item.getContentType());
        o.addProperty("version",      item.getVersion());
        o.addProperty("version_time", item.getVersionTime());
        if (item.getTextData() != null) o.addProperty("text_data", item.getTextData());
        return o;
    }

    private static JsonObject checkoutToJson(ItemCheckoutStatus co) {
        JsonObject o = new JsonObject();
        o.addProperty("id",           co.getCheckoutId());
        o.addProperty("type",         co.getCheckoutType().name());
        o.addProperty("user",         co.getUser());
        o.addProperty("version",      co.getCheckoutVersion());
        o.addProperty("time",         co.getCheckoutTime());
        o.addProperty("project_path", co.getProjectPath());
        return o;
    }

    private static String eventTypeName(int type) {
        if (type == RepositoryChangeEvent.REP_FOLDER_CREATED)    return "REP_FOLDER_CREATED";
        if (type == RepositoryChangeEvent.REP_ITEM_CREATED)      return "REP_ITEM_CREATED";
        if (type == RepositoryChangeEvent.REP_FOLDER_DELETED)    return "REP_FOLDER_DELETED";
        if (type == RepositoryChangeEvent.REP_FOLDER_MOVED)      return "REP_FOLDER_MOVED";
        if (type == RepositoryChangeEvent.REP_FOLDER_RENAMED)    return "REP_FOLDER_RENAMED";
        if (type == RepositoryChangeEvent.REP_ITEM_DELETED)      return "REP_ITEM_DELETED";
        if (type == RepositoryChangeEvent.REP_ITEM_RENAMED)      return "REP_ITEM_RENAMED";
        if (type == RepositoryChangeEvent.REP_ITEM_MOVED)        return "REP_ITEM_MOVED";
        if (type == RepositoryChangeEvent.REP_ITEM_CHANGED)      return "REP_ITEM_CHANGED";
        if (type == RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT) return "REP_OPEN_HANDLE_COUNT";
        return "UNKNOWN_" + type;
    }

    private static String strOrDefault(JsonObject obj, String key, String def) {
        return obj.has(key) ? obj.get(key).getAsString() : def;
    }
}
