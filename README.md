# binja-ghidra

A Binary Ninja plugin that connects to a Ghidra Server repository and imports its analysis — symbols, function names, and comments — directly into an open Binary Ninja binary view.

## What it does

Ghidra and Binary Ninja each have strengths. This plugin lets you use both on the same binary without manually copying names or comments between them. Connect to a running Ghidra Server, browse its repositories, and double-click any project file to pull its analysis into the currently open BN view.

**Sync goes both directions.**

| | BN ← Ghidra (import) | BN → Ghidra (checkin) |
|---|---|---|
| Symbols (labels, function names) | ✓ | ✓ |
| Comments (EOL/PRE/POST/PLATE/REP) | ✓ | ✓ |
| Function signatures (return type, calling convention) | ✓ | ✓ |
| Function parameters (rename, retype, add) | ✓ | ✓ |
| Data types (struct/union/enum/typedef + pointer/array) | ✓ | ✓ |
| Equates (constant names + references) | ✓ | ✓ |
| Bookmarks | ✓ | ✓ |
| Typed data items | ✓ | ✓ |
| Function flags (thunk, no-return, inline) | ✓ as BN tags | — |
| Local variables (storage-aware) | ✓ | partial — register-storage mapping not implemented |

## Architecture

```
Binary Ninja (C++ plugin)
    │  TCP / newline-delimited JSON
    ▼
ghidra-bridge-*.jar  (Java, runs as a subprocess)
    │  Java RMI / SSL
    ▼
Ghidra Server  (ghidraSvr, running on the network)
```

The plugin spawns a Java subprocess (the "bridge") on load. The bridge holds the RMI connection to the Ghidra Server and speaks a simple JSON protocol back to the plugin over a local TCP socket. This keeps all Java/RMI code out of the C++ process and lets the JVM start in the background while BN finishes loading.

The bridge JVM also initialises Ghidra's `Application` framework at startup so the write path can use Ghidra's high-level program-model APIs (`ProgramDB`, `DataTypeManager`, `SymbolTable`, `FunctionManager`) rather than raw `db.Table.putRecord()` writes — see [Checkin write path](#checkin-write-path) below.

### Components

| Path | Language | Role |
|------|----------|------|
| `plugin/` | C++ / Qt6 | Binary Ninja sidebar plugin |
| `bridge/` | Java 17 | Ghidra RMI client + JSON bridge server |

**Plugin (C++):**
- `plugin.cpp` — registers settings and the sidebar widget; eagerly starts the bridge JVM on load
- `GhidraConnection.cpp` — singleton; manages bridge lifecycle and all RMI-backed operations
- `BridgeProcess.cpp` — launches the bridge JAR as a subprocess with stdout/stderr pipes; reads the `READY port=N` handshake line
- `BridgeClient.cpp` — TCP client; sends JSON requests, receives responses, dispatches async events
- `SyncEngine.cpp` — applies a `GhidraDbExport` to a `BinaryView` (symbols, comments, flags)
- `ui/ProjectPanel.cpp` — sidebar widget: repo tree, connect dialog, activity log
- `ui/ConnectDialog.cpp` — host/port/user/password dialog

**Bridge (Java):**
- `BridgeMain.java` — argument parsing; initialises `UniversalIdGenerator` and the Ghidra `Application` framework; starts the TCP server; prints `READY port=N` to stdout
- `BridgeServer.java` — accepts one TCP client connection and hands it a `BridgeConnection`
- `BridgeConnection.java` — JSON request dispatcher; serialises Ghidra API responses to JSON; handles `opCheckin` (creates a new program version on the server)
- `GhidraSession.java` — authenticated RMI session; wraps `RemoteRepositoryServerHandle`
- `EventStreamer.java` — background thread per open repo; pushes `RepositoryChangeEvent`s to the plugin as async JSON events
- `DatabaseExporter.java` — read path: extracts symbol/comment/function-flag/data-type/equate/bookmark tables from a `ManagedBufferFileHandle` (Ghidra's remote DB buffer) via raw `db.jar` access
- `ProgramApplier.java` — write path: opens the buffer file as a real `ProgramDB` and applies all BN-side changes through Ghidra's high-level APIs (see [Checkin write path](#checkin-write-path) below)
- `DatabaseImporter.java` — legacy raw-write helpers kept only as a test seam; production `apply(...)` delegates to `ProgramApplier`

## Checkin write path

`opCheckin` opens the program's managed buffer file in write mode, constructs a `ProgramDB` over it, and applies BN-side changes through Ghidra's program-model APIs. **Raw `db.Table.putRecord()` writes are avoided** — they were the source of every checkin-corruption bug we ever hit:

| Wrong-tier write | Failure mode |
|---|---|
| `setIntValue(col, longTypeId)` on Function Data table | `IntField.setLongValue` silently `l2i`-truncates → StackPurge corrupted on every signature update |
| `setByteValue(col, isUnion)` on V5V6 Composite Data Types | column is `BooleanField` in Ghidra 12.x → `IllegalFieldAccessException` ("Illegal field access") |
| `setIntValue(col, 0)` on V2 Typedef Flags column | column is `ShortField` → same crash, different schema |
| Writing composite header without component-settings rows | `CompositeEditorModel.cloneAllComponentSettings` throws `ArrayIndexOutOfBoundsException` when struct is opened in Ghidra |
| Writing PARAMETER symbol with `SYM_ADDR_COL` = RAM address | `Address is not a VariableAddress` thrown by `FunctionDB.loadSymbolBasedVariables` on any function access |
| Passing `null` `DBChangeSet` to `DBHandle.save()` | server writes a 0-byte change-data file → next checkout fails with `EOFException` in `ProgramContentHandler.loadProgramChangeSet` |

`ProgramApplier` doesn't have these traps because it routes through `DataTypeManager.addDataType`, `SymbolTable.createLabel`, `Listing.setComment`, `Function.setReturnType`, etc. — APIs that maintain Ghidra's interlocking-table invariants automatically. It also runs a `cleanupBadVariableSymbols` pass at the start of every checkin to purge corruption left in the database by older bridge versions.

`server-package/CleanupBadVariableSymbols.java` is a standalone `GhidraScript` that runs the same cleanup via `analyzeHeadless` — useful when a file is too corrupted to open in the Ghidra GUI.

## Testing

```sh
./test.sh          # macOS / Linux: tiers 0-3 (C++ unit + BN-headless + Java)
test.bat           # Windows equivalent
test.bat --parity  # cross-DB parity tier only (C++ BN tests + gradlew parityTest)
test.bat --e2e     # live Ghidra-server E2E (starts a local ghidraSvr)
```

The suite is organised in five tiers. Tiers 2–4 exist to prove one property:
**the same compatible data ends up stored in both the .bndb and the Ghidra
program database** (the compatibility matrix at the top of this README).

| Tier | What | Where | Gate |
|---|---|---|---|
| 0 | Pure unit tests | `plugin/test/*.cpp` (`binja-ghidra-tests`), bridge `*Test.java` | always |
| 1 | Ghidra-DB round-trip | bridge `*RoundTripTest.java` (`ProgramApplier` against a real `ProgramDB`) | needs `ghidra.home` / `GHIDRA_HOME` |
| 2 | BN BinaryView/.bndb round-trip | `plugin/test/bn/` (`binja-ghidra-bn-tests`; headless binaryninjacore) | SKIPs cleanly without a headless-capable BN license (`BN_LICENSE` env honoured) |
| 3 | Cross-DB parity | `CanonicalParityTest` (C++ **and** Java) against the shared goldens in `testdata/parity/fixtures/` | with tiers 1+2 |
| 4 | Live-server E2E | bridge `LiveServerE2ETest` — boots a real `ghidraSvr` in a temp dir, seeds via `analyzeHeadless`, drives checkout → export → checkin → re-export over RMI | `test.bat --e2e` (sets `GHIDRA_E2E=1`) |

**Parity oracle (tier 3).** Both sides independently verify against the same
checked-in canonical JSON (the bridge `DatabaseExporter` shape). Import
direction: the golden loads into a `ProgramDB` (Java) and into a BinaryView
via `SyncEngine` (C++), and each re-export must equal the golden. Checkin
direction: scripted BN edits must produce exactly
`fixtures/checkin/*/expected-preview.json` (C++), and applying that preview via
`ProgramApplier` must re-export as `expected-after.json` (Java). If both sides
match the shared goldens, the two databases agree by transitivity. Field
compare modes and the type-name normalization table live in
[testdata/parity/RULES.md](testdata/parity/RULES.md); the test binary is
`testdata/bin/parity_x64.bin` (layout in `parity_x64.md`).

Long-standing regression pins on the Java side:
  - `DataTypesRoundTripTest.struct_cloneSettings_doesNotThrow` — composite settings must stay consistent with header (cloneAllComponentSettings crash)
  - `FunctionSignaturesRoundTripTest.returnType_doesNotCorruptStackPurge` — IntField truncation
  - `ParametersRoundTripTest.noParameterSymbol_endsUpAtRamAddress` — VariableAddress invariant

Round-trip and parity tests require a Ghidra install (used at runtime for
language services). The path is read from the `ghidra.home` Gradle system
property or `GHIDRA_HOME` env var; `build.gradle` passes `ghidraHome` through
by default. Tier-2/3 C++ tests additionally need `binaryninjacore` loadable
(the scripts put the BN install dir on `PATH`).

## Prerequisites

| Dependency | Notes |
|------------|-------|
| Binary Ninja (commercial) | Tested against the version matching `api_REVISION.txt` in the BN install |
| Ghidra Server | Tested with Ghidra 12.0.4. Must be running and reachable over RMI/SSL |
| Java 17+ JDK | Eclipse Adoptium JDK 21 recommended |
| CMake 3.24+ | |
| Ninja | |
| C++ compiler | MSVC 2022+ on Windows; clang on macOS; gcc/clang on Linux |
| Qt 6.7+ | See [Qt setup](#qt-setup) below; `qmake` must be on `PATH` at build time |
| Gradle (via wrapper) | The bridge uses the Gradle wrapper — no separate install needed |
| **Poetry** *(Qt build only)* | Required only when building Qt from the `qt-build` submodule. Install with `pip install poetry` or `pipx install poetry`. |
| **libclang 19** *(Qt build only)* | Required by Qt's build system. See `qt-build/README.md` for download instructions. |

## Qt setup

The plugin links against the same Qt 6 build that Binary Ninja uses. You have two options:

**Option A — Use an existing Qt install** (fastest if you already have Qt)

Pass `Qt6_DIR` pointing at your Qt CMake directory:
```sh
Qt6_DIR=/path/to/Qt/6.x.y/clang_64/lib/cmake/Qt6 ./build.sh
```
On macOS the build script auto-detects Qt if it was installed by the Qt online installer under `/usr/local/Qt*`.

**Option B — Build Qt from the `qt-build` submodule** (~1-2 hours, once per machine)

The `qt-build` submodule (Vector35's Qt build scripts) compiles Qt 6 with Binary Ninja's patches. It requires Poetry and libclang 19 (see Prerequisites above and `qt-build/README.md`).

Qt is installed to `qt/<version>/<compiler>/` inside the repo:

| Platform | Install path |
|----------|-------------|
| macOS | `qt/6.10.1/clang_64/` |
| Linux x86-64 | `qt/6.10.1/gcc_64/` |
| Windows | `qt/6.10.1/msvc2022_64/` |

```sh
# First time on a new machine:
./build.sh qt          # compiles Qt — takes 1-2 hours

# All subsequent builds (Qt cached in qt/, reused automatically):
./build.sh
```

The `qt` step is only needed once. CMake and the build scripts detect the built Qt in `qt/` on every subsequent run and skip the submodule entirely. The `qt/` directory is gitignored.

## Building

### Fresh checkout

```sh
git clone https://github.com/mutinylaboratories/ghidra_svr_bridge.git
cd ghidra_svr_bridge
git submodule update --init   # populates binaryninja-api and qt-build (~seconds)
```

Then follow the Qt setup above (Option A or B), and run:

```sh
./build.sh install
```

### macOS / Linux

```sh
# Incremental build of both components
./build.sh

# Full clean rebuild + install into BN plugins folder
./build.sh clean install

# Build only the C++ plugin
./build.sh plugin

# Build only the Java bridge
./build.sh bridge

# Build Qt once on a machine without Qt installed
./build.sh qt
```

Environment variables (all optional — the script sets sensible defaults):

```sh
BN_INSTALL=/Applications/Binary\ Ninja.app/Contents/MacOS
Qt6_DIR=/usr/local/Qt-6.7.2/lib/cmake/Qt6
```

### Windows

Edit the paths at the top of `build.bat` to match your environment before first use:

```bat
set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot"
set "VSDEVCMD=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
set "Qt6_DIR=C:\qt\v6.7.2\lib\cmake\Qt6"
set "BN_INSTALL=C:\Program Files\Vector35\BinaryNinja"
```

```bat
rem Incremental build of both components
build.bat

rem Full clean rebuild + install into BN plugins folder
build.bat clean install

rem Build only the C++ plugin
build.bat plugin

rem Build only the Java bridge
build.bat bridge

rem Build Qt once on a machine without Qt installed
build.bat qt
```

The C++ build uses CMake FetchContent to clone `binaryninja-api` at the exact commit recorded in `api_REVISION.txt`, so the plugin ABI always matches the installed BN version. Ghidra is downloaded automatically by CMake on first configure if `GHIDRA_HOME` is not set.

## Configuration

After installing, set these in Binary Ninja's settings (`Edit → Preferences → Settings`, search "Ghidra"):

| Setting | Description |
|---------|-------------|
| `ghidra.javaExe` | Full path to `java.exe` |
| `ghidra.ghidraHome` | Root of your Ghidra installation (contains `Ghidra/Framework/…`) |
| `ghidra.trustAllCerts` | Set `true` if your Ghidra Server uses a self-signed certificate |
| `ghidra.defaultHost` | Pre-fills the Connect dialog |
| `ghidra.defaultPort` | Default: `13100` |
| `ghidra.defaultUser` | Pre-fills the Connect dialog |

## Usage

1. Open a binary in Binary Ninja.
2. Open the **Ghidra** sidebar (the red "G" icon).
3. Click **Connect…** and enter your server credentials.
4. The repository tree populates. Click the expand arrow (▶) on a repository to reveal its folders and project files.
5. Project files appear **bold and blue**. Double-click one to import its analysis into the currently open binary view.
6. The activity log shows import progress and the address range of applied symbols.

**Prerequisite for step 5:** the program file must be committed to the Ghidra Server repository (not just open locally in Ghidra). In Ghidra: right-click the file in the Project window → *Version Control → Add to Version Control…*.

## Bridge protocol

The plugin and bridge communicate over a local TCP socket using newline-delimited JSON. Every request carries an integer `id` and a string `op`; every response echoes the `id`. Async events (server-side repository changes) carry an `"event"` key instead.

| Op | Direction | Purpose |
|---|---|---|
| `ping`, `status`, `connect`, `disconnect` | request/response | session lifecycle |
| `list_repos`, `open_repo`, `close_repo` | request/response | repo enumeration |
| `list_items`, `get_subfolders` | request/response | repo browsing |
| `get_versions`, `get_checkouts` | request/response | version control state |
| `checkout`, `terminate_checkout` | request/response | exclusive write lock |
| `open_db` | request/response | read full Ghidra DB → JSON (heavy) |
| `checkin` | request/response | apply BN-side changes → new repo version (heavy, via `ProgramApplier`) |
| `download_binary`, `upload_binary` | request/response | move the original binary in/out |
| `delete_item` | request/response | remove file from repo |
| `repo_changed` | event (async) | server-side `RepositoryChangeEvent` push |

## Continuing on another machine

The repository contains everything needed to rebuild from scratch. Per-developer setup that isn't in git:

1. **Clone + submodules**:
   ```sh
   git clone https://github.com/mutinylaboratories/ghidra_svr_bridge.git
   cd ghidra_svr_bridge
   git submodule update --init --recursive
   ```
2. **Local Ghidra path**: create `bridge/gradle.properties`:
   ```properties
   ghidraHome=C:/Users/<you>/ghidra/ghidra_12.0.4_PUBLIC
   ```
   (Forward slashes work on Windows too — Gradle prefers them.)
3. **Ghidra + Binary Ninja installations**: same setup as your other machines.
4. **Qt**: either point `Qt6_DIR` at an existing install or run `./build.sh qt` (Windows: `build.bat qt`) once.
5. **Binary Ninja release channel**: the plugin's ABI must match the BN you run. Select the channel when building; the script fetches the matching `binaryninja-api` commit from GitHub:
   ```sh
   ./build.sh --channel stable    # default — latest stable release (from GitHub)
   ./build.sh --channel dev        # latest dev (dev branch head, from GitHub)
   ./build.sh --bn-api <commit>   # explicit commit, no GitHub lookup (escape hatch)
   ```
   `--channel` and `--bn-api` are mutually exclusive; with neither, the **stable** channel is used. `--channel` queries the [Vector35/binaryninja-api](https://github.com/Vector35/binaryninja-api) GitHub (latest `stable/*` release, or the `dev` branch head) so it needs network access. If your installed BN lags the latest release, pass `--bn-api` with the exact SHA from that install's `api_REVISION.txt`.

When opening a fresh Claude Code session, the best onboarding pointers are this README plus the current state on `dev`:

- Architecture and write-path invariants: this file
- Production write path: `bridge/src/main/java/com/ghidra_svr/bridge/ProgramApplier.java`
- Test harness: `bridge/src/test/java/com/ghidra_svr/bridge/ProgramTestBase.java`
- Round-trip suites: `bridge/src/test/java/com/ghidra_svr/bridge/*RoundTripTest.java`
- Recent commits: `git log --oneline` — each subject line says what changed and why

## Known limitations / pending work

- **Local variable storage**: `ProgramApplier` skips `is_local` parameter entries because mapping BN register indices to Ghidra storage requires a per-architecture register-table translation. Parameters work; locals don't sync yet.
- **Authentication**: only username + password. PKI and SSH-key callbacks are not yet handled.
- **Single address space**: `DatabaseExporter` assumes a single RAM address space. Overlay spaces or Harvard architectures may produce incorrect addresses.
- **Change-set merge**: the bridge writes an *empty* `DBChangeSet` to keep checkouts working. Ghidra's merge-on-checkout machinery therefore can't auto-resolve concurrent edits between BN and Ghidra users — last writer wins.
