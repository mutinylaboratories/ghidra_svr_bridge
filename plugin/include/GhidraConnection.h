#pragma once
#include "BridgeClient.h"
#include "BridgeProcess.h"
#include <binaryninjaapi.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ---------------------------------------------------------------------------
// Data transfer objects (mirror the bridge JSON shapes)
// ---------------------------------------------------------------------------

struct RepoItem {
    std::string name;
    std::string parentPath;
    std::string path;
    std::string fileId;
    int         itemType    = 0; // 1=FILE, 2=DATABASE, 3=TEXT_DATA_FILE
    std::string contentType;
    int         version     = -1;
    int64_t     versionTime = 0;
};

struct CheckoutInfo {
    int64_t     id          = 0;
    std::string type;        // "NORMAL" | "EXCLUSIVE" | "TRANSIENT"
    std::string user;
    int         version     = -1;
    int64_t     time        = 0;
    std::string projectPath;
};

struct VersionInfo {
    int         version     = -1;
    int64_t     time        = 0;
    std::string user;
    std::string comment;
};

// ---------------------------------------------------------------------------
// Database export — returned by openDatabase()
// ---------------------------------------------------------------------------

/** Symbol types matching Ghidra's SymbolType ordinals. */
enum class GhidraSymbolType : int {
    Label     = 0,
    Library   = 1,
    Namespace = 2,
    Class     = 3,
    Function  = 4,
    Parameter = 5,
    LocalVar  = 6,
    GlobalVar = 7,
    External  = 8,
};

/** Symbol source — 0=DEFAULT (auto), 1=ANALYSIS, 2=IMPORTED, 3=USER_DEFINED */
enum class GhidraSymbolSource : int {
    Default  = 0,
    Analysis = 1,
    Imported = 2,
    User     = 3,
};

struct GhidraSymbol {
    int64_t          key         = 0;
    std::string      name;
    uint64_t         addr        = 0;
    GhidraSymbolType type        = GhidraSymbolType::Label;
    GhidraSymbolSource source    = GhidraSymbolSource::Default;
    int64_t          namespaceId = 0;
};

struct GhidraComment {
    uint64_t    addr = 0;
    std::string eol, pre, post, plate, rep;
    std::string encodedKey; // "0x..." encoded Ghidra address — used for write-back
};

struct GhidraFuncFlags {
    int64_t key     = 0;
    bool    thunk   = false;
    bool    noReturn= false;
    bool    isInline= false;
};

struct GhidraFuncSig {
    int64_t     key               = 0;   // Functions table key (= symbol key)
    std::string callingConvention;        // "" = default / unknown
    std::string returnTypeName;           // "" = void/unknown; resolved from datatype tables
    int64_t     returnTypeId      = -1;  // raw Ghidra datatype ID (for write-back)
};

struct GhidraEquateRef {
    uint64_t    addr     = 0;
    int         opIndex  = 0;
};

struct GhidraEquate {
    int64_t                  id    = 0;
    std::string              name;
    int64_t                  value = 0;
    std::vector<GhidraEquateRef> refs;
};

struct GhidraBookmark {
    std::string type;
    uint64_t    addr     = 0;
    std::string category;
    std::string comment;
};

struct GhidraParameter {
    int64_t     key      = 0;
    uint64_t    funcAddr = 0;
    std::string name;
    bool        isParam  = true;
    int         ordinal  = 0;
    std::string typeName;    // resolved type name (e.g. "MyStruct", "int32_t"); empty = unknown
    int64_t     typeId = -1; // raw Ghidra DataTypeId; -1 = unknown
};

struct GhidraDataTypeMember {
    int         offset   = 0;
    int64_t     typeId   = 0;
    std::string name;
    std::string comment;
    int         size     = 0;
    int         ordinal  = 0;
    std::string typeName; // resolved type name (e.g. "DWORD", "MyStruct"); empty = unknown
};

struct GhidraEnumValue {
    std::string name;
    int64_t     value   = 0;
    std::string comment;
};

struct GhidraDataType {
    int64_t     id               = 0;
    std::string kind;            // "struct" | "union" | "enum" | "typedef"
    std::string name;
    std::string comment;
    int         size             = 0;
    int64_t     underlyingTypeId = 0;   // typedef only
    std::string underlyingTypeName;     // resolved name for typedefs (e.g. "DWORD" → "uint32_t")
    std::vector<GhidraDataTypeMember> members; // struct/union
    std::vector<GhidraEnumValue>      values;  // enum
};

struct GhidraDataItem {
    uint64_t addr   = 0;
    int64_t  typeId = 0;
};

struct GhidraMemoryBlock {
    std::string name;
    uint64_t    addr        = 0;
    uint64_t    size        = 0;
    bool        read        = true;
    bool        write       = false;
    bool        execute     = false;
    bool        initialized = true;
    bool        overlay     = false; // overlay / non-default address space — skip on apply
};

struct GhidraXrefStats {
    int fromCount = 0;
    int toCount   = 0;
};

/** Changes collected from the BN view that are pending check-in. */
struct GhidraCheckinPreview {
    struct SymbolRename {
        int64_t     key;
        uint64_t    addr;
        std::string originalName;
        std::string newName;
    };
    struct CommentChange {
        uint64_t    addr;
        std::string text;
        std::string encodedKey;
    };
    struct EquateRename {
        int64_t     id;
        std::string name;
    };
    struct BookmarkChange {
        std::string op;       // "add" | "delete"
        std::string type;
        uint64_t    addr     = 0;
        std::string category;
        std::string comment;
    };
    struct ParamRename {
        int64_t     key;
        std::string name;
        std::string typeName;  // empty = no type change
    };
    struct DataTypeChange {
        std::string op;      // "add" | "update"
        std::string kind;    // "struct" | "union" | "enum" | "typedef"
        std::string name;
        int64_t     ghidraId = 0;   // 0 for new types; existing Ghidra DB key for updates
        int         size     = 0;
        std::string underlyingTypeName; // typedef only
        struct Member { std::string name; int offset; int size; std::string typeName; };
        struct Value  { std::string name; int64_t value; };
        std::vector<Member> members;   // struct/union only
        std::vector<Value>  values;    // enum only
    };
    struct DataItemChange {
        std::string op;       // "add" | "delete"
        uint64_t    addr = 0;
        std::string typeName; // BN type name string, e.g. "MyStruct"
    };
    struct FuncSigChange {
        int64_t     key;
        std::string callingConvention;   // "" = no change to CC
        std::string returnTypeName;      // "" = no change to return type
    };
    /** A BN user-defined symbol at an address Ghidra had no symbol record for. */
    struct NewSymbol {
        uint64_t    addr;
        std::string name;
        bool        isFunction; // true → Ghidra Function type; false → Label
    };
    /** A BN user-named parameter or register-local that Ghidra had no record for. */
    struct NewParam {
        uint64_t    funcAddr; // BN address of the owning function
        int         ordinal;  // for params: 0-based index; for reg locals: BN register index
        std::string name;
        std::string typeName; // empty = unknown
        bool        isLocal;  // false = PARAMETER (type=6), true = LOCAL_VAR (type=7)
    };
    /** A new equate binding (addr+opIndex pair not in the Ghidra baseline). */
    struct NewEquateRef {
        int64_t  equateId;
        uint64_t addr;    // BN address of the instruction
        int      opIndex; // operand index within the instruction
    };
    std::vector<SymbolRename>  renames;
    std::vector<CommentChange> comments;
    std::vector<EquateRename>  equateRenames;
    std::vector<BookmarkChange> bookmarkChanges;
    std::vector<ParamRename>   paramRenames;
    std::vector<DataTypeChange> dataTypeChanges;
    std::vector<DataItemChange> dataItemChanges;
    std::vector<FuncSigChange>  funcSigChanges;
    std::vector<NewSymbol>      newSymbols;
    std::vector<NewParam>       newParams;
    std::vector<NewEquateRef>   newEquateRefs;

    bool empty() const {
        return renames.empty() && comments.empty() &&
               equateRenames.empty() && bookmarkChanges.empty() &&
               paramRenames.empty() && dataTypeChanges.empty() &&
               dataItemChanges.empty() && funcSigChanges.empty() &&
               newSymbols.empty() && newParams.empty() &&
               newEquateRefs.empty();
    }
};

/** Everything extracted from one Ghidra program database. */
struct GhidraDbExport {
    std::vector<GhidraSymbol>    symbols;
    std::vector<GhidraComment>   comments;
    std::vector<GhidraFuncFlags> funcFlags;
    std::vector<GhidraFuncSig>   funcSigs;
    std::vector<GhidraEquate>    equates;
    std::vector<GhidraBookmark>  bookmarks;
    std::vector<GhidraParameter> parameters;
    std::vector<GhidraDataType>  dataTypes;
    std::vector<GhidraDataItem>  dataItems;
    std::vector<GhidraMemoryBlock> memoryBlocks;
    GhidraXrefStats              xrefStats;
    std::vector<std::string>     diag;      // diagnostic lines from the bridge
    uint64_t                     imageBase = 0; // Ghidra segment-0 base VA
};

struct GhidraEvent {
    std::string repo;
    std::string type;         // "REP_ITEM_CHANGED" etc.
    std::string parentPath;
    std::string name;
    std::string newParentPath;
    std::string newName;
};

// ---------------------------------------------------------------------------
// GhidraConnection — singleton owning the bridge process/client
// ---------------------------------------------------------------------------

/**
 * High-level API for the Ghidra server connection.
 *
 * Two bridge modes are supported (configured via ghidra.bridgeMode):
 *
 *   "local"   The bridge JAR is spawned as a child process on the same
 *             machine as Binary Ninja.  Convenient for single-machine
 *             setups (development, BN + Ghidra on the same host).
 *
 *   "remote"  The bridge runs as a persistent service on the Ghidra server
 *             machine (started with server/start-bridge.sh).  Binary Ninja
 *             connects to it over the network — no Java required on the
 *             BN client machine.
 *
 * All methods that contact the server block the calling thread — run them
 * from BN background tasks, not from the main/UI thread.
 */
class GhidraConnection {
public:
    static GhidraConnection& instance();

    GhidraConnection(const GhidraConnection&) = delete;
    GhidraConnection& operator=(const GhidraConnection&) = delete;

    // -----------------------------------------------------------------------
    // Bridge lifecycle
    // -----------------------------------------------------------------------

    /**
     * Ensure the bridge is ready, using whichever mode is configured.
     *
     * In "local" mode: spawns the bridge JAR as a child process (safe to call
     * repeatedly — no-ops if already running).
     *
     * In "remote" mode: opens a TCP connection to the bridge service running
     * on @p remoteHost at ghidra.bridgePort (safe to call if already connected).
     *
     * Called automatically by connectToServer(); you only need to call this
     * directly if you want to pre-warm the connection.
     */
    bool connectBridge(const std::string& remoteHost, std::string& errorOut);

    /** Disconnect from the bridge (and implicitly from the Ghidra server).
     *  In local mode, also terminates the bridge child process. */
    void disconnectBridge();

    bool isBridgeConnected() const;

    // -----------------------------------------------------------------------
    // Server connection
    // -----------------------------------------------------------------------

    bool connectToServer(const std::string& host, int port,
                         const std::string& user, const std::string& password,
                         std::string& errorOut);
    void disconnectFromServer();
    bool isServerConnected() const { return m_serverConnected; }
    const std::string& connectedUser() const { return m_user; }
    const std::string& connectedHost() const { return m_host; }
    int                connectedPort() const { return m_port; }

    // -----------------------------------------------------------------------
    // Repository operations  (all block; call from background thread)
    // -----------------------------------------------------------------------

    std::vector<std::string> listRepos(std::string& errorOut);

    bool openRepo(const std::string& repo, std::string& errorOut);
    void closeRepo(const std::string& repo);

    std::vector<RepoItem>   listItems(const std::string& repo,
                                       const std::string& folder,
                                       std::string& errorOut);
    std::vector<std::string> getSubfolders(const std::string& repo,
                                            const std::string& folder,
                                            std::string& errorOut);
    std::vector<VersionInfo> getVersions(const std::string& repo,
                                          const std::string& folder,
                                          const std::string& item,
                                          std::string& errorOut);
    std::vector<CheckoutInfo> getCheckouts(const std::string& repo,
                                            const std::string& folder,
                                            const std::string& item,
                                            std::string& errorOut);

    CheckoutInfo checkout(const std::string& repo,
                          const std::string& folder,
                          const std::string& item,
                          const std::string& checkoutType,
                          std::string& errorOut);

    GhidraDbExport openDatabase(const std::string& repo,
                                const std::string& folder,
                                const std::string& item,
                                int version,
                                std::string& errorOut);

    struct BinaryFile {
        std::string          filename;
        std::vector<uint8_t> bytes;
    };

    std::vector<BinaryFile> downloadBinary(const std::string& repo,
                                           const std::string& folder,
                                           const std::string& item,
                                           int version,
                                           std::string& errorOut);

    bool uploadBinary(const std::string& repo,
                      const std::string& folder,
                      const std::string& item,
                      const std::vector<uint8_t>& bytes,
                      const std::string& comment,
                      bool keepCheckout,
                      const std::string& analysisJson,
                      std::string& errorOut);

    bool terminateCheckout(const std::string& repo,
                           const std::string& folder,
                           const std::string& item,
                           int64_t checkoutId,
                           std::string& errorOut);

    bool deleteItem(const std::string& repo,
                    const std::string& folder,
                    const std::string& item,
                    std::string& errorOut);

    // -----------------------------------------------------------------------
    // Write-back (check in BN annotations to Ghidra server)
    // -----------------------------------------------------------------------

    void storeCheckinState(
        std::unordered_map<uint64_t, int64_t>     addrToKey,
        std::unordered_map<uint64_t, std::string> addrToOriginalName,
        std::unordered_map<uint64_t, std::string> addrToCommentKey,
        std::unordered_map<uint64_t, std::string> addrToOriginalComment,
        std::unordered_map<uint64_t, std::string> addrToOriginalFuncComment,
        std::unordered_map<uint64_t, std::string> addrToCommentField,
        std::vector<GhidraDataType>               ghidraDataTypes,
        std::vector<GhidraParameter>              parameters,
        std::vector<GhidraBookmark>               bookmarks,
        std::vector<GhidraDataItem>               dataItems,
        std::vector<GhidraEquate>                 equates,
        std::vector<GhidraFuncSig>                funcSigs,
        uint64_t imageBase,
        const std::string& repo,
        const std::string& folder,
        const std::string& item);

    GhidraCheckinPreview collectCheckinChanges(
        BinaryNinja::Ref<BinaryNinja::BinaryView> view) const;

    bool checkin(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
                 const GhidraCheckinPreview& preview,
                 const std::string& comment,
                 std::string& errorOut);

    bool hasCheckinState() const { return !m_checkinItem.empty(); }
    bool isCheckinItem(const std::string& repo, const std::string& folder,
                       const std::string& item) const {
        return m_checkinRepo == repo && m_checkinFolder == folder && m_checkinItem == item;
    }
    const std::string& checkinRepo()   const { return m_checkinRepo; }
    const std::string& checkinFolder() const { return m_checkinFolder; }
    const std::string& checkinItem()   const { return m_checkinItem; }
    /** Drop all in-memory check-in state (address maps + item coordinates).
     *  Call after a successful check-in or checkout termination so the context
     *  menu reverts to showing "Check Out…" for the next editing round. */
    void clearCheckinState();

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    using EventHandler = std::function<void(GhidraEvent)>;
    void setEventHandler(EventHandler h);

    // -----------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------

    std::string bridgeMode()  const; // "local" | "remote"
    int         bridgePort()  const;
    std::string javaExe()     const;
    std::string bridgeJar()   const;
    std::string ghidraHome()  const;
    bool        trustAll()    const;

private:
    GhidraConnection() = default;

    // Local mode: bridge child process.
    std::unique_ptr<BridgeProcess> m_process;
    // Both modes: JSON-over-TCP client connected to the bridge.
    std::unique_ptr<BridgeClient>  m_client;

    bool        m_serverConnected = false;
    std::string m_user;
    std::string m_host;
    int         m_port = 0;

    EventHandler m_eventHandler;

    // Session password — stored ephemerally; cleared on disconnect.
    std::string m_password;

    // Checkin state — populated by storeCheckinState() after each import.
    std::unordered_map<uint64_t, int64_t>     m_addrToKey;
    std::unordered_map<uint64_t, std::string> m_addrToOriginalName;
    std::unordered_map<uint64_t, std::string> m_addrToCommentKey;
    std::unordered_map<uint64_t, std::string> m_addrToOriginalComment;
    std::unordered_map<uint64_t, std::string> m_addrToOriginalFuncComment;
    std::unordered_map<uint64_t, std::string> m_addrToCommentField; // addr → "eol"/"pre"/"post"/"rep"
    std::unordered_map<std::string, GhidraDataType> m_ghidraTypesByName;

    // Parameter baseline — keyed by Ghidra symbol key
    std::unordered_map<int64_t, std::string>  m_paramOriginalNameByKey;
    std::unordered_map<int64_t, std::string>  m_paramOriginalTypeByKey; // key → type name at checkout
    // (ghidraFuncAddr, ordinal) → Ghidra symbol key.  Params (ordinal = index)
    // and stack locals (ordinal = stack offset) live in separate maps: both
    // number from 0, so a shared map would let a parameter baseline swallow a
    // stack variable at offset 0 (e.g. BN's __return_addr) and vice versa.
    std::unordered_map<uint64_t, std::unordered_map<int, int64_t>> m_paramKeyByAddrOrdinal;
    std::unordered_map<uint64_t, std::unordered_map<int, int64_t>> m_localKeyByAddrOffset;
    // New params checked in since last checkout (ghidraFuncAddr → ordinal → name at last check-in).
    // Prevents re-queuing params that were already sent to Ghidra but have no DB key yet.
    std::unordered_map<uint64_t, std::unordered_map<int, std::string>> m_newParamBaseline;
    // New register-local vars checked in since last checkout (ghidraFuncAddr → bnRegIdx → name).
    // Separate from m_newParamBaseline to avoid ordinal collisions with param indices (both start at 0).
    std::unordered_map<uint64_t, std::unordered_map<int, std::string>> m_newRegLocalBaseline;

    // Bookmark baseline — set of (ghidraVA, tagTypeName, tagData) tuples
    struct BookmarkKey {
        uint64_t    addr;
        std::string tagTypeName; // "Ghidra: Note" etc.
        std::string tagData;
        bool operator==(const BookmarkKey& o) const {
            return addr == o.addr && tagTypeName == o.tagTypeName && tagData == o.tagData;
        }
    };
    struct BookmarkKeyHash {
        size_t operator()(const BookmarkKey& k) const {
            size_t h = std::hash<uint64_t>{}(k.addr);
            h ^= std::hash<std::string>{}(k.tagTypeName) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<std::string>{}(k.tagData)     + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_set<BookmarkKey, BookmarkKeyHash> m_ghidraBookmarkKeys;
    std::set<std::string>                            m_ghidraTagTypeNames;

    // Data item baseline — Ghidra VAs that had data items at checkout
    std::unordered_set<uint64_t> m_ghidraDataItemAddrs;

    // Equate baseline — id → name at checkout, id → value (for type lookup)
    std::unordered_map<int64_t, std::string> m_equateOriginalNameById;
    std::unordered_map<int64_t, int64_t>     m_equateValueById;
    // Equate ref baseline: equateId → set of (ghidraVA, opIndex) at checkout.
    // Used to detect new bindings the user applied in BN since checkout.
    struct EquateRefKey {
        uint64_t addr;
        int      opIndex;
        bool operator==(const EquateRefKey& o) const {
            return addr == o.addr && opIndex == o.opIndex;
        }
    };
    struct EquateRefKeyHash {
        size_t operator()(const EquateRefKey& k) const {
            return std::hash<uint64_t>{}(k.addr) ^
                   (std::hash<int>{}(k.opIndex) * 0x9e3779b9u);
        }
    };
    std::unordered_map<int64_t,
        std::unordered_set<EquateRefKey, EquateRefKeyHash>> m_equateRefsByEquateId;

    // Function signature baseline — keyed by Functions table key
    std::unordered_map<int64_t, std::string> m_funcOriginalCC;         // key → CC name at checkout
    std::unordered_map<int64_t, std::string> m_funcOriginalRetType;    // key → return type name at checkout
    std::unordered_map<int64_t, int64_t>     m_funcReturnTypeId;       // key → Ghidra return type ID

    uint64_t    m_imageBase   = 0;
    std::string m_checkinRepo, m_checkinFolder, m_checkinItem;

    // Internal: start the local bridge process and connect the client to it.
    bool startLocalBridge(std::string& errorOut);

    void onBridgeEvent(nlohmann::json evt);

    // Auto-detection helpers (local mode only).
    static std::string autoDetectBridgeJar();
    static std::string autoDetectGhidraHome();

    static RepoItem     itemFromJson(const nlohmann::json& j);
    static CheckoutInfo checkoutFromJson(const nlohmann::json& j);
    static VersionInfo  versionFromJson(const nlohmann::json& j);
};
