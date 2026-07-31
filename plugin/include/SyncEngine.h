#pragma once
#include "GhidraConnection.h"
#include <binaryninjaapi.h>
#include <unordered_map>

struct SyncResult {
    int      symbolsApplied  = 0;
    int      commentsApplied = 0;
    int      flagsApplied    = 0;
    int      functionsCreated = 0;
    int      sectionsAdded   = 0;
    int      segmentsAdded   = 0;
    uint64_t addrMin         = UINT64_MAX;
    uint64_t addrMax         = 0;
    std::string sampleSymbol;

    // Write-back maps — passed to GhidraConnection::storeCheckinState().
    std::unordered_map<uint64_t, int64_t>     addrToKey;             // bnAddr → symbol key
    std::unordered_map<uint64_t, std::string> addrToOriginalName;    // bnAddr → original name
    std::unordered_map<uint64_t, std::string> addrToCommentKey;      // bnAddr → encoded Ghidra addr
    std::unordered_map<uint64_t, std::string> addrToOriginalComment;     // bnAddr → imported address-level comment
    std::unordered_map<uint64_t, std::string> addrToOriginalFuncComment; // bnAddr → imported plate/function comment
    std::unordered_map<uint64_t, std::string> addrToCommentField;        // bnAddr → Ghidra column ("eol","pre","post","rep")
    std::vector<GhidraDataType>  ghidraDataTypes; // baseline — all types Ghidra had at checkout
    std::vector<GhidraParameter> parameters;      // for param baseline
    std::vector<GhidraBookmark>  bookmarks;        // for bookmark baseline
    std::vector<GhidraDataItem>  dataItems;        // for data-item baseline
    std::vector<GhidraEquate>    equates;          // equate baseline for rename detection
    std::vector<GhidraFuncSig>   funcSigs;         // function signature baseline
    uint64_t imageBase = 0;  // Ghidra segment-0 VA, needed for encoding new comment addresses
};

/**
 * Applies a GhidraDbExport to a Binary Ninja BinaryView.
 *
 * All methods block; call from a BN background worker thread, never from the
 * UI thread.
 */
class SyncEngine {
public:
    static SyncResult applyToView(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
                                  const GhidraDbExport& data);

    /**
     * Build the address↔key write-back maps from @p data WITHOUT modifying
     * @p view.  Used to restore check-in state after a restart (where
     * the user may have pending BN renames that must not be overwritten).
     */
    static SyncResult buildWritebackMaps(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
                                         const GhidraDbExport& data);

private:
    static BinaryNinja::Ref<BinaryNinja::TagType>
        getOrCreateTagType(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
                           const std::string& name);
};
