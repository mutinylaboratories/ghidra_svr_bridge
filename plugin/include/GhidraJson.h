#pragma once
#include "GhidraConnection.h"
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

// JSON <-> data-model conversion for the bridge protocol, extracted from
// GhidraConnection so the mapping can be exercised in tests without a live
// bridge connection.
namespace ghidra_json {

std::string toHex(uint64_t v);
uint64_t    parseHexAddr(const std::string& s);

/**
 * Decode a bridge `open_db` response into the plugin data model.
 *
 * Reads the category arrays (`symbols`, `comments`, `func_flags`, `equates`,
 * `bookmarks`, `parameters`, `data_types`, `data_items`, `memory_blocks`,
 * `xref_stats`, `diag`) plus `image_base`; transport fields (`ok`, `id`,
 * `error`) are ignored. Missing arrays yield empty vectors.
 */
GhidraDbExport parseDbExportJson(const nlohmann::json& resp);

/**
 * Encode a check-in preview as the bridge `checkin` request body — the nine
 * category arrays only (`symbols`, `comments`, `equate_renames`,
 * `equate_ref_adds`, `bookmark_changes`, `param_renames`,
 * `data_type_changes`, `data_item_changes`, `func_sig_changes`). The caller
 * adds transport/coordinate fields (`op`, `repo`, `folder`, `item`,
 * `comment`).
 *
 * @p rebase is bnBase − ghidraImageBase; all addresses are emitted in Ghidra
 * space (`bnAddr − rebase`). The two maps route an edited comment back to the
 * Ghidra column it was imported from: addresses present in
 * @p addrToOriginalFuncComment go to the `plate` column, otherwise
 * @p addrToCommentField supplies the column ("eol"/"pre"/"post"/"rep",
 * defaulting to "eol" for brand-new comments).
 */
nlohmann::json buildCheckinJson(
    const GhidraCheckinPreview& preview,
    int64_t rebase,
    const std::unordered_map<uint64_t, std::string>& addrToOriginalFuncComment,
    const std::unordered_map<uint64_t, std::string>& addrToCommentField);

} // namespace ghidra_json
