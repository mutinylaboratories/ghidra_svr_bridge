#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace parity {

/**
 * Canonicalize a type name into the shared stdint-family spelling used by
 * both sides of the parity comparison (rules in testdata/parity/RULES.md,
 * mirrored by the Java CanonicalAssert). Handles pointer ("T *" → "T*") and
 * array ("T [4]" → "T[4]") spellings recursively.
 */
std::string normalizeTypeName(const std::string& name);

/**
 * Compare a golden canonical export against a BN-side canonical export
 * (produced by bnCanonicalExport). Returns a list of human-readable issues;
 * empty means the two databases store the same compatible data.
 *
 * Per-category modes (RULES.md):
 *  - symbols, comments, equates, bookmarks, data items: EXACT set match
 *  - parameters: EXACT for params and stack locals in the golden
 *  - data types: golden→BN (extra BN-only types are not failures)
 *  - func_flags: IMPORT_ONLY — golden flags/cc/ret_type must appear in BN;
 *    fields absent from the golden are not compared
 *  - memory_blocks: presence of each non-overlay golden block as a section
 *  - xref_stats, DB keys/ids: IGNORED (identity, not content)
 */
std::vector<std::string> compareCanonical(const nlohmann::json& golden,
                                          const nlohmann::json& bnExport);

} // namespace parity
