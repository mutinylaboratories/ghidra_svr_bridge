#pragma once
#include "GhidraConnection.h"
#include <binaryninjaapi.h>
#include <nlohmann/json.hpp>

namespace parity {

/**
 * Walk a BinaryView and emit its Ghidra-syncable state in the canonical JSON
 * shape produced by the bridge's DatabaseExporter (snake_case keys, hex addr
 * strings). Addresses are converted to Ghidra space with
 * `ghidraAddr = bnAddr − (view start − reference.imageBase)`, so the output
 * is directly comparable against a golden canonical export regardless of the
 * base the view was loaded at.
 *
 * @p reference supplies probe points for state BN cannot enumerate:
 *  - equates: BN stores them as display overrides keyed by
 *    (address, value, operand); the exporter probes each reference ref site
 *    and emits only the refs that actually read back.
 *  - comment column routing: BN has one comment slot per address; the column
 *    (`eol`/`pre`/`post`/`rep`) is reconstructed from the reference comment
 *    at the same address, defaulting to `eol`.
 *
 * Auto-generated names (sub_/FUN_/off_/unk_/j_ + hex, arg/param_/var_/local_)
 * are never emitted — only user-meaningful state takes part in parity.
 */
nlohmann::json bnCanonicalExport(BinaryNinja::Ref<BinaryNinja::BinaryView> view,
                                 const GhidraDbExport& reference);

} // namespace parity
