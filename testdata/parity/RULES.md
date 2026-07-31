# Canonical parity rules

Shared contract between the C++ comparator (`plugin/test/support/CanonicalDiff.cpp`)
and the Java comparator (`bridge/src/test/java/com/ghidra_svr/bridge/CanonicalAssert.java`).
Both consume the same golden fixtures in `testdata/parity/fixtures/`. When you
change a rule here, change **both** implementations.

## Canonical form

The canonical model is the bridge `DatabaseExporter` JSON shape: snake_case
keys, addresses as `0x…` hex strings **in Ghidra address space**. The BN-side
exporter converts with `ghidraAddr = bnAddr − (bnBase − image_base)`; rebase is
therefore a pure test parameter and goldens never change with the load base.

## Compare modes per category

| Category | Mode | Notes |
|---|---|---|
| symbols | EXACT (both directions) | match on (addr, name, type 0/4/8); auto-generated names (`sub_/FUN_/off_/unk_/j_/data_` + hex, `arg*/param_*/var_*/local_*`) are excluded from the BN export before comparison; `source` and `ns`/`key` ids are identity, not content |
| comments | EXACT (both directions) | compared as (addr, column, text); goldens use a **single column per address** — BN has one comment slot per address, so multi-column Ghidra comments import merged and cannot round-trip per-column; `plate` = BN function comment |
| func_flags | IMPORT_ONLY | golden `thunk`/`no_ret`/`inline` must appear as BN `Ghidra: *` function tags; `cc`/`ret_type` compared only when set in the golden; nothing is pushed back |
| equates | EXACT (golden → BN) | matched by name; value + every golden ref (addr, op_index) must read back from BN's integer display overrides |
| bookmarks | EXACT (both directions) | (type, addr, category, comment); BN encodes as data tag `Ghidra: <type>` with `[category] comment` data |
| parameters | EXACT for params + stack locals | slot key = (func_addr, is_param, ordinal); ordinal = parameter index for params, stack offset for locals; **register locals are excluded from goldens** (BN↔Ghidra register storage mapping not implemented) |
| data_types | golden → BN | matched by name; struct/union: size + members by offset (name, normalized type); enum: full value-set + width; typedef: normalized underlying name; extra BN-only types are not failures; DB `id` is identity |
| data_items | golden → BN | (addr, resolved type name); golden `type_id` resolves through golden `data_types` |
| memory_blocks | presence | each non-overlay golden block must exist as a BN section (name, addr) |
| xref_stats | IGNORED | diagnostics only |

## Type-name normalization

Both comparators canonicalize type names into the stdint family before
comparing (table below, applied recursively through `T*` and `T[N]`; spaces
around `*`/`[` stripped; `struct/union/enum ` prefixes dropped):

| aliases | canonical |
|---|---|
| int, long | int32_t |
| uint, ulong, dword, undefined4 | uint32_t |
| byte, uchar, undefined1 | uint8_t |
| sbyte, char | int8_t |
| short | int16_t |
| ushort, word, undefined2 | uint16_t |
| longlong | int64_t |
| ulonglong, qword, undefined8 | uint64_t |
| bool, float, double | unchanged |

## Checkin-direction goldens

Checkin fixtures are triples in `fixtures/checkin/<name>/`:

- `baseline.json` — canonical DB state at checkout time
- `edits.json` — declarative description of the BN-side edits the C++ test
  performs (documentation for humans; the test code is authoritative)
- `expected-preview.json` — the checkin request body `buildCheckinJson` must
  produce (the nine category arrays)
- `expected-after.json` — canonical DB state after the Java side applies
  `expected-preview.json` via `ProgramApplier` and re-exports

If the C++ side produces `expected-preview.json` from the edits and the Java
side produces `expected-after.json` from that preview, the two databases agree
by transitivity.
