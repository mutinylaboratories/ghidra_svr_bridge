#!/usr/bin/env python3
"""Generate parity_x64.bin — the raw x86-64 blob used by the parity test suite.

The output is deterministic: running this script always produces byte-identical
output. It is checked in alongside the generated binary; re-run only when the
fixture layout needs to change, and update parity_x64.md to match.

The blob is loaded by tests with the Mapped loader (no PE/ELF header), platform
windows-x86_64, at image base 0x400000 (matching the Ghidra-side
ProgramTestBase) or any other base for rebase tests. All functions are created
by the tests themselves — analysis auto-discovery is never relied on.
"""

import struct
import sys
from pathlib import Path

SIZE = 512
blob = bytearray(b"\xcc" * SIZE)  # int3 filler: anything unexpected traps


def put(offset: int, data: bytes) -> None:
    blob[offset : offset + len(data)] = data


# --- code region -----------------------------------------------------------

# 0x000 func_ret: the smallest possible function.
#   ret
put(0x000, bytes.fromhex("c3"))

# 0x010 func_equate: immediate operand 500 (0x1F4) for equate tests
# (operand index 1 of the mov).
#   mov eax, 0x1F4
#   ret
put(0x010, bytes.fromhex("b8f4010000" "c3"))

# 0x020 func_frame: rbp-framed body with a stack local at [rbp-8]
# for stack-local variable tests.
#   push rbp
#   mov rbp, rsp
#   sub rsp, 0x20
#   mov [rbp-8], ecx
#   mov eax, [rbp-8]
#   add rsp, 0x20
#   pop rbp
#   ret
put(0x020, bytes.fromhex("55" "4889e5" "4883ec20" "894df8" "8b45f8" "4883c420" "5d" "c3"))

# 0x040 func_thunk: unconditional jump to func_ret — thunk-flag tests.
#   jmp func_ret   (rel32 = 0x000 - (0x040 + 5) = -0x45)
put(0x040, b"\xe9" + struct.pack("<i", 0x000 - (0x040 + 5)))

# 0x050 func_noret: infinite loop — no-return-flag tests.
#   jmp $
put(0x050, bytes.fromhex("ebfe"))

# --- data region (0x100..0x1FF) ---------------------------------------------

# 0x100: 8 bytes for a two-int32 struct data item ("Point"-shaped).
put(0x100, struct.pack("<ii", 3, 4))

# 0x110: a plain int32 data item.
put(0x110, struct.pack("<i", 500))

# 0x120: NUL-terminated string data.
put(0x120, b"GHIDRA\x00")

# Zero the rest of the data page so uninitialised-looking data reads cleanly.
for off in range(0x100, 0x200):
    if blob[off] == 0xCC:
        blob[off] = 0x00

out = Path(__file__).parent / "parity_x64.bin"
out.write_bytes(bytes(blob))
print(f"wrote {out} ({len(blob)} bytes)", file=sys.stderr)
