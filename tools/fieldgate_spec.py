#!/usr/bin/env python3
"""Emit the field-gating SLEIGH spec (P1 experiment — documented negative result).

Replaces the arithmetic context constraint (``byte = C + key - 1``) with fully
constant patterns gated by a context FIELD: ``key = K & byte = ENC_K(op)``.

RESULT: the field-gating ALSO breaks the disassembler fall-through (1
instruction), even with the key pinned per address by
``ghidra/ApplyContext.java``. A context variable in the opcode-byte constraint
breaks the fall-through regardless of field vs equation; the context-as-field
mechanism only supports fall-through when it selects length/operand size, not
the opcode value. The working path is ``tools/decrypt_bytecode.py`` (decrypt to
clear + constant patterns, no context).

Usage::

    python tools/fieldgate_spec.py <blob> <out.slaspec>
"""
from __future__ import annotations

import struct
import sys

ENGINE = 0x1AE1000
BC_OFF = 0x6575          # bytecode program entry
TAB_OFF = 0x5000         # dispatch table (256 x u32: opcode -> handler offset)
INITIAL_KEY = 0x75       # low byte of the dispatcher's initial key (0x407575)

# handler offset -> operand length (bytes following the encrypted opcode).
OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

_CONTROL_FLOW = frozenset({0x304, 0x7E9})  # jmp / ret_native
_MAX_CONSTRUCTORS = 300


def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def decrypt(byte: int, key: int) -> int:
    cl = (byte - key) & 0xFF
    cl = (cl + 1) & 0xFF
    cl = ror8(cl, 4)
    cl = (cl - 0x85) & 0xFF
    cl = (~cl) & 0xFF
    return cl


def main(argv: list[str]) -> int:
    blob_path = argv[0] if len(argv) > 0 else "data/vm_dbin.bin"
    out_path = argv[1] if len(argv) > 1 else "data/_fieldgate.slaspec"

    dbin = open(blob_path, "rb").read()
    tbl = struct.unpack_from("<256I", dbin, TAB_OFF)

    key = INITIAL_KEY
    pc = BC_OFF
    seen: set[tuple[int, int]] = set()  # (key, encrypted byte)
    while pc < len(dbin) and len(seen) < _MAX_CONSTRUCTORS:
        byte = dbin[pc]
        op = decrypt(byte, key)
        seen.add((key, byte))
        key = (key - op) & 0xFF
        hoff = tbl[op] - ENGINE
        olen = OPERAND_LEN.get(hoff, 0)
        pc += 1 + olen
        if op in _CONTROL_FLOW:
            break

    lines = [
        "define endian=little;",
        "define alignment=1;",
        "define space ram type=ram_space size=4 default;",
        "define space register type=register_space size=4;",
        "define token instr(8)",
        "  byte=(0,7)",
        ";",
        "define register offset=0x0 size=4 [ VPC VSP ];",
        "define register offset=0x2000 size=4 contextreg;",
        "define context contextreg",
        "  key=(0,7)",
        "  ;",
        "",
    ]
    for k, b in sorted(seen):
        lines.append(
            f":op_k{k:02X}_b{b:02X} is key = 0x{k:02X} & byte = 0x{b:02X} {{"
        )
        lines.append("  tmp1:4 = *:4 0x7FFF0000:4;")
        lines.append("}")
        lines.append("")
    spec = "\n".join(lines)
    open(out_path, "w", encoding="utf-8").write(spec)

    print(f"emitted {len(seen)} field-gated constructors to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
