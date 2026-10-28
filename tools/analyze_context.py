#!/usr/bin/env python3
"""Analyze the rolling-key context: sweep the bytecode, decrypt the opcodes,
and emit the per-address key map consumed by ``ghidra/ApplyContext.java``.

This is the paper's §5.4 technique made concrete: instead of relying on
Ghidra's best-effort ``globalset`` context flow, we pre-compute the rolling key
at each opcode address and pin it via the Ghidra program context.

NOTE (documented result): the per-address key map alone does NOT restore the
disassembler fall-through — an arithmetic context constraint breaks it at the
flow-analysis level, not the context-availability level. Use
``tools/decrypt_bytecode.py`` for a working decode.

Usage::

    python tools/analyze_context.py <blob> <context.txt>

The output is one ``<offset_hex> <key_hex>`` pair per line.
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
_MAX_INSTRUCTIONS = 300


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
    out_path = argv[1] if len(argv) > 1 else "data/context.txt"

    dbin = open(blob_path, "rb").read()
    tbl = struct.unpack_from("<256I", dbin, TAB_OFF)

    key = INITIAL_KEY
    pc = BC_OFF
    pairs: list[tuple[int, int]] = []
    while pc < len(dbin) and len(pairs) < _MAX_INSTRUCTIONS:
        op = decrypt(dbin[pc], key)
        pairs.append((pc, key))  # key BEFORE decrypting this opcode
        key = (key - op) & 0xFF
        hoff = tbl[op] - ENGINE
        olen = OPERAND_LEN.get(hoff, 0)
        pc += 1 + olen
        if op in _CONTROL_FLOW:
            break

    with open(out_path, "w", encoding="utf-8") as fh:
        for off, k in pairs:
            fh.write(f"{off:x} {k:02x}\n")

    print(f"emitted {len(pairs)} (offset, key) pairs to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
