#!/usr/bin/env python3
"""Phase-6 MVP: decrypt the VM bytecode to a clear image and emit a SLEIGH spec
against the clear (constant ``byte = opcode``) encoding.

Why this exists
---------------
The VMSpec pipeline models the rolling opcode key as a SLEIGH *context
variable* in the constructor pattern (``byte = C + key - 1``). That is the
correct paper-level model, but Ghidra's context flow is best-effort and
asynchronous (SLEIGH §8.3: a context change is only "a suggestion to the
disassembly engine"), so the context-dependent pattern breaks the disassembler
fall-through: each successor only parses if the committed key is already
available before its parse, otherwise no constructor matches and the chain
dies.

The paper resolves this with a Java analyzer that pins the context per
successor address (§5.4). This script is the *lighter* MVP that validates
phase 6: it decrypts the opcode bytes up-front (size-preserving) and emits a
spec with constant patterns, which chains cleanly.

Scope / limitations
-------------------
* Decrypts opcode bytes only; operand bytes are left untouched (still
  encrypted) and decode as "unknown".
* The linear walk stops at control-flow handlers (``jmp 0x304`` /
  ``ret_native 0x7E9``) because it cannot follow computed targets.
* Addresses are not relocated (size-preserving rewrite of the same blob).

Usage::

    python tools/decrypt_bytecode.py <blob> <out_clear.bin> <out_clear.slaspec>
"""
from __future__ import annotations

import struct
import sys

# VM-relative constants (see tools/gen_config.py; ENGINE is the host base).
ENGINE = 0x1AE1000
BC_OFF = 0x6575          # bytecode program entry
TAB_OFF = 0x5000         # dispatch table (256 x u32: opcode -> handler offset)
INITIAL_KEY = 0x75       # low byte of the dispatcher's initial key (0x407575)

# handler offset -> operand length (bytes following the encrypted opcode).
# Extracted from the reconstructed interpreter semantics (ettool2_vm.cpp).
OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

# Control-flow handlers: the linear walk cannot follow their computed targets.
_CONTROL_FLOW = frozenset({0x304, 0x7E9})  # jmp / ret_native

_MAX_INSTRUCTIONS = 300


def ror8(x: int, n: int) -> int:
    x &= 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def decrypt(byte: int, key: int) -> int:
    """Inverse of the dispatcher's opcode decryption (``key -= opcode``)."""
    cl = (byte - key) & 0xFF
    cl = (cl + 1) & 0xFF
    cl = ror8(cl, 4)
    cl = (cl - 0x85) & 0xFF
    cl = (~cl) & 0xFF
    return cl


def _clear_spec() -> str:
    """Emit the 256-constructor clear spec (constant patterns, no context)."""
    lines = [
        "define endian=little;",
        "define alignment=1;",
        "define space ram type=ram_space size=4 default;",
        "define space register type=register_space size=4;",
        "define token instr(8)",
        "  byte=(0,7)",
        ";",
        "define register offset=0x0 size=4 [ VPC VSP ];",
        "",
    ]
    for opcode in range(256):
        lines.append(f":op_{opcode:02X} is byte = 0x{opcode:02X} {{")
        lines.append("  tmp1:4 = *:4 0x7FFF0000:4;")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    blob_path = argv[0] if len(argv) > 0 else "data/vm_dbin.bin"
    out_clear = argv[1] if len(argv) > 1 else "data/_clear.bin"
    out_spec = argv[2] if len(argv) > 2 else "data/_clear.slaspec"

    dbin = open(blob_path, "rb").read()
    tbl = struct.unpack_from("<256I", dbin, TAB_OFF)

    # Walk the bytecode program, decrypting opcodes (size-preserving).
    clear = bytearray(dbin)
    key = INITIAL_KEY
    pc = BC_OFF
    trace: list[tuple[int, int, int]] = []  # (offset, opcode, operand_len)
    while pc < len(dbin):
        op = decrypt(dbin[pc], key)
        key = (key - op) & 0xFF
        hoff = tbl[op] - ENGINE
        olen = OPERAND_LEN.get(hoff, 0)
        clear[pc] = op  # replace encrypted opcode with clear opcode
        trace.append((pc, op, olen))
        pc += 1 + olen
        if op in _CONTROL_FLOW or len(trace) >= _MAX_INSTRUCTIONS:
            break

    open(out_clear, "wb").write(bytes(clear))
    open(out_spec, "w", encoding="utf-8").write(_clear_spec())

    print(f"decrypted {len(trace)} instructions (bytes {BC_OFF:#x}..{pc:#x})")
    print(f"first opcodes: {[hex(o) for _, o, _ in trace[:12]]}")
    print(f"wrote {out_clear} + {out_spec}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
