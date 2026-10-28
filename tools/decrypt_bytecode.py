#!/usr/bin/env python3
"""Phase-6 MVP: decrypt the VM bytecode to a clear image and emit a SLEIGH spec
against the clear (constant ``byte = opcode``) encoding.

Why this exists
---------------
The VMSpec pipeline models the rolling opcode key as a SLEIGH *context
variable* in the constructor pattern (``byte = C + key - 1``). That is the
correct paper-level model, but Ghidra's disassembler cannot chain fall-through
across an opcode-byte constraint that depends on context — regardless of
whether the context is used as an equation or as a field (both were probed and
fail). The working path is this: decrypt the opcode bytes up-front with a
flow-sensitive sweep (:mod:`vmspec.sweep`) and emit constant patterns, which
chain cleanly.

Scope / limitations
-------------------
* Decrypts opcode bytes only; operand bytes are left untouched (still
  encrypted) and decode as "unknown".
* The sweep stops at control-flow handlers (``jmp`` 0x304 / ``ret_native``
  0x7E9) because it cannot follow computed targets.
* Addresses are not relocated (size-preserving rewrite of the same blob).

Usage::

    python tools/decrypt_bytecode.py <blob> <out_clear.bin> <out_clear.slaspec>
"""
from __future__ import annotations

import struct
import sys

from vmspec.operand import decrypt_operand, handler_key_update
from vmspec.sweep import sweep

# VM-relative constants (see tools/gen_config.py; ENGINE is the host base).
ENGINE = 0x1AE1000
BC_OFF = 0x6575          # bytecode program entry
TAB_OFF = 0x5000         # dispatch table (256 x u32: opcode -> handler offset)
INITIAL_KEY = 0x407575   # dispatcher's initial 32-bit rolling key

# handler offset -> operand length (bytes following the encrypted opcode).
# Extracted from the reconstructed interpreter semantics (ettool2_vm.cpp).
OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

_CONTROL_FLOW_OFF = frozenset({0x304, 0x7E9})  # handler offsets: jmp / ret_native


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

    def step(op: int, addr: int, key: int, dbin: bytes):
        """Decrypt the operand + apply the handler's key update."""
        hoff = tbl[op] - ENGINE
        olen = OPERAND_LEN.get(hoff, 0)
        operand = dbin[addr + 1:addr + 1 + olen]
        clear = decrypt_operand(hoff, operand, key)
        next_key = handler_key_update(hoff, clear or b"", key)
        return addr + 1 + olen, next_key, clear

    # control-flow opcodes = table indices whose handler offset is jmp/ret_native
    control_flow = frozenset(
        op for op in range(256) if tbl[op] - ENGINE in _CONTROL_FLOW_OFF
    )
    result = sweep(dbin, BC_OFF, INITIAL_KEY, step, control_flow=control_flow)

    # materialize the clear image (size-preserving: opcode + operands -> clear)
    clear = bytearray(dbin)
    for addr, op in result.opcode_at.items():
        clear[addr] = op  # clear opcode
        operand = result.operand_at.get(addr)
        if operand:
            clear[addr + 1:addr + 1 + len(operand)] = operand

    open(out_clear, "wb").write(bytes(clear))
    open(out_spec, "w", encoding="utf-8").write(_clear_spec())

    first = sorted(result.opcode_at.items())[:12]
    n_operands = sum(1 for o in result.operand_at.values() if o is not None)
    print(f"decrypted {len(result.opcode_at)} instructions ({result.states} states)")
    print(f"first opcodes: {[hex(o) for _, o in first]}")
    print(f"operands decrypted: {n_operands}")
    if result.conflicts:
        print(f"WARNING: {len(result.conflicts)} key conflicts: "
              f"{[f'0x{a:x}:[0x{k1:08x},0x{k2:08x}]' for a, k1, k2 in result.conflicts[:5]]}")
    print(f"wrote {out_clear} + {out_spec}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
