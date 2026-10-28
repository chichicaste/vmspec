#!/usr/bin/env python3
"""Phase-6 MVP: decrypt the VM bytecode to a clear image and emit the clear
SLEIGH spec (deterministic skeleton + P-Code semantics).

Why this exists
---------------
The VMSpec pipeline models the rolling opcode key as a SLEIGH *context
variable* in the constructor pattern (``byte = C + key - 1``). That is the
correct paper-level model, but Ghidra's disassembler cannot chain fall-through
across an opcode-byte constraint that depends on context (see
``docs/fallthrough-critique.md``). The working path is: decrypt the opcode and
operand bytes up-front with a flow-sensitive sweep (:mod:`vmspec.sweep`) and
emit a clear spec (constant ``byte = opcode`` patterns) via the two-phase
skeleton (:mod:`vmspec.skeleton` ``mode="clear"`` + :mod:`vmspec.semantics`).

Scope / limitations
-------------------
* The sweep stops at control-flow handlers (``jmp`` 0x304 / ``ret_native``
  0x7E9) because it cannot follow computed targets.
* Addresses are not relocated (size-preserving rewrite of the same blob).

Usage::

    python tools/decrypt_bytecode.py <blob> <config.json> <out_clear.bin> <out_clear.slaspec>
"""
from __future__ import annotations

import sys

from vmspec.config import load_config
from vmspec.operand import decrypt_operand, handler_key_update
from vmspec.semantics import handler_pcode
from vmspec.skeleton import generate_skeleton
from vmspec.sweep import sweep

ENGINE = 0x1AE1000
BC_OFF = 0x6575          # bytecode program entry (blob offset)
INITIAL_KEY = 0x407575   # dispatcher's initial 32-bit rolling key

# handler offset -> operand length (bytes following the encrypted opcode).
# Mirrors vmspec.vm.OPERAND_LEN.
OPERAND_LEN: dict[int, int] = {
    0x00A: 1, 0x038: 2, 0x065: 1, 0x08E: 1, 0x12B: 1,
    0x14D: 4, 0x7F4: 1, 0x81C: 2, 0xB54: 1,
}

_CONTROL_FLOW_OFF = frozenset({0x304, 0x7E9})  # handler offsets: jmp / ret_native


def main(argv: list[str]) -> int:
    blob_path = argv[0] if len(argv) > 0 else "data/vm_dbin.bin"
    config_path = argv[1] if len(argv) > 1 else "data/config.json"
    out_clear = argv[2] if len(argv) > 2 else "data/_clear.bin"
    out_spec = argv[3] if len(argv) > 3 else "data/_clear.slaspec"

    config = load_config(config_path)
    dbin = open(blob_path, "rb").read()
    tbl = config.dispatch_table or _load_table(dbin)

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

    # the clear spec: deterministic skeleton (constant byte=opcode) + P-Code.
    spec, infos = generate_skeleton(
        config.vm_state,
        config.handlers,
        config.dispatch_table,
        engine=config.base_addr or ENGINE,
        mode="clear",
        semantics=handler_pcode,
    )
    open(out_spec, "w", encoding="utf-8", newline="\n").write(spec)

    n_operands = sum(1 for o in result.operand_at.values() if o is not None)
    print(f"decrypted {len(result.opcode_at)} instructions ({result.states} states)")
    print(f"operands decrypted: {n_operands}")
    if result.conflicts:
        print(
            f"WARNING: {len(result.conflicts)} key conflicts: "
            f"{[f'0x{a:x}:[0x{k1:08x},0x{k2:08x}]' for a, k1, k2 in result.conflicts[:5]]}"
        )
    print(f"wrote {out_clear} + {out_spec} ({len(infos)} constructors)")
    return 0


def _load_table(dbin: bytes) -> list[int]:
    """Fallback: read the 256-entry dispatch table directly from the blob."""
    import struct

    return list(struct.unpack_from("<256I", dbin, 0x5000))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
