#!/usr/bin/env python3
"""Phase-6: decrypt the full VM bytecode (all segments) to a clear image and
emit the clear SLEIGH spec (deterministic skeleton + P-Code semantics).

Why this exists
---------------
The VMSpec pipeline models the rolling opcode key as a SLEIGH *context
variable* in the constructor pattern (``byte = C + key - 1``). That is the
correct paper-level model, but Ghidra's disassembler cannot chain fall-through
across an opcode-byte constraint that depends on context (see
``docs/fallthrough-critique.md``). The working path is: decrypt the opcode and
operand bytes up-front and emit a clear spec (constant ``byte = opcode``
patterns) via the two-phase skeleton (``mode="clear"`` + ``handler_pcode``).

The full program is followed with :func:`vmspec.vm.run` (the stack-machine
interpreter): it resolves the ``jmp`` (0x304) target and continues through every
segment until ``ret_native`` (0x7E9). This covers more than the sweep, which
stops at the first control-flow handler.

Scope / limitations
-------------------
* Addresses are not relocated (size-preserving rewrite of the same blob).
* Phase 2 / phase 3 (the re-entrant programs entered via the native stubs at
  KEY2/KEY3) are not yet followed; this materialises the first entry's segments.

Usage::

    python tools/decrypt_bytecode.py <blob> <config.json> <out_clear.bin> <out_clear.slaspec>
"""
from __future__ import annotations

import sys

from vmspec.config import load_config
from vmspec.semantics import handler_pcode
from vmspec.skeleton import generate_skeleton
from vmspec.vm import run

ENGINE = 0x1AE1000
BC_OFF = 0x6575          # bytecode program entry (blob offset)
INITIAL_KEY = 0x407575   # dispatcher's initial 32-bit rolling key


def main(argv: list[str]) -> int:
    blob_path = argv[0] if len(argv) > 0 else "data/vm_dbin.bin"
    config_path = argv[1] if len(argv) > 1 else "data/config.json"
    out_clear = argv[2] if len(argv) > 2 else "data/_clear.bin"
    out_spec = argv[3] if len(argv) > 3 else "data/_clear.slaspec"

    config = load_config(config_path)
    dbin = open(blob_path, "rb").read()
    tbl = config.dispatch_table or _load_table(dbin)

    # follow the full program (segments + jmp) with the stack-machine interpreter
    entry = ENGINE + BC_OFF
    trace = list(run(dbin, tbl, entry, INITIAL_KEY))

    # materialize the clear image (size-preserving: opcode + operands -> clear)
    clear = bytearray(dbin)
    for pc, op, _key, operand, olen in trace:
        off = pc - ENGINE
        clear[off] = op
        if operand:
            clear[off + 1:off + 1 + olen] = operand

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

    n_operands = sum(1 for _pc, _op, _k, operand, _o in trace if operand)
    segments = _segment_breaks(trace)
    last = trace[-1]
    print(f"decrypted {len(trace)} instructions ({n_operands} operands)")
    if segments:
        print(f"jumps: {segments}")
    print(f"last: pc=0x{last[0]:X} opcode=0x{last[1]:02X}")
    print(f"wrote {out_clear} + {out_spec} ({len(infos)} constructors)")
    return 0


def _segment_breaks(trace: list[tuple]) -> list[str]:
    """The (from, to) pc pairs where the control flow jumped (not fall-through)."""
    breaks: list[str] = []
    prev_pc = None
    prev_len = 0
    for pc, _op, _k, _operand, olen in trace:
        if prev_pc is not None and pc != prev_pc + 1 + prev_len:
            breaks.append(f"0x{prev_pc:X}->0x{pc:X}")
        prev_pc = pc
        prev_len = olen
    return breaks


def _load_table(dbin: bytes) -> list[int]:
    """Fallback: read the 256-entry dispatch table directly from the blob."""
    import struct

    return list(struct.unpack_from("<256I", dbin, 0x5000))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
