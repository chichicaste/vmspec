#!/usr/bin/env python3
"""Phase 1-2 automation: extract VM state + handler enumeration from vm_dbin.bin.

Reads the VM bytecode blob (a self-contained image: native handlers + dispatch
table + bytecode program) and emits a ``config.json`` describing the VM state
and the discovered opcode handlers, ready for the VMSpec pipeline
(``python -m vmspec <binary> <config.json>``).

The blob layout (VM-relative):
  0x0000..0x0BFF   native handler code (51 handlers)
  0x1000           scratch data region
  0x4000           relocation table
  0x5000           handler table (256 x u32: opcode -> handler offset)
  0x6575           bytecode program entry

Reference: arXiv:2610.29566 (VMSpec).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

# VM-relative constants (ENGINE is the host address where the blob is mapped).
ENGINE = 0x1AE1000
DISPATCHER = 0x1AE1198  # shared VM dispatcher (fetch + decrypt + jmp [eax*4+0x1ae6000])
TAB_OFF = 0x5000  # dispatch table: opcode -> handler offset (256 entries)
BC_OFF = 0x6575  # bytecode program entry
DATA_OFF = 0x1000  # scratch data region

# handler offset -> mnemonic (from the reconstructed interpreter semantics).
MNEMONICS: dict[int, str] = {
    0x00A: "ld_data_u16",
    0x02D: "ld_data_u32",
    0x038: "push_u16",
    0x058: "ld_u8",
    0x065: "push_u8",
    0x07F: "shr_u16",
    0x08E: "st_data_u16",
    0x0B0: "and",
    0x0BF: "push_sp16",
    0x0C9: "ld_u8",
    0x0D4: "shl_u16",
    0x0E2: "push_sp",
    0x0EB: "st_u32",
    0x0F4: "mul_u32",
    0x10F: "and_u16",
    0x12B: "push_i8",
    0x14D: "push_u32",
    0x163: "st_u32",
    0x16C: "add_u32",
    0x176: "pop",
    0x1B5: "shrd",
    0x1C3: "add_u16",
    0x267: "shl_u16",
    0x276: "ld_u32",
    0x27F: "st_u32",
    0x287: "add_u8",
    0x292: "set_sp",
    0x29A: "st_u8",
    0x2A5: "ld_u8",
    0x2B1: "st_u8",
    0x2BC: "ld_u32",
    0x2D1: "shr_u16",
    0x2DF: "div_u64",
    0x2EC: "and_not",
    0x2FB: "st_u16",
    0x304: "jmp",
    0x30A: "shr_u32",
    0x7E9: "ret_native",
    0x7F4: "ld_data_u8",
    0x810: "imul_u32",
    0x81C: "push_u16",
    0xB40: "ld_u16",
    0xB49: "st_data_u32",
    0xB54: "st_data_u8",
    0xB7E: "st_u16",
    0xB88: "st_u8",
    0xB92: "set_sp16",
    0xB99: "st_u16",
    0xBA3: "shld",
    0xBB1: "ld_u16",
    0xBBB: "shl_u32",
}


def extract_handlers(dbin: bytes) -> tuple[list[dict], list[int]]:
    """Enumerate handlers from the dispatch table at ``dbin + TAB_OFF``.

    Returns a tuple ``(handlers, dispatch_table)``:

    * ``handlers`` — one descriptor ``{opcode, entry, end, mnemonic}`` per
      unique handler offset (the ``opcode`` is the first/canonical table index
      that maps to that handler);
    * ``dispatch_table`` — the 256-entry opcode -> handler mapping (each value
      is the absolute handler entry address), so the SLEIGH generator can emit
      one constructor per table index: the dispatcher's rolling-key update is
      ``key -= opcode``, which is per-index, not per-handler.

    Every handler is native x86 that ends with an absolute ``jmp`` into the
    shared dispatcher inside the blob, so ``end`` is ``DISPATCHER`` for all
    handlers and is used by the DSE as the exploration terminator.
    """
    # group opcodes by handler offset, and record the full opcode -> entry map
    by_offset: dict[int, list[int]] = {}
    dispatch: list[int] = []
    for op in range(256):
        raw = struct.unpack_from("<I", dbin, TAB_OFF + op * 4)[0]
        by_offset.setdefault(raw - ENGINE, []).append(op)
        dispatch.append(raw)  # absolute handler entry address for this opcode

    handlers: list[dict] = []
    for off in sorted(by_offset):
        handlers.append(
            {
                "opcode": by_offset[off][0],
                "entry": ENGINE + off,
                "end": DISPATCHER,
                "mnemonic": MNEMONICS.get(off, f"handler_{off:04X}"),
            }
        )
    return handlers, dispatch


def build_vm_state() -> dict:
    """Return the VM state descriptor for the blob.

    Includes ``base_addr`` (the host address where the raw blob is mapped, so
    the pipeline loads it with angr's ``blob`` backend) and ``arch``.
    """
    return {
        "vpc": "VPC",
        "vsp": "VSP",
        "regions": [
            {"name": "code", "kind": "code"},
            {"name": "data", "kind": "state"},
            {"name": "stack", "kind": "stack"},
        ],
        "context": ["key"],
        "entry": ENGINE + BC_OFF,
        "base_addr": ENGINE,
        "arch": "x86",
    }


def gen_config(blob_path: str | Path, out_path: str | Path) -> dict:
    """Read the blob and write the config.json; returns the config dict."""
    dbin = Path(blob_path).read_bytes()
    config = build_vm_state()
    handlers, dispatch = extract_handlers(dbin)
    config["handlers"] = handlers
    config["dispatch_table"] = dispatch
    Path(out_path).write_text(json.dumps(config, indent=2) + "\n")
    return config


if __name__ == "__main__":
    import sys

    blob = sys.argv[1] if len(sys.argv) > 1 else "data/vm_dbin.bin"
    out = sys.argv[2] if len(sys.argv) > 2 else "data/config.json"
    cfg = gen_config(blob, out)
    print(f"wrote {out}: {len(cfg['handlers'])} handlers, vpc={cfg['vpc']}, "
          f"vsp={cfg['vsp']}, context={cfg['context']}, entry=0x{cfg['entry']:X}, "
          f"base_addr=0x{cfg['base_addr']:X}, arch={cfg['arch']}")
